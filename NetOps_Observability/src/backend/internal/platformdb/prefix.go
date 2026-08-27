package platformdb

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// prefix.go — an OPTIONAL per-record capability on top of the blob Backend.
//
// WHY. The blob contract (one Save = one whole collection) is O(collection)
// per write: the device store's bulk onboarding measured 155 devices/s at
// small N collapsing to 14/s by 3.3k devices, because every Put re-marshalled
// and re-wrote the entire fleet (O(N²) total). Stores that need linear
// onboarding persist ONE RECORD PER KEY under a shared prefix instead, using
// the existing per-key Save as the upsert plus the two operations below.
//
// SCOPE. The capability is defined over the backend's BLOB key space only:
//   - FileKV: a key is a file path, so a prefix is a directory subtree;
//   - PGStore: a key is an app_kv row, so a prefix is a `key LIKE p||'%'`
//     scan. Keys that resolve to a NORMALIZED table (specFor) are out of
//     scope — callers of this capability must use keys whose basenames do not
//     collide with the rowSpecs registry (per-record keys are hash-named, so
//     they never do) and must not collide with the "import:done:" marker
//     namespace (per-record keys are absolute paths, so they never do).
//
// Prefixes and keys are SERVER-GENERATED (derived from a store's configured
// path plus a hex hash) — never attacker-controlled. The LIKE escaping in the
// PG implementation is defence in depth, not an input-validation boundary.

// PrefixBackend is the optional capability. A Backend that also implements it
// supports enumerating all records under a key prefix and deleting a single
// record. Deleting an absent key is NOT an error (deletes are idempotent).
type PrefixBackend interface {
	Backend
	// LoadPrefix returns every stored record whose key starts with prefix,
	// keyed by the FULL original key (so each key round-trips through
	// Save/Load/Delete unchanged). An empty result is (empty map, nil) —
	// "nothing stored yet" is an answer, not an error.
	LoadPrefix(prefix string) (map[string][]byte, error)
	// Delete removes one record. Absent key → nil.
	Delete(key string) error
}

// ErrNoPrefixCapability reports that the active backend is blob-only. Wiring
// should consult ActivePrefix at construction and fall back to whole-blob
// persistence instead of ever seeing this at runtime.
var ErrNoPrefixCapability = errors.New("active store backend does not support prefix operations")

// ActivePrefix reports whether the active backend implements the prefix
// capability, returning it when so. Wiring-time seam: callers decide
// per-record vs whole-blob persistence ONCE, at store construction.
func ActivePrefix() (PrefixBackend, bool) {
	pb, ok := active.(PrefixBackend)
	return pb, ok
}

// LoadPrefix / Delete delegate to the active backend (the package-level
// helpers mirror Load/Save so store seams stay backend-agnostic).
func LoadPrefix(prefix string) (map[string][]byte, error) {
	pb, ok := active.(PrefixBackend)
	if !ok {
		return nil, ErrNoPrefixCapability
	}
	return pb.LoadPrefix(prefix)
}

func Delete(key string) error {
	pb, ok := active.(PrefixBackend)
	if !ok {
		return ErrNoPrefixCapability
	}
	return pb.Delete(key)
}

// ---- FileKV ----------------------------------------------------------------

// LoadPrefix walks the directory subtree the prefix maps to. A prefix ending
// in "/" is the directory itself; otherwise the walk starts at the parent
// directory and filters on the full prefix. A directory that does not exist
// yet is an empty store, not an error. In-flight atomic-write temporaries
// (Save's "<key>.tmp") are never committed records and are skipped.
//
// The walk and every read are ROOT-SCOPED (os.OpenRoot): a symlink planted
// inside the subtree cannot pull the scan outside it (TOCTOU traversal,
// gosec G122).
//
// The per-file READS run on a BOUNDED WORKER POOL. A directory's blocking
// fs.ReadFile syscalls are the cost here; done one-at-a-time a lab subtree of
// 38,666 deletion tombstones took >6 min of uninterruptible disk I/O and
// wedged boot before the api ever reached its listener. A single walk
// goroutine still enumerates paths (preserving the exact skip/prefix
// semantics); each qualifying file's read is handed to the pool, and results
// merge into `out` under a mutex. Correctness is unchanged: keys are unique
// per path, so no read can overwrite or drop another's entry.
func (f FileKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	resolved := f.resolve(prefix)
	// resolve() joins relative keys under the root via filepath.Join, which
	// strips a trailing separator — restore it so a directory-style prefix
	// stays directory-style and key reconstruction below stays exact.
	if strings.HasSuffix(prefix, "/") && !strings.HasSuffix(resolved, "/") {
		resolved += "/"
	}
	dir := resolved
	if !strings.HasSuffix(resolved, "/") {
		dir = filepath.Dir(resolved)
	}
	dir = filepath.Clean(dir)
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][]byte{}, nil // no subtree yet = nothing stored under the prefix
	}
	if err != nil {
		return nil, fmt.Errorf("open prefix %s: %w", prefix, err)
	}
	defer func() { _ = root.Close() }() // read-only handle; Close cannot lose data
	rfs := root.FS()

	// Bound concurrency: enough to overlap disk I/O without spawning one
	// goroutine per (potentially tens of thousands of) files.
	bound := runtime.GOMAXPROCS(0) * 4
	if bound > 32 {
		bound = 32
	}
	if bound < 1 {
		bound = 1
	}
	sem := make(chan struct{}, bound) // bounded pool of read slots
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex // guards out and firstErr
		out      = map[string][]byte{}
		firstErr error
	)
	// fail records the FIRST read/walk error and cancels the context so the
	// walk stops enumerating and any slot-blocked dispatch unblocks promptly.
	fail := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
			cancel()
		}
		mu.Unlock()
	}

	walkErr := fs.WalkDir(rfs, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return fs.SkipAll // a read already failed; stop enumerating
		}
		full := filepath.Join(dir, p)
		if d.IsDir() || strings.HasSuffix(full, ".tmp") || !strings.HasPrefix(full, resolved) {
			return nil
		}
		// resolve() only prepends fileRoot, so full == resolved + suffix and
		// the original (unresolved) key reconstructs as prefix + suffix. This
		// is a pure string op on walk-local values — safe to compute here.
		key := prefix + strings.TrimPrefix(full, resolved)
		// Acquire a pool slot, honouring cancellation so a failed read cannot
		// leave the walk blocked on a full semaphore.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return fs.SkipAll
		}
		wg.Add(1)
		go func(p, key string) {
			defer wg.Done()
			defer func() { <-sem }()
			b, err := fs.ReadFile(rfs, p) // root-scoped: cannot follow a link out of dir
			if err != nil {
				fail(err)
				return
			}
			mu.Lock()
			out[key] = b
			mu.Unlock()
		}(p, key)
		return nil
	})
	wg.Wait() // all in-flight reads have finished; out/firstErr now stable

	// A directory-enumeration error is a scan failure just like a read error.
	// SkipAll is our own cancellation signal (WalkDir maps it to a nil return),
	// not a real error.
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		fail(walkErr)
	}
	if firstErr != nil {
		return nil, fmt.Errorf("scan prefix %s: %w", prefix, firstErr)
	}
	return out, nil
}

// Delete removes the record's file. Absent file → nil (idempotent).
func (f FileKV) Delete(key string) error {
	if err := os.Remove(f.resolve(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ---- PGStore ---------------------------------------------------------------

// escapeLike neutralizes LIKE metacharacters in a prefix so it matches
// literally (paired with ESCAPE '\'). Keys are server-generated (see the
// header) — this is defence in depth, not input validation.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// LoadPrefix scans app_kv rows under the prefix. Blob key space only — see
// the SCOPE note in the file header.
func (p *PGStore) LoadPrefix(prefix string) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, err := p.db.pool.Query(ctx,
		`SELECT key, data FROM app_kv WHERE key LIKE $1 ESCAPE '\'`, escapeLike(prefix)+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var key string
		var data []byte
		if err := rows.Scan(&key, &data); err != nil {
			return nil, err
		}
		out[key] = data
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes one app_kv row. Absent row → nil (DELETE of zero rows is not
// an error; idempotent by construction).
func (p *PGStore) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := p.db.pool.Exec(ctx, `DELETE FROM app_kv WHERE key = $1`, key)
	return err
}
