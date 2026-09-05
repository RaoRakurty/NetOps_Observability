package platformdb

import (
	"context"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// backendkind.go — WHICH backend is active, and is it healthy (tracker 245).
//
// The selectors (main.newApplicationStore and friends) used to ask exactly one
// question — ActivePG() — and treat "not Postgres" as "anything else, silently".
// For a registry that has NO file implementation that answered "keep the
// records in RAM and lose them on the next restart", with nothing in the API or
// the UI able to say so (tracker 245: the Applications registry).
//
// A selector must therefore be able to ask a THIRD question: what backend did
// the operator actually configure? Kind() answers it, and it is the same value
// for the whole process life — there is no failover, by design: a Postgres
// outage must NEVER redirect authoritative writes into files or RAM, because
// records written elsewhere diverge from the authoritative store and nothing
// reconciles them afterwards.
//
// Health() is the second half: "configured postgres but the database is down"
// is a DIFFERENT state from "file backend, registry unsupported" and from
// "tenant genuinely has no records". Every one of the three is reportable.

// Backend kinds. These are the values STORE_BACKEND resolves to (main's
// initStoreBackend owns the env parsing; unknown values are a boot error there,
// never a silent downgrade to one of these).
const (
	// KindFile is the durable, dependency-free JSON-on-the-data-volume backend.
	// Explicit compatibility / Postgres-less mode.
	KindFile = "file"
	// KindPostgres is the authoritative, RLS-protected relational backend and
	// the default for new normal installations.
	KindPostgres = "postgres"
	// KindMemory is an EPHEMERAL development/test backend. It must only ever be
	// reached by explicit selection: nothing may fall back into it.
	KindMemory = "memory"
)

// kind is the active backend's kind, set together with `active` by the Use*
// functions. Guarded by the same "set once at boot, before any store is
// constructed" discipline as `active` itself.
var kind = KindFile

// Kind reports the active backend kind (one of KindFile/KindPostgres/KindMemory).
func Kind() string { return kind }

// IsPersistent reports whether a backend kind survives a process restart.
func IsPersistent(k string) bool { return k == KindFile || k == KindPostgres }

// Health probes the active backend and reports whether it can serve right now.
// The reason is operator-facing text, never a DSN, credential or raw driver
// error (which can carry the connection string).
func Health(ctx context.Context) (bool, string) {
	switch a := active.(type) {
	case *PGStore:
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := a.db.pool.Ping(pctx); err != nil {
			// Deliberately NOT err.Error(): pgx connection errors embed the DSN.
			return false, "database unavailable"
		}
		return true, ""
	case MemKV:
		return true, ""
	default:
		// File backend: the data volume is the store. A missing/unwritable root
		// is the only failure mode worth probing, and it is cheap.
		root := fileRoot
		if root == "" {
			return true, ""
		}
		if _, err := os.Stat(root); err != nil {
			return false, "data volume unavailable"
		}
		return true, ""
	}
}

// UseMemory selects the EPHEMERAL in-memory backend. It exists for tests and
// for a deliberate `STORE_BACKEND=memory` development run — never as a fallback
// from a persistent backend, and never in a packaged deployment default.
func UseMemory() {
	active = MemKV{m: &sync.Map{}}
	kind = KindMemory
}

// MemKV is an in-process Backend (+PrefixBackend). Nothing it holds survives the
// process. Handed out only by UseMemory.
type MemKV struct{ m *sync.Map }

func (k MemKV) Load(key string) ([]byte, error) {
	v, ok := k.m.Load(key)
	if !ok {
		return nil, &os.PathError{Op: "open", Path: key, Err: os.ErrNotExist}
	}
	b, _ := v.([]byte)
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (k MemKV) Save(key string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	k.m.Store(key, cp)
	return nil
}

// LoadPrefix implements the per-record capability so stores that opt into
// prefix persistence (devices) behave identically on this backend.
func (k MemKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	out := map[string][]byte{}
	keys := []string{}
	k.m.Range(func(key, _ any) bool {
		s, _ := key.(string)
		if strings.HasPrefix(s, prefix) {
			keys = append(keys, s)
		}
		return true
	})
	sort.Strings(keys)
	for _, s := range keys {
		b, err := k.Load(s)
		if err != nil {
			continue // raced with a Delete; an absent record is not an error
		}
		out[s] = b
	}
	return out, nil
}

func (k MemKV) Delete(key string) error {
	k.m.Delete(key)
	return nil
}
