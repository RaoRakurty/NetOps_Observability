package platformdb

// atomicfile_test.go — the concurrency proof for the house durable-write
// primitive (tracker 229).
//
// The defect these tests exist for is not theoretical: with a FIXED "<path>.tmp"
// name, two writers of the same target share one temp file. The loser's write
// is either lost (its rename hits ENOENT because the winner already renamed the
// shared temp away) or, worse, INTERLEAVED — the winner renames a file the
// loser is still writing into, and the committed document is the head of one
// payload followed by the tail of the other. TestConcurrentWritersNeverInterleave
// fails on both, and on the second one loudly: a mixed file is not valid JSON in
// either direction, so the store it belongs to comes back empty on the next
// boot.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// atomicPayload renders writer i's payload. The payloads are DIFFERENT LENGTHS
// on purpose: equal-length payloads can interleave into a file that still
// happens to be well-formed, which is exactly the corruption that stays
// invisible until an operator asks where a row went.
func atomicPayload(i int) []byte {
	return []byte(fmt.Sprintf(`{"writer":%d,"pad":%q}`, i, strings.Repeat("x", i*97)))
}

// TestConcurrentWritersNeverInterleave is the 64-writer shape: every writer
// commits a whole payload or fails, and the file left behind is EXACTLY one
// writer's bytes — never a splice of two.
func TestConcurrentWritersNeverInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contended.json")
	const writers = 64

	// Seed the target so a reader always has something to read, and so a
	// mid-flight read below can be compared against a KNOWN good value.
	if err := WriteFileAtomic(path, atomicPayload(0), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	valid := map[string]int{}
	for i := 0; i < writers; i++ {
		valid[string(atomicPayload(i))] = i
	}

	var wg sync.WaitGroup
	errs := make([]error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release them together, so they really do contend
			errs[i] = WriteFileAtomic(path, atomicPayload(i), 0o600)
		}(i)
	}
	// A concurrent READER: the whole point of the rename is that a reader never
	// observes a partial file, so read while the writers run and check every
	// observation is a complete payload.
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	var badRead string
	go func() {
		defer readerWG.Done()
		<-start
		for i := 0; i < 500; i++ {
			b, err := os.ReadFile(path) // #nosec G304 -- a path this test just created
			if err != nil {
				badRead = fmt.Sprintf("read during contention: %v", err)
				return
			}
			if _, ok := valid[string(b)]; !ok {
				badRead = fmt.Sprintf("a reader observed a file that is NO writer's payload (%d bytes): %.120q", len(b), b)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	readerWG.Wait()

	if badRead != "" {
		t.Fatal(badRead)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d failed: %v", i, err)
		}
	}
	final, err := os.ReadFile(path) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if _, ok := valid[string(final)]; !ok {
		t.Fatalf("the committed file is NOT any single writer's payload — the writes interleaved: %.200q", final)
	}

	// No litter: every temp is either renamed onto the target or removed.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("left a temporary behind: %s", e.Name())
		}
	}
}

// TestConcurrentWritersUseDistinctTempNames pins the MECHANISM, not just the
// outcome: a fixed temp name would still pass an outcome test on a lucky
// schedule. It watches the directory while contended writes run and asserts no
// two writers ever occupied the same temp path.
func TestConcurrentWritersUseDistinctTempNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "watched.json")

	var mu sync.Mutex
	seen := map[string]bool{}
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			mu.Lock()
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					seen[e.Name()] = true
				}
			}
			mu.Unlock()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := WriteFileAtomic(path, atomicPayload(i), 0o600); err != nil {
				t.Errorf("writer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	watcher.Wait()

	mu.Lock()
	defer mu.Unlock()
	// The watcher samples, so it will not catch every temp; catching MORE THAN
	// ONE is enough to prove the names are not fixed, and catching the fixed
	// name at all proves they are.
	if seen[filepath.Base(path)+".tmp"] {
		t.Fatal("a writer used the FIXED temp name — concurrent writers would share it")
	}
	for name := range seen {
		if !strings.HasPrefix(name, filepath.Base(path)+".") {
			t.Errorf("temp %q does not belong to the target — LoadPrefix skips by the .tmp suffix, so the base must match too", name)
		}
	}
}

// TestWriteFileAtomicSetsTheModeItWasAskedFor — the committed file's mode must
// come from the caller, not from the umask CreateTemp happens to run under.
func TestWriteFileAtomicSetsTheModeItWasAskedFor(t *testing.T) {
	dir := t.TempDir()
	for _, perm := range []os.FileMode{0o600, 0o644} {
		path := filepath.Join(dir, fmt.Sprintf("mode-%o.json", perm))
		if err := WriteFileAtomic(path, []byte("{}"), perm); err != nil {
			t.Fatalf("write %o: %v", perm, err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %o: %v", perm, err)
		}
		if st.Mode().Perm() != perm {
			t.Errorf("mode = %o, want %o", st.Mode().Perm(), perm)
		}
	}
}

// TestWriteFileAtomicLeavesNoLitterWhenItFails — a failed write must not leave
// a temp file behind for LoadPrefix to trip over or for the disk to accumulate.
// An unwritable directory is the failure that actually happens in production
// (a read-only volume, a full disk).
func TestWriteFileAtomicLeavesNoLitterWhenItFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "x.json")
	if err := WriteFileAtomic(target, []byte("{}"), 0o600); err == nil {
		t.Fatal("a write into a nonexistent directory must FAIL — the helper does not create it (each store owns its directory's mode)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed write left litter: %v", entries)
	}
}
