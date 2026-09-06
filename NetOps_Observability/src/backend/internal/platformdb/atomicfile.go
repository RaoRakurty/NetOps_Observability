package platformdb

// atomicfile.go — the house durable-write primitive, lifted out of
// FileKV.Save so every file-backed store in the backend shares ONE
// implementation of it instead of a copy each.
//
// Why it is shared rather than re-derived per store: the copies drifted, and
// the drift was invisible. `Save` learned the unique temp name in 7ec92152
// after the audit trail lost writes on every restart; eleven other call sites
// kept writing `path + ".tmp"` and kept the race (tracker 229). A store that
// wants a durable write should not have to know the failure mode to avoid it.

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path durably: a temp file in the SAME
// directory (so the rename below cannot cross a filesystem boundary and is
// therefore atomic), then a rename over the target. A reader either sees the
// previous contents or the new ones — never a truncated or interleaved file.
//
// The temp name is UNIQUE per call (os.CreateTemp). A FIXED "<path>.tmp" makes
// two concurrent writers of the same target corrupt each other:
//
//	A: write tmp → B: write tmp → A: rename(tmp,path) ok → B: rename(tmp,path) ENOENT
//
// — B's write is silently LOST, and the only trace is an ENOENT on a rename
// that names a file the caller believed it had just written. Worse, if B's
// payload is longer than A's, A can rename a file B is still mid-write into: a
// reader then gets a document that is half A and half B, valid JSON in neither
// direction. That bug cost the audit trail its durability once already.
//
// The name keeps the ".tmp" SUFFIX ("<base>.<random>.tmp") because LoadPrefix
// skips in-flight temporaries by exactly that suffix — see prefix.go.
//
// perm is the mode the COMMITTED file ends up with; it is set explicitly on the
// temp before the rename so the result never depends on the process umask.
// The parent directory is NOT created here: a store knows what mode its own
// directory must have (0700 for sealed blobs, 0750 for the licence, 0755 for
// the shared data root), and guessing on its behalf is how a private tree ends
// up world-readable.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		// Litter cleanup on every failure path. The temp file is a
		// never-committed record nothing can read, and there is no useful
		// recovery from failing to abandon a file we are already abandoning —
		// the returned error is the one the caller must act on.
		_ = tmp.Close()     // best-effort: closing an abandoned temp file; the write error is what matters
		_ = os.Remove(name) // best-effort: unlink of an uncommitted temp; nothing can read it either way
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	committed = true
	return nil
}
