// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultPath is where an operator drops a licence by hand (design §3:
// "drop the file at data/api/licence.json"). The api's data volume is mounted
// at /data, so the in-container path is /data/api/licence.json.
const DefaultPath = "/data/api/licence.json"

// Store owns the licence document's durable home and the evaluated State
// derived from it.
//
// Implementations MUST be safe for concurrent use: gates read State on
// admission paths while the platform-admin page installs a new file.
type Store interface {
	// State returns the current evaluated state, re-reading the backing file
	// when it has changed on disk. NEVER fails: a store that cannot read or
	// verify its file falls back to Community and puts the reason in
	// State.LoadError, because a licence problem must never be able to take the
	// product down — only to remove commercial capability.
	State() State
	// Reload forces a re-read regardless of the poll interval.
	Reload() State
	// Install validates raw and, only if it verifies, writes it durably and
	// returns the new state. A refused document NEVER reaches the disk.
	Install(raw []byte, now time.Time) (State, error)
	// Raw returns the installed document bytes, or an fs.ErrNotExist-wrapped
	// error when no licence is installed.
	Raw() ([]byte, error)
	// Remove deletes the installed licence and returns the resulting Community
	// state. Removing an absent licence is not an error.
	Remove() (State, error)
	// Path is the document's location, for the admin page and the runbook.
	Path() string
}

// FileStore is the file-backed Store: one JSON document at Path.
//
// It deliberately does NOT go through internal/platformdb. That package's
// Backend is pluggable (files or Postgres rows), and the licence must be a
// FILE the operator can copy in, copy out, diff, and verify offline with
// `correlix-licence verify` — a row in a database the customer cannot reach
// with an editor would break the design's offline promise.
//
// The durable-write contract is the platformdb one, reproduced here for exactly
// that reason: unique temp name in the same directory, then an atomic rename.
type FileStore struct {
	path     string
	verifier Verifier
	now      func() time.Time
	// poll bounds how often a State() call may stat the file. Gates call State()
	// on admission paths; a stat is cheap but not free, and a licence changes
	// about once a year.
	poll time.Duration

	mu        sync.Mutex
	state     State
	loaded    bool
	lastStat  time.Time
	stampSize int64
	stampMod  time.Time
}

// FileStoreOptions configures a FileStore. Every field has a working default so
// the common construction is NewFileStore(path, FileStoreOptions{}).
type FileStoreOptions struct {
	// Verifier defaults to DefaultVerifier() (the keys embedded in this build).
	Verifier Verifier
	// Now defaults to time.Now. Injected so grace and expiry are testable
	// without sleeping.
	Now func() time.Time
	// Poll is the minimum interval between change checks. Defaults to
	// DefaultPollInterval.
	Poll time.Duration
}

// DefaultPollInterval is how often State() will re-stat the licence file. Five
// seconds makes a hand-dropped file take effect promptly ("validated at boot
// and on change", design §3) without putting a syscall on every admission.
const DefaultPollInterval = 5 * time.Second

// NewFileStore builds a file-backed Store. It does not touch the disk: the
// first State() call loads, so construction cannot fail and a missing licence
// is never a boot error.
func NewFileStore(path string, opt FileStoreOptions) *FileStore {
	s := &FileStore{
		path:     path,
		verifier: opt.Verifier,
		now:      opt.Now,
		poll:     opt.Poll,
	}
	if s.verifier == nil {
		s.verifier = DefaultVerifier()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.poll <= 0 {
		s.poll = DefaultPollInterval
	}
	return s
}

func (s *FileStore) Path() string { return s.path }

// State returns the current state, reloading when the file changed.
func (s *FileStore) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.loaded {
		s.loadLocked(now)
		return s.state
	}
	if now.Sub(s.lastStat) < s.poll {
		return s.state
	}
	s.lastStat = now
	fi, err := os.Stat(s.path)
	switch {
	case err != nil:
		// Gone, or unreadable. If we were holding a licence, drop to Community
		// and say why; if we already were Community, nothing changed.
		if s.state.Source == SourceFile || s.state.LoadError != "" {
			s.loadLocked(now)
		}
		return s.state
	case fi.Size() != s.stampSize || !fi.ModTime().Equal(s.stampMod):
		s.loadLocked(now)
	default:
		// Unchanged bytes, but time moved: re-evaluate so a licence that crossed
		// its expiry or the end of its grace since the last read reports the new
		// state without anyone touching the file.
		s.reevaluateLocked(now)
	}
	return s.state
}

// Reload forces a re-read regardless of the poll interval.
func (s *FileStore) Reload() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked(s.now())
	return s.state
}

// loadLocked reads and verifies the file, or falls back to Community.
func (s *FileStore) loadLocked(now time.Time) {
	s.loaded = true
	s.lastStat = now
	s.stampSize, s.stampMod = 0, time.Time{}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		st := Community()
		if !errors.Is(err, fs.ErrNotExist) {
			// A licence file that exists but cannot be read is a real problem the
			// operator must see — but it still must not stop the product, so it
			// is Community plus a loud reason, never a boot failure.
			st.LoadError = fmt.Sprintf("cannot read %s: %v", s.path, err)
		}
		s.state = st
		return
	}
	if fi, statErr := os.Stat(s.path); statErr == nil {
		s.stampSize, s.stampMod = fi.Size(), fi.ModTime()
	}
	st, err := s.verifier.Verify(raw, now)
	if err != nil {
		bad := Community()
		bad.LoadError = err.Error()
		s.state = bad
		return
	}
	s.state = st
}

// reevaluateLocked re-runs the expiry/grace evaluation against a new `now`
// without re-reading the file.
func (s *FileStore) reevaluateLocked(now time.Time) {
	if s.state.Source != SourceFile {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	if st, err := s.verifier.Verify(raw, now); err == nil {
		s.state = st
	}
}

// Install validates raw and, only if it verifies, writes it durably.
//
// The order is the guarantee: a document that does not verify NEVER touches the
// disk, so a bad upload cannot displace a working licence. The operator gets the
// exact reason back and keeps the tier they had.
func (s *FileStore) Install(raw []byte, now time.Time) (State, error) {
	st, err := s.verifier.Verify(raw, now)
	if err != nil {
		return s.State(), err
	}
	if err := atomicWrite(s.path, raw); err != nil {
		return s.State(), fmt.Errorf("licence: verified but could not be stored at %s: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
	s.loaded = true
	s.lastStat = now
	if fi, statErr := os.Stat(s.path); statErr == nil {
		s.stampSize, s.stampMod = fi.Size(), fi.ModTime()
	}
	return st, nil
}

// Raw returns the installed document bytes.
func (s *FileStore) Raw() ([]byte, error) { return os.ReadFile(s.path) }

// Remove deletes the installed licence. Removing an absent one is not an error:
// the caller asked for "no licence installed" and that is the resulting state.
func (s *FileStore) Remove() (State, error) {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return s.State(), err
	}
	return s.Reload(), nil
}

// atomicWrite is the platformdb durable-write contract (internal/platformdb
// kv.go FileKV.Save), reproduced for the licence file's own path.
//
// The temp name is UNIQUE per call (os.CreateTemp) rather than a fixed
// "<path>.tmp": two concurrent writes of a fixed temp name corrupt each other
// (A writes tmp, B writes tmp, A renames, B's rename fails ENOENT and B's write
// is silently LOST). That bug cost the audit trail its durability once already;
// it is not repeated here.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	// 0750, not platformdb's 0755: /data/api is created by and for the api
	// process alone, and a licence is a commercial document nothing else on the
	// host has any business enumerating.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// Same directory ⇒ same filesystem ⇒ the rename below is atomic.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		// Litter cleanup on every failure path: the temp file is a
		// never-committed record nothing can read, and there is no useful
		// recovery from failing to abandon a file we are already abandoning.
		_ = tmp.Close()     // best-effort: closing an abandoned temp; the write error is what matters
		_ = os.Remove(name) // best-effort: unlink of an uncommitted temp
	}()
	// CreateTemp opens 0600; set it explicitly so the mode does not depend on
	// the process umask. The licence is not a secret, but it IS a signed
	// artifact whose integrity matters — world-writable would be wrong.
	if err := tmp.Chmod(0o600); err != nil {
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
