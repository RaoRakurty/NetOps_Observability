// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package credfile reads a service credential from a FILE, so the secret never
// has to travel in a URL, an argv or a container's declared environment
// (tracker 367 layer 1; CLAUDE.md §8).
//
// The file is the one scripts/install.py renders from .env into a read-only,
// bind-mounted DIRECTORY (data/secrets/<group>/<identity>/password). Mounting
// the directory rather than the file is what makes rotation live: an atomic
// rename on the host shows up as a new inode inside the container, and File
// notices it within one recheck interval — no restart.
//
// Contract (each point is tested):
//
//   - The file is re-stat'ed at most once per recheck interval (default 1 s),
//     and re-read only when its identity (device+inode), size or mtime changed.
//   - One trailing "\n" is trimmed; nothing else is. A value that is empty,
//     longer than MaxSecretBytes, or contains a byte outside printable ASCII
//     (0x20–0x7E) is refused — a stray CR, NUL or second line is a broken
//     render, not part of the password.
//   - A transient failure (stat/read error, a refused value mid-rewrite) keeps
//     the LAST GOOD value: a credential that was valid a second ago is still
//     the best answer, and dropping it would turn a host hiccup into an outage.
//   - A credential that has NEVER loaded is an error, always. Callers must
//     refuse to send the request — never fall back to an anonymous one.
//   - Errors describe the file and the failure, never the value.
//
// Safe for concurrent use. Dependency-free (stdlib only, §6).
package credfile

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// MaxSecretBytes bounds a credential. Generated service passwords are 24
// characters; a kilobyte is generous for any operator-supplied value and small
// enough that a wrong path (a log, a binary) is refused rather than sent.
const MaxSecretBytes = 1024

// DefaultRecheck is how often the file's identity is re-checked.
const DefaultRecheck = time.Second

var (
	// ErrNotLoaded: no valid value has ever been read. The caller must not
	// send the request it wanted the credential for.
	ErrNotLoaded = errors.New("credential has never loaded")
	// ErrEmpty: the file is empty (after trimming one trailing newline).
	ErrEmpty = errors.New("credential file is empty")
	// ErrTooLarge: the file holds more than MaxSecretBytes.
	ErrTooLarge = fmt.Errorf("credential file is larger than %d bytes", MaxSecretBytes)
	// ErrNonPrintable: a byte outside printable ASCII (0x20–0x7E).
	ErrNonPrintable = errors.New("credential contains a byte outside printable ASCII")
	// ErrNotRegular: the path is a directory, device, socket …
	ErrNotRegular = errors.New("credential path is not a regular file")
)

// FS is the filesystem seam. The default is the real OS; tests inject faults.
type FS interface {
	Stat(name string) (fs.FileInfo, error)
	Open(name string) (io.ReadCloser, error)
}

type osFS struct{}

func (osFS) Stat(name string) (fs.FileInfo, error) { return os.Stat(name) }

func (osFS) Open(name string) (io.ReadCloser, error) {
	// #nosec G304 -- the path is operator configuration (a *_PASSWORD_FILE env var naming a mounted secret), not request input
	return os.Open(name)
}

// Options tunes a File. The zero value is the production configuration.
type Options struct {
	// Recheck is the minimum interval between stat calls. <= 0 means
	// DefaultRecheck.
	Recheck time.Duration
	// Now is the clock. nil means time.Now.
	Now func() time.Time
	// FS is the filesystem. nil means the real OS.
	FS FS
	// OnStateChange is called when the error state CHANGES: with the new
	// error when a failure differs from the last one reported, and with nil
	// once a refresh succeeds again. It runs while the File's mutex is held,
	// so it must not call back into the File. It is never given a secret.
	// nil disables it.
	OnStateChange func(err error)
}

// File is a file-backed secret.
type File struct {
	path string
	opt  Options

	mu           sync.Mutex
	value        string
	loaded       bool
	held         fs.FileInfo // identity of the file the held value came from
	checked      time.Time   // last stat attempt (zero = never)
	lastErr      error       // most recent failure; nil after a success
	lastReported string      // dedupes OnStateChange
	failures     uint64      // every failed refresh, for a counter metric
}

// New returns a File for path. It does not touch the filesystem: the first
// Value call loads it, so construction never fails on a not-yet-rendered file
// and the error surfaces on the request path, where it is acted on.
func New(path string, opt Options) (*File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("credfile: empty path")
	}
	if opt.Recheck <= 0 {
		opt.Recheck = DefaultRecheck
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.FS == nil {
		opt.FS = osFS{}
	}
	return &File{path: path, opt: opt}, nil
}

// Path is the file this credential is read from (safe to log).
func (f *File) Path() string { return f.path }

// Value returns the current credential. It re-checks the file at most once
// per recheck interval. It returns an error wrapping ErrNotLoaded until a
// valid value has been read at least once; after that, transient failures
// keep returning the last good value (see Status for the failure itself).
func (f *File) Value() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.opt.Now()
	if f.checked.IsZero() || now.Sub(f.checked) >= f.opt.Recheck || now.Before(f.checked) {
		f.checked = now
		f.refreshLocked()
	}
	if !f.loaded {
		if f.lastErr != nil {
			return "", fmt.Errorf("%w from %s: %w", ErrNotLoaded, f.path, f.lastErr)
		}
		return "", fmt.Errorf("%w from %s", ErrNotLoaded, f.path)
	}
	return f.value, nil
}

// Status reports whether a value is held, the total number of failed
// refreshes, and the most recent failure (nil when the last refresh succeeded).
func (f *File) Status() (loaded bool, failures uint64, lastErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded, f.failures, f.lastErr
}

func (f *File) refreshLocked() {
	fi, err := f.opt.FS.Stat(f.path)
	if err != nil {
		f.failLocked(fmt.Errorf("stat %s: %w", f.path, err))
		return
	}
	if !fi.Mode().IsRegular() {
		f.failLocked(fmt.Errorf("%s: %w", f.path, ErrNotRegular))
		return
	}
	if f.loaded && f.held != nil && unchanged(f.held, fi) {
		f.okLocked()
		return
	}
	v, err := f.read()
	if err != nil {
		f.failLocked(fmt.Errorf("%s: %w", f.path, err))
		return
	}
	f.value, f.loaded, f.held = v, true, fi
	f.okLocked()
}

// unchanged: same inode on the same device, same size, same mtime. A rename
// over the path (the renderer's atomic write) changes the inode; an in-place
// rewrite changes size or mtime.
func unchanged(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func (f *File) read() (string, error) {
	rc, err := f.opt.FS.Open(f.path)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }() // read-only handle; a close error cannot lose data
	// +2: one byte over the limit plus the allowed trailing newline is
	// enough to tell "too large" from "exactly at the limit".
	raw, err := io.ReadAll(io.LimitReader(rc, MaxSecretBytes+2))
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return Parse(raw)
}

// Parse applies the credential format to raw file bytes: trim ONE trailing
// "\n", then refuse empty, oversized or non-printable values. Exposed so other
// readers of the same files (and their tests) share one definition.
func Parse(raw []byte) (string, error) {
	s := string(raw)
	s = strings.TrimSuffix(s, "\n")
	if len(s) == 0 {
		return "", ErrEmpty
	}
	if len(s) > MaxSecretBytes {
		return "", ErrTooLarge
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
			return "", ErrNonPrintable
		}
	}
	return s, nil
}

func (f *File) failLocked(err error) {
	f.lastErr = err
	f.failures++
	if msg := err.Error(); msg != f.lastReported {
		f.lastReported = msg
		if f.opt.OnStateChange != nil {
			f.opt.OnStateChange(err)
		}
	}
}

func (f *File) okLocked() {
	f.lastErr = nil
	if f.lastReported != "" {
		f.lastReported = ""
		if f.opt.OnStateChange != nil {
			f.opt.OnStateChange(nil)
		}
	}
}

// Basic is an HTTP Basic credential whose password is file-backed.
type Basic struct {
	user string
	pw   *File
}

// NewBasic validates the username (non-empty, printable ASCII, no ':' — RFC
// 7617 forbids it in a user-id) and binds it to the password file.
func NewBasic(user string, pw *File) (*Basic, error) {
	if pw == nil {
		return nil, errors.New("credfile: nil password file")
	}
	if user == "" {
		return nil, errors.New("credfile: empty username")
	}
	if strings.ContainsRune(user, ':') {
		return nil, errors.New("credfile: username contains ':'")
	}
	if _, err := Parse([]byte(user)); err != nil {
		return nil, fmt.Errorf("credfile: username: %w", err)
	}
	return &Basic{user: user, pw: pw}, nil
}

// User is the username (not a secret).
func (b *Basic) User() string { return b.user }

// File is the password source.
func (b *Basic) File() *File { return b.pw }

// Header returns the Authorization header value ("Basic <base64>"), or an
// error wrapping ErrNotLoaded when the password has never loaded.
func (b *Basic) Header() (string, error) {
	pw, err := b.pw.Value()
	if err != nil {
		return "", err
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(b.user+":"+pw)), nil
}
