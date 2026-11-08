// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package credfile

import (
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a manual clock: tests advance it past the recheck interval
// explicitly, so nothing here sleeps or depends on wall time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// faultFS wraps the real OS and can be told to fail Stat or Open, and counts
// both so the rate limit and the change detection are observable.
type faultFS struct {
	mu         sync.Mutex
	failStat   error
	failOpen   error
	stats      int
	opens      int
	underlying FS
}

func (f *faultFS) Stat(name string) (fs.FileInfo, error) {
	f.mu.Lock()
	f.stats++
	err := f.failStat
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.underlying.Stat(name)
}

func (f *faultFS) Open(name string) (io.ReadCloser, error) {
	f.mu.Lock()
	f.opens++
	err := f.failOpen
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.underlying.Open(name)
}

func (f *faultFS) set(stat, open error) {
	f.mu.Lock()
	f.failStat, f.failOpen = stat, open
	f.mu.Unlock()
}

func (f *faultFS) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, f.opens
}

// writeAtomic replaces path the way scripts/install.py does: temp + rename,
// so the path gets a NEW inode.
func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

func fixture(t *testing.T, content string) (string, *clock, *faultFS, *File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	writeAtomic(t, path, content)
	c := newClock()
	ffs := &faultFS{underlying: osFS{}}
	f, err := New(path, Options{Now: c.Now, FS: ffs})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return path, c, ffs, f
}

func mustValue(t *testing.T, f *File, want string) {
	t.Helper()
	got, err := f.Value()
	if err != nil {
		t.Fatalf("Value: unexpected error %v", err)
	}
	if got != want {
		t.Fatalf("Value = %q, want %q", got, want)
	}
}

func TestParseFormat(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
		err  error
	}{
		{"plain", "s3cret", "s3cret", nil},
		{"one trailing newline trimmed", "s3cret\n", "s3cret", nil},
		{"only ONE newline trimmed", "s3cret\n\n", "", ErrNonPrintable},
		{"CRLF is not trimmed", "s3cret\r\n", "", ErrNonPrintable},
		{"leading/inner space kept", " a b ", " a b ", nil},
		{"empty", "", "", ErrEmpty},
		{"newline only", "\n", "", ErrEmpty},
		{"NUL refused", "a\x00b", "", ErrNonPrintable},
		{"tab refused", "a\tb", "", ErrNonPrintable},
		{"DEL refused", "a\x7fb", "", ErrNonPrintable},
		{"UTF-8 refused", "pässword", "", ErrNonPrintable},
		{"second line refused", "a\nb", "", ErrNonPrintable},
		{"exactly the limit", strings.Repeat("x", MaxSecretBytes), strings.Repeat("x", MaxSecretBytes), nil},
		{"limit plus newline", strings.Repeat("x", MaxSecretBytes) + "\n", strings.Repeat("x", MaxSecretBytes), nil},
		{"one over the limit", strings.Repeat("x", MaxSecretBytes+1), "", ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse([]byte(tc.raw))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("Parse(%q) err = %v, want %v", tc.raw, err, tc.err)
				}
				if got != "" {
					t.Fatalf("Parse returned a value alongside an error: %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Parse(%q) = %q, %v — want %q", tc.raw, got, err, tc.want)
			}
		})
	}
}

func TestFileLoadsAndTrims(t *testing.T) {
	_, _, _, f := fixture(t, "pw-one\n")
	mustValue(t, f, "pw-one")
	if loaded, failures, lastErr := f.Status(); !loaded || lastErr != nil || failures != 0 {
		t.Fatalf("Status = %v %v %d, want loaded, no error, 0 failures", loaded, lastErr, failures)
	}
}

// A rotated file (atomic rename = new inode) is picked up after the recheck
// interval and not before.
func TestFilePicksUpRotationAfterRecheck(t *testing.T) {
	path, c, _, f := fixture(t, "old")
	mustValue(t, f, "old")
	writeAtomic(t, path, "new")
	mustValue(t, f, "old") // within the interval: no re-stat
	c.Advance(DefaultRecheck)
	mustValue(t, f, "new")
}

// An in-place rewrite (same inode) is detected by size/mtime.
func TestFilePicksUpInPlaceRewrite(t *testing.T) {
	path, c, _, f := fixture(t, "aaaa")
	mustValue(t, f, "aaaa")
	if err := os.WriteFile(path, []byte("bbbbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Advance(DefaultRecheck)
	mustValue(t, f, "bbbbbb")
}

// Stat is rate-limited, and an unchanged file is never re-read.
func TestFileRateLimitsStatAndSkipsUnchangedRead(t *testing.T) {
	_, c, ffs, f := fixture(t, "pw")
	for i := 0; i < 50; i++ {
		mustValue(t, f, "pw")
	}
	if stats, opens := ffs.counts(); stats != 1 || opens != 1 {
		t.Fatalf("50 calls inside one interval: stats=%d opens=%d, want 1/1", stats, opens)
	}
	c.Advance(DefaultRecheck)
	mustValue(t, f, "pw")
	if stats, opens := ffs.counts(); stats != 2 || opens != 1 {
		t.Fatalf("after one interval on an unchanged file: stats=%d opens=%d, want 2/1", stats, opens)
	}
}

// The core availability promise: a transient failure keeps the last good
// value, reports the failure once, and recovers.
func TestFileTransientErrorKeepsLastGood(t *testing.T) {
	path, c, ffs, _ := fixture(t, "good")
	var mu sync.Mutex
	var events []error
	f, err := New(path, Options{Now: c.Now, FS: ffs, OnStateChange: func(e error) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustValue(t, f, "good")

	ffs.set(errors.New("EIO"), nil)
	for i := 0; i < 3; i++ {
		c.Advance(DefaultRecheck)
		mustValue(t, f, "good")
	}
	loaded, failures, lastErr := f.Status()
	if !loaded || lastErr == nil || failures != 3 {
		t.Fatalf("during the fault: Status = %v %v %d, want loaded + error + 3 failures", loaded, lastErr, failures)
	}

	// A refused value mid-rewrite (empty file) is ALSO transient.
	ffs.set(nil, nil)
	writeAtomic(t, path, "")
	c.Advance(DefaultRecheck)
	mustValue(t, f, "good")

	writeAtomic(t, path, "better")
	c.Advance(DefaultRecheck)
	mustValue(t, f, "better")
	if _, _, lastErr := f.Status(); lastErr != nil {
		t.Fatalf("recovered, but Status still reports %v", lastErr)
	}

	mu.Lock()
	defer mu.Unlock()
	// Dedupe: three identical stat failures report ONCE; the empty-file
	// refusal is a different failure; then one recovery.
	if len(events) != 3 || events[0] == nil || events[1] == nil || events[2] != nil {
		t.Fatalf("OnStateChange events = %v, want [stat-error, empty-error, nil]", events)
	}
	if !errors.Is(events[1], ErrEmpty) {
		t.Fatalf("second event = %v, want ErrEmpty", events[1])
	}
}

// Fail closed: a credential that never loaded is an error on every call, and
// the error says why — without leaking anything.
func TestFileNeverLoadedRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"missing": func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
		"empty": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "password")
			writeAtomic(t, p, "")
			return p
		},
		"too large": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "password")
			writeAtomic(t, p, strings.Repeat("y", MaxSecretBytes+5))
			return p
		},
		"directory": func(t *testing.T) string { return t.TempDir() },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			f, err := New(mk(t), Options{Now: c.Now})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				v, err := f.Value()
				if !errors.Is(err, ErrNotLoaded) {
					t.Fatalf("Value err = %v, want ErrNotLoaded", err)
				}
				if v != "" {
					t.Fatalf("Value returned %q alongside ErrNotLoaded", v)
				}
				c.Advance(DefaultRecheck)
			}
			if loaded, _, _ := f.Status(); loaded {
				t.Fatal("Status reports loaded for a credential that never loaded")
			}
		})
	}
}

// A file that appears AFTER the first failed attempt (render raced the
// container start) is picked up on the next recheck.
func TestFileLateRenderIsPickedUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	c := newClock()
	f, err := New(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Value(); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("before render: err = %v", err)
	}
	writeAtomic(t, path, "late")
	c.Advance(DefaultRecheck)
	mustValue(t, f, "late")
}

func TestErrorsNeverCarryTheSecret(t *testing.T) {
	const secret = "TOPSECRET-VALUE"
	path, c, ffs, f := fixture(t, secret)
	mustValue(t, f, secret)
	writeAtomic(t, path, secret+"\x00") // refused value that CONTAINS the secret
	c.Advance(DefaultRecheck)
	if _, err := f.Value(); err != nil {
		t.Fatalf("last good must still be served: %v", err)
	}
	_, _, lastErr := f.Status()
	if lastErr == nil || strings.Contains(lastErr.Error(), secret) {
		t.Fatalf("lastErr = %v — must exist and must not contain the secret", lastErr)
	}
	ffs.set(nil, errors.New("open failed"))
	c.Advance(DefaultRecheck)
	if _, err := f.Value(); err != nil {
		t.Fatalf("last good must survive an open failure: %v", err)
	}
}

func TestNewRejectsEmptyPath(t *testing.T) {
	if _, err := New("  ", Options{}); err == nil {
		t.Fatal("New accepted an empty path")
	}
}

func TestBasicHeader(t *testing.T) {
	_, _, _, f := fixture(t, "pa:ss\n")
	b, err := NewBasic("svc-api", f)
	if err != nil {
		t.Fatal(err)
	}
	h, err := b.Header()
	if err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc-api:pa:ss"))
	if h != want {
		t.Fatalf("Header = %q, want %q", h, want)
	}
	if b.User() != "svc-api" || b.File() != f {
		t.Fatal("accessors do not round-trip")
	}
}

func TestBasicRefusesWhenPasswordNeverLoaded(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "absent"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBasic("svc-api", f)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := b.Header(); !errors.Is(err, ErrNotLoaded) || h != "" {
		t.Fatalf("Header = %q, %v — want empty + ErrNotLoaded", h, err)
	}
}

func TestNewBasicValidatesUser(t *testing.T) {
	_, _, _, f := fixture(t, "pw")
	for _, bad := range []string{"", "a:b", "svc\napi", "svc\x00"} {
		if _, err := NewBasic(bad, f); err == nil {
			t.Fatalf("NewBasic accepted username %q", bad)
		}
	}
	if _, err := NewBasic("svc-api", nil); err == nil {
		t.Fatal("NewBasic accepted a nil file")
	}
}

// Concurrent readers during rotation: every value observed is one of the two
// complete values — never torn, never empty, never an error once loaded. The
// -race detector (CI only on this host) is what makes this test sharp.
func TestFileConcurrentUseDuringRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	writeAtomic(t, path, "alpha")
	f, err := New(path, Options{Recheck: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	mustValue(t, f, "alpha")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				v, err := f.Value()
				if err != nil {
					errs <- "error: " + err.Error()
					return
				}
				if v != "alpha" && v != "bravo" {
					errs <- "torn value: " + v
					return
				}
				_, _, _ = f.Status()
			}
		}()
	}
	for i := 0; i < 200; i++ {
		next := "alpha"
		if i%2 == 0 {
			next = "bravo"
		}
		writeAtomic(t, path, next)
	}
	close(stop)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
