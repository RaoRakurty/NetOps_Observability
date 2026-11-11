// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets the ntfy sender (safehttp, SSRF guard) reach the httptest
// servers on 127.0.0.1, exactly as notify's own tests do. NOTHING in this
// package's tests ever talks to a real ntfy topic or a real Twilio number:
// every sender is aimed at an httptest server below.
func TestMain(m *testing.M) {
	if err := os.Setenv("SSRF_ALLOW_PRIVATE", "true"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// ── fixtures built at runtime (never a credential-shaped literal) ───────────

func fakeSecret(tag string) string { return "placeholder-" + tag + "-" + strings.Repeat("x", 16) }
func fakeSID() string              { return "AC" + strings.Repeat("a1", 16) }

const (
	phoneA    = "+14155550100"
	phoneB    = "+14155550101"
	phoneFrom = "+14155550199"
)

// ── platform kv fake ────────────────────────────────────────────────────────

type memKV struct {
	mu      sync.Mutex
	data    map[string][]byte
	loadErr error
	saveErr error
	saves   int
}

func newMemKV() *memKV { return &memKV{data: map[string][]byte{}} }

func (k *memKV) Load(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loadErr != nil {
		return nil, k.loadErr
	}
	b, ok := k.data[key]
	if !ok {
		return nil, fmt.Errorf("absent: %w", os.ErrNotExist)
	}
	return append([]byte(nil), b...), nil
}

func (k *memKV) Save(key string, b []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.saveErr != nil {
		return k.saveErr
	}
	k.saves++
	k.data[key] = append([]byte(nil), b...)
	return nil
}

func (k *memKV) raw() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return string(k.data[DefaultKey])
}

func (k *memKV) put(t *testing.T, c Config) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	k.data[DefaultKey] = b
	k.mu.Unlock()
}

func (k *memKV) setLoadErr(err error) {
	k.mu.Lock()
	k.loadErr = err
	k.mu.Unlock()
}

// fakeSeal is a reversible, FIELD-BOUND transform standing in for the vault:
// a ciphertext opened under another field id fails, as AES-GCM AAD would.
func fakeSeal(field, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	return "sealed:" + field + ":" + base64.StdEncoding.EncodeToString([]byte(v)), nil
}

func fakeOpen(field, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	rest, ok := strings.CutPrefix(v, "sealed:"+field+":")
	if !ok {
		return "", errors.New("wrong field or not sealed")
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	return string(b), err
}

// logSpy records structured log lines.
type logSpy struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSpy) log(level, msg string, f map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf("%s: %s %v", level, msg, f))
}

func (l *logSpy) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logSpy) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func newTestStore(t *testing.T, kv *memKV, logs *logSpy) *Store {
	t.Helper()
	return NewStore(StoreDeps{Key: DefaultKey, Load: kv.Load, Save: kv.Save, Seal: fakeSeal, Open: fakeOpen, Log: logs.log})
}

// ── provider fakes ──────────────────────────────────────────────────────────

type capture struct {
	Path   string
	Auth   string
	User   string
	Pass   string
	Title  string
	Body   string
	To     string
	Header http.Header
}

// fakeProvider is an httptest server that records every request and answers
// with a scripted status (default 200). Its response body is a recognizable
// marker so a test can prove no provider text is ever echoed.
type fakeProvider struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []capture
	status int
	signal chan capture
}

const providerMarker = "PROVIDER-BODY-MUST-NEVER-BE-ECHOED +14155550100 secret-detail"

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{status: http.StatusOK, signal: make(chan capture, 256)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16)) // test fake: a short read only shortens the capture
		c := capture{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Title: r.Header.Get("Title"), Header: r.Header.Clone()}
		c.User, c.Pass, _ = r.BasicAuth()
		if form, err := url.ParseQuery(string(b)); err == nil && form.Get("To") != "" {
			c.To, c.Body = form.Get("To"), form.Get("Body")
		} else {
			c.Body = string(b)
		}
		f.mu.Lock()
		f.got = append(f.got, c)
		st := f.status
		f.mu.Unlock()
		f.signal <- c
		if st == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(st)
		_, _ = io.WriteString(w, providerMarker) // test fake: the client may have gone
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProvider) setStatus(s int) {
	f.mu.Lock()
	f.status = s
	f.mu.Unlock()
}

func (f *fakeProvider) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func (f *fakeProvider) await(t *testing.T, n int) []capture {
	t.Helper()
	out := make([]capture, 0, n)
	for i := 0; i < n; i++ {
		select {
		case c := <-f.signal:
			out = append(out, c)
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d/%d never reached the fake provider", i+1, n)
		}
	}
	return out
}

func (f *fakeProvider) quiet(t *testing.T) {
	t.Helper()
	select {
	case c := <-f.signal:
		t.Fatalf("unexpected request reached the fake provider: %+v", c)
	case <-time.After(200 * time.Millisecond):
	}
}

// liveConfig is a complete record pointing both channels at the fakes. It is
// written straight into the kv (bypassing Validate, which rightly insists on
// https — the fakes are plain http on loopback).
func liveConfig(ntfy, twilio *fakeProvider) Config {
	c := DefaultConfig()
	c.Ntfy.Enabled = true
	c.Ntfy.Server = ntfy.srv.URL
	c.Ntfy.Topic = "corr-platform-test"
	c.Ntfy.Token = fakeSecret("ntfy")
	c.SMS.Enabled = true
	c.SMS.AccountSID = fakeSID()
	c.SMS.AuthToken = fakeSecret("twilio")
	c.SMS.From = phoneFrom
	c.SMS.To = []string{phoneA, phoneB}
	_ = twilio // the Twilio origin is a RouterDeps seam, not a stored field
	return c
}

// sealedForKV seals a record the way the store writes it.
func sealedForKV(t *testing.T, c Config) Config {
	t.Helper()
	var err error
	if c.Ntfy.Token, err = fakeSeal(FieldNtfyToken, c.Ntfy.Token); err != nil {
		t.Fatal(err)
	}
	if c.SMS.AuthToken, err = fakeSeal(FieldSMSAuthToken, c.SMS.AuthToken); err != nil {
		t.Fatal(err)
	}
	return c
}
