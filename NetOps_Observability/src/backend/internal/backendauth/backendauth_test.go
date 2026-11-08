// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backendauth

// Tracker 367 layer 1: the backend credential transport.
//
//   - URL userinfo never reaches the wire (stripped on every request);
//   - a file-backed credential is attached ONLY to the origin it was
//     configured for, wins over userinfo, never overrides a caller's own
//     Authorization, and never follows a redirect off that origin;
//   - a credential that never loaded refuses the request — nothing is sent;
//   - legacy userinfo is still honoured, flagged by variable name only.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/internal/credfile"
)

// client is what the api's backendHTTPClient builds: this Transport over the
// default transport plus CheckRedirect.
func client(set *Set) *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     Transport{Base: http.DefaultTransport, Creds: func() *Set { return set }},
		CheckRedirect: CheckRedirect,
	}
}

// recorder is a backend that records the Authorization header and whether
// userinfo reached it, and counts hits.
type recorder struct {
	srv   *httptest.Server
	hits  atomic.Int64
	auth  atomic.Value // string
	wireU atomic.Value // string
}

func newRecorder(t *testing.T, h http.HandlerFunc) *recorder {
	t.Helper()
	r := &recorder{}
	r.auth.Store("")
	r.wireU.Store("")
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.auth.Store(req.Header.Get("Authorization"))
		r.wireU.Store(req.URL.User.String())
		if h != nil {
			h(w, req)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) Auth() string { return r.auth.Load().(string) }

// current is the set the next get() uses (tests in this package run serially).
var current *Set

func useCreds(t *testing.T, set *Set) {
	t.Helper()
	current = set
	t.Cleanup(func() { current = nil })
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// envMap is a getenv over a fixed map.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func mustParseCreds(t *testing.T, env map[string]string) (*Set, []string) {
	t.Helper()
	set, warns, err := Parse(envMap(env), credfile.Options{})
	if err != nil {
		t.Fatalf("parseBackendCredentials: %v", err)
	}
	return set, warns
}

func basicOf(user, pass string) string { return BasicHeader(user, pass) }

func get(t *testing.T, rawURL string, hdr http.Header) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := client(current).Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return resp, err
}

func withUser(t *testing.T, raw, user, pass string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pass)
	return u.String()
}

// ── legacy behaviour (unchanged) ────────────────────────────────────────────

func TestTransportAppliesLegacyUserinfoAsBasicAuth(t *testing.T) {
	useCreds(t, nil)
	rec := newRecorder(t, nil)
	if _, err := get(t, withUser(t, rec.srv.URL, "svc-api", "sekret"), nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.Auth() != basicOf("svc-api", "sekret") {
		t.Fatalf("Authorization = %q — want basic svc-api:sekret", rec.Auth())
	}
	if u := rec.wireU.Load().(string); u != "" {
		t.Fatalf("userinfo leaked to the wire: %q", u)
	}
}

func TestTransportNoUserinfoPassthrough(t *testing.T) {
	useCreds(t, nil)
	rec := newRecorder(t, nil)
	if _, err := get(t, rec.srv.URL, nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if a := rec.Auth(); a != "" {
		t.Fatalf("unexpected Authorization header %q on a credential-less URL", a)
	}
}

// ── origin scoping ──────────────────────────────────────────────────────────

func TestFileCredentialOnlyToItsOrigin(t *testing.T) {
	vm := newRecorder(t, nil)
	other := newRecorder(t, nil)
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "vm-pw\n"),
	})
	useCreds(t, set)

	if _, err := get(t, vm.srv.URL+"/api/v1/query", nil); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != basicOf("svc-api", "vm-pw") {
		t.Fatalf("configured origin got Authorization %q", vm.Auth())
	}
	if _, err := get(t, other.srv.URL+"/api/v1/query", nil); err != nil {
		t.Fatal(err)
	}
	if a := other.Auth(); a != "" {
		t.Fatalf("a DIFFERENT origin (same host, other port) received the credential: %q", a)
	}
}

func TestTwoBackendsEachGetTheirOwnCredential(t *testing.T) {
	vm := newRecorder(t, nil)
	osr := newRecorder(t, nil)
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                  vm.srv.URL,
		"METRICS_URL":                   vm.srv.URL,
		"VICTORIA_AUTH_USER":            "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE":   writeSecret(t, "vm-pw"),
		"OPENSEARCH_URL":                osr.srv.URL,
		"OPENSEARCH_AUTH_USER":          "svc_api",
		"OPENSEARCH_AUTH_PASSWORD_FILE": writeSecret(t, "os-pw"),
	})
	useCreds(t, set)
	if _, err := get(t, vm.srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, osr.srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != basicOf("svc-api", "vm-pw") || osr.Auth() != basicOf("svc_api", "os-pw") {
		t.Fatalf("credentials crossed backends: vm=%q os=%q", vm.Auth(), osr.Auth())
	}
}

func TestExplicitAuthorizationIsNeverOverridden(t *testing.T) {
	vm := newRecorder(t, nil)
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "vm-pw"),
	})
	useCreds(t, set)
	if _, err := get(t, vm.srv.URL, http.Header{"Authorization": {"Bearer caller-token"}}); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != "Bearer caller-token" {
		t.Fatalf("caller's Authorization replaced: %q", vm.Auth())
	}
	// Even with userinfo on the URL, the caller's header wins and the
	// userinfo is still stripped.
	if _, err := get(t, withUser(t, vm.srv.URL, "x", "y"), http.Header{"Authorization": {"Bearer caller-token"}}); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != "Bearer caller-token" || vm.wireU.Load().(string) != "" {
		t.Fatalf("auth=%q wire-userinfo=%q", vm.Auth(), vm.wireU.Load())
	}
}

// ── redirects ───────────────────────────────────────────────────────────────

func TestCrossOriginRedirectDropsCredential(t *testing.T) {
	target := newRecorder(t, nil)
	vm := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+"/landed", http.StatusFound)
	})
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "vm-pw"),
	})
	useCreds(t, set)

	// File credential: attached to the first hop only.
	if _, err := get(t, vm.srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != basicOf("svc-api", "vm-pw") {
		t.Fatalf("first hop Authorization = %q", vm.Auth())
	}
	if target.hits.Load() != 1 || target.Auth() != "" {
		t.Fatalf("redirect target hits=%d Authorization=%q — the credential followed the redirect", target.hits.Load(), target.Auth())
	}

	// Caller-explicit header: net/http keeps Authorization across a PORT
	// change on the same hostname; the origin rule drops it.
	if _, err := get(t, vm.srv.URL, http.Header{"Authorization": {"Bearer caller-token"}}); err != nil {
		t.Fatal(err)
	}
	if target.Auth() != "" {
		t.Fatalf("explicit Authorization followed a cross-origin redirect: %q", target.Auth())
	}
}

func TestSameOriginRedirectKeepsCredential(t *testing.T) {
	vm := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "vm-pw"),
	})
	useCreds(t, set)
	if _, err := get(t, vm.srv.URL+"/start", nil); err != nil {
		t.Fatal(err)
	}
	if vm.hits.Load() != 2 || vm.Auth() != basicOf("svc-api", "vm-pw") {
		t.Fatalf("hits=%d last Authorization=%q — same-origin hop must keep the credential", vm.hits.Load(), vm.Auth())
	}
}

func TestRedirectLimitIsKept(t *testing.T) {
	useCreds(t, nil)
	loop := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	})
	if _, err := get(t, loop.srv.URL, nil); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("err = %v, want the 10-redirect limit", err)
	}
}

// ── fail closed ─────────────────────────────────────────────────────────────

type closeTracker struct {
	io.Reader
	closed atomic.Bool
}

func (c *closeTracker) Close() error { c.closed.Store(true); return nil }

func TestNeverLoadedCredentialRefusesTheRequest(t *testing.T) {
	vm := newRecorder(t, nil)
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": filepath.Join(t.TempDir(), "not-rendered"),
	})
	useCreds(t, set)

	body := &closeTracker{Reader: bytes.NewReader([]byte("x"))}
	req, err := http.NewRequest(http.MethodPost, vm.srv.URL+"/api/v1/import/prometheus", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client(current).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request was sent without its credential")
	}
	if !errors.Is(err, ErrCredentialUnavailable) || !errors.Is(err, credfile.ErrNotLoaded) {
		t.Fatalf("err = %v, want ErrCredentialUnavailable wrapping ErrNotLoaded", err)
	}
	if vm.hits.Load() != 0 {
		t.Fatalf("backend saw %d request(s) — an anonymous request escaped", vm.hits.Load())
	}
	if !body.closed.Load() {
		t.Fatal("RoundTripper contract: the request body must be closed on error")
	}
	// And userinfo on the URL does NOT rescue it: the configured file is
	// authoritative, so a broken file is a refusal, not a silent fallback.
	if _, err := get(t, withUser(t, vm.srv.URL, "svc-api", "legacy"), nil); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("legacy userinfo bypassed a broken file credential: %v", err)
	}
	if vm.hits.Load() != 0 {
		t.Fatal("request reached the backend")
	}
}

// ── legacy userinfo: flagged by NAME, file wins ─────────────────────────────

func TestLegacyUserinfoFlaggedByNameOnly(t *testing.T) {
	const secret = "LEAKME-123"
	set, warns := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":   "https://svc-api:" + secret + "@vmauth:8427",
		"METRICS_URL":    "https://vmauth:8427",
		"OPENSEARCH_URL": "https://svc_api:" + secret + "@opensearch:9200",
	})
	if !set.Legacy("VICTORIA_URL") || set.Legacy("METRICS_URL") || !set.Legacy("OPENSEARCH_URL") {
		t.Fatalf("legacy map = %v", set.legacy)
	}
	if len(warns) != 2 {
		t.Fatalf("want exactly one warning per legacy var, got %d: %q", len(warns), warns)
	}
	joined := strings.Join(warns, "\n")
	if strings.Contains(joined, secret) {
		t.Fatalf("a warning carries the secret: %q", joined)
	}
	for _, v := range []string{"VICTORIA_URL", "OPENSEARCH_URL"} {
		if !strings.Contains(joined, v) {
			t.Fatalf("no warning names %s: %q", v, joined)
		}
	}
	useCreds(t, set)
	var buf bytes.Buffer
	WriteMetrics(&buf, current)
	out := buf.String()
	for _, want := range []string{
		`netops_config_url_credential{var="VICTORIA_URL"} 1`,
		`netops_config_url_credential{var="METRICS_URL"} 0`,
		`netops_config_url_credential{var="OPENSEARCH_URL"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret) {
		t.Fatal("metrics carry the secret")
	}
}

func TestFileWinsOverUserinfo(t *testing.T) {
	vm := newRecorder(t, nil)
	legacy := withUser(t, vm.srv.URL, "svc-api", "OLD-userinfo")
	set, warns := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                legacy,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "NEW-file"),
	})
	useCreds(t, set)
	if _, err := get(t, legacy, nil); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != basicOf("svc-api", "NEW-file") {
		t.Fatalf("Authorization = %q — the file must win over userinfo", vm.Auth())
	}
	if vm.wireU.Load().(string) != "" {
		t.Fatal("userinfo reached the wire")
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "file wins") || strings.Contains(joined, "OLD-userinfo") {
		t.Fatalf("warnings = %q", joined)
	}
	if !set.Legacy("VICTORIA_URL") {
		t.Fatal("the legacy gauge must stay 1 while the userinfo is still configured")
	}
}

// A rotated file is used by the very next request after the recheck window —
// the live-rotation promise end to end through the transport.
func TestRotatedFileUsedWithoutRestart(t *testing.T) {
	vm := newRecorder(t, nil)
	path := writeSecret(t, "first")
	now := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	set, _, err := Parse(envMap(map[string]string{
		"VICTORIA_URL":                vm.srv.URL,
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": path,
	}), credfile.Options{Now: func() time.Time { return time.Unix(0, clock.Load()) }})
	if err != nil {
		t.Fatal(err)
	}
	useCreds(t, set)
	if _, err := get(t, vm.srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	clock.Add(int64(2 * time.Second))
	if _, err := get(t, vm.srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if vm.Auth() != basicOf("svc-api", "second") {
		t.Fatalf("after rotation Authorization = %q", vm.Auth())
	}
}

// ── configuration errors (fail closed at boot) ──────────────────────────────

func TestCredentialConfigErrors(t *testing.T) {
	pw := writeSecret(t, "pw")
	cases := map[string]map[string]string{
		"user without file": {"VICTORIA_AUTH_USER": "svc-api"},
		"file without user": {"OPENSEARCH_AUTH_PASSWORD_FILE": pw},
		"user with colon": {
			"VICTORIA_AUTH_USER": "svc:api", "VICTORIA_AUTH_PASSWORD_FILE": pw},
		"non-http url": {
			"VICTORIA_URL": "ftp://vmauth:21", "VICTORIA_AUTH_USER": "svc-api", "VICTORIA_AUTH_PASSWORD_FILE": pw},
		"one origin, two backends": {
			"VICTORIA_URL": "https://shared:8427", "VICTORIA_AUTH_USER": "svc-api", "VICTORIA_AUTH_PASSWORD_FILE": pw,
			"OPENSEARCH_URL": "https://SHARED:8427/", "OPENSEARCH_AUTH_USER": "svc_api", "OPENSEARCH_AUTH_PASSWORD_FILE": pw},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(envMap(env), credfile.Options{}); err == nil {
				t.Fatal("configuration accepted")
			}
		})
	}
}

func TestMalformedURLErrorNamesTheVariableNotTheValue(t *testing.T) {
	const secret = "PCT-LEAK"
	_, _, err := Parse(envMap(map[string]string{
		"VICTORIA_URL":                "https://svc-api:" + secret + "%zz@vmauth:8427",
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "pw"),
	}), credfile.Options{})
	if err == nil {
		t.Fatal("malformed URL accepted")
	}
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "VICTORIA_URL") {
		t.Fatalf("err = %q — must name the variable and not echo the value", err)
	}
}

func TestPlaintextCredentialWarns(t *testing.T) {
	_, warns := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                "http://victoria:8428",
		"VICTORIA_AUTH_USER":          "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE": writeSecret(t, "pw"),
	})
	if len(warns) != 1 || !strings.Contains(warns[0], "plaintext") {
		t.Fatalf("warnings = %q, want one plaintext warning", warns)
	}
}

func TestDefaultOriginWhenNoURLSet(t *testing.T) {
	set, _ := mustParseCreds(t, map[string]string{
		"OPENSEARCH_AUTH_USER":          "svc_api",
		"OPENSEARCH_AUTH_PASSWORD_FILE": writeSecret(t, "pw"),
	})
	if set.ForOrigin("http://opensearch:9200") == nil {
		t.Fatal("with no OPENSEARCH_URL the credential must bind to the call sites' default origin")
	}
}

func TestOriginOf(t *testing.T) {
	cases := map[string]string{
		"https://vmauth:8427/api/v1/query": "https://vmauth:8427",
		"HTTPS://VMAuth:8427":              "https://vmauth:8427",
		"https://vmauth":                   "https://vmauth:443",
		"http://victoria":                  "http://victoria:80",
		"http://u:p@victoria:8428/x":       "http://victoria:8428",
		"http://[::1]:9200":                "http://[::1]:9200",
		"ftp://host:21":                    "",
		"/relative":                        "",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := OriginOf(u); got != want {
			t.Fatalf("OriginOf(%q) = %q, want %q", in, got, want)
		}
	}
	if OriginOf(nil) != "" {
		t.Fatal("OriginOf(nil)")
	}
}

func TestHasUserinfo(t *testing.T) {
	cases := map[string]bool{
		"":                                   false,
		"https://vmauth:8427":                false,
		"https://svc:pw@vmauth:8427":         true,
		"https://token@vmauth:8427":          true,
		"https://svc:p%zz@vmauth:8427":       true, // unparseable, still flagged
		"https://vmauth:8427/path@not-creds": false,
	}
	for in, want := range cases {
		if got := HasUserinfo(in); got != want {
			t.Fatalf("HasUserinfo(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCredentialLoadedMetrics(t *testing.T) {
	set, _ := mustParseCreds(t, map[string]string{
		"VICTORIA_URL":                  "https://vmauth:8427",
		"VICTORIA_AUTH_USER":            "svc-api",
		"VICTORIA_AUTH_PASSWORD_FILE":   writeSecret(t, "pw"),
		"OPENSEARCH_URL":                "https://opensearch:9200",
		"OPENSEARCH_AUTH_USER":          "svc_api",
		"OPENSEARCH_AUTH_PASSWORD_FILE": filepath.Join(t.TempDir(), "absent"),
	})
	for _, c := range set.Credentials() {
		_, _ = c.Basic().File().Value() // first load attempt
	}
	useCreds(t, set)
	var buf bytes.Buffer
	WriteMetrics(&buf, current)
	out := buf.String()
	for _, want := range []string{
		`netops_backend_credential_loaded{backend="victoria"} 1`,
		`netops_backend_credential_loaded{backend="opensearch"} 0`,
		`netops_backend_credential_reload_errors_total{backend="opensearch"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q:\n%s", want, out)
		}
	}
}
