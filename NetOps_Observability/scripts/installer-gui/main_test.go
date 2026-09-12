// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// correlix-setup contract tests: token/session gate, state machine, check
// parsing, single-flight phase execution, credential extraction. A fake
// runner stands in for the shell scripts (§11: mock the boundary, test the
// orchestration). P1 hardening + P2 API tests live in hardening_test.go.
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner replays a canned output for every start() call and records what
// it was asked to run.
type fakeRunner struct {
	out  string
	fail bool

	mu     sync.Mutex
	argvs  [][]string
	stdins [][]byte
	envs   [][]string
}

func (f *fakeRunner) start(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
	f.mu.Lock()
	f.argvs = append(f.argvs, append([]string(nil), argv...))
	f.stdins = append(f.stdins, append([]byte(nil), stdin...))
	f.envs = append(f.envs, append([]string(nil), extraEnv...))
	f.mu.Unlock()
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, f.out)
		if f.fail {
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		} else {
			_ = pw.Close()
		}
	}()
	return pr, nil
}

func (f *fakeRunner) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.argvs)
}

func (f *fakeRunner) argv(i int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < 0 {
		i += len(f.argvs)
	}
	if i < 0 || i >= len(f.argvs) {
		return nil
	}
	return f.argvs[i]
}

type runnerFunc func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error)

func (f runnerFunc) start(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
	return f(dir, stdin, extraEnv, argv...)
}

// newTestServer builds a hermetic server: temp bundle dir, empty fake host
// filesystem, deterministic probes, disabled auto-shutdown timers.
func newTestServer(t *testing.T, r runner) (*server, *httptest.Server) {
	t.Helper()
	s := newServer(t.TempDir(), "tok123", r)
	s.fsRoot = t.TempDir()
	s.probePort = func(int) bool { return true }
	s.statfs = func(string) (uint64, error) { return 1 << 30, nil }
	s.shutdownFn = func(string) {}
	s.afterFunc = func(time.Duration, func()) *time.Timer { return time.NewTimer(time.Hour) }
	ts := httptest.NewTLSServer(s.handler())
	t.Cleanup(ts.Close)
	return s, ts
}

// sessionClient exchanges the one-time token for a session cookie and returns
// a client that carries it (the browser flow).
func sessionClient(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: ts.Client().Transport, Jar: jar}
	res, err := c.Get(ts.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session exchange: got %d, want 200", res.StatusCode)
	}
	return c
}

func postJSON(t *testing.T, c *http.Client, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func waitPhase(t *testing.T, s *server, want Phase) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.st.mu.Lock()
		p := s.st.phase
		s.st.mu.Unlock()
		if p == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("phase never reached %s", want)
}

const minimalProfile = `{"version":1,"port":8000,"tls":"no"}`

func TestTokenGate(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	c := ts.Client()

	for _, url := range []string{"/", "/api/state", "/api/stream", "/api/facts", "/api/support-bundle"} {
		res, err := c.Get(ts.URL + url)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s without token: got %d, want 403", url, res.StatusCode)
		}
	}
	res, err := c.Get(ts.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("with token: got %d, want 200", res.StatusCode)
	}
}

func TestCheckParsesPassAndFix(t *testing.T) {
	fr := &fakeRunner{out: "== audit\n  PASS  docker present\n  FIX   vm.max_map_count too low\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/run/check", "{}", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseNeedsPrep)

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if len(s.st.checks) != 2 || s.st.checks[0].OK != true || s.st.checks[1].OK != false {
		t.Fatalf("checks parsed wrong: %+v", s.st.checks)
	}
	if len(s.st.checkOut) == 0 {
		t.Fatal("raw check output not retained for the support bundle")
	}
}

func TestCheckAllPassIsReady(t *testing.T) {
	fr := &fakeRunner{out: "  PASS  docker present\n  PASS  disk ok\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/check", "{}", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseReady)
}

func TestPrepareRequiresPassword(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/prepare", `{}`, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("prepare without password: got %d, want 400", res.StatusCode)
	}
	var out struct{ Error string }
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Error == "" {
		t.Error("error body missing JSON error message")
	}
}

func TestPrepareArgvStdinAndFirewall(t *testing.T) {
	fr := &fakeRunner{out: "  PASS  everything\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/prepare", `{"password":"hunter2","firewall":true}`, nil)
	res.Body.Close()
	// prepare succeeds → internal re-check runs → all-PASS → ready.
	waitPhase(t, s, PhaseReady)

	argv := fr.argv(0)
	want := []string{"sudo", "-k", "-S", "-p", "", "bash", "./prepare-host.sh", "--firewall"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("prepare argv = %q, want %q", argv, want)
	}
	fr.mu.Lock()
	stdin := string(fr.stdins[0])
	fr.mu.Unlock()
	if stdin != "hunter2\n" {
		t.Fatalf("sudo stdin = %q, want password + newline", stdin)
	}
}

func TestSingleFlight(t *testing.T) {
	// A runner that blocks until released — a second job must be refused.
	pr, pw := io.Pipe()
	blocking := runnerFunc(func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
		return pr, nil
	})
	s, ts := newTestServer(t, blocking)
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first install: got %d, want 200", res.StatusCode)
	}
	waitPhase(t, s, PhaseInstalling)

	res2 := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k2"})
	res2.Body.Close()
	if res2.StatusCode != http.StatusConflict {
		t.Fatalf("second install with a new key while running: got %d, want 409", res2.StatusCode)
	}
	// Check must also be refused while installing (single-flight).
	res3 := postJSON(t, c, ts.URL+"/api/run/check", "{}", nil)
	var out struct{ Started bool }
	_ = json.NewDecoder(res3.Body).Decode(&out)
	res3.Body.Close()
	if out.Started {
		t.Fatal("check started while an install was running (single-flight broken)")
	}
	_ = pw.Close()
	waitPhase(t, s, PhaseInstalled)
}

func TestInstallExtractsCredentials(t *testing.T) {
	fr := &fakeRunner{out: "  Open the UI:   http://10.0.0.5:8000\n  Password:      s3cr3tPW\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)

	s.st.mu.Lock()
	uiURL, adminPW := s.st.uiURL, s.st.adminPW
	s.st.mu.Unlock()
	if uiURL != "http://10.0.0.5:8000" || adminPW != "s3cr3tPW" {
		t.Fatalf("credential extraction wrong: url=%q pw=%q", uiURL, adminPW)
	}

	// The fixed argv + progress env must have reached the runner (I1).
	argv := fr.argv(0)
	if len(argv) < 5 || argv[0] != "bash" || argv[1] != "./install-correlix.sh" || argv[2] != "install" || argv[3] != "--config" {
		t.Fatalf("install argv = %q, want bash ./install-correlix.sh install --config <path>", argv)
	}
	if !strings.HasPrefix(argv[4], s.bundle) {
		t.Fatalf("config path %q not inside the bundle dir %q", argv[4], s.bundle)
	}
	fr.mu.Lock()
	env := strings.Join(fr.envs[0], " ")
	fr.mu.Unlock()
	if !strings.Contains(env, "CORRELIX_PROGRESS_JSON=1") {
		t.Fatalf("CORRELIX_PROGRESS_JSON=1 not passed to the engine (env=%q)", env)
	}

	// /api/state exposes the scraped result (fallback path: no .env written).
	res2, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var st struct {
		Phase  string `json:"phase"`
		Result struct {
			URL           string `json:"url"`
			AdminUser     string `json:"admin_user"`
			AdminPassword string `json:"admin_password"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res2.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Phase != "installed" || st.Result.URL != "http://10.0.0.5:8000" ||
		st.Result.AdminUser != "admin" || st.Result.AdminPassword != "s3cr3tPW" {
		t.Fatalf("state result wrong: %+v", st)
	}
}
