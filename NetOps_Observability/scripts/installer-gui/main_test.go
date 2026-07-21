// correlix-setup contract tests: token gate, state machine, check parsing,
// single-flight phase execution. A fake runner stands in for the shell
// scripts (§11: mock the boundary, test the orchestration).
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRunner struct {
	out    string
	fail   bool
	calls  atomic.Int32
	gotCmd atomic.Value // []string of last argv
}

func (f *fakeRunner) start(dir, stdin string, argv ...string) (io.ReadCloser, func() error, error) {
	f.calls.Add(1)
	f.gotCmd.Store(append([]string(nil), argv...))
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, f.out)
		if f.fail {
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		} else {
			_ = pw.Close()
		}
	}()
	return pr, func() error { return nil }, nil
}

func newTestServer(r runner) (*server, *httptest.Server) {
	s := &server{bundle: ".", token: "tok123", st: &state{phase: PhaseIdle}, run: r}
	ts := httptest.NewServer(s.routes())
	return s, ts
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

func TestTokenGate(t *testing.T) {
	_, ts := newTestServer(&fakeRunner{})
	defer ts.Close()

	for _, url := range []string{"/", "/api/state", "/api/stream"} {
		res, err := http.Get(ts.URL + url)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s without token: got %d, want 403", url, res.StatusCode)
		}
	}
	res, err := http.Get(ts.URL + "/api/state?t=tok123")
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
	s, ts := newTestServer(fr)
	defer ts.Close()

	res, err := http.Post(ts.URL+"/api/run/check?t=tok123", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	waitPhase(t, s, PhaseNeedsPrep)

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if len(s.st.checks) != 2 || s.st.checks[0].OK != true || s.st.checks[1].OK != false {
		t.Fatalf("checks parsed wrong: %+v", s.st.checks)
	}
}

func TestCheckAllPassIsReady(t *testing.T) {
	fr := &fakeRunner{out: "  PASS  docker present\n  PASS  disk ok\n"}
	s, ts := newTestServer(fr)
	defer ts.Close()
	res, _ := http.Post(ts.URL+"/api/run/check?t=tok123", "application/json", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseReady)
}

func TestPrepareRequiresPassword(t *testing.T) {
	_, ts := newTestServer(&fakeRunner{})
	defer ts.Close()
	res, err := http.Post(ts.URL+"/api/run/prepare?t=tok123", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("prepare without password: got %d, want 400", res.StatusCode)
	}
}

func TestSingleFlight(t *testing.T) {
	// A runner that blocks until released — second phase start must be refused.
	pr, pw := io.Pipe()
	blocking := runnerFunc(func(dir, stdin string, argv ...string) (io.ReadCloser, func() error, error) {
		return pr, func() error { return nil }, nil
	})
	s, ts := newTestServer(blocking)
	defer ts.Close()

	res, _ := http.Post(ts.URL+"/api/run/install?t=tok123", "application/json", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseInstalling)

	res2, _ := http.Post(ts.URL+"/api/run/install?t=tok123", "application/json", nil)
	var out struct{ Started bool }
	_ = json.NewDecoder(res2.Body).Decode(&out)
	res2.Body.Close()
	if out.Started {
		t.Fatal("second install started while one was running (single-flight broken)")
	}
	_ = pw.Close()
}

type runnerFunc func(dir, stdin string, argv ...string) (io.ReadCloser, func() error, error)

func (f runnerFunc) start(dir, stdin string, argv ...string) (io.ReadCloser, func() error, error) {
	return f(dir, stdin, argv...)
}

func TestInstallExtractsCredentials(t *testing.T) {
	fr := &fakeRunner{out: "  Open the UI:   http://10.0.0.5:8000\n  Password:      s3cr3tPW\n"}
	s, ts := newTestServer(fr)
	defer ts.Close()
	res, _ := http.Post(ts.URL+"/api/run/install?t=tok123", "application/json", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if s.st.uiURL != "http://10.0.0.5:8000" || s.st.adminPW != "s3cr3tPW" {
		t.Fatalf("credential extraction wrong: url=%q pw=%q", s.st.uiURL, s.st.adminPW)
	}
}
