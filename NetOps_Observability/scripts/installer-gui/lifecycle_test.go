// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Install-job lifecycle tests (FMEA 2026-09-15 §2 rows 2 and 6, §3.1 G1-G7):
// the install outlives the wizard process, a failed install never auto-stops
// the wizard, the page is told about a failure even when the engine died
// without a result marker, a retry does not inherit the previous run's
// verdict, /api/done cannot schedule a shutdown mid-install, and the initial
// administrator password is handed over exactly once and never retained in the
// log ring, the SSE history, /api/state or any file the wizard writes.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// jobFileForTest is the on-disk job-state file name (kept literal here so the
// test pins the operator-visible name, not whatever the constant says).
const jobFileForTest = "correlix-setup-install.job.json"

// waitFile polls for path to exist, failing the test after d.
func waitFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared within %s", filepath.Base(path), d)
}

// --- G1: the install child survives the wizard process ----------------------

// TestHelperWizardProcess is not a test on its own: it is the "wizard" process
// TestDetachedInstallSurvivesWizardExit launches and then kills. It starts an
// install through the real HTTP handler and the real execRunner, reports ready
// once the child is running, and exits abruptly — no cleanup, no Wait, exactly
// like a crashed or restarted correlix-setup.
func TestHelperWizardProcess(t *testing.T) {
	if os.Getenv("CX_HELPER_WIZARD") != "1" {
		t.Skip("helper process for TestDetachedInstallSurvivesWizardExit")
	}
	bundle := os.Getenv("CX_HELPER_BUNDLE")
	s := newServer(bundle, "tok123", execRunner{})
	s.fsRoot = filepath.Join(bundle, "fsroot")
	s.probePort = func(int) bool { return true }
	s.statfs = func(string) (uint64, error) { return 1 << 30, nil }
	s.shutdownFn = func(string) {}
	s.afterFunc = func(time.Duration, func()) *time.Timer { return time.NewTimer(time.Hour) }
	ts := httptest.NewTLSServer(s.handler())
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "helper"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Printf("HELPER-FAILED install POST %d\n", res.StatusCode)
		os.Exit(3)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(bundle, "child.pid")); err == nil {
			fmt.Println("HELPER-READY")
			os.Exit(0) // the wizard dies here; the install must not
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Println("HELPER-FAILED child never started")
	os.Exit(4)
}

// stubDetachedInstaller writes an install-correlix.sh that records its pid,
// waits for a go-ahead file (so the wizard has certainly died first), then
// writes more output — which kills it with SIGPIPE if its stdout is still a
// pipe owned by the dead wizard — and finally drops a "finished" file.
func stubDetachedInstaller(t *testing.T, bundle string) {
	t.Helper()
	script := `#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
echo $$ > "$here/child.pid.tmp" && mv "$here/child.pid.tmp" "$here/child.pid"
echo '@CX@ {"kind":"stage","id":"env","title":"Environment","status":"start"}'
for _ in $(seq 1 400); do [ -f "$here/go" ] && break; sleep 0.05; done
echo 'still writing after the wizard died'
echo '@CX@ {"kind":"stage","id":"env","title":"Environment","status":"ok"}'
echo '@CX@ {"kind":"result","status":"ok","url":"http://127.0.0.1:8000","admin_user":"admin"}'
touch "$here/finished"
`
	if err := os.WriteFile(filepath.Join(bundle, "install-correlix.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "prepare-host.sh"), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestDetachedInstallSurvivesWizardExit(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	bundle := t.TempDir()
	stubDetachedInstaller(t, bundle)

	// #nosec G204 — re-executes this test binary as the helper wizard.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperWizardProcess$", "-test.v", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "CX_HELPER_WIZARD=1", "CX_HELPER_BUNDLE="+bundle)
	// Its own process group, like a wizard started from a terminal: a terminal
	// hang-up or Ctrl-C signals the whole foreground group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helperPgid := cmd.Process.Pid
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "HELPER-") {
				ready <- sc.Text()
				break
			}
		}
		_, _ = io.Copy(io.Discard, out) // drain so the helper never blocks on stdout
	}()
	select {
	case line := <-ready:
		if line != "HELPER-READY" {
			t.Fatalf("helper wizard: %s", line)
		}
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(-helperPgid, syscall.SIGKILL)
		t.Fatal("helper wizard never reported ready")
	}
	// The terminal the wizard ran in goes away: SIGHUP to its process group.
	if err := syscall.Kill(-helperPgid, syscall.SIGHUP); err != nil && err != syscall.ESRCH {
		t.Fatalf("signal the wizard's process group: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Logf("helper wizard exit: %v (expected: it was killed or exited)", err)
	}

	pidBytes, err := os.ReadFile(filepath.Join(bundle, "child.pid"))
	if err != nil {
		t.Fatal(err)
	}
	childPid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-childPid, syscall.SIGKILL) })

	if err := os.WriteFile(filepath.Join(bundle, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFile(t, filepath.Join(bundle, "finished"), 20*time.Second)

	// The job-state file names the child, carries no secret-bearing argv, and
	// is private to the installing user.
	jobPath := filepath.Join(bundle, jobFileForTest)
	fi, err := os.Stat(jobPath)
	if err != nil {
		t.Fatalf("no job-state file next to the log: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("job-state file mode %v, want 0600", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(jobPath)
	if err != nil {
		t.Fatal(err)
	}
	var job struct {
		Pid   int    `json:"pid"`
		Argv0 string `json:"argv0"`
		Argv1 string `json:"argv1"`
		Log   string `json:"log"`
	}
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatalf("job-state file is not JSON: %v", err)
	}
	if job.Pid != childPid {
		t.Fatalf("job-state pid %d, want the install child %d", job.Pid, childPid)
	}
	if job.Argv0 != "bash" || job.Argv1 != "./install-correlix.sh" {
		t.Fatalf("job-state argv0/1 = %q %q", job.Argv0, job.Argv1)
	}
	if strings.Contains(string(raw), "--config") {
		t.Fatal("job-state file carries argv beyond [0..1]")
	}
	logBytes, err := os.ReadFile(job.Log)
	if err != nil {
		t.Fatalf("install log named by the job file: %v", err)
	}
	if !strings.Contains(string(logBytes), "still writing after the wizard died") ||
		!strings.Contains(string(logBytes), `"kind":"result"`) {
		t.Fatalf("the child's output after the wizard died is not in the log:\n%s", logBytes)
	}
}

// --- G3: no auto-stop after a failed install ---------------------------------

func TestFailedInstallNeverArmsAutoStop(t *testing.T) {
	fr := &fakeRunner{out: "boom\n", fail: true}
	s, ts := newTestServer(t, fr)
	var mu sync.Mutex
	var durs []time.Duration
	s.afterFunc = func(d time.Duration, f func()) *time.Timer {
		mu.Lock()
		durs = append(durs, d)
		mu.Unlock()
		return time.NewTimer(time.Hour)
	}
	stopped := make(chan string, 1)
	s.shutdownFn = func(reason string) { stopped <- reason }
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseError)
	time.Sleep(100 * time.Millisecond) // let any post-result scheduling land
	mu.Lock()
	got := append([]time.Duration(nil), durs...)
	mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("a failed install scheduled an auto-stop %v — the operator would have nothing to reconnect to", got)
	}
	select {
	case r := <-stopped:
		t.Fatalf("wizard stopped itself after a failure: %s", r)
	default:
	}
}

// --- G7: /api/done cannot schedule a shutdown while nothing is installed ------

func TestDoneRefusedUnlessInstalled(t *testing.T) {
	pr, pw := io.Pipe()
	blocking := runnerFunc(func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
		return pr, nil
	})
	s, ts := newTestServer(t, blocking)
	var mu sync.Mutex
	armed := 0
	s.afterFunc = func(time.Duration, func()) *time.Timer {
		mu.Lock()
		armed++
		mu.Unlock()
		return time.NewTimer(time.Hour)
	}
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalling)

	res = postJSON(t, c, ts.URL+"/api/done", "{}", nil)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("/api/done during an install: got %d, want 409", res.StatusCode)
	}
	if !strings.Contains(string(b), "installing") {
		t.Fatalf("the 409 must name the phase, got %s", b)
	}
	mu.Lock()
	n := armed
	mu.Unlock()
	if n != 0 {
		t.Fatal("/api/done armed a shutdown while the install was running")
	}
	_ = pw.Close()
	waitPhase(t, s, PhaseInstalled)
}

// --- G4: a child that dies without a result marker still ends the page -------

func TestChildDeathWithoutMarkerEmitsFailResult(t *testing.T) {
	fr := &fakeRunner{out: "@CX@ {\"kind\":\"stage\",\"id\":\"bundle\",\"title\":\"images\",\"status\":\"start\"}\n", fail: true}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseError)

	s.st.logMu.Lock()
	events := append([]string(nil), s.st.events...)
	s.st.logMu.Unlock()
	for _, e := range events {
		var ev struct{ Kind, Status string }
		if json.Unmarshal([]byte(e), &ev) == nil && ev.Kind == "result" && ev.Status == "fail" {
			return
		}
	}
	t.Fatalf("no result:fail event reached the stream — the page would sit on the progress bar forever: %q", events)
}

// --- G6: a retry does not inherit the previous run's verdict ------------------

func TestRetryDoesNotInheritAStaleFailure(t *testing.T) {
	fr := &fakeRunner{out: "@CX@ {\"kind\":\"result\",\"status\":\"fail\"}\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseError)

	s.run = &fakeRunner{out: "installed fine, engine predates markers\n"}
	res = postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k2"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("retry: got %d", res.StatusCode)
	}
	waitPhase(t, s, PhaseInstalled)
}

// --- row 6: the initial administrator password ------------------------------

func TestInitialPasswordIsHandedOverOnceAndNeverRetained(t *testing.T) {
	const pw = "s3cr3tPW-9x"
	out := "Starting engine\n" +
		"  Open the UI:   http://10.0.0.5:8000\n" +
		"  Password:      \x1b[1m" + pw + "\x1b[0m\n" +
		"ADMIN_INITIAL_PASSWORD=" + pw + "\n" +
		`{"username":"admin","password":"` + pw + `"}` + "\n" +
		"echoing the raw value " + pw + " after the banner\n" +
		"@CX@ {\"kind\":\"result\",\"status\":\"ok\",\"url\":\"http://10.0.0.5:8000\",\"admin_user\":\"admin\"}\n"
	s, ts := newTestServer(t, &fakeRunner{out: out})
	writeFixture(t, filepath.Join(s.bundle, "deployment", "docker", ".env"),
		"ADMIN_USERNAME=admin\nADMIN_INITIAL_PASSWORD="+pw+"\n")
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)

	s.st.logMu.Lock()
	buffered := strings.Join(s.st.logBuf, "\n") + strings.Join(s.st.events, "\n")
	s.st.logMu.Unlock()
	if strings.Contains(buffered, pw) {
		t.Fatal("the initial password was retained in the log ring / SSE history")
	}
	if !strings.Contains(buffered, "Starting engine") {
		t.Fatal("redaction must not drop ordinary output")
	}

	stateBody := func() string {
		r, err := c.Get(ts.URL + "/api/state")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for i := 0; i < 2; i++ {
		if strings.Contains(stateBody(), pw) {
			t.Fatalf("/api/state snapshot %d serves the initial password", i+1)
		}
	}

	// The one-time handover to the authenticated page still works — once.
	res = postJSON(t, c, ts.URL+"/api/credential", "{}", nil)
	var cred struct {
		AdminUser     string `json:"admin_user"`
		AdminPassword string `json:"admin_password"`
	}
	if err := json.NewDecoder(res.Body).Decode(&cred); err != nil {
		res.Body.Close()
		t.Fatalf("credential handover: status %d, undecodable body: %v", res.StatusCode, err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || cred.AdminPassword != pw || cred.AdminUser != "admin" {
		t.Fatalf("credential handover: got %d %+v", res.StatusCode, cred)
	}
	res = postJSON(t, c, ts.URL+"/api/credential", "{}", nil)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusGone || strings.Contains(string(b), pw) {
		t.Fatalf("second credential request: got %d %s, want 410 without the password", res.StatusCode, b)
	}
	if strings.Contains(stateBody(), pw) {
		t.Fatal("/api/state serves the password after the handover")
	}

	// Nothing the wizard wrote to disk keeps it either.
	entries, err := os.ReadDir(s.bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.bundle, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), pw) {
			t.Fatalf("%s written by the wizard still contains the initial password", e.Name())
		}
	}
}

// --- page resilience (ui.html) ----------------------------------------------

// TestWizardSurvivesALostOrStalledStream pins the page-side self-healing: a
// global error handler, an EventSource error handler, an inactivity watchdog
// that says "stalled / reconnecting" and re-polls with capped backoff, and a
// resync from /api/state on reconnect — so a restarted wizard or a dropped
// connection never again leaves a frozen progress bar.
func TestWizardSurvivesALostOrStalledStream(t *testing.T) {
	page, _, script := uiParts(t)
	for _, want := range []string{
		"es.onerror",
		"es.onopen",
		"addEventListener('error'",
		"addEventListener('unhandledrejection'",
		"const STALL_MS",
		"function checkStall(",
		"function scheduleReconnect(",
		"function resyncFromState(",
		"RECONNECT_MAX_MS",
		"'heartbeat'",
		"/api/credential",
		"/api/run/resume",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("ui.html script is missing %q", want)
		}
	}
	for _, words := range []string{"stalled", "reconnecting"} {
		if !strings.Contains(strings.ToLower(page), words) {
			t.Errorf("the page never tells the operator the stream is %s", words)
		}
	}
	if strings.Contains(script, "admin_pw") {
		t.Error("the page still reads a password out of /api/state")
	}
	// The reconnect path must resync from server state, not only reopen the
	// stream — pin that scheduleReconnect fetches /api/state.
	i := strings.Index(script, "function scheduleReconnect(")
	if i >= 0 {
		body := script[i:]
		if j := strings.Index(body, "\n}\n"); j > 0 {
			body = body[:j]
		}
		if !strings.Contains(body, "api('/api/state')") || !strings.Contains(body, "resyncFromState(") {
			t.Error("scheduleReconnect must re-read /api/state and resync the page from it")
		}
	}
}
