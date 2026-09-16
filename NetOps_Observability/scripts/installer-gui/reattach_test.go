// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Re-attach tests (FMEA 2026-09-15 §3.1 G2, §3.9): a (re)started wizard reads
// the job-state file and either follows a live install exactly as if it had
// launched it, or reports a dead one as "interrupted" and offers a safe re-run
// with the recorded answers — and never starts a second install while one is
// alive, whichever wizard process started it.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// startLiveJob launches the stub installer detached (the production path),
// waits until it runs, and records the job-state file the way a wizard that
// then died would have left it. The caller releases it by creating <bundle>/go.
func startLiveJob(t *testing.T, s *server) *jobState {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	stubDetachedInstaller(t, s.bundle)
	logFile, logPath, err := createJobLog(s.bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"bash", "./install-correlix.sh", "install", "--config", "/nonexistent.json"}
	proc, err := execRunner{}.startDetached(s.bundle, logFile, nil, argv...)
	if err != nil {
		t.Fatal(err)
	}
	var reap sync.Once
	reapFn := func() { reap.Do(func() { _, _ = proc.wait() }) }
	go reapFn()
	t.Cleanup(func() {
		_ = syscall.Kill(-proc.pid, syscall.SIGKILL) // the job may already be gone; justified
	})
	waitFile(t, filepath.Join(s.bundle, "child.pid"), 10*time.Second)
	p := Profile{Version: 1, Port: 8000, TLS: "no"}
	job := &jobState{
		Version: 1, Pid: proc.pid, ProcStart: proc.procStart, StartedUTC: time.Now().UTC().Format(time.RFC3339),
		Argv0: argv[0], Argv1: argv[1], Log: logPath, Detached: true, Profile: &p,
	}
	if err := writeJobState(filepath.Join(s.bundle, jobFileName), job); err != nil {
		t.Fatal(err)
	}
	return job
}

func fastJobClocks(s *server) {
	s.jobPoll = 30 * time.Millisecond
	s.tailPoll = 30 * time.Millisecond
	s.heartbeatEvery = 50 * time.Millisecond
}

func readJobFile(t *testing.T, s *server) *jobState {
	t.Helper()
	j, err := readJobState(filepath.Join(s.bundle, jobFileName))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func waitJobOutcome(t *testing.T, s *server, want string) *jobState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if j, err := readJobState(filepath.Join(s.bundle, jobFileName)); err == nil && j.Outcome == want {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job-state outcome never became %q (have %+v)", want, readJobFile(t, s))
	return nil
}

func TestReattachStreamsALiveJob(t *testing.T) {
	s, ts := newTestServer(t, &fakeRunner{})
	fastJobClocks(s)
	startLiveJob(t, s)

	s.recoverJob()
	waitPhase(t, s, PhaseInstalling)
	c := sessionClient(t, ts)

	// The SSE stream replays the live log's progress as if we had launched it.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	sawStart, sawHeartbeat, sawResult := false, false, false
	released := false
	for sc.Scan() && !(sawStart && sawHeartbeat && sawResult) {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var ev struct{ Kind, ID, Status, Phase string }
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		switch {
		case ev.Kind == "stage" && ev.ID == "env" && ev.Status == "start":
			sawStart = true
		case ev.Kind == "heartbeat" && ev.Phase != "":
			sawHeartbeat = true
		case ev.Kind == "result" && ev.Status == "ok":
			sawResult = true
		}
		if sawStart && sawHeartbeat && !released {
			released = true
			if err := os.WriteFile(filepath.Join(s.bundle, "go"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !sawStart || !sawHeartbeat || !sawResult {
		t.Fatalf("re-attached stream: stage start=%v heartbeat=%v result=%v", sawStart, sawHeartbeat, sawResult)
	}
	waitPhase(t, s, PhaseInstalled)

	r, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Result struct{ URL string } `json:"result"`
		Job    struct {
			Reattached bool   `json:"reattached"`
			Outcome    string `json:"outcome"`
		} `json:"job"`
	}
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if st.Result.URL != "http://127.0.0.1:8000" || !st.Job.Reattached || st.Job.Outcome != "ok" {
		t.Fatalf("state after re-attached completion: %+v", st)
	}
	j := waitJobOutcome(t, s, "ok")
	if j.SettledBy != "log-marker" || j.ExitCode != nil {
		t.Fatalf("a re-attached job cannot know the exit code; settled_by=%q exit=%v", j.SettledBy, j.ExitCode)
	}
}

func TestDeadJobIsReportedInterruptedAndCanBeRunAgain(t *testing.T) {
	fr := &fakeRunner{out: "@CX@ {\"kind\":\"result\",\"status\":\"ok\",\"url\":\"http://10.0.0.9:8000\",\"admin_user\":\"admin\"}\n"}
	s, ts := newTestServer(t, fr)
	fastJobClocks(s)

	// A pid that certainly belonged to something else and is gone now.
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Skipf("cannot spawn a short-lived process: %v", err)
	}
	logFile, logPath, err := createJobLog(s.bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(logFile, "Correlix installer\n"+
		"@CX@ {\"kind\":\"stage\",\"id\":\"env\",\"title\":\"Environment\",\"status\":\"ok\"}\n"+
		"@CX@ {\"kind\":\"stage\",\"id\":\"bundle\",\"title\":\"Loading images\",\"status\":\"start\"}\n"+
		"Loaded image: netops/api:1\n")
	if cerr := logFile.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: 1, Port: 8000, TLS: "yes", AdminUser: "netops"}
	if err := writeJobState(filepath.Join(s.bundle, jobFileName), &jobState{
		Version: 1, Pid: gone.Process.Pid, ProcStart: "1", StartedUTC: "2026-09-15T02:51:00Z",
		Argv0: "bash", Argv1: "./install-correlix.sh", Log: logPath, Detached: true, Profile: &p,
	}); err != nil {
		t.Fatal(err)
	}

	s.recoverJob()
	waitPhase(t, s, PhaseError)
	c := sessionClient(t, ts)
	r, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Stages []Stage `json:"stages"`
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
		Job struct {
			Outcome   string `json:"outcome"`
			Resumable bool   `json:"resumable"`
		} `json:"job"`
	}
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if st.Result.Status != "interrupted" || st.Job.Outcome != "interrupted" || !st.Job.Resumable {
		t.Fatalf("dead job: %+v", st)
	}
	var bundle *Stage
	for i := range st.Stages {
		if st.Stages[i].ID == "bundle" {
			bundle = &st.Stages[i]
		}
	}
	if bundle == nil || bundle.Status != "fail" || !strings.Contains(bundle.Message, "interrupted") {
		t.Fatalf("the stage that was running when it died must say so: %+v", st.Stages)
	}
	if j := readJobFile(t, s); j.Outcome != "interrupted" || j.SettledBy != "no-result-marker" {
		t.Fatalf("job-state not settled: %+v", j)
	}

	// The safe re-run uses the RECORDED answers, not whatever a reloaded page has.
	res := postJSON(t, c, ts.URL+"/api/run/resume", "{}", map[string]string{"Idempotency-Key": "again-1"})
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resume: got %d %s", res.StatusCode, b)
	}
	waitPhase(t, s, PhaseInstalled)
	argv := fr.argv(-1)
	if len(argv) < 5 || argv[3] != "--config" {
		t.Fatalf("resume argv = %q", argv)
	}
	// The profile file is removed once the run settles, so the recorded answers
	// are checked through the job-state file of the new run.
	j := waitJobOutcome(t, s, "ok")
	if j.Profile == nil || j.Profile.TLS != "yes" || j.Profile.AdminUser != "netops" {
		t.Fatalf("resume did not reuse the recorded profile: %+v", j.Profile)
	}
}

func TestNoSecondInstallWhileADetachedJobIsAlive(t *testing.T) {
	fr := &fakeRunner{out: "must never run\n"}
	s, ts := newTestServer(t, fr)
	fastJobClocks(s)
	startLiveJob(t, s)
	c := sessionClient(t, ts)

	// A different wizard process (this server never re-attached) must still
	// refuse: the job-state file and /proc are the authority, not memory.
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "second"})
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.Contains(string(b), "still running") {
		t.Fatalf("second install while one is alive: got %d %s", res.StatusCode, b)
	}
	res = postJSON(t, c, ts.URL+"/api/run/resume", "{}", map[string]string{"Idempotency-Key": "second-r"})
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("resume while one is alive: got %d, want 409", res.StatusCode)
	}
	if fr.calls() != 0 {
		t.Fatal("a second installer was spawned while the first was alive")
	}
	// The refusal also adopts the live job so this page follows it.
	waitPhase(t, s, PhaseInstalling)
	if err := os.WriteFile(filepath.Join(s.bundle, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitPhase(t, s, PhaseInstalled)
}

func TestReusedPidIsNotMistakenForTheInstall(t *testing.T) {
	s, _ := newTestServer(t, &fakeRunner{})
	fastJobClocks(s)
	self := os.Getpid()
	start, err := procStartTime(s.procRoot, self)
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	logFile, logPath, err := createJobLog(s.bundle, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	// Same pid AND same start time, but the process is this test binary, not
	// install-correlix.sh: the cmdline check must refuse to call it our install.
	job := &jobState{Version: 1, Pid: self, ProcStart: start, Argv0: "bash", Argv1: "./install-correlix.sh", Log: logPath, Detached: true}
	if s.jobAlive(job) {
		t.Fatal("an unrelated live process was taken for the install job")
	}
}

func TestSuccessAutoStopWaitsForAnIdlePage(t *testing.T) {
	s, ts := newTestServer(t, &fakeRunner{out: "done\n"})
	var mu sync.Mutex
	cur := time.Now()
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return cur }
	var fire func()
	var durs []time.Duration
	s.afterFunc = func(d time.Duration, f func()) *time.Timer {
		mu.Lock()
		fire, durs = f, append(durs, d)
		mu.Unlock()
		return time.NewTimer(time.Hour)
	}
	reasons := make(chan string, 2)
	s.shutdownFn = func(r string) { reasons <- r }
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)

	if resultShutdown < 30*time.Minute {
		t.Fatalf("the unacknowledged-success auto-stop is %s — it must be a long idle", resultShutdown)
	}
	// The page polled a moment ago: the timer firing must postpone, not stop.
	if r, err := c.Get(ts.URL + "/api/state"); err == nil {
		r.Body.Close()
	}
	mu.Lock()
	f := fire
	mu.Unlock()
	f()
	select {
	case r := <-reasons:
		t.Fatalf("stopped while the operator's page was polling: %s", r)
	default:
	}
	mu.Lock()
	rearmed := len(durs) >= 2
	cur = cur.Add(pagePollGrace + time.Minute)
	f = fire
	mu.Unlock()
	if !rearmed {
		t.Fatal("a postponed auto-stop was not re-armed")
	}
	f()
	select {
	case r := <-reasons:
		if !strings.Contains(r, "no page activity") {
			t.Fatalf("the stop reason must say why: %q", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an idle page after a success never let the wizard stop")
	}
}
