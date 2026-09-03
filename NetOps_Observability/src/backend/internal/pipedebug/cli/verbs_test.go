package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/pipedebug"
)

const vMarker = "01j9abcdefghjkmnpqrstvwxyz"

// fakeAPI is a stand-in for the debug route family, so the verbs are exercised
// end to end (session layout, timeline join, exit code, revert) with no stack.
type fakeAPI struct {
	mu       sync.Mutex
	levelPut []map[string]any
	stages   []pipedebug.Entry
	srv      *httptest.Server
	// notSwitchable names modules the fake refuses to raise, the way vector and
	// syslog-ng really do.
	notSwitchable map[string]string
}

func newFakeAPI(t *testing.T, stages []pipedebug.Entry) *fakeAPI {
	t.Helper()
	f := &fakeAPI{stages: stages, notSwitchable: map[string]string{
		"vector": pipedebug.VectorLevelReason,
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"tok"}`))
	})
	mux.HandleFunc("/api/debug/trace", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w,
			`{"marker":%q,"kind":"syslog","device":"spine1","tenant":"t1","injected":true,"ttl_seconds":5,"synthetic":true}`, vMarker)
	})
	mux.HandleFunc("/api/debug/trace/", func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(pipedebug.TraceStatus{
			Marker: vMarker, Kind: pipedebug.KindSyslog, Device: "spine1", Tenant: "t1",
			Done: true, Stages: f.stages,
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/debug/loglevel", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.levelPut = append(f.levelPut, req)
		f.mu.Unlock()
		module, _ := req["module"].(string)
		if reason, off := f.notSwitchable[module]; off {
			_, _ = fmt.Fprintf(w, `{"module":%q,"applied":false,"level":"debug","reason":%q}`, module, reason)
			return
		}
		_, _ = fmt.Fprintf(w,
			`{"module":%q,"applied":true,"level":%q,"revert_at":%q}`,
			module, req["level"], time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	cl, err := NewClient(context.Background(), Credentials{Base: f.srv.URL, Token: "tok", User: "unit"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func (f *fakeAPI) puts() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.levelPut))
	copy(out, f.levelPut)
	return out
}

// tapRunner answers `docker ps` with a container name and `vector tap` with the
// canned event lines.
type tapRunner struct{ lines []string }

func (r *tapRunner) Run(_ context.Context, _ string, _ []string) (string, string, error) {
	return "netops-x-1\n", "", nil
}

func (r *tapRunner) Stream(_ context.Context, _ string, _ []string, onLine func(string)) error {
	for _, l := range r.lines {
		onLine(l)
	}
	return nil
}

// ── trace ───────────────────────────────────────────────────────────────────

func TestRunTraceJoinsHostAndServerStagesIntoOneSession(t *testing.T) {
	serverStages := []pipedebug.Entry{
		{Stage: pipedebug.StageKafka, Verdict: pipedebug.VerdictNotObservable, Reason: "peek not configured", Query: "peek"},
		{Stage: pipedebug.StageOpenSearch, Verdict: pipedebug.VerdictSeen,
			FirstSeen: time.Date(2026, 9, 4, 11, 5, 8, 0, time.UTC), EvidenceRef: "idx#1", Query: "os"},
		{Stage: pipedebug.StageAPI, Verdict: pipedebug.VerdictSeen,
			FirstSeen: time.Date(2026, 9, 4, 11, 5, 9, 0, time.UTC), Query: "ring"},
	}
	f := newFakeAPI(t, serverStages)
	tapped := fmt.Sprintf(`{"timestamp":"2026-09-04T11:05:07Z","message":"cx_synthetic=true cx_debug=%s probe"}`, vMarker)
	coll := NewCollector(&tapRunner{lines: []string{
		`{"timestamp":"2026-09-04T11:05:07Z","message":"someone else's traffic"}`,
		tapped,
	}}, "netops")

	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	code, err := RunTrace(context.Background(), TraceOptions{
		Kind: pipedebug.KindSyslog, Device: "spine1", Tenant: "t1",
		TTL: 2 * time.Second, Root: root, Project: "netops",
	}, f.client(t), coll, &out)
	if err != nil {
		t.Fatalf("RunTrace: %v", err)
	}
	if code != 0 {
		t.Errorf("exit %d — the api stage was seen, so the trace must exit 0:\n%s", code, out.String())
	}

	sessions, err := pipedebug.ListSessions(root)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions: %v %v", sessions, err)
	}
	session := sessions[0]

	// The §3 layout: all ten module files, none empty.
	for _, st := range pipedebug.Stages {
		data, err := os.ReadFile(filepath.Join(session, st.LogFile())) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatalf("%s: %v", st.LogFile(), err)
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			t.Errorf("%s is empty", st.LogFile())
		}
	}

	// PRIVACY: the tap saw two events; only the marked one is on disk.
	ingress, err := os.ReadFile(filepath.Join(session, "ingress.log")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ingress), "someone else's traffic") {
		t.Error("an unrelated tenant's tapped event was written into the session")
	}
	if !strings.Contains(string(ingress), vMarker) {
		t.Error("the marked event was not retained")
	}

	// The timeline carries both halves, in pipeline order, with the latency
	// measured across them.
	raw, err := os.ReadFile(filepath.Join(session, "timeline.json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var tl pipedebug.Timeline
	if err := json.Unmarshal(raw, &tl); err != nil {
		t.Fatal(err)
	}
	if tl.Marker != vMarker {
		t.Errorf("timeline marker = %q", tl.Marker)
	}
	got := map[pipedebug.Stage]pipedebug.Verdict{}
	for _, e := range tl.Entries {
		got[e.Stage] = e.Verdict
	}
	for stage, want := range map[pipedebug.Stage]pipedebug.Verdict{
		pipedebug.StageIngress:    pipedebug.VerdictSeen,          // from the tap
		pipedebug.StageParser:     pipedebug.VerdictSeen,          // from the tap
		pipedebug.StageKafka:      pipedebug.VerdictNotObservable, // from the api
		pipedebug.StageOpenSearch: pipedebug.VerdictSeen,          // from the api
		pipedebug.StageUI:         pipedebug.VerdictNotObservable, // W2
	} {
		if got[stage] != want {
			t.Errorf("stage %s = %q, want %q", stage, got[stage], want)
		}
	}
	// ingress at 11:05:07, opensearch at 11:05:08 → 1000 ms across the halves.
	for _, e := range tl.Entries {
		if e.Stage == pipedebug.StageOpenSearch {
			if e.LatencyFromPrevMS == nil {
				t.Error("no latency measured from the host half to the server half")
			}
		}
	}

	// The manifest names who ran it and which redaction pass ran.
	manRaw, err := os.ReadFile(filepath.Join(session, "manifest.json")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var man pipedebug.Manifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatal(err)
	}
	if man.Actor != "unit" || man.Marker != vMarker || man.Redaction == "" {
		t.Errorf("manifest: %+v", man)
	}
	if !strings.Contains(out.String(), "VERDICT:") {
		t.Error("the summary was not printed to the operator")
	}
}

func TestRunTraceExitsNonZeroWhenTheRecordNeverReachesTheAPI(t *testing.T) {
	f := newFakeAPI(t, []pipedebug.Entry{
		{Stage: pipedebug.StageOpenSearch, Verdict: pipedebug.VerdictNotSeen, Reason: "no document", Query: "os"},
		{Stage: pipedebug.StageAPI, Verdict: pipedebug.VerdictNotSeen, Reason: "no line", Query: "ring"},
	})
	coll := NewCollector(&tapRunner{}, "netops")
	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	code, err := RunTrace(context.Background(), TraceOptions{
		Kind: pipedebug.KindSyslog, Device: "spine1", TTL: time.Second, Root: root,
	}, f.client(t), coll, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code == 0 {
		t.Error("a trace that never reached the api exited 0 — a scripted caller would read a broken pipeline as healthy")
	}
	if !strings.Contains(out.String(), "did NOT reach") {
		t.Errorf("the summary does not say the record was lost:\n%s", out.String())
	}
}

// --passive is W2. It must REFUSE, not quietly inject a synthetic record the
// operator explicitly declined.
func TestPassiveRefusesRatherThanSilentlyInjecting(t *testing.T) {
	f := newFakeAPI(t, nil)
	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	code, err := RunTrace(context.Background(), TraceOptions{
		Kind: pipedebug.KindSyslog, Device: "spine1", Passive: true, TTL: time.Second, Root: root,
	}, f.client(t), NewCollector(&tapRunner{}, "netops"), &out)
	if err == nil || code == 0 {
		t.Fatal("--passive was accepted and silently degraded into an injection")
	}
	sessions, _ := pipedebug.ListSessions(root)
	if len(sessions) != 1 {
		t.Fatalf("no session recorded the refusal: %v", sessions)
	}
	data, err := os.ReadFile(filepath.Join(sessions[0], "ingress.log")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "W2") {
		t.Errorf("the refusal is not explained in the session: %s", data)
	}
}

// ── logs ────────────────────────────────────────────────────────────────────

// THE invariant of the `logs` verb: every module it raised is reverted, and a
// module that could not be raised is still tailed and says so.
func TestRunLogsRaisesRevertsAndIsHonestAboutTheRest(t *testing.T) {
	f := newFakeAPI(t, nil)
	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	code, err := RunLogs(context.Background(), LogsOptions{
		Modules: []pipedebug.Module{pipedebug.ModuleAPI, pipedebug.ModuleVector},
		For:     500 * time.Millisecond, Root: root, Project: "netops",
	}, f.client(t), NewCollector(&tapRunner{lines: []string{"a log line"}}, "netops"), &out)
	if err != nil || code != 0 {
		t.Fatalf("RunLogs: %v (code %d)", err, code)
	}

	puts := f.puts()
	var raisedAPI, revertedAPI, raisedVector, revertedVector bool
	for _, p := range puts {
		switch {
		case p["module"] == "api" && p["level"] == "debug":
			raisedAPI = true
		case p["module"] == "api" && p["level"] == "info":
			revertedAPI = true
		case p["module"] == "vector" && p["level"] == "debug":
			raisedVector = true
		case p["module"] == "vector" && p["level"] == "info":
			revertedVector = true
		}
	}
	if !raisedAPI || !revertedAPI {
		t.Errorf("api was not raised AND reverted: %v", puts)
	}
	if !raisedVector {
		t.Error("vector was never asked — the CLI must ask and REPORT the refusal, not skip it")
	}
	if revertedVector {
		t.Error("vector was reverted although it was never raised — the CLI must not un-set what it did not set")
	}
	if !strings.Contains(out.String(), "not runtime-switchable") {
		t.Errorf("the operator was not told why vector was not raised:\n%s", out.String())
	}

	sessions, err := pipedebug.ListSessions(root)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions: %v %v", sessions, err)
	}
	// The vector module writes into parser.log; its header must record that the
	// level was NOT raised, with the reason.
	data, err := os.ReadFile(filepath.Join(sessions[0], "parser.log")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "NOT raised") {
		t.Errorf("parser.log does not record that the level was not raised:\n%s", data)
	}
	if !strings.Contains(string(data), "a log line") {
		t.Error("a non-switchable module was not tailed — the container log is available either way")
	}
	// Every module file exists, including the ones this session did not select.
	for _, st := range pipedebug.Stages {
		if _, err := os.Stat(filepath.Join(sessions[0], st.LogFile())); err != nil {
			t.Errorf("%s missing from a logs session", st.LogFile())
		}
	}
}

// A cancelled context (what Ctrl-C produces) must still revert.
func TestRunLogsRevertsWhenTheOperatorInterrupts(t *testing.T) {
	f := newFakeAPI(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	if _, err := RunLogs(ctx, LogsOptions{
		Modules: []pipedebug.Module{pipedebug.ModuleAPI},
		For:     30 * time.Second, Root: root, Project: "netops",
	}, f.client(t), NewCollector(&tapRunner{lines: []string{"x"}}, "netops"), &out); err != nil {
		t.Fatal(err)
	}
	reverted := false
	for _, p := range f.puts() {
		if p["module"] == "api" && p["level"] == "info" {
			reverted = true
		}
	}
	if !reverted {
		t.Error("Ctrl-C left the api at debug — the CLI-side revert did not run")
	}
}

func TestRunLogsClampsTheWindow(t *testing.T) {
	f := newFakeAPI(t, nil)
	root := filepath.Join(t.TempDir(), "debug")
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := RunLogs(ctx, LogsOptions{
		Modules: []pipedebug.Module{pipedebug.ModuleAPI},
		For:     99 * time.Hour, Root: root, Project: "netops",
	}, f.client(t), NewCollector(&tapRunner{}, "netops"), &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range f.puts() {
		if p["level"] == "debug" {
			if got, _ := p["for_seconds"].(float64); int(got) != int(pipedebug.MaxWindow.Seconds()) {
				t.Errorf("for_seconds = %v, want the %v cap", got, pipedebug.MaxWindow)
			}
		}
	}
	if !strings.Contains(out.String(), "hard cap") {
		t.Errorf("the operator was not told about the cap:\n%s", out.String())
	}
}

// ── the CLI surface ─────────────────────────────────────────────────────────

func TestRunRejectsAnUnknownVerbAndPrintsUsage(t *testing.T) {
	var out, errBuf strings.Builder
	if code := Run([]string{"nonsense"}, &out, &errBuf); code != 2 {
		t.Errorf("unknown verb exited %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "USAGE") {
		t.Error("no usage printed for an unknown verb")
	}
	out.Reset()
	if code := Run(nil, &out, &errBuf); code != 2 {
		t.Errorf("no verb exited %d, want 2", code)
	}
	out.Reset()
	if code := Run([]string{"--help"}, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "SAFETY") {
		t.Errorf("--help exited %d / %q", code, out.String())
	}
}

func TestTraceVerbValidatesBeforeItTouchesTheNetwork(t *testing.T) {
	var out, errBuf strings.Builder
	for _, args := range [][]string{
		{"--kind", "flow", "--device", "spine1"},
		{"--kind", "syslog", "--device", ""},
		{"--kind", "syslog", "--device", "spine 1"},
	} {
		errBuf.Reset()
		if code := RunTraceCLI(context.Background(), args, &out, &errBuf); code != 2 {
			t.Errorf("%v exited %d, want 2", args, code)
		}
		if errBuf.Len() == 0 {
			t.Errorf("%v was refused with no message", args)
		}
	}
}

func TestLogsVerbValidatesTheModuleList(t *testing.T) {
	var out, errBuf strings.Builder
	if code := RunLogsCLI(context.Background(), []string{"--modules", "postgres"}, &out, &errBuf); code != 2 {
		t.Errorf("an unknown module exited %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--modules") {
		t.Errorf("the refusal does not name the flag: %q", errBuf.String())
	}
}

func TestDebugRootIsUnderTheDeploymentDataDirectory(t *testing.T) {
	if got := DebugRoot("/opt/correlix"); got != filepath.Join("/opt/correlix", "data", "debug") {
		t.Errorf("DebugRoot = %q", got)
	}
}
