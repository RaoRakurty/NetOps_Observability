package pipedebug

// sessions_test.go — the W3 (in-GUI viewer) surface: the session routes, the
// read side of /api/debug/loglevel, and the session the api writes for a trace
// started from the GUI.
//
// What these tests are FOR, in order of importance:
//  1. the gate (§3a rule 3) — every new route refuses an unauthorized caller;
//  2. tenant scope (§3a rule 1) — a scoped principal never sees, opens, reads a
//     module of, or downloads another tenant's session, and gets a 404 rather
//     than a 403 so the id's existence is not confirmed;
//  3. the closed grammars — a session id and a module name that did not come
//     out of this tool's own vocabulary never reach the filesystem;
//  4. the bounds — module reads are capped in bytes and lines, the listing is
//     capped, and the bundle refuses rather than truncates;
//  5. the honest states — an absent root, an absent module file and an empty
//     index all say WHY instead of rendering as "nothing happened".

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sessTestMarker = "01j9abcdefghjkmnpqrstvwxyz"

// writeFixtureSession lays down a session directory the way the writer does.
func writeFixtureSession(t *testing.T, root, marker, tenant string, started time.Time) string {
	t.Helper()
	sess, err := NewSession(root, "trace", marker, started, Manifest{
		Kind: KindSyslog, Device: "spine1", Tenant: tenant, Actor: "owner",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	entries := []Entry{
		{Stage: StageKafka, Verdict: VerdictSeen, FirstSeen: started.Add(time.Second), Query: "peek"},
		{Stage: StageOpenSearch, Verdict: VerdictNotSeen, Reason: "not indexed", Query: "search"},
		{Stage: StageVictoria, Verdict: VerdictNotObservable, Reason: "no series for this kind", Query: "export"},
	}
	for _, e := range entries {
		if err := sess.Header(e.Stage, string(e.Stage), "test", 0); err != nil {
			t.Fatalf("header: %v", err)
		}
		if err := sess.Line(e.Stage, "info", "stage "+string(e.Stage), map[string]any{"verdict": string(e.Verdict)}); err != nil {
			t.Fatalf("line: %v", err)
		}
	}
	if err := sess.EnsureAllModules(hostOnlyReason); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	tl := BuildTimeline(marker, KindSyslog, "spine1", tenant, started, entries)
	if err := sess.WriteTimeline(tl); err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if err := sess.WriteSummary(RenderSummary(tl, sess.Dir())); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if err := sess.Close(started); err != nil {
		t.Fatalf("close: %v", err)
	}
	return filepath.Base(sess.Dir())
}

func sessionAPI(t *testing.T, root string) (*API, *fakeBackend) {
	t.Helper()
	f := newFakeBackend()
	deps := f.deps()
	deps.SessionRoot = root
	return New(deps), f
}

// ── the gate ────────────────────────────────────────────────────────────────

// §3a rule 3: the session family is platform plumbing that can return a
// tenant's own log line. An unauthorized caller must be stopped before any
// directory is read.
func TestSessionRoutesRefuseAnUnauthorizedCaller(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC))
	api, f := sessionAPI(t, root)
	f.authOK = false

	for _, rt := range []struct {
		name string
		h    http.HandlerFunc
		path string
	}{
		{"index", api.HandleSessions, "/api/debug/sessions"},
		{"detail", api.HandleSession, "/api/debug/sessions/" + id},
		{"module", api.HandleSession, "/api/debug/sessions/" + id + "/module/kafka"},
		{"bundle", api.HandleSession, "/api/debug/sessions/" + id + "/bundle"},
		{"loglevel-read", api.HandleLogLevel, "/api/debug/loglevel"},
	} {
		w := call(t, rt.h, http.MethodGet, rt.path, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: unauthorized caller got %d, want 403", rt.name, w.Code)
		}
	}
	if len(f.snap().audits) != 0 {
		t.Errorf("a refused caller produced audit records: %v", f.snap().audits)
	}
}

// Every one of these routes can hand back tenant telemetry, so every one of
// them is AUDITED, not merely gated.
func TestEverySessionReadIsAudited(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Now().UTC())
	api, f := sessionAPI(t, root)

	call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id, "")
	call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id+"/module/kafka", "")
	call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id+"/bundle", "")
	call(t, api.HandleLogLevel, http.MethodGet, "/api/debug/loglevel", "")

	want := map[string]bool{
		"debug.sessions.list": false, "debug.sessions.get": false,
		"debug.sessions.module": false, "debug.sessions.bundle": false,
		"debug.loglevel.status": false,
	}
	for _, a := range f.snap().audits {
		if _, ok := want[a["action"].(string)]; ok {
			want[a["action"].(string)] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("%s was not audited", action)
		}
	}
}

// ── tenant scope (§3a rule 1) ───────────────────────────────────────────────

func TestAScopedPrincipalNeverSeesAnotherTenantsSession(t *testing.T) {
	root := t.TempDir()
	mine := writeFixtureSession(t, root, sessTestMarker, "acme", time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC))
	theirs := writeFixtureSession(t, root, "01j9zyxwvtsrqpnmkjhgfedcba", "globex", time.Date(2026, 9, 4, 12, 5, 0, 0, time.UTC))

	api, f := sessionAPI(t, root)
	f.principal = Principal{Subject: "acme-admin", Tenant: "acme", Cross: false}

	w := call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	var idx SessionIndex
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(idx.Sessions) != 1 || idx.Sessions[0].ID != mine {
		t.Fatalf("scoped principal saw %d sessions (%+v), want only its own", len(idx.Sessions), idx.Sessions)
	}

	// Cross-tenant GET / module / bundle are all the SAME 404 an absent session
	// gets — never a 403, which would confirm the id exists.
	for _, path := range []string{
		"/api/debug/sessions/" + theirs,
		"/api/debug/sessions/" + theirs + "/module/kafka",
		"/api/debug/sessions/" + theirs + "/bundle",
	} {
		w := call(t, api.HandleSession, http.MethodGet, path, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "forbidden") {
			t.Errorf("%s: the body admits the session exists: %q", path, w.Body.String())
		}
	}
	// And the cross-tenant owner sees both.
	f.principal = Principal{Subject: "owner", Cross: true}
	w = call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	idx = SessionIndex{}
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(idx.Sessions) != 2 {
		t.Fatalf("platform owner saw %d sessions, want 2", len(idx.Sessions))
	}
	// Newest first — the directory stamp sorts chronologically.
	if idx.Sessions[0].ID != theirs {
		t.Errorf("index is not newest-first: %v", []string{idx.Sessions[0].ID, idx.Sessions[1].ID})
	}
}

// ── closed grammars ─────────────────────────────────────────────────────────

func TestSessionIDGrammarRejectsAnythingThisToolDidNotWrite(t *testing.T) {
	good := "20260904T1105Z-trace-" + sessTestMarker
	if !ValidSessionID(good) {
		t.Fatalf("%q should be a valid session id", good)
	}
	bad := []string{
		"", "..", "../../etc", "20260904T1105Z-trace-" + sessTestMarker + "/../..",
		"20260904T1105Z-shell-" + sessTestMarker,     // verb outside the closed set
		"20260904T1105Z-trace-NOTAMARKER",            // marker grammar
		"20261399T1105Z-trace-" + sessTestMarker,     // impossible date
		"20260904T1105-trace-" + sessTestMarker,      // stamp shape
		"20260904T1105Z-trace-" + sessTestMarker[:4], // short marker
	}
	for _, s := range bad {
		if ValidSessionID(s) {
			t.Errorf("%q was accepted as a session id", s)
		}
	}
}

// The SECOND lock: even if the id grammar were loosened, a path that resolved
// outside the debug root must not be returned. gosec's taint rule (G703) is
// excluded tree-wide on the finding that no handler builds a path from request
// input — this file is the first that does, so the containment check is the
// thing that keeps that exclusion true here.
func TestSessionPathNeverEscapesTheDebugRoot(t *testing.T) {
	root := t.TempDir()
	good := "20260904T1105Z-trace-" + sessTestMarker
	dir, err := sessionPath(root, good)
	if err != nil {
		t.Fatalf("a valid id was refused: %v", err)
	}
	if filepath.Dir(dir) != filepath.Clean(root) {
		t.Errorf("session path %q is not directly under %q", dir, root)
	}
	for _, bad := range []string{"..", "../..", ".", "", "/etc", "20260904T1105Z-trace-" + sessTestMarker + "/.."} {
		if _, err := sessionPath(root, bad); err == nil {
			t.Errorf("sessionPath accepted %q", bad)
		}
	}
}

func TestSessionRouteRefusesATraversingIDAndAnUnknownModule(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Now().UTC())
	// A file the route must never be able to reach, one level up from the root.
	secret := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(secret, []byte("not for the debugger"), 0o600); err != nil {
		t.Fatalf("write bait: %v", err)
	}
	api, _ := sessionAPI(t, root)

	for _, path := range []string{
		"/api/debug/sessions/..%2f..%2fsecret.txt",
		"/api/debug/sessions/" + id + "/module/..%2f..%2fsecret.txt",
		"/api/debug/sessions/" + id + "/module/manifest.json",
		"/api/debug/sessions/" + id + "/module/summary",
	} {
		w := call(t, api.HandleSession, http.MethodGet, path, "")
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 400/404", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "not for the debugger") {
			t.Fatalf("%s SERVED A FILE OUTSIDE THE SESSION: %q", path, w.Body.String())
		}
	}
}

// ── bounds (§9) ─────────────────────────────────────────────────────────────

func TestAModuleReadIsBoundedInLinesAndSaysSo(t *testing.T) {
	root := t.TempDir()
	started := time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC)
	id := writeFixtureSession(t, root, sessTestMarker, "acme", started)
	// Append far more lines than the cap allows.
	path := filepath.Join(root, id, StageKafka.LogFile())
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open module file: %v", err)
	}
	for i := 0; i < maxModuleLines+50; i++ {
		if _, err := f.WriteString("{\"msg\":\"filler\"}\n"); err != nil {
			t.Fatalf("write filler: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	api, _ := sessionAPI(t, root)
	w := call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id+"/module/kafka", "")
	if w.Code != http.StatusOK {
		t.Fatalf("module read got %d", w.Code)
	}
	var out ModuleLog
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Lines) > maxModuleLines {
		t.Errorf("module read returned %d lines, cap is %d", len(out.Lines), maxModuleLines)
	}
	if !out.Truncated || out.Reason == "" {
		t.Error("a truncated module read must SAY it was truncated and why")
	}
}

// A module file this session never wrote is a 200 with the reason — the session
// exists, the module simply produced nothing in it.
func TestAMissingModuleFileIsAnHonestAnswerNotAnError(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Now().UTC())
	if err := os.Remove(filepath.Join(root, id, StageKafka.LogFile())); err != nil {
		t.Fatalf("remove: %v", err)
	}
	api, _ := sessionAPI(t, root)
	w := call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id+"/module/kafka", "")
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 with a reason", w.Code)
	}
	var out ModuleLog
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Reason == "" {
		t.Error("a missing module file answered with no reason — that is the silent-failure shape")
	}
}

func TestTheIndexIsBoundedAndSaysWhenItIsTruncated(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		writeFixtureSession(t, root, NewMarker(base.Add(time.Duration(i)*time.Hour)), "acme", base.Add(time.Duration(i)*time.Hour))
	}
	api, _ := sessionAPI(t, root)
	w := call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions?limit=2", "")
	var idx SessionIndex
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(idx.Sessions) != 2 || !idx.Truncated {
		t.Fatalf("limit=2 returned %d sessions, truncated=%v", len(idx.Sessions), idx.Truncated)
	}
}

// ── honest empty states (§10) ───────────────────────────────────────────────

func TestAnEmptyIndexAlwaysCarriesTheReasonItIsEmpty(t *testing.T) {
	// (a) no root configured at all.
	f := newFakeBackend()
	api := New(f.deps())
	w := call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	var idx SessionIndex
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(idx.Sessions) != 0 || idx.Reason == "" {
		t.Errorf("an unconfigured session root answered %d sessions, reason %q", len(idx.Sessions), idx.Reason)
	}

	// (b) configured but nothing written yet.
	api2, _ := sessionAPI(t, filepath.Join(t.TempDir(), "never-created"))
	w = call(t, api2.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	idx = SessionIndex{}
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if idx.Reason == "" {
		t.Error("an empty debug root answered with no reason")
	}
}

// ── the bundle ──────────────────────────────────────────────────────────────

func TestTheBundleIsATarGzWithVerifiableChecksums(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC))
	api, _ := sessionAPI(t, root)

	w := call(t, api.HandleSession, http.MethodGet, "/api/debug/sessions/"+id+"/bundle", "")
	if w.Code != http.StatusOK {
		t.Fatalf("bundle got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.Bytes()
	sum := sha256.Sum256(body)
	if got := w.Header().Get("X-Correlix-Bundle-SHA256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("the declared digest %q does not match the body", got)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, id) {
		t.Errorf("Content-Disposition %q does not name the session", cd)
	}

	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	tr := tar.NewReader(zr)
	members := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read member: %v", err)
		}
		members[h.Name] = data
	}
	if _, ok := members["BUNDLE-README.txt"]; !ok {
		t.Error("the bundle carries no README stating which redaction pass ran")
	}
	sums, ok := members["SHA256SUMS"]
	if !ok {
		t.Fatal("the bundle carries no SHA256SUMS")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed SHA256SUMS line %q", line)
		}
		data, ok := members[parts[1]]
		if !ok {
			t.Errorf("SHA256SUMS names %q, which is not in the archive", parts[1])
			continue
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != parts[0] {
			t.Errorf("checksum mismatch for %q", parts[1])
		}
	}
	if _, ok := members[filepath.Join(id, "timeline.json")]; !ok {
		t.Error("the bundle does not carry the session's timeline")
	}
}

func TestTheBundleRefusesRatherThanTruncates(t *testing.T) {
	root := t.TempDir()
	id := writeFixtureSession(t, root, sessTestMarker, "acme", time.Now().UTC())
	var buf bytes.Buffer
	// A one-byte limit is over-run by the README alone.
	if _, err := WriteBundleTar(&buf, []string{filepath.Join(root, id)}, 1); err == nil {
		t.Fatal("an over-limit bundle was written instead of refused")
	}
}

// ── the read side of /api/debug/loglevel ────────────────────────────────────

func TestLogLevelStatusIsHonestAboutWhatItCanRead(t *testing.T) {
	f := newFakeBackend()
	deps := f.deps()
	sw := NewLevelSwitch(ModuleAPI, func(Level) error { return nil })
	deps.LevelReaders = map[Module]LevelReader{ModuleAPI: sw}
	api := New(deps)

	sw.Set(LevelDebug, time.Minute)

	w := call(t, api.HandleLogLevel, http.MethodGet, "/api/debug/loglevel", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status got %d", w.Code)
	}
	var st LevelStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(st.Modules) != len(Modules) {
		t.Fatalf("status listed %d modules, want %d", len(st.Modules), len(Modules))
	}
	if st.MaxWindowSeconds != int(MaxWindow.Seconds()) {
		t.Errorf("status advertises a %ds cap, the code enforces %v", st.MaxWindowSeconds, MaxWindow)
	}
	by := map[Module]LevelState{}
	for _, m := range st.Modules {
		by[m.Module] = m
	}
	if got := by[ModuleAPI]; got.Source != LevelSourceLive || got.Level != LevelDebug || got.RevertAt.IsZero() {
		t.Errorf("the api's own switch is not reported live with its revert time: %+v", got)
	}
	// A module with no runtime switch reports switchable:false WITH the reason
	// the PUT would give — the panel and the action must agree.
	for _, m := range []Module{ModuleRouter, ModuleIngress} {
		got := by[m]
		if got.Switchable || got.Reason == "" {
			t.Errorf("%s reported switchable=%v reason=%q; want false with a reason", m, got.Switchable, got.Reason)
		}
	}
	// Nothing has been requested for correlation, so it is UNKNOWN — never a
	// guessed "info".
	if got := by[ModuleCorrelation]; got.Source != LevelSourceUnknown || got.Level != "" {
		t.Errorf("correlation reported %+v; want an unknown level, not a guess", got)
	}

	// After a PUT, the same module reports the last REQUEST, labelled as such.
	f.corrLevel = LevelChange{Module: ModuleCorrelation, Applied: true, Level: LevelDebug, RevertAt: time.Now().Add(time.Minute)}
	if w := call(t, api.HandleLogLevel, http.MethodPut, "/api/debug/loglevel", `{"module":"correlation","level":"debug","for_seconds":60}`); w.Code != http.StatusOK {
		t.Fatalf("put got %d", w.Code)
	}
	w = call(t, api.HandleLogLevel, http.MethodGet, "/api/debug/loglevel", "")
	st = LevelStatus{}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, m := range st.Modules {
		if m.Module != ModuleCorrelation {
			continue
		}
		if m.Source != LevelSourceLastRequest || m.Level != LevelDebug {
			t.Errorf("correlation after a raise: %+v; want the last request reported as such", m)
		}
	}
}

// ── the session a GUI trace writes ──────────────────────────────────────────

// A trace started from the GUI has no host-side collector, so the session it
// writes must SAY which stages the host CLI collects instead of leaving those
// module files empty (design §3 — an empty file reads as "nothing happened").
func TestAGUITraceWritesEveryModuleFileWithAnHonestHostSideReason(t *testing.T) {
	root := t.TempDir()
	f := newFakeBackend()
	deps := f.deps()
	deps.SessionRoot = root
	api := New(deps)

	started := time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC)
	spec, note := api.persistSpecFor(true, Principal{Subject: "owner", Cross: true},
		KindSyslog, "spine1", "acme", sessTestMarker, started, false)
	if spec == nil || note != "" {
		t.Fatalf("persistSpecFor refused a writable root: spec=%v note=%q", spec, note)
	}
	st := TraceStatus{Marker: sessTestMarker, Kind: KindSyslog, Device: "spine1", Tenant: "acme", Started: started}
	entries := []Entry{{Stage: StageKafka, Verdict: VerdictSeen, FirstSeen: started.Add(time.Second), Query: "peek"}}

	dir, err := api.writeSession(spec, st, entries)
	if err != nil {
		t.Fatalf("write session: %v", err)
	}
	if filepath.Base(dir) != spec.ID {
		t.Errorf("the receipt promised session %q and the writer wrote %q", spec.ID, filepath.Base(dir))
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("session directory is %v, want 0700 — it holds tenant telemetry", perm)
	}
	for _, stage := range Stages {
		data, err := os.ReadFile(filepath.Join(dir, stage.LogFile()))
		if err != nil {
			t.Fatalf("module file %s: %v", stage.LogFile(), err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			t.Errorf("%s is EMPTY — an empty module file reads as 'nothing happened'", stage.LogFile())
		}
	}
	host, err := os.ReadFile(filepath.Join(dir, StageRouter.LogFile()))
	if err != nil {
		t.Fatalf("router file: %v", err)
	}
	if !strings.Contains(string(host), "correlix-debug") {
		t.Errorf("the host-only stage does not name the CLI that CAN collect it: %s", host)
	}

	// And the session is immediately readable through the routes.
	w := call(t, api.HandleSessions, http.MethodGet, "/api/debug/sessions", "")
	var idx SessionIndex
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(idx.Sessions) != 1 || idx.Sessions[0].Tenant != "acme" || idx.Sessions[0].Seen != 1 {
		t.Fatalf("the written session did not come back through the index: %+v", idx.Sessions)
	}
}

// Asking for a session on a build that has no root must be TOLD, not silently
// dropped — otherwise the GUI shows a session id that will never exist.
func TestAPersistRequestOnARootlessBuildIsRefusedOutLoud(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	spec, note := api.persistSpecFor(true, Principal{Cross: true}, KindSyslog, "spine1", "acme", sessTestMarker, time.Now().UTC(), false)
	if spec != nil {
		t.Fatal("a rootless build promised a session directory")
	}
	if note == "" {
		t.Error("a refused session request produced no explanation")
	}
}
