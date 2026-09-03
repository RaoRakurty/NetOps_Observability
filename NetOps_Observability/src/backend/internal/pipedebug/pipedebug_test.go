package pipedebug

import (
	"strings"
	"testing"
	"time"
)

// The grammars are the security boundary: every value below is interpolated
// into a query, a container argv or a file name AFTER passing one of them.

func TestParseKindIsAClosedSet(t *testing.T) {
	for _, ok := range []string{"syslog", "TRAP", " trap "} {
		if _, err := ParseKind(ok); err != nil {
			t.Errorf("ParseKind(%q) rejected a legal kind: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "flow", "gnmi", "syslog;rm -rf /", "../etc"} {
		if _, err := ParseKind(bad); err == nil {
			t.Errorf("ParseKind(%q) accepted an illegal kind", bad)
		}
	}
}

func TestParseStageAndServerStageSplit(t *testing.T) {
	if _, err := ParseStage("opensearch"); err != nil {
		t.Fatalf("opensearch rejected: %v", err)
	}
	if _, err := ParseStage("../../etc/passwd"); err == nil {
		t.Error("a path traversal was accepted as a stage name")
	}
	// The host-side stages must NOT be servable by the API: the API has no
	// docker socket, so claiming them would be a fabricated answer.
	for _, host := range []Stage{StageIngress, StageParser, StageRouter, StageUI} {
		if IsServerStage(host) {
			t.Errorf("%s is host-collected but claimed as a server stage", host)
		}
	}
	for _, srv := range ServerStages {
		if !IsServerStage(srv) {
			t.Errorf("%s is in ServerStages but IsServerStage says no", srv)
		}
	}
}

// The design's §3 layout is a CONTRACT: one file per module, those exact names.
func TestEveryStageHasItsOwnLogFileAndTheyAreDistinct(t *testing.T) {
	want := map[string]bool{
		"ingress.log": true, "parser.log": true, "kafka.log": true, "router.log": true,
		"opensearch.log": true, "victoria.log": true, "clickhouse.log": true,
		"correlation.log": true, "api.log": true, "ui.log": true,
	}
	seen := map[string]bool{}
	for _, st := range Stages {
		f := st.LogFile()
		if seen[f] {
			t.Errorf("two stages share the log file %q", f)
		}
		seen[f] = true
		if !want[f] {
			t.Errorf("stage %s writes %q, which is not in the design's §3 layout", st, f)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("the §3 layout has %d files, the stage table produces %d", len(want), len(seen))
	}
}

func TestParseModulesRejectsUnknownAndDuplicate(t *testing.T) {
	got, err := ParseModules("api, correlation ,vector")
	if err != nil || len(got) != 3 {
		t.Fatalf("legal module list rejected: %v %v", got, err)
	}
	for _, bad := range []string{"api,api", "postgres", "", " , "} {
		if _, err := ParseModules(bad); err == nil {
			t.Errorf("ParseModules(%q) accepted an illegal list", bad)
		}
	}
}

func TestEveryModuleMapsToAComposeServiceAndALogFile(t *testing.T) {
	for _, m := range Modules {
		svc, ok := ComposeService(m)
		if !ok || svc == "" {
			t.Errorf("module %s has no compose service — the CLI would have nothing to exec against", m)
		}
		if ModuleStage(m).LogFile() == "" {
			t.Errorf("module %s has no session log file", m)
		}
	}
}

// A module raised to debug must ALWAYS come back down: the window is clamped,
// and a non-positive request becomes a default rather than "forever".
func TestClampWindowNeverYieldsUnbounded(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{0, DefaultWindow},
		{-time.Hour, DefaultWindow},
		{time.Minute, time.Minute},
		{99 * time.Hour, MaxWindow},
	}
	for _, c := range cases {
		if got := ClampWindow(c.in); got != c.want {
			t.Errorf("ClampWindow(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	if ClampTraceTTL(99*time.Hour) != MaxTraceTTL || ClampTraceTTL(0) != DefaultTraceTTL {
		t.Error("ClampTraceTTL does not bound the trace follow")
	}
}

func TestMarkerIsUlidShapedTimeOrderedAndValidated(t *testing.T) {
	t0 := time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC)
	a := NewMarker(t0)
	b := NewMarker(t0.Add(time.Second))
	if !ValidMarker(a) || !ValidMarker(b) {
		t.Fatalf("NewMarker produced an invalid marker: %q %q", a, b)
	}
	if len(a) != MarkerLen {
		t.Fatalf("marker length %d, want %d", len(a), MarkerLen)
	}
	if a >= b {
		t.Errorf("markers are not time-ordered: %q >= %q", a, b)
	}
	if a == NewMarker(t0) {
		t.Error("two markers minted in the same millisecond collided — the entropy tail is not random")
	}
	for _, bad := range []string{"", "short", strings.Repeat("z", 27), "01j9abcdefghjkmnpqrstvwxy!", "01J9ABCDEFGHJKMNPQRSTVWXYZ"} {
		if ValidMarker(bad) {
			t.Errorf("ValidMarker(%q) accepted a malformed marker", bad)
		}
	}
	// The canonical UPPER-case ULID an operator might paste is normalised, not
	// rejected.
	up := strings.ToUpper(a)
	if got, err := NormalizeMarker(up); err != nil || got != a {
		t.Errorf("NormalizeMarker(%q) = %q, %v; want %q", up, got, err, a)
	}
}

func TestMarkerIsLowerCaseBecauseOpenSearchLowerCasesTokens(t *testing.T) {
	m := NewMarker(time.Now())
	if m != strings.ToLower(m) {
		t.Error("the marker is not lower case; the analysed `message` field stores lower-cased tokens, so an upper-case marker would be stored differently from how it is queried")
	}
}

// ── timeline ────────────────────────────────────────────────────────────────

func TestBuildTimelineOrdersByPipelineNotByArrival(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tl := BuildTimeline("01j9abcdefghjkmnpqrstvwxyz", KindSyslog, "spine1", "t1", base, []Entry{
		{Stage: StageAPI, Verdict: VerdictSeen, FirstSeen: base.Add(3 * time.Second)},
		{Stage: StageIngress, Verdict: VerdictSeen, FirstSeen: base},
		{Stage: StageOpenSearch, Verdict: VerdictSeen, FirstSeen: base.Add(2 * time.Second)},
	})
	got := make([]string, 0, len(tl.Entries))
	for _, e := range tl.Entries {
		got = append(got, string(e.Stage))
	}
	want := "ingress,opensearch,api"
	if strings.Join(got, ",") != want {
		t.Errorf("timeline order = %v, want %s", got, want)
	}
	if tl.Entries[0].Index != 1 || tl.Entries[2].Index != 9 {
		t.Errorf("stage indices are not the pipeline positions: %d, %d", tl.Entries[0].Index, tl.Entries[2].Index)
	}
}

func TestLatencyIsMeasuredFromThePreviousSEENStageAndIsAbsentWhenThereIsNone(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tl := BuildTimeline("01j9abcdefghjkmnpqrstvwxyz", KindSyslog, "d", "t", base, []Entry{
		{Stage: StageIngress, Verdict: VerdictSeen, FirstSeen: base},
		{Stage: StageKafka, Verdict: VerdictNotObservable, Reason: "peek off"},
		{Stage: StageOpenSearch, Verdict: VerdictSeen, FirstSeen: base.Add(1500 * time.Millisecond)},
	})
	if tl.Entries[0].LatencyFromPrevMS != nil {
		t.Error("the first seen stage must have NO latency, not zero — zero reads as 'instant'")
	}
	if tl.Entries[1].LatencyFromPrevMS != nil {
		t.Error("an unobservable stage must not carry a latency")
	}
	if tl.Entries[2].LatencyFromPrevMS == nil || *tl.Entries[2].LatencyFromPrevMS != 1500 {
		t.Errorf("latency skipped the unobservable stage incorrectly: %v", tl.Entries[2].LatencyFromPrevMS)
	}
}

// Exit 0 ONLY when the record reached the UI-facing API (design §1): a scripted
// caller must not read a broken pipeline as a healthy one.
func TestExitCodeIsZeroOnlyWhenTheRecordReachedTheAPI(t *testing.T) {
	base := time.Now().UTC()
	reached := BuildTimeline("01j9abcdefghjkmnpqrstvwxyz", KindSyslog, "d", "t", base, []Entry{
		{Stage: StageAPI, Verdict: VerdictSeen, FirstSeen: base},
	})
	if reached.ExitCode() != 0 {
		t.Error("a trace that reached the api must exit 0")
	}
	for _, v := range []Verdict{VerdictNotSeen, VerdictNotObservable} {
		lost := BuildTimeline("01j9abcdefghjkmnpqrstvwxyz", KindSyslog, "d", "t", base, []Entry{
			{Stage: StageOpenSearch, Verdict: VerdictSeen, FirstSeen: base},
			{Stage: StageAPI, Verdict: v, Reason: "x"},
		})
		if lost.ExitCode() == 0 {
			t.Errorf("a trace whose api stage is %s must NOT exit 0", v)
		}
	}
}

func TestSummaryNamesTheLastSeenStageAndFlagsUnobservableOnes(t *testing.T) {
	base := time.Now().UTC()
	tl := BuildTimeline("01j9abcdefghjkmnpqrstvwxyz", KindSyslog, "spine1", "t1", base, []Entry{
		{Stage: StageIngress, Verdict: VerdictSeen, FirstSeen: base},
		{Stage: StageParser, Verdict: VerdictSeen, FirstSeen: base},
		{Stage: StageKafka, Verdict: VerdictNotObservable, Reason: "the peek is not configured"},
		{Stage: StageOpenSearch, Verdict: VerdictNotSeen, Reason: "no document"},
	})
	out := RenderSummary(tl, "/tmp/session")
	for _, want := range []string{
		"did NOT reach the UI-facing API",
		"last stage that saw it: parser",
		"not observable' stage was NOT checked",
		"the peek is not configured",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q:\n%s", want, out)
		}
	}
}
