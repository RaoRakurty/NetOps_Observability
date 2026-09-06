package experience

// reliability_test.go — tracker 253. The grade is only worth having if it is
// computed from REAL run sequences, so these cases are sequences an operator
// would recognise on sight: a flapping check, a check that is steadily and
// honestly failing, one recovering from an outage, one whose RUNNER is broken,
// and one that has simply not run often enough to be judged.
//
// The load-bearing distinction, and the reason the whole lane exists: a
// STEADILY FAILING check is TRUSTWORTHY (it is measuring something real and
// saying so) while a FLAPPING one is not. Grading them the same way is how a
// flaky test pages a human at 03:00 for a service that was never down.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// runSeq builds a run history from an outcome string: S success, F failure,
// E runner error, K skipped. Oldest first, one minute apart, one vantage.
func runSeq(defID, outcomes string, vantage string) []SyntheticRun {
	out := make([]SyntheticRun, 0, len(outcomes))
	for i, c := range outcomes {
		r := SyntheticRun{
			ID: defID + "-" + string(rune('a'+i%26)) + itoaSmall(i), TenantID: "acme",
			DefinitionID: defID, DefinitionVersion: 1, VantageID: vantage,
			StartedAt:  testNow.Add(time.Duration(i-len(outcomes)) * time.Minute),
			Provenance: prov(SourceSynthetic, time.Duration(i-len(outcomes))*time.Minute),
		}
		r.EndedAt = r.StartedAt.Add(200 * time.Millisecond)
		switch c {
		case 'S':
			r.Outcome, r.DurationMs = RunSuccess, 120
		case 'F':
			r.Outcome, r.FailReason, r.DurationMs = RunFailure, "timeout", 10000
		case 'E':
			r.Outcome, r.FailReason = RunError, "runner"
		case 'K':
			r.Outcome = RunSkipped
		}
		out = append(out, r)
	}
	return out
}

func itoaSmall(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func TestGradeReliabilityOnRealRunSequences(t *testing.T) {
	cases := []struct {
		name      string
		outcomes  string
		wantGrade string
		trusted   bool
		why       string
	}{
		{
			name: "flapping check is flaky and may not page", outcomes: "SFSFSFSFSFSFSFSF",
			wantGrade: ReliabilityFlaky, trusted: false,
			why: "a check that changes its mind every other run is measuring the test, not the service",
		},
		{
			name: "steady failure is TRUSTWORTHY evidence", outcomes: "FFFFFFFFFFFFFFFF",
			wantGrade: ReliabilitySolid, trusted: true,
			why: "a check that consistently says the service is down is a check that can raise an incident",
		},
		{
			name: "steady success is solid", outcomes: "SSSSSSSSSSSSSSSS",
			wantGrade: ReliabilitySolid, trusted: true,
		},
		{
			name: "recovering after an outage is noisy, not flaky", outcomes: "SSSSSSFFFFFFFFFFSSSS",
			wantGrade: ReliabilityNoisy, trusted: true,
			why: "two transitions across twenty runs is an incident with a recovery, not a flaky test",
		},
		{
			name: "broken runner is broken and may not page", outcomes: "EEEEEEEEEEEFSF",
			wantGrade: ReliabilityBroken, trusted: false,
			why: "the runner failing is not the target failing",
		},
		{
			name: "too few runs stays unknown", outcomes: "SFS",
			wantGrade: ReliabilityUnknown, trusted: false,
			why: "three runs cannot tell a flaky check from an outage",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeReliability("dem-1", runSeq("dem-1", tc.outcomes, "prober"))
			if got.Grade != tc.wantGrade {
				t.Fatalf("grade = %q, want %q (%s); reason=%q flips=%d errors=%d",
					got.Grade, tc.wantGrade, tc.why, got.Reason, got.Flips, got.RunnerErrors)
			}
			if got.Trustworthy() != tc.trusted {
				t.Fatalf("Trustworthy() = %v, want %v (%s)", got.Trustworthy(), tc.trusted, tc.why)
			}
			if got.Runs != len(tc.outcomes) {
				t.Fatalf("Runs = %d, want %d", got.Runs, len(tc.outcomes))
			}
			if got.Reason == "" {
				t.Fatal("every grade must carry a reason a human can read")
			}
		})
	}
}

func TestGradeReliabilityCountsVantagesAndRetries(t *testing.T) {
	runs := runSeq("dem-1", "SSSSSSSSSS", "prober-a")
	runs = append(runs, runSeq("dem-1", "SSSSSSSSSS", "prober-b")...)
	for i := range runs {
		if i%3 == 0 {
			runs[i].Retries = 1
		}
	}
	got := GradeReliability("dem-1", runs)
	if got.Vantages != 2 {
		t.Fatalf("Vantages = %d, want 2 — a second vantage is what makes agreement possible", got.Vantages)
	}
	if got.RetriedRuns == 0 {
		t.Fatal("retried runs must be counted: a check that only passes on retry is not a healthy check")
	}
	if got.Grade != ReliabilityNoisy {
		t.Fatalf("grade = %q, want noisy — a third of the runs needed a retry", got.Grade)
	}
}

func TestGradeAllSkipsDefinitionsWithNoRuns(t *testing.T) {
	got := GradeAll(map[string][]SyntheticRun{
		"dem-1": runSeq("dem-1", "SSSSSSSSSS", "prober"),
		"dem-2": nil,
	})
	if _, ok := got["dem-2"]; ok {
		t.Fatal("a definition with no runs must be ABSENT, not present as an `unknown` grade: " +
			"an absent key cannot be misread as a computed verdict")
	}
	if got["dem-1"].Grade != ReliabilitySolid {
		t.Fatalf("dem-1 grade = %q, want solid", got["dem-1"].Grade)
	}
}

// TestFlakyCheckCannotRaiseAHighSeverityIncident is the whole point of the row:
// the grade has to reach severityFor, or the rule that refuses to page on a
// flaky check never bites.
func TestFlakyCheckCannotRaiseAHighSeverityIncident(t *testing.T) {
	build := func(rel map[string]SyntheticReliability) ExperienceIncident {
		items := []EvidenceItem{ev("dem-1", ModalityActiveProbe, "prober", -20*time.Minute)}
		items[0].Entity = "dem-1"
		b := Bundle{
			TenantID: "acme", Window: testWindow(), Now: testNow,
			Evidence: items, Reliability: rel,
		}
		got := Detect(b)
		if len(got) != 1 {
			t.Fatalf("expected one incident, got %d", len(got))
		}
		return got[0]
	}
	trusted := build(map[string]SyntheticReliability{
		"dem-1": GradeReliability("dem-1", runSeq("dem-1", "FFFFFFFFFFFFFFFF", "prober")),
	})
	flaky := build(map[string]SyntheticReliability{
		"dem-1": GradeReliability("dem-1", runSeq("dem-1", "SFSFSFSFSFSFSFSF", "prober")),
	})
	if severityRank(flaky.Severity) >= severityRank(trusted.Severity) {
		t.Fatalf("a flaky check produced severity %q, no lower than the trustworthy check's %q — "+
			"the reliability grade is not reaching severityFor", flaky.Severity, trusted.Severity)
	}
}

// ── the coverage surface reads the same grades ──────────────────────────────

type stubRunSource struct {
	runs map[string][]SyntheticRun
	err  error
}

func (s stubRunSource) Runs(_ context.Context, tenant string) (map[string][]SyntheticRun, error) {
	if s.err != nil {
		return nil, s.err
	}
	if tenant != "acme" {
		// The real store is tenant-keyed; the stub proves the surface asks for
		// ONE tenant and gets nothing for anyone else.
		return map[string][]SyntheticRun{}, nil
	}
	return s.runs, nil
}

func TestCoverageReliabilityNoteTellsTheTruthAboutGrading(t *testing.T) {
	if got := CoverageReliabilityNote(false, 0, 3, nil); !strings.Contains(got, "No source of per-run records is wired") {
		t.Fatalf("unwired note = %q", got)
	}
	if got := CoverageReliabilityNote(true, 0, 3, nil); !strings.Contains(got, "not been graded") && !strings.Contains(got, "enough runs") {
		t.Fatalf("ungraded note = %q", got)
	}
	if got := CoverageReliabilityNote(true, 2, 0, nil); !strings.Contains(got, "graded from their own run history") {
		t.Fatalf("graded note = %q", got)
	}
	if got := CoverageReliabilityNote(true, 2, 0, errQueryStub); !strings.Contains(got, "could not be read") {
		t.Fatalf("error note = %q", got)
	}
	for _, note := range []string{
		CoverageReliabilityNote(false, 0, 3, nil),
		CoverageReliabilityNote(true, 0, 3, nil),
		CoverageReliabilityNote(true, 1, 2, nil),
		CoverageReliabilityNote(true, 2, 0, errQueryStub),
	} {
		if strings.Contains(note, "aggregate series") {
			t.Fatalf("the note still claims the prober publishes only aggregate series: %q", note)
		}
	}
}

var errQueryStub = errStub("the metrics store did not answer")

type errStub string

func (e errStub) Error() string { return string(e) }

// TestCoverageServesTheGradesTheDetectorUses is the end-to-end half: the
// coverage endpoint must report the SAME grade the incident detector consults,
// or the screen can tell an operator a check is trustworthy while the engine is
// quietly refusing to trust it.
func TestCoverageServesTheGradesTheDetectorUses(t *testing.T) {
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	journey := checkoutJourney()
	store := NewFileStore("")
	if _, cerr := store.CreateJourney(context.Background(), journey); cerr != nil {
		t.Fatal(cerr)
	}
	saved, lerr := store.ListJourneys(context.Background(), "acme")
	if lerr != nil || len(saved) != 1 {
		t.Fatalf("journey not stored: %v %d", lerr, len(saved))
	}
	// The stored journey's step→target bindings are what the coverage model
	// joins on; the fixture binds all three steps to dem-1..3.
	targets := []dem.Target{
		{ID: "dem-1", TenantID: "acme", Name: "browse", Kind: dem.KindHTTP, Host: "shop.example", IntervalSec: 60},
		{ID: "dem-2", TenantID: "acme", Name: "cart", Kind: dem.KindHTTP, Host: "cart.example", IntervalSec: 60},
		{ID: "dem-3", TenantID: "acme", Name: "pay", Kind: dem.KindHTTP, Host: "pay.example", IntervalSec: 60},
	}
	runs := map[string][]SyntheticRun{
		"dem-1": runSeq("dem-1", "SSSSSSSSSSSSSSSS", "prober"), // solid
		"dem-2": runSeq("dem-2", "SFSFSFSFSFSFSFSF", "prober"), // flaky
		// dem-3 has no runs at all: ungraded, and the surface must say so.
	}
	api, err := NewAPI(Deps{
		Authz: func(http.ResponseWriter, *http.Request, dem.Gate) (dem.Principal, bool) {
			return dem.Principal{Tenant: "acme", Subject: "operator"}, true
		},
		Store:   store,
		Targets: &memCatalogue{rows: targets},
		Runs:    stubRunSource{runs: runs},
		Policy:  policy,
		Enabled: true,
		Now:     func() time.Time { return testNow },
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		},
		WriteError: func(w http.ResponseWriter, status int, e error) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Error()})
		},
		LogWarn:  func(string, map[string]any) {},
		Counters: NewCounters(),
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	code, body := call(t, api.HandleCoverage, http.MethodGet, "/api/dem/synthetics/coverage", "", nil)
	if code != http.StatusOK {
		t.Fatalf("coverage: %d %s", code, body)
	}
	var resp struct {
		RunsConfigured bool           `json:"runs_configured"`
		Graded         int            `json:"graded_checks"`
		Ungraded       int            `json:"ungraded_checks"`
		Note           string         `json:"reliability_note"`
		Coverage       CoverageReport `json:"coverage"`
	}
	if jerr := json.Unmarshal(body, &resp); jerr != nil {
		t.Fatalf("decode: %v (%s)", jerr, body)
	}
	if !resp.RunsConfigured {
		t.Fatal("a wired run source reported itself as unwired")
	}
	if resp.Graded != 2 || resp.Ungraded != 1 {
		t.Fatalf("graded=%d ungraded=%d, want 2/1 (dem-3 has no runs)", resp.Graded, resp.Ungraded)
	}
	if strings.Contains(resp.Note, "aggregate series") {
		t.Fatalf("the stale not-wired note survived: %q", resp.Note)
	}
	if resp.Coverage.Flaky != 1 {
		t.Fatalf("flaky_tests = %d, want 1 — the flapping check is not reaching the coverage model", resp.Coverage.Flaky)
	}
	grades := map[string]string{}
	for _, a := range resp.Coverage.Actions {
		grades[a.StepID] = a.ReliabilityGrade
	}
	if grades["browse"] != ReliabilitySolid {
		t.Fatalf("browse grade = %q, want solid", grades["browse"])
	}
	if grades["cart"] != ReliabilityFlaky {
		t.Fatalf("cart grade = %q, want flaky", grades["cart"])
	}
	if grades["pay"] != ReliabilityUnknown {
		t.Fatalf("pay grade = %q, want unknown — a check nobody graded is not a check that passed", grades["pay"])
	}
}

func TestCoverageSaysSoWhenNoRunSourceIsWired(t *testing.T) {
	api, _ := newTestAPI(t, nil)
	code, body := call(t, api.HandleCoverage, http.MethodGet, "/api/dem/synthetics/coverage", "", nil)
	if code != http.StatusOK {
		t.Fatalf("coverage: %d %s", code, body)
	}
	var resp struct {
		RunsConfigured bool   `json:"runs_configured"`
		Note           string `json:"reliability_note"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RunsConfigured {
		t.Fatal("an unwired run source reported itself as wired")
	}
	if !strings.Contains(resp.Note, "not a check that passed") {
		t.Fatalf("the unwired note lost its honesty clause: %q", resp.Note)
	}
}

// TestWireRunOutcomesMatchTheExperienceVocabulary pins the two halves of the
// run vocabulary together. internal/dem cannot import this package (the
// dependency runs the other way), so the wire constants are declared twice on
// purpose — and a drift between them would silently reclassify every run the
// prober publishes.
func TestWireRunOutcomesMatchTheExperienceVocabulary(t *testing.T) {
	for _, pair := range [][2]string{
		{dem.RunSuccess, RunSuccess},
		{dem.RunFailure, RunFailure},
		{dem.RunError, RunError},
		{dem.RunSkipped, RunSkipped},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("run outcome drifted: wire %q vs domain %q", pair[0], pair[1])
		}
		if !dem.ValidRunOutcome(pair[1]) {
			t.Fatalf("the wire refuses an outcome the grader produces: %q", pair[1])
		}
	}
}
