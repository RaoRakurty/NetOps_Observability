package rcafeedback

// feedback_test.go — unit tests for the RCA operator-verdict domain (CLAUDE.md
// §11): the vocabulary/validation boundary, the false-positive arithmetic, and
// the file backend's tenant isolation + bound. The HTTP-path isolation contract
// is proven in the root package (rca_feedback_isolation_test.go); the Postgres
// backend's RLS backstop in rca_feedback_pg_isolation_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ptr(v int) *int { return &v }

func TestValidateVocabularyAndBounds(t *testing.T) {
	ok := []struct {
		name string
		in   Feedback
		ver  int
	}{
		{"correct, no part", Feedback{Verdict: "correct"}, 0},
		{"wrong with part", Feedback{Verdict: "wrong", WrongPart: "cause", Reason: "the seam owner was the ISP, not us"}, 0},
		{"partial with part", Feedback{Verdict: "partial", WrongPart: "affected"}, 0},
		{"version at the object's current", Feedback{Verdict: "wrong", CorrelationVersion: ptr(3)}, 3},
		{"version with unknown object version", Feedback{Verdict: "wrong", CorrelationVersion: ptr(9999)}, 0},
		{"reason exactly at the cap", Feedback{Verdict: "wrong", Reason: strings.Repeat("é", MaxReasonChars)}, 0},
	}
	for _, c := range ok {
		f := c.in
		if err := Validate(&f, c.ver); err != nil {
			t.Errorf("%s: valid input rejected: %v", c.name, err)
		}
	}

	bad := []struct {
		name string
		in   Feedback
		ver  int
	}{
		{"empty verdict", Feedback{}, 0},
		{"unknown verdict", Feedback{Verdict: "maybe"}, 0},
		{"unknown wrong_part", Feedback{Verdict: "wrong", WrongPart: "vibes"}, 0},
		{"wrong_part on a correct verdict", Feedback{Verdict: "correct", WrongPart: "cause"}, 0},
		{"reason one rune over the cap", Feedback{Verdict: "wrong", Reason: strings.Repeat("é", MaxReasonChars+1)}, 0},
		{"version zero", Feedback{Verdict: "wrong", CorrelationVersion: ptr(0)}, 5},
		{"version negative", Feedback{Verdict: "wrong", CorrelationVersion: ptr(-1)}, 5},
		{"version ahead of the object", Feedback{Verdict: "wrong", CorrelationVersion: ptr(6)}, 5},
		{"version past the ceiling", Feedback{Verdict: "wrong", CorrelationVersion: ptr(MaxCorrelationVersion + 1)}, 0},
	}
	for _, c := range bad {
		f := c.in
		if err := Validate(&f, c.ver); err == nil {
			t.Errorf("%s: invalid input accepted (%+v)", c.name, c.in)
		}
	}
}

func TestValidateNormalizesAndTrims(t *testing.T) {
	f := Feedback{Verdict: "  WRONG ", WrongPart: " Cause ", Reason: "  spaced  "}
	if err := Validate(&f, 0); err != nil {
		t.Fatalf("normalization rejected: %v", err)
	}
	if f.Verdict != "wrong" || f.WrongPart != "cause" || f.Reason != "spaced" {
		t.Fatalf("not normalized: %+v", f)
	}
}

// TestSummarizeArithmetic pins the metric definition itself: the rate is
// wrong / (correct + wrong + partial) — partial counts in the denominator, not
// the numerator — and an empty sample has NO rate rather than a rate of zero.
func TestSummarizeArithmetic(t *testing.T) {
	empty := Summarize(nil)
	if empty.N != 0 || empty.FalsePositiveRate != nil {
		t.Fatalf("an empty sample must have no rate, got %+v", empty)
	}
	if empty.ByTemplate == nil {
		t.Fatal("by_template must be an empty slice, never nil (a null breaks the client)")
	}

	s := Summarize([]Bucket{
		{Verdict: "correct", Template: "link_down", N: 6},
		{Verdict: "wrong", Template: "link_down", N: 2},
		{Verdict: "partial", Template: "link_down", N: 2},
		{Verdict: "wrong", Template: "bgp_flap", N: 1},
		{Verdict: "correct", Template: "", N: 1}, // no template → "undetermined"
		{Verdict: "wrong", Template: "bgp_flap", N: 0},
		{Verdict: "correct", Template: "bgp_flap", N: -3}, // never subtracts
	})
	if s.Correct != 7 || s.Wrong != 3 || s.Partial != 2 || s.N != 12 {
		t.Fatalf("counts wrong: %+v", s.Counts)
	}
	if s.FalsePositiveRate == nil || *s.FalsePositiveRate != 3.0/12.0 {
		t.Fatalf("false_positive_rate must be wrong/N = 0.25, got %v", s.FalsePositiveRate)
	}
	// Breakdown ordered by N desc, then template asc.
	if len(s.ByTemplate) != 3 {
		t.Fatalf("want 3 templates, got %+v", s.ByTemplate)
	}
	if s.ByTemplate[0].Template != "link_down" || s.ByTemplate[0].N != 10 ||
		s.ByTemplate[0].FalsePositiveRate == nil || *s.ByTemplate[0].FalsePositiveRate != 0.2 {
		t.Fatalf("link_down bucket wrong: %+v", s.ByTemplate[0])
	}
	if s.ByTemplate[1].Template != "bgp_flap" || s.ByTemplate[1].N != 1 ||
		*s.ByTemplate[1].FalsePositiveRate != 1 {
		t.Fatalf("bgp_flap bucket wrong: %+v", s.ByTemplate[1])
	}
	if s.ByTemplate[2].Template != "undetermined" || s.ByTemplate[2].N != 1 ||
		*s.ByTemplate[2].FalsePositiveRate != 0 {
		t.Fatalf("untemplated bucket wrong: %+v", s.ByTemplate[2])
	}
	// A rate of exactly 0 must still be SERIALIZED (0 ≠ null): "nobody called
	// this template a false positive" is a real answer.
	blob, err := json.Marshal(s.ByTemplate[2])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"false_positive_rate":0`) {
		t.Fatalf("zero rate must serialize as 0, got %s", blob)
	}
	nullBlob, err := json.Marshal(empty.Counts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nullBlob), `"false_positive_rate":null`) {
		t.Fatalf("an empty sample must serialize a null rate, got %s", nullBlob)
	}
}

func TestSummarizeIgnoresUnknownVerdicts(t *testing.T) {
	s := Summarize([]Bucket{
		{Verdict: "correct", Template: "t", N: 1},
		{Verdict: "sideways", Template: "t", N: 99}, // must not move the denominator
	})
	if s.N != 1 || *s.FalsePositiveRate != 0 {
		t.Fatalf("an unknown verdict moved the rate: %+v", s.Counts)
	}
}

// ---- file backend -------------------------------------------------------------

func add(t *testing.T, s Store, tenant, corr, verdict string, at time.Time) Feedback {
	t.Helper()
	f, err := s.Add(context.Background(), tenant, false, Feedback{
		TenantID: tenant, CorrelationID: corr, Verdict: verdict,
		TopHypothesis: "link_down", CreatedBy: "op@" + tenant, CreatedAt: at,
	})
	if err != nil {
		t.Fatalf("add %s/%s: %v", tenant, verdict, err)
	}
	return f
}

func TestFileStoreIsTenantKeyed(t *testing.T) {
	st := NewFileStore("")
	now := time.Now().UTC()
	mine := add(t, st, "acme", "c-1", "wrong", now)
	add(t, st, "globex", "c-1", "correct", now)

	got, err := st.List(context.Background(), "acme", false, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != mine.ID {
		t.Fatalf("TENANT LEAK: acme's list on a shared case id returned %+v", got)
	}
	// Cross-tenant (platform owner) sees both.
	all, err := st.List(context.Background(), "acme", true, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("cross-tenant list must see both, got %+v", all)
	}
	// The aggregate obeys the same scope.
	b, err := st.Buckets(context.Background(), "acme", false, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if s := Summarize(b); s.N != 1 || s.Wrong != 1 {
		t.Fatalf("TENANT LEAK in the aggregate: %+v", s.Counts)
	}
}

func TestFileStoreListIsNewestFirstAndWindowed(t *testing.T) {
	st := NewFileStore("")
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	add(t, st, "acme", "c-1", "correct", base)
	newest := add(t, st, "acme", "c-1", "wrong", base.Add(time.Hour))

	got, err := st.List(context.Background(), "acme", false, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != newest.ID {
		t.Fatalf("list must be newest-first: %+v", got)
	}
	// A window that starts after the older row excludes it.
	b, err := st.Buckets(context.Background(), "acme", false, base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if s := Summarize(b); s.N != 1 || s.Wrong != 1 {
		t.Fatalf("window not applied: %+v", s.Counts)
	}
}

func TestFileStoreBoundsPerCase(t *testing.T) {
	st := NewFileStore("")
	now := time.Now().UTC()
	for i := 0; i < MaxPerCase; i++ {
		add(t, st, "acme", "c-1", "correct", now)
	}
	if _, err := st.Add(context.Background(), "acme", false, Feedback{
		TenantID: "acme", CorrelationID: "c-1", Verdict: "correct",
	}); !errors.Is(err, ErrLimit) {
		t.Fatalf("the per-case bound must be enforced, got %v", err)
	}
	// A different case of the same tenant is unaffected.
	add(t, st, "acme", "c-2", "correct", now)
}

func TestFileStoreRoundTripsThroughDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_feedback.json")
	st := NewFileStore(path)
	now := time.Now().UTC().Truncate(time.Millisecond)
	want := add(t, st, "acme", "c-1", "partial", now)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the store did not persist: %v", err)
	}
	reloaded := NewFileStore(path)
	got, err := reloaded.List(context.Background(), "acme", false, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != want.ID || got[0].Verdict != "partial" {
		t.Fatalf("reload lost the row: %+v", got)
	}
	// And a foreign tenant still sees nothing after a reload.
	if other, err := reloaded.List(context.Background(), "globex", false, "c-1"); err != nil || len(other) != 0 {
		t.Fatalf("TENANT LEAK after reload: %+v (%v)", other, err)
	}
}

func TestMetricsCountByVerdict(t *testing.T) {
	m := NewMetrics()
	m.Inc("wrong")
	m.Inc("wrong")
	m.Inc("correct")
	m.Inc("nonsense") // dropped, never mislabelled
	var sb strings.Builder
	m.Write(&sb)
	out := sb.String()
	for _, want := range []string{
		`netops_rca_feedback_total{verdict="correct"} 1`,
		`netops_rca_feedback_total{verdict="wrong"} 2`,
		`netops_rca_feedback_total{verdict="partial"} 0`,
		`# TYPE netops_rca_feedback_total counter`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q:\n%s", want, out)
		}
	}
	// A nil receiver must be inert (the store may be unconfigured).
	var nilM *Metrics
	nilM.Inc("wrong")
	nilM.Write(&sb)
}
