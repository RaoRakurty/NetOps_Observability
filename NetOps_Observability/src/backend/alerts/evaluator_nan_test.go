package alerts

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// evaluator_nan_test.go — F-21 companion (the one with the worse consequence).
//
// strconv.ParseFloat("NaN", 64) SUCCEEDS. The evaluator discarded the error and
// carried the NaN into the Sample. NaN then compares FALSE against every
// threshold — NaN > x, NaN < x and NaN == x are all false — so any rule reading
// that value silently concluded "not breaching". A metric going NaN
// (stddev_over_time over one sample, a 0/0 rate, an increase() across a counter
// reset) disabled the alert built on it with no signal anywhere.

// vmServer serves a VictoriaMetrics instant-query reply with the given values.
func vmServer(t *testing.T, values ...string) *httptest.Server {
	t.Helper()
	type series struct {
		Metric map[string]string `json:"metric"`
		Value  []any             `json:"value"`
	}
	var result []series
	for i, v := range values {
		result = append(result, series{
			Metric: map[string]string{"device": fmt.Sprintf("leaf%d", i)},
			Value:  []any{1784667176.0, v},
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": result},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNonFiniteSamplesAreDroppedAndCounted is the regression: a NaN sample must
// never reach the alert as a value that compares false against everything.
func TestNonFiniteSamplesAreDroppedAndCounted(t *testing.T) {
	srv := vmServer(t, "NaN", "92.5", "+Inf")
	t.Setenv("VICTORIA_URL", srv.URL)

	before := NonFiniteSamples()
	got, err := Evaluate(Rule{Name: "HighCPU", Expr: "cpu_usage > 90"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d samples, want 1 — the NaN and +Inf samples must be dropped, not carried "+
			"into an alert whose threshold they silently fail (F-21)", len(got))
	}
	if got[0].Value != 92.5 {
		t.Errorf("surviving sample value = %v, want 92.5", got[0].Value)
	}
	if NonFiniteSamples() != before+2 {
		t.Errorf("non-finite counter = %d, want +2 — a series producing NaN must be VISIBLE, "+
			"because every alert on it is quietly dead", NonFiniteSamples()-before)
	}
}

// TestParseSampleValueMatchesTheThresholdSemantics documents WHY dropping is the
// right answer: the comparison the alert would have made is false in both
// directions, so a NaN is indistinguishable from "healthy" to every rule.
func TestParseSampleValueMatchesTheThresholdSemantics(t *testing.T) {
	for _, s := range []string{"NaN", "nan", "+Inf", "-Inf", "Inf", "infinity"} {
		if _, ok := parseSampleValue(s); ok {
			t.Errorf("parseSampleValue(%q) accepted a non-finite value — strconv does, so this is the only guard", s)
		}
	}
	if v, ok := parseSampleValue("0"); !ok || v != 0 {
		t.Errorf("parseSampleValue(\"0\") = (%v,%v) — a legitimate zero must survive", v, ok)
	}
	if _, ok := parseSampleValue("not-a-number"); ok {
		t.Error("parseSampleValue accepted garbage")
	}
}

// TestAllNaNResultDoesNotFireAnAlert: if EVERY series is NaN the rule must
// evaluate to "no firing series" — the same as no data — rather than firing
// with a meaningless value.
func TestAllNaNResultDoesNotFireAnAlert(t *testing.T) {
	srv := vmServer(t, "NaN", "NaN")
	t.Setenv("VICTORIA_URL", srv.URL)

	got, err := Evaluate(Rule{Name: "AllNaN", Expr: "up == 0"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d samples from an all-NaN result, want 0", len(got))
	}
}
