package metricval

// F-21 parse-boundary contract (moved from package main's resource_bounds_test
// with the code, 2026-07-27). The end-to-end shape — a NaN sample must degrade
// one field, never empty a whole JSON response — stays with the integrator's
// writeJSON in package main.

import "testing"

// TestParseRejectsNonFinite: ParseFloat ACCEPTS "NaN"/"Inf". This is
// the parse boundary that must not.
func TestParseRejectsNonFinite(t *testing.T) {
	for _, s := range []string{"NaN", "nan", "+Inf", "-Inf", "inf", "Infinity"} {
		if v, ok := Parse(s); ok {
			t.Errorf("Parse(%q) = (%v, true) — strconv accepts it, so this helper is the only thing that can reject it", s, v)
		}
	}
	for _, s := range []string{"", "abc", "1.2.3"} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) reported ok on malformed input", s)
		}
	}
	if v, ok := Parse(" 42.5 "); !ok || v != 42.5 {
		t.Errorf("Parse(\" 42.5 \") = (%v,%v), want (42.5,true)", v, ok)
	}
}

// TestSanitizeGuardsComputedValues: 0/0 in a rate calculation produces NaN
// without any string ever being parsed.
func TestSanitizeGuardsComputedValues(t *testing.T) {
	var zero float64
	if got := Sanitize(zero / zero); got != 0 {
		t.Errorf("Sanitize(NaN) = %v, want 0", got)
	}
	if got := Sanitize(1 / zero); got != 0 {
		t.Errorf("Sanitize(+Inf) = %v, want 0", got)
	}
	if got := Sanitize(3.5); got != 3.5 {
		t.Errorf("Sanitize(3.5) = %v, want 3.5", got)
	}
}
