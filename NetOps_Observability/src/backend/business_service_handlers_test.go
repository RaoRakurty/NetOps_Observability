package main

import "testing"

// bizSvcOwner: empty = unset (valid); non-empty follows the printable
// single-line ≤128 name rule.
func TestBizSvcOwnerBounds(t *testing.T) {
	valid := []string{"", "   ", "payments-sre", "Team Payments (EMEA)", "a.rakurty@example.com"}
	for _, s := range valid {
		if !bizSvcOwner(s) {
			t.Errorf("bizSvcOwner(%q) = false, want true", s)
		}
	}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	invalid := []string{"line\nbreak", "ctrl\x01char", string(long)}
	for _, s := range invalid {
		if bizSvcOwner(s) {
			t.Errorf("bizSvcOwner(%q) = true, want false", s)
		}
	}
}
