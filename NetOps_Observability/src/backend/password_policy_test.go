// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/internal/secpolicy"
)

func TestPasswordClassCount(t *testing.T) {
	cases := map[string]int{
		"":            0,
		"abcdef":      1, // lower
		"ABCDEF":      1, // upper
		"123456":      1, // digit
		"!@#$%^":      1, // symbol
		"abcABC":      2,
		"abc123":      2,
		"abcABC123":   3,
		"abcABC123!@": 4,
	}
	for pw, want := range cases {
		if got := secpolicy.ClassCount(pw); got != want {
			t.Errorf("secpolicy.ClassCount(%q) = %d, want %d", pw, got, want)
		}
	}
}

func TestValidatePasswordAgainstPolicy(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		rules   passwordRules
		wantErr bool
	}{
		{"meets length", "abcdefghijkl", passwordRules{MinLength: 12}, false},
		{"too short for policy", "abcdefghij", passwordRules{MinLength: 12}, true},
		{"policy below hard floor still enforces 8", "abc", passwordRules{MinLength: 4}, true},
		{"exactly hard floor", "abcdefgh", passwordRules{MinLength: 0}, false},
		{"complexity met", "Abcdef12", passwordRules{MinLength: 8, ComplexityClasses: 3}, false},
		{"complexity unmet", "abcdefgh", passwordRules{MinLength: 8, ComplexityClasses: 3}, true},
		{"complexity off ignores classes", "abcdefgh", passwordRules{MinLength: 8, ComplexityClasses: 0}, false},
		{"all four classes", "Abcdef1!", passwordRules{MinLength: 8, ComplexityClasses: 4}, false},
		{"multibyte counts by rune", "éééééééééééé", passwordRules{MinLength: 12}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordAgainstPolicy(tc.pw, tc.rules)
			if (err != nil) != tc.wantErr {
				t.Errorf("validatePasswordAgainstPolicy(%q, %+v) err = %v, wantErr = %v", tc.pw, tc.rules, err, tc.wantErr)
			}
		})
	}
}
