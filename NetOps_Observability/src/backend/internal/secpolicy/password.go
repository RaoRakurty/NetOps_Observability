// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secpolicy

// password.go — the password-rule half of the #24 Security Policy wiring.
// Rules are RESOLVED by the caller (the policy engine and the per-scope
// settings both feed it, stricter-wins); this file owns the pure validation.

import (
	"fmt"
	"unicode"
)

// Rules is the subset of the resolved password policy the change-password
// path enforces and the UI reflects.
type Rules struct {
	MinLength         int `json:"min_length"`
	ComplexityClasses int `json:"complexity_classes"`
}

// RequiredClasses folds the scope settings' four complexity toggles into the
// number of distinct character classes they demand.
func RequiredClasses(ss Settings) int {
	classes := 0
	for _, on := range []bool{ss.RequireUppercase, ss.RequireLowercase, ss.RequireNumber, ss.RequireSpecial} {
		if on {
			classes++
		}
	}
	return classes
}

// ClassCount counts how many distinct character classes — lowercase,
// uppercase, digit, symbol — appear in pw. Pure.
func ClassCount(pw string) int {
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			n++
		}
	}
	return n
}

// ValidatePassword enforces the resolved rules on a candidate password. Pure
// (no IO) so it is unit-testable in isolation. Returns a clear, user-facing
// error describing the unmet requirement.
func ValidatePassword(pw string, rules Rules) error {
	min := rules.MinLength
	if min < 8 {
		min = 8 // never enforce below the global hard floor
	}
	// Count by runes, not bytes, so multi-byte characters count once.
	if length := len([]rune(pw)); length < min {
		return fmt.Errorf("password must be at least %d characters", min)
	}
	if rules.ComplexityClasses > 0 {
		if got := ClassCount(pw); got < rules.ComplexityClasses {
			return fmt.Errorf("password must include at least %d of: lowercase, uppercase, digit, symbol", rules.ComplexityClasses)
		}
	}
	return nil
}
