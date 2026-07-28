package main

import (
	"errors"
	"fmt"
	"net/http"
	"unicode"

	"netops/backend/policy"
)

// password_policy.go wires the #24 Security Policy engine into self-service
// password changes. Previously change-password enforced only a hardcoded 8-char
// floor (users.ValidatePassword); now the new password is validated against the
// caller's *resolved* policy — `password.min_length` and
// `password.complexity_classes` (System → Tenant → Role → User). The same
// resolved rules are exposed read-only at GET /api/auth/password-policy so the
// UI can show live requirements. Zero-trust: validation is server-side and
// authoritative; the endpoint is advisory only.

// passwordRules is the subset of the resolved password policy the change-password
// path enforces and the UI reflects.
type passwordRules struct {
	MinLength         int `json:"min_length"`
	ComplexityClasses int `json:"complexity_classes"`
}

// callerPasswordRules resolves the effective password rules for the principal's
// own subject (tenant/role/user). Missing settings fall back to the catalog
// defaults via the resolver, so this never returns a weaker-than-baseline rule.
func (s *server) callerPasswordRules(claims jwtClaims) passwordRules {
	rules := passwordRules{MinLength: 8} // conservative floor if nothing is wired
	// #24 policy engine (System→Tenant→Role→User).
	if s.secPolicy != nil {
		sub := policy.Subject{Tenant: claims.Tenant, Role: claims.Role, User: claims.Sub}
		if r, ok := s.secPolicy.ResolveSetting(sub, "password.min_length"); ok {
			rules.MinLength = int(r.Value.Num)
		}
		if r, ok := s.secPolicy.ResolveSetting(sub, "password.complexity_classes"); ok {
			rules.ComplexityClasses = int(r.Value.Num)
		}
	}
	// Per-scope Security Settings (the password toggles the admin UI exposes). Take
	// the STRICTER of the two systems so neither weakens the other and the UI's
	// require_uppercase/lowercase/number/special toggles are actually enforced.
	if s.securitySettings != nil {
		scope := claims.Tenant
		if scope == "" {
			scope = "provider"
		}
		ss := s.securitySettings.Get(scope)
		if ss.MinPasswordLength > rules.MinLength {
			rules.MinLength = ss.MinPasswordLength
		}
		classes := 0
		for _, on := range []bool{ss.RequireUppercase, ss.RequireLowercase, ss.RequireNumber, ss.RequireSpecial} {
			if on {
				classes++
			}
		}
		if classes > rules.ComplexityClasses {
			rules.ComplexityClasses = classes
		}
	}
	return rules
}

// passwordClassCount counts how many distinct character classes — lowercase,
// uppercase, digit, symbol — appear in pw. Pure.
func passwordClassCount(pw string) int {
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

// validatePasswordAgainstPolicy enforces the resolved rules on a candidate
// password. Pure (no IO) so it is unit-testable in isolation. Returns a clear,
// user-facing error describing the unmet requirement.
func validatePasswordAgainstPolicy(pw string, rules passwordRules) error {
	min := rules.MinLength
	if min < 8 {
		min = 8 // never enforce below the global hard floor
	}
	// Count by runes, not bytes, so multi-byte characters count once.
	if length := len([]rune(pw)); length < min {
		return fmt.Errorf("password must be at least %d characters", min)
	}
	if rules.ComplexityClasses > 0 {
		if got := passwordClassCount(pw); got < rules.ComplexityClasses {
			return fmt.Errorf("password must include at least %d of: lowercase, uppercase, digit, symbol", rules.ComplexityClasses)
		}
	}
	return nil
}

// handlePasswordPolicy: GET /api/auth/password-policy. Returns the caller's own
// resolved password rules so the change-password form can render live
// requirements. Authenticated (any logged-in user); advisory — the server
// re-validates authoritatively on change.
func (s *server) handlePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	writeJSON(w, http.StatusOK, s.callerPasswordRules(claims))
}
