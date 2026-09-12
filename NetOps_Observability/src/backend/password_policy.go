// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// password_policy.go — main-side wiring for #24 password-rule enforcement
// (validation lives in internal/secpolicy, extracted P2 RA.2). This file keeps
// the RESOLUTION — it composes two live stores (the policy engine and the
// per-scope Security Settings, stricter-wins) — and the advisory endpoint.

import (
	"errors"
	"net/http"

	"netops/backend/internal/secpolicy"
	"netops/backend/policy"
)

type passwordRules = secpolicy.Rules

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
			scope = ScopeProvider
		}
		ss := s.securitySettings.Get(scope)
		if ss.MinPasswordLength > rules.MinLength {
			rules.MinLength = ss.MinPasswordLength
		}
		if classes := secpolicy.RequiredClasses(ss); classes > rules.ComplexityClasses {
			rules.ComplexityClasses = classes
		}
	}
	return rules
}

func validatePasswordAgainstPolicy(pw string, rules passwordRules) error {
	return secpolicy.ValidatePassword(pw, rules)
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
