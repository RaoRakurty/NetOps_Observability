// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// security_settings.go — main-side wiring for the scope-wide Security Settings
// domain (internal/secpolicy, extracted P2 RA.2). The model, store, defaults
// and clamps live in the package; this file keeps the aliases and the handler
// (scope authorization reads live stores: isPlatformOwner + reachesTenant).

import (
	"encoding/json"
	"errors"
	"net/http"

	"netops/backend/internal/secpolicy"
)

// ScopeProvider is the settings scope for the platform-owner (provider) realm.
const ScopeProvider = secpolicy.ScopeProvider

type (
	SecuritySettings      = secpolicy.Settings
	securitySettingsStore = secpolicy.Store
)

func newSecuritySettingsStore(path string) (*securitySettingsStore, error) {
	return secpolicy.NewStore(path)
}

func normalizeSettingsScope(scope string) string { return secpolicy.NormalizeScope(scope) }

// handleSecuritySettings serves GET/PUT /api/security-settings?scope=provider|<tenant>.
func (s *server) handleSecuritySettings(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	scope := normalizeSettingsScope(r.URL.Query().Get("scope"))
	// Provider-scope settings are platform-owner only; a tenant's settings need
	// the platform owner or that tenant's admin.
	if scope == ScopeProvider {
		if !isPlatformOwner(claims) {
			writeError(w, http.StatusForbidden, errors.New("platform administrator required"))
			return
		}
	} else if !isPlatformOwner(claims) && !s.reachesTenant(claims.Sub, scope) {
		writeError(w, http.StatusForbidden, errors.New("not your scope"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.securitySettings.Get(scope))
	case http.MethodPut:
		var in SecuritySettings
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.securitySettings.Set(scope, in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("security", "security settings updated", map[string]any{"scope": scope, "by": claims.Sub})
		writeJSON(w, http.StatusOK, out)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
