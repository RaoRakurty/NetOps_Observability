// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tacacs_wiring.go — what stays in main after the TACACS+ wire client moved to
// internal/tacacs (Phase-2 W1.9): the login handler and the source-compat
// alias. The kv config store is in auth_config.go.

import (
	"errors"
	"net/http"

	"netops/backend/internal/tacacs"
)

type TACACS = tacacs.Client

func (s *server) handleTACACSLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	// F-32: PRE-AUTH route — a TACACS+ sign-in is a username/password pair.
	if err := decodeJSONBody(w, r, authCredentialBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	t := s.tacacs.effective().client()
	if !t.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("tacacs authentication not configured"))
		return
	}
	ok, err := t.Authenticate(req.Username, req.Password)
	if err != nil {
		logInfo("auth", "tacacs login error", map[string]any{"user": req.Username, "reason": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("tacacs authentication unavailable"))
		return
	}
	if !ok {
		logInfo("auth", "tacacs login failed", map[string]any{"user": req.Username})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	// Provisioning + account-state gates + session, shared with LDAP (auth.go).
	// H1: refuses outright when the username names a LOCALLY-managed account.
	// THE USERNAME IS THE WHOLE KEY HERE, and that is safe only because this
	// path has exactly ONE realm (tracker 279d): there is one platform-global
	// TACACS+ configuration, so one directory and one username namespace.
	//
	// If that stops being true — a per-tenant server — this call becomes a
	// cross-realm account takeover, the second realm's identity receiving the
	// first realm's account, role and tenant, looking exactly like a successful
	// sign-in. Thread the realm down to the account lookup first. The premise
	// is pinned by TestBearerUsernameIsOneGlobalNamespace.
	s.completeFederatedLogin(w, r, req.Username, "", req.Username, t.DefaultRole(), "tacacs", t.DefaultTenant())
}
