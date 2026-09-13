// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tacacs_wiring.go — what stays in main after the TACACS+ wire client moved to
// internal/tacacs (Phase-2 W1.9): the login handler and the source-compat
// alias. The kv config store is in auth_config.go.

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/internal/tacacs"
	"netops/backend/internal/users"
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
	// Resolution + account-state gates + session, shared with LDAP (auth.go).
	//
	// THE KEY IS ("tacacs:" + host:port, lower(login)) — tracker 300 §2.3. The
	// login name is the only subject TACACS+ has, which is exactly why the SERVER
	// that accepted it is in the key: the same `admin` accepted by two different
	// TACACS+ servers is two principals, not one. H1: refuses outright when the
	// tuple would reach a LOCALLY-managed account.
	s.completeFederatedLogin(w, r, tacacsAssertion(t, req.Username))
}

// tacacsAssertion is the TACACS+ door. The login name is the only subject that
// exists on the wire, so subject and legacy username coincide — which is exactly
// why the issuer (the server that accepted it) has to be in the key.
func tacacsAssertion(t *TACACS, login string) users.Assertion {
	return users.Assertion{
		Identity: users.Identity{
			TenantID: t.DefaultTenant(),
			Issuer:   users.TACACSIssuer(t.Addr()),
			Subject:  strings.ToLower(strings.TrimSpace(login)),
			Protocol: users.ProtocolTACACS,
			// The login name is not a directory handle; there is no DN to record.
			SubjectKind: users.SubjectKindLogin,
		},
		DisplayName:    login,
		Role:           t.DefaultRole(),
		LegacyUsername: login,
	}
}
