// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/internal/session"
)

// session_handlers.go — admin visibility + control over live sessions (Phase 3):
//   GET    /api/sessions[?user=]   list sessions (scoped: owner=all, admin=tenant)
//   DELETE /api/sessions/{id}      revoke a session (instant kill via withAuth)

// sessionView is the admin-facing projection of a Session. A session holds no
// secrets, so this just enriches it with the user's display name + tenant.
type sessionView struct {
	session.Session
	DisplayName string `json:"display_name,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
}

func (s *server) handleSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := make([]sessionView, 0)
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	tenant, cross := principalTenant(claims)
	userFilter := strings.TrimSpace(r.URL.Query().Get("user"))
	for _, x := range s.sessions.List() {
		if userFilter != "" && !strings.EqualFold(x.UserID, userFilter) {
			continue
		}
		u, _ := s.users.Get(x.UserID)
		// Tenant scoping: the platform owner sees all; a tenant admin sees only its
		// own tenant's users' sessions (strict isolation).
		if !sameTenant(u.TenantID, tenant, cross) {
			continue
		}
		out = append(out, sessionView{Session: x, DisplayName: u.DisplayName, TenantID: u.TenantID})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("session id required"))
		return
	}
	if s.sessions == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sess, found := s.sessions.Get(id)
	if !found {
		writeError(w, http.StatusNotFound, errors.New("session not found"))
		return
	}
	tenant, cross := principalTenant(claims)
	u, _ := s.users.Get(sess.UserID)
	if !sameTenant(u.TenantID, tenant, cross) {
		writeError(w, http.StatusForbidden, errors.New("not permitted"))
		return
	}
	// F-70: an admin "kill session" that returned 204 while the revoke never
	// reached disk produced a false compliance artifact — a SESSION_REVOKED
	// audit record for a session that came back on the next restart. Surface
	// the failure instead, and only write the record for a kill that stuck.
	if _, err := s.sessions.Revoke(id); err != nil {
		logError("session", "admin revoke did not persist", map[string]any{"session": id, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, errors.New("session could not be revoked"))
		return
	}
	s.recordSessionEvent(r, "SESSION_REVOKED", sess.UserID, id, u.TenantID, map[string]any{"reason": "admin", "by": claims.Sub})
	w.WriteHeader(http.StatusNoContent)
}
