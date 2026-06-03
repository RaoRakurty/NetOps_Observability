package main

import (
	"net/http"

	"netops/backend/notify"
)

// itsm.go — read-only status for the ITSM connectors, backing Administration →
// ITSM. Gated on alerts:read (viewing incident state is an alerts concern). The
// status is scoped to the caller's tenant: each tenant sees only its OWN
// ServiceNow/Jira connector (the platform owner sees the global one).
// Configuration lives in itsm_config.go (admin-editable, per-tenant).

func (s *server) handleITSMServiceNow(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := principalTenant(claims)
	sn := s.serviceNowFor(tenant)
	if sn == nil || !sn.Configured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"configured": false,
			"open":       []notify.ServiceNowTicket{},
		})
		return
	}
	tickets := sn.Tickets()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"configured": true,
		"threshold":  sn.ThresholdName(),
		"open":       tickets,
		"open_count": len(tickets),
		"auto_close": true,
	})
}

func (s *server) handleITSMJira(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := principalTenant(claims)
	j := s.jiraFor(tenant)
	if j == nil || !j.Configured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"configured": false,
			"open":       []notify.JiraTicket{},
		})
		return
	}
	tickets := j.Tickets()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"configured": true,
		"project":    j.ProjectKey(),
		"threshold":  j.ThresholdName(),
		"open":       tickets,
		"open_count": len(tickets),
		"auto_close": true,
	})
}
