package main

import (
	"net/http"

	"netops/backend/notify"
)

// itsm.go — read-only status for the ServiceNow ITSM connector, backing
// Administration → ITSM. Gated on alerts:read (viewing incident state is an
// alerts concern). Configuration itself is env-driven (secrets never traverse
// the UI), consistent with the other notifier integrations.

func (s *server) handleITSMServiceNow(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "alerts", LevelRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.servicenow == nil || !s.servicenow.Configured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"configured": false,
			"open":       []notify.ServiceNowTicket{},
		})
		return
	}
	tickets := s.servicenow.Tickets()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"configured": true,
		"threshold":  s.servicenow.ThresholdName(),
		"open":       tickets,
		"open_count": len(tickets),
		"auto_close": true,
	})
}
