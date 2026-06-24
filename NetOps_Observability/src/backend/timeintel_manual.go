package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/timeintel"
)

// timeintel_manual.go — operator-supplied lifecycle timestamps for RCA Time
// Intelligence (#84 P1d). Engine + ITSM phases are derived; an operator can supply
// the human/response phases the platform can't observe (acknowledged, mitigated,
// service recovered, ticket closed, impact onset). Every write is AUDITED, the owner
// tenant is stamped from the TOKEN (never the body), and cross-tenant access is
// impossible (the store enforces RLS / tenant filter).

// manualEventTypes are the ONLY lifecycle events an operator may set by hand. Engine-
// owned phases (first_signal/detected/correlation_completed/root_domain_identified/
// owner_identified/evidence_ready) are excluded — a human must not fake the engine's
// isolation evidence (that would corrupt MTTI/MTTC).
var manualEventTypes = map[timeintel.EventType]bool{
	timeintel.EvImpactStarted:     true,
	timeintel.EvTicketCreated:     true,
	timeintel.EvAcknowledged:      true,
	timeintel.EvMitigationStarted: true,
	timeintel.EvMitigated:         true,
	timeintel.EvRecovered:         true,
	timeintel.EvResolved:          true,
	timeintel.EvClosed:            true,
}

// handleCorrelationTimeEvents routes the manual-event write path:
//   POST   /api/correlations/{id}/time-events           (add/edit a manual event)
//   DELETE /api/correlations/{id}/time-events/{eventID}  (remove one)
func (s *server) handleCorrelationTimeEvents(w http.ResponseWriter, r *http.Request, id, eventID string) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodPost:
		s.createManualTimeEvent(w, r, claims, tenant, id)
	case http.MethodDelete:
		s.deleteManualTimeEvent(w, r, claims, tenant, cross, id, eventID)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST or DELETE"))
	}
}

func (s *server) createManualTimeEvent(w http.ResponseWriter, r *http.Request, claims jwtClaims, tenant, id string) {
	if s.incidentTimeline == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("timeline store unavailable"))
		return
	}
	var body struct {
		EventType string  `json:"event_type"`
		EventTime string  `json:"event_time"` // RFC3339
		Note      string  `json:"note"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	et := timeintel.EventType(strings.TrimSpace(body.EventType))
	if !manualEventTypes[et] {
		writeJSONError(w, http.StatusBadRequest, "event_type not editable by hand (engine-owned phases are excluded)", "event_type_not_editable")
		return
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(body.EventTime))
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("event_time must be RFC3339"))
		return
	}
	conf := body.Confidence
	if conf <= 0 || conf > 1 {
		conf = 1
	}
	ev := incidentTimelineEvent{
		TenantID:      tenant, // stamped from the TOKEN, never the body
		ID:            randID(),
		CorrelationID: id,
		EventType:     et,
		EventTime:     ts.UTC(),
		Source:        timeintel.SrcUserEntered,
		Confidence:    conf,
		SourceSystem:  "manual",
		Note:          strings.TrimSpace(body.Note),
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     claims.Sub,
	}
	if err := s.incidentTimeline.Put(r.Context(), ev); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// AUDIT every manual edit (CLAUDE.md §8 + spec): who, which incident, which phase.
	s.auditManualEdit(r, claims, tenant, "rca_time_event_set", id, map[string]any{
		"event_type": string(et), "event_time": ts.UTC().Format(time.RFC3339), "note": ev.Note,
	})
	writeJSON(w, http.StatusOK, ev)
}

func (s *server) deleteManualTimeEvent(w http.ResponseWriter, r *http.Request, claims jwtClaims, tenant string, cross bool, id, eventID string) {
	if s.incidentTimeline == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("timeline store unavailable"))
		return
	}
	if eventID == "" {
		writeError(w, http.StatusBadRequest, errors.New("event id required"))
		return
	}
	ok, err := s.incidentTimeline.Delete(r.Context(), tenant, cross, id, eventID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		// Not found OR another tenant's row — same 404 either way (no cross-tenant reveal).
		writeError(w, http.StatusNotFound, errors.New("event not found"))
		return
	}
	s.auditManualEdit(r, claims, tenant, "rca_time_event_delete", id, map[string]any{"event_id": eventID})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// auditManualEdit records a manual timeline edit to the audit trail (deny-by-default:
// the only way to write a manual event is through this audited path).
func (s *server) auditManualEdit(r *http.Request, claims jwtClaims, tenant, action, corrID string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	detail["action"] = action
	detail["correlation_id"] = corrID
	_, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// manualLifecycle overlays the caller's stored manual events onto a derived lifecycle
// (user-entered timestamps WIN — operator truth fills the phases the platform can't
// observe). Tenant-scoped: only the caller's own events are loaded.
func (s *server) manualLifecycle(r *http.Request, claims jwtClaims, id string, lc timeintel.Lifecycle) bool {
	if s.incidentTimeline == nil {
		return false
	}
	tenant, cross := principalTenant(claims)
	events, err := s.incidentTimeline.List(r.Context(), tenant, cross, id)
	if err != nil || len(events) == 0 {
		return false
	}
	for _, e := range events {
		lc[e.EventType] = timeintel.EventStamp{At: e.EventTime, Source: e.Source, Confidence: e.Confidence}
	}
	return true
}
