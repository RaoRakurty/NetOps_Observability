package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// incidents_http.go — the Incident ingestion hook (alert → incident) and the
// tenant-scoped REST API. All endpoints are RLS-scoped + audited by the request
// middleware; the incident system is Postgres-only (409 on the file backend).

// ingestAlertIncident folds a newly-firing alert into an incident (source=alert),
// deduped by the alert's stable id. Best-effort: an ingestion failure must NEVER
// disrupt alerting. The incident's tenant is the firing device's tenant (a
// stack-level alert with no device → platform tenant "").
func (s *server) ingestAlertIncident(a models.Alert) {
	if s.incidents == nil {
		return // Postgres backend only
	}
	tenant := ""
	if a.DeviceID != "" {
		for _, d := range s.discovery.Devices() {
			if d.ID == a.DeviceID {
				tenant = deviceTenant(d)
				break
			}
		}
	}
	title := a.Summary
	if title == "" {
		title = a.Rule
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inc, created, err := s.incidents.Ingest(ctx, IncidentInput{
		TenantID: tenant, Title: title, Description: a.Description, Severity: a.Severity,
		SourceType: "alert", SourceID: a.Rule, DedupKey: "alert:" + a.ID, Actor: "alert-engine",
	})
	if err != nil {
		logError("incidents", "ingest alert", map[string]any{"alert_id": a.ID, "error": err.Error()})
		return
	}
	fields := map[string]any{"incident_id": inc.ID, "tenant_id": inc.TenantID, "severity": inc.Severity, "source_type": "alert"}
	if created {
		s.incidentCreated(inc)
		s.notifyIncidentSlackActions(inc)
		logInfo("incidents", "incident created", fields)
		// Auto-policy: critical incidents promote to an ITSM ticket (dedup by the
		// incident itself; the sync worker is idempotent). Skipped if no ITSM is
		// configured so we don't enqueue jobs that only dead-letter.
		if legacyAlertITSMEnabled() && autoTicketEligible(inc.Severity) && s.reportPipeline != nil && s.itsmConfiguredFor(inc.TenantID) {
			if _, err := s.reportPipeline.EnqueueIncidentSync(ctx, inc.TenantID, inc.ID); err != nil {
				logError("incidents", "auto-enqueue sync", map[string]any{"incident_id": inc.ID, "error": err.Error()})
			}
		}
	} else {
		s.incidentDeduped()
		logInfo("incidents", "incident deduplicated", fields)
	}
}

// legacyAlertITSMEnabled gates the DEPRECATED raw-incident→ITSM projection
// (#103 lane rule): default OFF — the RCA policy lane owns customer filing.
func legacyAlertITSMEnabled() bool { return os.Getenv("FEATURE_LEGACY_ALERT_ITSM") == "true" }

// notifyIncidentSlackActions posts an interactive Slack message (Acknowledge /
// Resolve / Escalate buttons that carry the incident id) for a newly created
// incident, when Slack is configured and the incident meets the channel's
// severity threshold. This is the OUTBOUND half of the bidirectional Slack loop
// (#43a): a button click round-trips through the integration webhook to drive the
// incident's lifecycle. Best-effort + async — it must never block or fail ingest.
func (s *server) notifyIncidentSlackActions(inc Incident) {
	if s.notifyCfg == nil {
		return
	}
	url, minSev, ok := s.notifyCfg.slackIncidentTarget()
	if !ok || !notify.SeverityAtLeast(inc.Severity, minSev) {
		return
	}
	go func() {
		if err := notify.NewSlack(url).SendIncident(notify.IncidentNotice{
			IncidentID: inc.ID, DisplayID: incidentDisplayID(inc.ID),
			Title: inc.Title, Severity: inc.Severity, Status: inc.Status,
		}); err != nil {
			logError("incidents", "slack incident actions", map[string]any{"incident_id": inc.ID, "error": err.Error()})
			return
		}
		// Record the delivery on the incident timeline (feeds the "Notified via"
		// column, #103 UX-1). Best-effort: bookkeeping must never fail alerting.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.incidents.MarkNotified(ctx, inc.ID, "slack"); err != nil {
			logError("incidents", "record slack delivery", map[string]any{"incident_id": inc.ID, "error": err.Error()})
		}
	}()
}

// ---- REST API --------------------------------------------------------------

// handleIncidents serves GET /api/incidents (tenant-scoped list with filters).
func (s *server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if s.incidents == nil {
		writeError(w, http.StatusConflict, errIncidentsUnavailable)
		return
	}
	tenant, cross := principalTenant(claims)
	q := IncidentQuery{
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			q.Limit = n
		}
	}
	if b := r.URL.Query().Get("before"); b != "" {
		if tm, err := time.Parse(time.RFC3339, b); err == nil {
			q.Before = tm
		}
	}
	list, err := s.incidents.List(r.Context(), tenant, cross, q)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if list == nil {
		list = []Incident{}
	}
	writeJSON(w, http.StatusOK, list)
}

// handleIncidentByID serves /api/incidents/{id} and /{id}/{action}.
func (s *server) handleIncidentByID(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if s.incidents == nil {
		writeError(w, http.StatusConflict, errIncidentsUnavailable)
		return
	}
	tenant, cross := principalTenant(claims)
	rest := strings.TrimPrefix(r.URL.Path, "/api/incidents/")
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
	id := parts[0]
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("incident id required"))
		return
	}
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	// Read path: GET the incident + its timeline.
	if action == "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inc, events, found, err := s.incidents.Get(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errIncidentNotFound)
			return
		}
		if events == nil {
			events = []IncidentEvent{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"incident": inc, "events": events})
		return
	}

	// Merged timeline: lifecycle events ⨝ ITSM sync events, time-ordered (#43 §9).
	if action == "timeline" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		inc, events, found, err := s.incidents.Get(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errIncidentNotFound)
			return
		}
		var sync []timelineEntry
		if s.integrations != nil {
			if sync, err = s.integrations.ListSyncEventsForIncident(r.Context(), tenant, cross, id); err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
		}
		timeline := mergeTimeline(events, sync)
		if timeline == nil {
			timeline = []timelineEntry{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"incident": inc, "timeline": timeline})
		return
	}

	// Mutation path: ack | resolve | investigate | close | note | assign — needs write.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requirePerm(w, r, "alerts", LevelWrite); !ok {
		return
	}
	var body struct {
		Note  string `json:"note"`
		Owner string `json:"owner"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	actor := claims.Sub

	var inc Incident
	var err error
	switch action {
	case "ack", "acknowledge":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, statusAcknowledged, actor, body.Note)
	case "resolve":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, statusResolved, actor, body.Note)
		if err == nil {
			s.incidentResolved()
		}
	case "investigate":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, statusInvestigating, actor, body.Note)
	case "close":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, statusClosed, actor, body.Note)
	case "reopen":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, statusOpen, actor, body.Note)
	case "note":
		if strings.TrimSpace(body.Note) == "" {
			writeError(w, http.StatusBadRequest, errors.New("note required"))
			return
		}
		inc, err = s.incidents.AddNote(r.Context(), tenant, cross, id, actor, body.Note)
	case "assign":
		inc, err = s.incidents.Assign(r.Context(), tenant, cross, id, body.Owner, actor)
	case "promote":
		// Manually project this incident to the external ITSM system (async).
		var found bool
		inc, _, found, err = s.incidents.Get(r.Context(), tenant, cross, id)
		if err == nil && !found {
			err = errIncidentNotFound
		}
		if err == nil && s.reportPipeline == nil {
			err = errIncidentsUnavailable
		}
		if err == nil && !legacyAlertITSMEnabled() {
			err = errors.New("legacy incident→ITSM sync is deprecated (#103): tickets file via RCA auto-ticketing policies")
		}
		if err == nil {
			_, err = s.reportPipeline.EnqueueIncidentSync(r.Context(), inc.TenantID, inc.ID)
		}
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown incident action: "+action))
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, errIncidentNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, errBadTransition):
			writeError(w, http.StatusBadRequest, err)
		case errors.Is(err, errIncidentsUnavailable):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	logInfo("incidents", "incident "+action, map[string]any{"incident_id": inc.ID, "tenant_id": inc.TenantID, "severity": inc.Severity, "actor": actor})
	writeJSON(w, http.StatusOK, inc)
}

var errIncidentsUnavailable = errors.New("the incident system requires the Postgres backend")
