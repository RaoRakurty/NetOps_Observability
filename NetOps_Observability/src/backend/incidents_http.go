// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/integration"
	"netops/backend/internal/incident"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/notify"

	"netops/backend/internal/httppage"
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
		if legacyAlertITSMEnabled() && incident.AutoTicketEligible(inc.Severity) && s.reportPipeline != nil && s.itsmConfiguredFor(inc.TenantID) {
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
	safeGo("incident-slack-notify", func() {
		if err := notify.NewSlack(url).SendIncident(notify.IncidentNotice{
			IncidentID: inc.ID, DisplayID: incident.DisplayID(inc.ID),
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
	})
}

// ---- REST API --------------------------------------------------------------

// MaxManualIncidentTitle bounds the operator's own words. It is generous enough
// for a sentence and small enough that a title is never a payload.
const MaxManualIncidentTitle = 200

// MaxManualIncidentDescription bounds the optional longer statement.
const MaxManualIncidentDescription = 4000

// maxManualIncidentBody bounds the request itself (§15 LLM04 / §9: no unbounded read).
const maxManualIncidentBody = 16 << 10

// clipRunes bounds a remote string by RUNES, so a multi-byte word is never cut
// in half into an invalid sequence.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// normalizeManualTitle collapses the operator's whitespace and bounds the result.
// Nothing else is invented: the title is what they will recognise the case by.
func normalizeManualTitle(s string) string {
	return clipRunes(strings.Join(strings.Fields(s), " "), MaxManualIncidentTitle)
}

// handleManualIncident serves POST /api/incidents — an operator describes a
// problem in their own words and gets an investigation record back.
//
// WHY IT EXISTS. The Troubleshooting page used to carry a second, parallel
// surface for "a symptom I can describe but cannot act on" (owner, 2026-09-06:
// "one place we can describe the problem but cannot do anything its just fixed
// page"). There is now ONE way in: a described symptom becomes a record through
// the SAME seam an alert-born incident uses (incident.Repo.Ingest, source
// `manual`), so every action that hangs off a case — escalation, the lifecycle,
// the timeline — works on it without a second store or a second vocabulary.
//
// §3a. The owning tenant is stamped from the TOKEN. A tenant in the body is
// REFUSED (400) rather than ignored, so a client that believes it can choose an
// owner learns otherwise instead of silently writing to its own tenant. A
// cross-tenant (platform) principal owns no tenant and is refused the same way.
//
// Idempotent by the incident store's own dedup rule: describing the same
// symptom twice while the first is open folds into it (200) instead of minting
// a second record (201).
func (s *server) handleManualIncident(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
	if !ok {
		return
	}
	// §3: validate at the boundary, before asking whether the store is wired.
	if err := httppage.RejectUnknownQuery(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		// Accepted ONLY so it can be refused by name (§3a): the owner is the
		// token's tenant, never the payload's.
		TenantID string `json:"tenant_id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxManualIncidentBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return
	}
	if strings.TrimSpace(body.TenantID) != "" {
		writeError(w, http.StatusBadRequest, errors.New(
			"tenant_id is not accepted here: the owning tenant is stamped from your token"))
		return
	}
	title := normalizeManualTitle(body.Title)
	if title == "" {
		writeError(w, http.StatusBadRequest, errors.New("title is required: describe the problem in your own words"))
		return
	}
	sev := strings.TrimSpace(body.Severity)
	if sev == "" {
		sev = "medium"
	}
	if !incident.ValidSeverity(sev) {
		writeError(w, http.StatusBadRequest, fmt.Errorf(
			"severity must be one of %s (got %q)", strings.Join(incident.Severities, ", "), sev))
		return
	}
	if s.incidents == nil {
		writeError(w, http.StatusConflict, errIncidentsUnavailable)
		return
	}
	tenant, cross := principalTenant(claims)
	if cross {
		writeError(w, http.StatusBadRequest, errors.New(
			"a platform-wide principal owns no tenant: sign in as a tenant operator to open an investigation"))
		return
	}
	inc, created, err := s.incidents.Ingest(r.Context(), incident.Input{
		TenantID:    tenant,
		Title:       title,
		Description: clipRunes(strings.TrimSpace(body.Description), MaxManualIncidentDescription),
		Severity:    sev,
		SourceType:  incident.SourceManual,
		Actor:       claims.Sub,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"incident": inc, "created": created})
}

// handleIncidents serves GET /api/incidents (tenant-scoped list with filters)
// and POST /api/incidents (an operator's described problem → a manual record).
func (s *server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleManualIncident(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	// §3: validate the request at the boundary, BEFORE asking whether the store
	// happens to be available. A malformed request is a 400 whether or not the
	// backend is wired.
	//
	// F-74: every one of these parameters used to be accepted and then quietly
	// turned into something else — an unknown `severity` became the `info`
	// predicate, a malformed `limit` or `before` was dropped on the floor, and
	// an over-large `limit` was clamped. Each is now applied as written or
	// refused by name with a 400.
	if err := httppage.RejectUnknownQuery(r, "status", "severity", "before"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := httppage.Parse(r, 100, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q := IncidentQuery{
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Limit:    page.Limit,
		Offset:   page.Offset,
	}
	if q.Status != "" && !incident.ValidStatus(q.Status) {
		writeError(w, http.StatusBadRequest, fmt.Errorf(
			"status must be one of open, acknowledged, investigating, resolved, closed (got %q)", q.Status))
		return
	}
	if q.Severity != "" && !incident.ValidSeverity(q.Severity) {
		writeError(w, http.StatusBadRequest, fmt.Errorf(
			"severity must be one of %s (got %q)", strings.Join(incident.Severities, ", "), q.Severity))
		return
	}
	if b := r.URL.Query().Get("before"); b != "" {
		tm, perr := time.Parse(time.RFC3339, b)
		if perr != nil {
			writeError(w, http.StatusBadRequest, errors.New("before must be an RFC3339 timestamp"))
			return
		}
		q.Before = tm
	}
	if s.incidents == nil {
		writeError(w, http.StatusConflict, errIncidentsUnavailable)
		return
	}
	tenant, cross := principalTenant(claims)
	total, err := s.incidents.Count(r.Context(), tenant, cross, q)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	list, err := s.incidents.List(r.Context(), tenant, cross, q)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if list == nil {
		list = []Incident{}
	}
	httppage.LogTruncated("/api/incidents", page, len(list), total)
	httppage.Write(w, "incidents", list, page, len(list), total)
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
			writeError(w, http.StatusNotFound, incident.ErrNotFound)
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
			writeError(w, http.StatusNotFound, incident.ErrNotFound)
			return
		}
		var sync []integration.TimelineEntry
		if s.integrations != nil {
			if sync, err = s.integrations.ListSyncEventsForIncident(r.Context(), tenant, cross, id); err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
		}
		timeline := integration.MergeTimeline(events, sync)
		if timeline == nil {
			timeline = []integration.TimelineEntry{}
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
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) // best-effort: note/owner are optional; a bad body just omits them
	actor := claims.Sub

	var inc Incident
	var err error
	switch action {
	case "ack", "acknowledge":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, incident.StatusAcknowledged, actor, body.Note)
	case "resolve":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, incident.StatusResolved, actor, body.Note)
		if err == nil {
			s.incidentResolved()
		}
	case "investigate":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, incident.StatusInvestigating, actor, body.Note)
	case "close":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, incident.StatusClosed, actor, body.Note)
	case "reopen":
		inc, err = s.incidents.Transition(r.Context(), tenant, cross, id, incident.StatusOpen, actor, body.Note)
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
			err = incident.ErrNotFound
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
		case errors.Is(err, incident.ErrNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, incident.ErrBadTransition):
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

// ── internal/incident wiring (source-compat shims + backend selector) ────────

type (
	Incident      = incident.Incident
	IncidentInput = incident.Input
	IncidentQuery = incident.Query
	IncidentEvent = incident.Event
	incidentsRepo = incident.Repo
)

// newIncidentStore selects the backend: Postgres only (RLS). Returns nil on the
// file/dev backend — the incident system is a SaaS feature; handlers answer 409.
func newIncidentStore() incidentsRepo {
	if ps, ok := platformdb.ActivePG(); ok {
		return incident.NewPGStore(ps.DB())
	}
	return nil
}
