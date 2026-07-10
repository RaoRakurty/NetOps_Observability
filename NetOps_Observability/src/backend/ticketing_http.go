package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ticketing_http.go — the REST surface for RCA auto-ticketing (#78 P3):
//   - incident policy CRUD + a pure decision simulator
//   - per-correlation ticket read (link + audit history) and manual create/sync
//   - tenant-scoped outbox + audit observability
//   - ticket_status on the correlation detail (wired in serveCorrelationDetail)
//
// Tenancy (CLAUDE.md §3a): every read scopes by principalTenant(claims) and every
// write stamps TenantID from the token, never the body. Per-tenant ticketing data
// → requirePerm + tenant filter (policies are administration; ticket reads ride
// the same infrastructure:read as the correlation object they describe; manual
// ticket actions are infrastructure:write). A cross-tenant resource a caller can't
// see returns 404, never reveals another tenant's id.

// ── incident policies — /api/incident-policies[/{id}[/test]] ──────────────────

func (s *server) handleIncidentPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "administration", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		policies, err := s.ticketing.ListPolicies(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "administration", LevelWrite)
		if !ok {
			return
		}
		s.upsertIncidentPolicy(w, r, claims, "")
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleIncidentPolicyByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/incident-policies/")
	id, sub, _ := strings.Cut(rest, "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	// POST /{id}/test — pure policy simulator (no external call, no enqueue).
	if sub == "test" {
		s.handleIncidentPolicyTest(w, r, id)
		return
	}
	if sub != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "administration", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		p, found, err := s.ticketing.GetPolicy(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !found {
			http.NotFound(w, r) // never reveal another tenant's policy id
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "administration", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		if _, found, _ := s.ticketing.GetPolicy(r.Context(), tenant, cross, id); !found {
			http.NotFound(w, r) // a PUT must not mint/hijack a policy across tenants
			return
		}
		s.upsertIncidentPolicy(w, r, claims, id)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "administration", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		deleted, err := s.ticketing.DeletePolicy(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !deleted {
			http.NotFound(w, r)
			return
		}
		s.auditTicketing(r, claims, "DELETE", r.URL.Path, map[string]any{"policy_id": id})
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// upsertIncidentPolicy decodes, stamps the tenant from the token, validates, and
// persists. id != "" pins the id (PUT); otherwise a create mints one.
func (s *server) upsertIncidentPolicy(w http.ResponseWriter, r *http.Request, claims jwtClaims, id string) {
	var in incidentPolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _ := principalTenant(claims)
	in.TenantID = tenant // §3a #2: owner from the principal, NEVER the body
	if id != "" {
		in.ID = id
	}
	if strings.TrimSpace(in.ID) == "" {
		in.ID = randID()
	}
	if in.ExternalSystem == "" {
		in.ExternalSystem = "servicenow"
	}
	if in.MinVerdict == "" {
		in.MinVerdict = "suspected"
	}
	if err := validateIncidentPolicy(in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.ticketing.PutPolicy(r.Context(), in); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.auditTicketing(r, claims, "PUT", "/api/incident-policies/"+in.ID,
		map[string]any{"policy_id": in.ID, "enabled": in.Enabled, "min_verdict": in.MinVerdict})
	writeJSON(w, http.StatusOK, in)
}

// validateIncidentPolicy bounds the operator-supplied policy (zero-trust input).
func validateIncidentPolicy(p incidentPolicy) error {
	if p.ExternalSystem != "servicenow" {
		return errors.New("external_system must be servicenow")
	}
	if p.MinVerdict != "suspected" && p.MinVerdict != "confirmed" {
		return errors.New("min_verdict must be suspected or confirmed")
	}
	if len(p.Name) > 160 {
		return errors.New("name too long (max 160)")
	}
	if p.RequirePersistenceSeconds < 0 || p.RequirePersistenceSeconds > 86400 {
		return errors.New("require_persistence_seconds out of range [0, 86400]")
	}
	if p.SuppressFlappingSeconds < 0 || p.SuppressFlappingSeconds > 86400 {
		return errors.New("suppress_flapping_seconds out of range [0, 86400]")
	}
	if p.DefaultImpact < 0 || p.DefaultImpact > 4 || p.DefaultUrgency < 0 || p.DefaultUrgency > 4 {
		return errors.New("default impact/urgency out of range [0, 4]")
	}
	if len(p.AssignmentGroup) > 120 {
		return errors.New("assignment_group too long (max 120)")
	}
	return nil
}

// handleIncidentPolicyTest simulates a policy against caller-supplied facts. Pure:
// no object load, no external call, no enqueue — it just runs evalTicketDecision
// so an operator can see WHY a hypothetical object would or wouldn't ticket.
func (s *server) handleIncidentPolicyTest(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "administration", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	policy, found, err := s.ticketing.GetPolicy(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Verdict            string `json:"verdict"`
		PeakSeverity       string `json:"peak_severity"`
		Internal           bool   `json:"internal"`
		ProbeOnly          bool   `json:"probe_only"`
		LowAuthorityProbe  bool   `json:"low_authority_probe"`
		HasAffectedEntity  bool   `json:"has_affected_entity"`
		PersistenceSeconds int    `json:"persistence_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	facts := corrTicketFacts{
		Verdict: in.Verdict, Internal: in.Internal, ProbeOnly: in.ProbeOnly,
		LowAuthorityProbe: in.LowAuthorityProbe, PeakSeverity: in.PeakSeverity,
		HasAffectedEntity: in.HasAffectedEntity,
		WindowStart:       time.Unix(0, 0).UTC(),
		WindowEnd:         time.Unix(int64(in.PersistenceSeconds), 0).UTC(),
	}
	writeJSON(w, http.StatusOK, evalTicketDecision(facts, policy, nil, time.Now().UTC()))
}

// ── per-correlation tickets — routed from handleCorrelationByID ───────────────

// handleCorrelationTickets serves the ticket subresources of one correlation
// object: GET .../tickets (link + audit history), POST .../ticket (manual create),
// POST .../ticket/sync (manual update of an open ticket). id is already validated.
func (s *server) handleCorrelationTickets(w http.ResponseWriter, r *http.Request, id, sub string) {
	switch {
	case sub == "tickets" && r.Method == http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		link, found, err := s.ticketing.GetLink(r.Context(), tenant, cross, id, "servicenow")
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		audit, _ := s.ticketing.ListAudit(r.Context(), tenant, cross, id)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": ticketStatusView(link, found),
			"audit":  audit,
		})
	case sub == "ticket" && r.Method == http.MethodPost:
		s.manualTicketAction(w, r, id, "create")
	case sub == "ticket/sync" && r.Method == http.MethodPost:
		s.manualTicketAction(w, r, id, "update")
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("unsupported ticket action"))
	}
}

// manualTicketAction is an operator-initiated create/sync: it builds the payload
// from the live RCA object (scoped to the caller's tenant so a cross-tenant id
// 404s) and enqueues the action. The outbox idempotency key keeps it at-most-once.
func (s *server) manualTicketAction(w http.ResponseWriter, r *http.Request, id, action string) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, _ := principalTenant(claims)
	if tenant == "" {
		writeError(w, http.StatusBadRequest, errors.New("select a tenant to ticket (no tenant in scope)"))
		return
	}
	// Scope the read to the caller's tenant: a non-owner only reaches its own
	// object; an owner viewing a tenant reaches that tenant's. Cross-tenant id → 404.
	payload, policy, status, err := s.buildTicketPayloadForObject(r.Context(), tenant, id)
	if err != nil {
		writeError(w, status, err)
		return
	}
	system := orDefault(policy.ExternalSystem, "servicenow")
	if action == "update" {
		// Sync only makes sense for an existing open ticket.
		link, found, _ := s.ticketing.GetLink(r.Context(), tenant, false, id, system)
		if !found || !link.openTicket() {
			writeError(w, http.StatusConflict, errors.New("no open ticket to sync for this object"))
			return
		}
		if err := enqueueTicketUpdate(r.Context(), s.ticketing, tenant, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	} else {
		if err := enqueueTicketCreate(r.Context(), s.ticketing, tenant, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}
	s.auditTicketing(r, claims, "POST", r.URL.Path, map[string]any{"corr_object_id": id, "action": action})
	writeJSON(w, http.StatusAccepted, map[string]any{"enqueued": action, "corr_object_id": id, "system": system})
}

// buildTicketPayloadForObject loads one correlation object's latest slice at the
// given tenant scope and assembles the ticket payload from the SAME RCA view the
// UI renders (no second brain). Returns the resolving policy too (for system +
// defaults). status is an HTTP status for the caller to surface on error.
func (s *server) buildTicketPayloadForObject(ctx context.Context, scope, id string) (ticketPayload, incidentPolicy, int, error) {
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(ctx, scope, id, 0)
	if err != nil {
		return ticketPayload{}, incidentPolicy{}, status, err
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	view := buildRcaPathView(id, meta, sigRows, edgeRows)
	facts := buildCorrTicketFacts(meta, sigRows, view)
	policy := (&ticketSweeper{store: s.ticketing}).resolvePolicy(ctx, scope)
	payload := buildTicketPayload(view, facts, policy, envOr("RCA_BASE_URL", ""))
	return payload, policy, http.StatusOK, nil
}

// ── outbox + audit observability — /api/tickets/{outbox,audit} ────────────────

func (s *server) handleTicketsOutbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	items, err := s.ticketing.ListOutbox(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outbox": items})
}

func (s *server) handleTicketsAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	corrID := strings.TrimSpace(r.URL.Query().Get("corr_object_id"))
	if corrID != "" && !isUUIDToken(corrID) {
		writeError(w, http.StatusBadRequest, errors.New("invalid corr_object_id"))
		return
	}
	entries, err := s.ticketing.ListAudit(r.Context(), tenant, cross, corrID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

// ── shared helpers ────────────────────────────────────────────────────────────

// ticketStatusView projects a ticket link into the status surface the correlation
// detail + RCA Inspector render. No link → not_created (an honest empty state).
func ticketStatusView(l ticketLink, found bool) map[string]any {
	if !found {
		return map[string]any{"state": "not_created"}
	}
	// Links written before the InstanceURL fix stored the FULL incident URL
	// (…/nav_to.do?…) instead of the bare instance; strip the path so the
	// deep-link below isn't doubled (found live against a real PDI, 2026-07-10).
	base := l.InstanceURL
	if i := strings.Index(base, "/nav_to.do"); i >= 0 {
		base = base[:i]
	}
	out := map[string]any{
		"state":          orDefault(l.Status, "pending"),
		"system":         l.ExternalSystem,
		"ticket_number":  l.TicketNumber,
		"sys_id":         l.SysID,
		"instance_url":   base,
		"last_verdict":   l.LastVerdict,
		"last_synced_at": l.LastSyncedAt,
	}
	if l.SysID != "" && base != "" {
		out["url"] = strings.TrimRight(base, "/") + "/nav_to.do?uri=incident.do?sys_id=" + l.SysID
	}
	return out
}

// ticketStatusForObject is the read used by serveCorrelationDetail to attach
// ticket_status. Best-effort: a store error degrades to not_created rather than
// failing the whole object read.
func (s *server) ticketStatusForObject(r *http.Request, id string) map[string]any {
	if s.ticketing == nil {
		return map[string]any{"state": "not_created"}
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		return map[string]any{"state": "not_created"}
	}
	tenant, cross := principalTenant(claims)
	link, found, err := s.ticketing.GetLink(r.Context(), tenant, cross, id, "servicenow")
	if err != nil {
		return map[string]any{"state": "not_created"}
	}
	return ticketStatusView(link, found)
}

func (s *server) auditTicketing(r *http.Request, claims jwtClaims, method, path string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: method, Path: path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}
