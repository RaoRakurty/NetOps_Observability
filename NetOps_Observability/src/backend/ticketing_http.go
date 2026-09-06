// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/rca"
	"netops/backend/internal/ticketing"
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
		if _, found, _ := s.ticketing.GetPolicy(r.Context(), tenant, cross, id); !found { // best-effort: a read error reads as not-found
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
	var in ticketing.IncidentPolicy
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
	// Only ONE policy may be enabled per (tenant, external system): the sweeper
	// resolves a single governing policy, so a second enabled one would silently
	// shadow the first (live incident 2026-07-10: a leftover permissive validation
	// policy kept flooding a real PDI while a stricter policy appeared active).
	// Refuse loudly instead, naming the conflict.
	if in.Enabled {
		existing, err := s.ticketing.ListPolicies(r.Context(), tenant, false)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		for _, p := range existing {
			if p.Enabled && p.ID != in.ID && p.ExternalSystem == in.ExternalSystem {
				s.tktPolicyConflicts.Add(1)
				writeError(w, http.StatusConflict, fmt.Errorf(
					"policy %q is already enabled for %s — only one enabled policy per system; disable it first",
					orDefault(p.Name, p.ID), in.ExternalSystem))
				return
			}
		}
	}
	if err := s.ticketing.PutPolicy(r.Context(), in); err != nil {
		// The store enforces the one-enabled invariant transactionally (partial
		// unique index / in-store lock) — the pre-check above is only the friendly
		// message; a racing enable that slips past it still lands here as 409.
		if errors.Is(err, ticketing.ErrPolicyConflict) {
			s.tktPolicyConflicts.Add(1)
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.auditTicketing(r, claims, "PUT", "/api/incident-policies/"+in.ID,
		map[string]any{"policy_id": in.ID, "enabled": in.Enabled, "min_verdict": in.MinVerdict})
	writeJSON(w, http.StatusOK, in)
}

// validateIncidentPolicy bounds the operator-supplied policy (zero-trust input).
func validateIncidentPolicy(p ticketing.IncidentPolicy) error {
	return ticketing.ValidateIncidentPolicy(p)
}

// handleIncidentPolicyTest simulates a policy against caller-supplied facts. Pure:
// no object load, no external call, no enqueue — it just runs ticketing.EvalDecision
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
	facts := ticketing.CorrFacts{
		Verdict: in.Verdict, Internal: in.Internal, ProbeOnly: in.ProbeOnly,
		LowAuthorityProbe: in.LowAuthorityProbe, PeakSeverity: in.PeakSeverity,
		HasAffectedEntity: in.HasAffectedEntity,
		WindowStart:       time.Unix(0, 0).UTC(),
		WindowEnd:         time.Unix(int64(in.PersistenceSeconds), 0).UTC(),
	}
	// Name the EXACT policy evaluated (id + last-modified as its version): a
	// simulator verdict is only trustworthy if the operator can tell which
	// configuration produced it (2026-07-10: a shadowed policy made the active
	// configuration ambiguous). Additive keys — create/reason stay top-level.
	dec := ticketing.EvalDecision(facts, policy, nil, time.Now().UTC())
	out := map[string]any{
		"create":            dec.Create,
		"reason":            dec.Reason,
		"policy_id":         policy.ID,
		"policy_name":       policy.Name,
		"policy_enabled":    policy.Enabled,
		"policy_updated_at": policy.UpdatedAt,
	}
	// Differential guard: the simulator happily evaluates ANY saved policy, but
	// the runtime resolves ONE governing policy per tenant — tell the operator
	// when the dry-run's policy is not what the sweeper would actually apply
	// (the exact ambiguity behind the 2026-07-10 shadowed-policy flood).
	res := (&ticketSweeper{store: s.ticketing, srv: s}).resolvePolicyState(r.Context(), policy.TenantID, policy.ExternalSystem)
	switch {
	case res.State == policyStateActive && res.Policy.ID == policy.ID:
		out["runtime_state"] = "active"
	case res.State == policyStateHeld:
		out["runtime_state"] = "held"
	case res.State == policyStateOptedOut:
		out["runtime_state"] = "opted_out"
	default:
		out["runtime_state"] = "shadowed"
		out["runtime_policy_id"] = res.Policy.ID
		out["runtime_policy_name"] = res.Policy.Name
	}
	writeJSON(w, http.StatusOK, out)
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
		var pdView map[string]any
		// destinations covers EVERY policy destination (ServiceNow, PagerDuty,
		// Slack) in ticketing.TicketSystems order — the card renders all of them; the
		// status/pagerduty keys stay for older clients.
		destinations := []map[string]any{}
		for _, system := range ticketing.TicketSystems {
			l, lFound, lErr := s.ticketing.GetLink(r.Context(), tenant, cross, id, system)
			if lErr != nil || !lFound {
				continue
			}
			v := ticketStatusView(l, true)
			destinations = append(destinations, v)
			if system == "pagerduty" {
				pdView = v
			}
		}
		audit, _, _ := s.ticketing.ListAudit(r.Context(), tenant, cross, id, ticketing.AuditDefaultPage, 0) // best-effort: a read error yields an empty audit page
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       ticketStatusView(link, found),
			"pagerduty":    pdView,
			"destinations": destinations,
			"audit":        audit,
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
	tenant, cross := principalTenant(claims)
	if tenant == "" {
		writeError(w, http.StatusBadRequest, errors.New("select a tenant to ticket (no tenant in scope)"))
		return
	}
	// Read scope mirrors the sweeper: a cross-tenant principal loads the slice at
	// "__all__" — the CH row policy is STRICT (tenant_id = scope, no untagged
	// allowance), so scoping a platform owner to the literal "global" would never
	// match the platform's own objects (tenant_id=""). A tenant-scoped caller
	// stays confined to its tenant, so a cross-tenant id 404s at the read.
	scope := tenant
	if cross {
		scope = "__all__"
	}
	payload, policy, owner, mergedInto, status, err := s.buildTicketPayloadForObject(r.Context(), scope, id)
	if err != nil {
		writeError(w, status, err)
		return
	}
	// The object's OWNING tenant (from its row, ""→global) keys the policy, link,
	// and outbox — same authority the sweeper uses. Default-closed: if the row
	// policy ever lets a foreign row through, a tenant-scoped caller still 404s.
	if !cross && owner != canonicalCorrTenant(tenant) {
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	// A merged object is superseded: ticketing it would double-file the incident
	// (the sweeper only ever tickets the surviving object). Refuse with the
	// canonical id — an explicit contract, never a misleading 404. Checked after
	// the ownership guard so the redirect never leaks across tenants. The chain
	// is followed to the TERMINAL survivor (A→B→C answers C, not B) so the
	// operator's retry lands on a live object in one hop.
	if mergedInto != "" {
		canonical, depth := s.resolveMergeChain(r.Context(), scope, owner, id, mergedInto)
		s.tktMergedRedirects.Add(1)
		logInfo("ticketing", "manual ticket on merged object refused — canonical redirect",
			map[string]any{"requested_correlation_id": id, "canonical_correlation_id": canonical,
				"merge_depth": depth, "tenant": owner, "ticket_path": "manual", "action": action})
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                    "this correlation object was merged — act on the surviving object instead",
			"requested_correlation_id": id,
			"canonical_correlation_id": canonical,
			"merge_depth":              depth,
		})
		return
	}
	system := orDefault(policy.ExternalSystem, "servicenow")
	// Honest refusal beats a 202 that dead-letters: an operator's manual create
	// on a tenant with no ticketing connection can never reach ServiceNow.
	if s.itsmCfg != nil {
		if _, connOK := s.itsmCfg.SystemConfigFor(owner, system); !connOK {
			writeError(w, http.StatusConflict,
				errors.New("no ticketing connection configured for this tenant — set up the ServiceNow connection under Incident Response → Integrations first"))
			return
		}
	}
	// M10: the enqueue reports whether a row actually landed. Answering 202 for
	// a deduped no-op told the operator work was queued when nothing was — a
	// dead-lettered create looked permanently "accepted" while never retrying.
	var enqueued bool
	if action == "update" {
		// Sync only makes sense for an existing open ticket.
		link, found, _ := s.ticketing.GetLink(r.Context(), owner, false, id, system) // best-effort: a read error reads as no-link
		if !found || !link.Open() {
			writeError(w, http.StatusConflict, errors.New("no open ticket to sync for this object"))
			return
		}
		var err error
		if enqueued, err = ticketing.EnqueueUpdate(r.Context(), s.ticketing, owner, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	} else {
		var err error
		if enqueued, err = ticketing.EnqueueCreate(r.Context(), s.ticketing, owner, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}
	s.auditTicketing(r, claims, "POST", r.URL.Path, map[string]any{"corr_object_id": id, "action": action, "enqueued": enqueued})
	if !enqueued {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          "an equivalent " + action + " is already queued or in flight for this object",
			"corr_object_id": id, "system": system,
		})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"enqueued": action, "corr_object_id": id, "system": system})
}

// buildTicketPayloadForObject loads one correlation object's latest slice at the
// given tenant scope and assembles the ticket payload from the SAME RCA view the
// UI renders (no second brain). Returns the resolving policy and the object's
// OWNING tenant (row tenant_id canonicalized ""→global) — the policy is resolved
// under the owner, never the read scope (which may be "__all__" for a
// cross-tenant caller). status is an HTTP status for the caller to surface on error.
// mergedInto is non-empty when the object was merged into another correlation —
// the caller decides how to surface that (only AFTER its ownership guard, so a
// leaked foreign row never discloses another tenant's canonical id).
func (s *server) buildTicketPayloadForObject(ctx context.Context, scope, id string) (ticketing.Payload, ticketing.IncidentPolicy, string, string, int, error) {
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(ctx, scope, id, 0)
	if err != nil {
		return ticketing.Payload{}, ticketing.IncidentPolicy{}, "", "", status, err
	}
	owner := canonicalCorrTenant(asString(meta["tenant_id"]))
	mergedInto := ""
	if asString(meta["state"]) == "merged" {
		mergedInto = asString(meta["merged_into"])
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	rca.MergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	view := rca.BuildPathView(id, meta, sigRows, edgeRows)
	facts := buildCorrTicketFacts(meta, sigRows, view)
	policy := (&ticketSweeper{store: s.ticketing, srv: s}).resolvePolicy(ctx, owner, "servicenow")
	payload := buildTicketPayload(view, facts, policy, envOr("RCA_BASE_URL", ""))
	return payload, policy, owner, mergedInto, http.StatusOK, nil
}

// resolveMergeChain delegates the bounded/cycle-safe/tenant-fenced walk to
// ticketing.ResolveMergeChain (P2 RA.12); the scoped projection read stays
// here as the injected hop reader.
func (s *server) resolveMergeChain(ctx context.Context, scope, owner, requested, first string) (string, int) {
	return ticketing.ResolveMergeChain(ctx, owner, requested, first, isUUIDToken,
		func(ctx context.Context, id string) (ticketing.MergeHop, error) {
			sql := `SELECT tenant_id, state, coalesce(toString(merged_into), '') AS merged_into
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
			rows, err := s.chRowsScope(ctx, scope, sql)
			if err != nil {
				return ticketing.MergeHop{}, err
			}
			if len(rows) == 0 {
				return ticketing.MergeHop{}, nil
			}
			return ticketing.MergeHop{
				Found:      true,
				Tenant:     asString(rows[0]["tenant_id"]),
				State:      asString(rows[0]["state"]),
				MergedInto: asString(rows[0]["merged_into"]),
			}, nil
		})
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
	limit, err := intQuery(r, "limit", ticketing.OutboxDefaultPage, 1, ticketing.MaxPage)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, err := intQuery(r, "offset", 0, 0, 1<<30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	items, total, err := s.ticketing.ListOutbox(r.Context(), tenant, cross, limit, offset)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// F-66: this endpoint had no LIMIT at all and served 22 MB. `total` is the
	// caller's real row count, so a client can tell "that is everything" from
	// "that is the first page" instead of guessing.
	writeJSON(w, http.StatusOK, map[string]any{
		"outbox": items, "total": total, "limit": limit, "offset": offset,
		"has_more": offset+len(items) < total,
	})
}

// handleTicketsLinks lists the caller-tenant's ticket links (UX-1 "notified
// via"): every external destination an RCA object was filed to, with state.
// The RCA candidate list joins these client-side by correlation id — a bounded
// Postgres read that keeps the ClickHouse-streamed list handler untouched.
func (s *server) handleTicketsLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)

	// F-67: an exact per-object lookup for the surfaces that must never guess.
	// A link the caller did not receive renders as "not_created", so answering
	// a detail view from a truncated top-N page is how a real ServiceNow ticket
	// becomes "no ticket filed" and an operator files a duplicate.
	if corrID := strings.TrimSpace(r.URL.Query().Get("corr_object_id")); corrID != "" {
		if !isUUIDToken(corrID) {
			writeError(w, http.StatusBadRequest, errors.New("invalid corr_object_id"))
			return
		}
		links, err := s.ticketing.ListLinksForCorr(r.Context(), tenant, cross, corrID)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		out := make([]map[string]any, 0, len(links))
		for _, l := range links {
			v := ticketStatusView(l, true)
			v["corr_object_id"] = l.CorrObjectID
			out = append(out, v)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"links": out, "total": len(out), "complete": true,
		})
		return
	}

	limit, err := intQuery(r, "limit", ticketing.LinksDefaultPage, 1, ticketing.MaxPage)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, err := intQuery(r, "offset", 0, 0, 1<<30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	links, total, err := s.ticketing.ListLinksForTenant(r.Context(), tenant, cross, limit, offset)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	out := make([]map[string]any, 0, len(links))
	for _, l := range links {
		v := ticketStatusView(l, true)
		v["corr_object_id"] = l.CorrObjectID
		out = append(out, v)
	}
	// `complete` says outright whether this response is the whole set. A client
	// joining by correlation id MUST NOT read a miss as "no ticket filed" when
	// complete is false — it means "not in this page".
	writeJSON(w, http.StatusOK, map[string]any{
		"links": out, "total": total, "limit": limit, "offset": offset,
		"has_more": offset+len(out) < total,
		"complete": offset == 0 && len(out) == total,
	})
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
	limit, err := intQuery(r, "limit", ticketing.AuditDefaultPage, 1, ticketing.MaxPage)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, err := intQuery(r, "offset", 0, 0, 1<<30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	entries, total, err := s.ticketing.ListAudit(r.Context(), tenant, cross, corrID, limit, offset)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"audit": entries, "total": total, "limit": limit, "offset": offset,
		"has_more": offset+len(entries) < total,
	})
}

// ── shared helpers ────────────────────────────────────────────────────────────

// ticketStatusView projects a ticket link into the status surface (package).
func ticketStatusView(l ticketing.Link, found bool) map[string]any {
	return ticketing.StatusView(l, found)
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
	if !found {
		// No ITSM ticket — fall through the other policy destinations so the
		// card isn't blind when a tenant runs PagerDuty- or Slack-only.
		for _, system := range ticketing.TicketSystems {
			if system == "servicenow" {
				continue
			}
			if l, lFound, lErr := s.ticketing.GetLink(r.Context(), tenant, cross, id, system); lErr == nil && lFound {
				return ticketStatusView(l, true)
			}
		}
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
