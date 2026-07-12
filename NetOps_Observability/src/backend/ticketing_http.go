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
		if errors.Is(err, errPolicyConflict) {
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
func validateIncidentPolicy(p incidentPolicy) error {
	switch p.ExternalSystem {
	case "servicenow", "pagerduty", "slack":
	default:
		return errors.New("external_system must be servicenow, pagerduty, or slack")
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
	for _, v := range []int{p.ImpactConfirmedCritical, p.UrgencyConfirmedCritical, p.ImpactConfirmed, p.UrgencyConfirmed} {
		if v < 0 || v > 4 {
			return errors.New("priority mapping impact/urgency out of range [0, 4] (0 = automatic)")
		}
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
	// Name the EXACT policy evaluated (id + last-modified as its version): a
	// simulator verdict is only trustworthy if the operator can tell which
	// configuration produced it (2026-07-10: a shadowed policy made the active
	// configuration ambiguous). Additive keys — create/reason stay top-level.
	dec := evalTicketDecision(facts, policy, nil, time.Now().UTC())
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
	case res.state == policyStateActive && res.policy.ID == policy.ID:
		out["runtime_state"] = "active"
	case res.state == policyStateHeld:
		out["runtime_state"] = "held"
	case res.state == policyStateOptedOut:
		out["runtime_state"] = "opted_out"
	default:
		out["runtime_state"] = "shadowed"
		out["runtime_policy_id"] = res.policy.ID
		out["runtime_policy_name"] = res.policy.Name
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
		// Slack) in ticketSystems order — the card renders all of them; the
		// status/pagerduty keys stay for older clients.
		destinations := []map[string]any{}
		for _, system := range ticketSystems {
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
		audit, _ := s.ticketing.ListAudit(r.Context(), tenant, cross, id)
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
		if _, connOK := s.itsmCfg.ticketSystemConfig(owner, system); !connOK {
			writeError(w, http.StatusConflict,
				errors.New("no ticketing connection configured for this tenant — set up the ServiceNow connection under Incident Response → Integrations first"))
			return
		}
	}
	if action == "update" {
		// Sync only makes sense for an existing open ticket.
		link, found, _ := s.ticketing.GetLink(r.Context(), owner, false, id, system)
		if !found || !link.openTicket() {
			writeError(w, http.StatusConflict, errors.New("no open ticket to sync for this object"))
			return
		}
		if err := enqueueTicketUpdate(r.Context(), s.ticketing, owner, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	} else {
		if err := enqueueTicketCreate(r.Context(), s.ticketing, owner, system, payload); err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
	}
	s.auditTicketing(r, claims, "POST", r.URL.Path, map[string]any{"corr_object_id": id, "action": action})
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
func (s *server) buildTicketPayloadForObject(ctx context.Context, scope, id string) (ticketPayload, incidentPolicy, string, string, int, error) {
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(ctx, scope, id, 0)
	if err != nil {
		return ticketPayload{}, incidentPolicy{}, "", "", status, err
	}
	owner := canonicalCorrTenant(asString(meta["tenant_id"]))
	mergedInto := ""
	if asString(meta["state"]) == "merged" {
		mergedInto = asString(meta["merged_into"])
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	view := buildRcaPathView(id, meta, sigRows, edgeRows)
	facts := buildCorrTicketFacts(meta, sigRows, view)
	policy := (&ticketSweeper{store: s.ticketing, srv: s}).resolvePolicy(ctx, owner, "servicenow")
	payload := buildTicketPayload(view, facts, policy, envOr("RCA_BASE_URL", ""))
	return payload, policy, owner, mergedInto, http.StatusOK, nil
}

// resolveMergeChain follows merged_into pointers from `first` to the terminal
// surviving correlation object. Bounded (≤ maxMergeDepth hops) and cycle-safe;
// it never follows a pointer across the owning tenant boundary — a hop that
// resolves to a foreign-owned row stops the walk at the last same-owner id
// (the first pointer itself came from the caller-authorized row, so returning
// it discloses nothing new). Best-effort: an unreadable hop terminates the walk
// at the last known id rather than failing the caller's 409. Returns the most
// canonical id reached plus the number of hops it represents (1 = direct).
func (s *server) resolveMergeChain(ctx context.Context, scope, owner, requested, first string) (string, int) {
	const maxMergeDepth = 5
	// The requested id is seeded too: a cycle back to it (A→B→A) must stop the
	// walk rather than "canonicalize" to the very object the caller started from.
	seen := map[string]bool{requested: true, first: true}
	cur, depth := first, 1
	for depth < maxMergeDepth {
		if !isUUIDToken(cur) {
			return cur, depth
		}
		sql := `SELECT tenant_id, state, coalesce(toString(merged_into), '') AS merged_into
  FROM netops.corr_objects
 WHERE correlation_id = '` + cur + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
		rows, err := s.chRowsScope(ctx, scope, sql)
		if err != nil || len(rows) == 0 {
			return cur, depth
		}
		if canonicalCorrTenant(asString(rows[0]["tenant_id"])) != owner {
			// Merge pointer crossed a tenant boundary — an engine invariant
			// violation. Stop at the last same-owner id, never disclose further.
			logWarn("ticketing", "INVARIANT VIOLATION: merge chain crossed tenant boundary — walk stopped",
				map[string]any{"correlation_id": cur, "tenant": owner, "merge_depth": depth})
			return cur, depth
		}
		next := asString(rows[0]["merged_into"])
		if asString(rows[0]["state"]) != "merged" || next == "" {
			return cur, depth // terminal survivor
		}
		if seen[next] {
			logWarn("ticketing", "INVARIANT VIOLATION: merge chain cycle — walk stopped",
				map[string]any{"correlation_id": next, "tenant": owner, "merge_depth": depth})
			return cur, depth
		}
		seen[next] = true
		cur, depth = next, depth+1
	}
	return cur, depth
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
	links, err := s.ticketing.ListLinksForTenant(r.Context(), tenant, cross, 1000)
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
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
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
	if l.SysID != "" && base != "" && orDefault(l.ExternalSystem, "servicenow") == "servicenow" {
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
	if !found {
		// No ITSM ticket — fall through the other policy destinations so the
		// card isn't blind when a tenant runs PagerDuty- or Slack-only.
		for _, system := range ticketSystems {
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
