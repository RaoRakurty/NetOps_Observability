package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// ticketing_sweeper.go — the policy→enqueue path for RCA auto-ticketing (#78 P3).
//
// The sweeper is the bridge between the correlation engine and the outbox: on an
// interval it scans recently-active correlation objects ACROSS ALL TENANTS, and
// for each one evaluates the owning tenant's incident policy. Objects that pass
// get a create (or, for an already-open ticket whose RCA state changed, an
// update) ENQUEUED into ticket_outbox. It NEVER calls ServiceNow itself — the
// outbox worker (ticketing_worker.go) drains the queue — and it NEVER blocks
// correlation. Dormant unless FEATURE_RCA_TICKETING.
//
// Reuse, no second brain: the ticket payload + policy facts come straight from
// buildRcaPathView (the single RCA decision) via the request-free chRowsScope /
// loadCorrSlice read path, so the sweeper re-derives no RCA verdict.
//
// Tenant isolation (CLAUDE.md §3a): the candidate scan reads cross-tenant
// ("__all__") because the worker spans every tenant, but each object carries its
// own tenant_id from the corr_objects row, and EVERY downstream write (link
// lookup, outbox enqueue) is stamped + scoped to that owning tenant — never a
// request body. A tenant can only ever ticket its own correlation objects.

type ticketSweeper struct {
	srv     *server
	store   ticketingStore
	since   time.Duration // look-back window for "recently active" objects
	limit   int           // max candidates per tick (bounds work)
	baseURL string        // RCA deep-link base (RCA_BASE_URL); "" → "/app"
}

// sweepCandidate is one recently-active object the sweeper will evaluate. tenant
// is the object's OWNER (from the corr_objects row), the authority for every
// downstream tenant-scoped write.
type sweepCandidate struct {
	id     string
	tenant string
}

func newTicketSweeper(srv *server, store ticketingStore) *ticketSweeper {
	since := 30 * time.Minute
	if v := os.Getenv("RCA_TICKETING_LOOKBACK"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			since = d
		}
	}
	return &ticketSweeper{
		srv:     srv,
		store:   store,
		since:   since,
		limit:   500,
		baseURL: envOr("RCA_BASE_URL", ""),
	}
}

// Run drives tick() on an interval until ctx is cancelled. Dormant unless wired
// in (FEATURE_RCA_TICKETING) — ticketing is opt-in.
func (sw *ticketSweeper) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := sw.tick(ctx, time.Now().UTC()); err != nil {
				logWarn("ticketing", "sweep failed", map[string]any{"error": err.Error()})
			} else if n > 0 {
				logInfo("ticketing", "sweep enqueued ticket actions", map[string]any{"count": n})
			}
		}
	}
}

// tick scans one batch of candidates and evaluates each. Returns the number of
// ticket actions enqueued.
func (sw *ticketSweeper) tick(ctx context.Context, now time.Time) (int, error) {
	cands, err := sw.candidates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if sw.evaluate(ctx, c, now) {
			n++
		}
	}
	return n, nil
}

// candidates lists recently-active, customer-relevant objects across all tenants.
// Only suspected/confirmed, non-merged objects in the look-back window — the
// policy still re-checks every gate; this is just a cheap pre-filter that keeps
// the per-object loadCorrSlice work bounded.
// Served from the corr_current HOT projection (#101): the sweeper runs every
// 60s, so its pre-filter must be O(active objects) like every other hot read —
// corr_objects_latest folds the whole history table per sweep. chaos_fixture
// rows are excluded HERE, not in the policy gates: an intentional storm source
// (e.g. the lab .120 fixture) must never open customer tickets.
func (sw *ticketSweeper) candidates(ctx context.Context) ([]sweepCandidate, error) {
	sql := `
SELECT toString(correlation_id) AS correlation_id,
       tenant_id                AS tenant_id
  FROM netops.corr_current FINAL
 WHERE window_start >= now() - INTERVAL ` + intToString(int(sw.since.Seconds())) + ` SECOND
   AND verdict_tier IN ('suspected','confirmed')
   AND merged_into IS NULL
   AND chaos_fixture = ''
 ORDER BY window_start ASC
 LIMIT ` + intToString(sw.limit) + `
 FORMAT JSON`
	rows, err := sw.srv.chRowsScope(ctx, "__all__", sql)
	if err != nil {
		return nil, err
	}
	out := make([]sweepCandidate, 0, len(rows))
	for _, row := range rows {
		id := asString(row["correlation_id"])
		if !isUUIDToken(id) {
			continue
		}
		out = append(out, sweepCandidate{id: id, tenant: canonicalCorrTenant(asString(row["tenant_id"]))})
	}
	return out, nil
}

// canonicalCorrTenant maps a correlation object's stored tenant to the canonical
// app tenant key used by the ticketing stores. The correlation engine writes ""
// for platform/global-owned (untagged) telemetry, but the platform admin manages
// that tenant's incident policy + ServiceNow connection under the canonical global
// id (principalTenant → "global"). Collapse ""→global here so policy resolution,
// the ticket link, and the outbox all key the SAME tenant the operator configured.
// A real (non-global) tenant id passes through unchanged, so isolation is intact.
//
// Without this, a GLOBAL object (tenant_id="") never matched a configured global
// policy (stored under "global") and the sweeper silently fell back to the default
// policy — i.e. a platform-tenant policy could never take effect.
// Case/whitespace-normalized via normTenant first — the app layer is already
// case-insensitive on tenant keys (principalTenant lowercases, every store key
// goes through normTenant), so canonicalizing here closes the one seam where a
// raw row value could bypass that. It never collapses two distinct real tenant
// ids (opaque lowercase t_… ids), only ""↔global representations.
func canonicalCorrTenant(t string) string {
	t = normTenant(t)
	if t == "" {
		return TenantGlobal
	}
	return t
}

// evaluate loads one object's RCA slice, decides via the owning tenant's policy,
// and enqueues a create (or an update when an open ticket's RCA state changed).
// Returns true when it enqueued an action.
func (sw *ticketSweeper) evaluate(ctx context.Context, c sweepCandidate, now time.Time) bool {
	// Load the latest slice cross-tenant; the object's tenant authority comes from
	// the candidate row (c.tenant), never from this read.
	meta, sigRows, evRows, edgeRows, _, err := sw.srv.loadCorrSlice(ctx, "__all__", c.id, 0)
	if err != nil {
		logWarn("ticketing", "sweep load slice failed",
			map[string]any{"corr_object_id": c.id, "error": err.Error()})
		return false
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	view := buildRcaPathView(c.id, meta, sigRows, edgeRows)
	facts := buildCorrTicketFacts(meta, sigRows, view)

	// #103: every destination system evaluates ITS OWN policy independently —
	// a ServiceNow ticket and a PagerDuty page for the same RCA object are
	// separate policy decisions, separate links, separate outbox rows.
	acted := false
	for _, system := range ticketSystems {
		policy := sw.resolvePolicy(ctx, c.tenant, system)
		if !policy.Enabled {
			continue // opted out / held / opt-in system without a policy
		}

		// A tenant with no connection for THIS system can never send — enqueuing
		// anyway just manufactures dead letters (live 2026-07-11: 1,372 DLQ rows
		// for one unconnected tenant at ~1/min). Skip; once connected the object
		// re-enqueues naturally on the next sweep.
		if sw.srv != nil && sw.srv.itsmCfg != nil {
			if _, ok := sw.srv.itsmCfg.ticketSystemConfig(c.tenant, system); !ok {
				continue
			}
		}

		link, found, err := sw.store.GetLink(ctx, c.tenant, false, c.id, system)
		if err != nil {
			logWarn("ticketing", "sweep link lookup failed",
				map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
			continue
		}
		var lp *ticketLink
		if found {
			lp = &link
		}

		act := decideSweepAction(view, facts, policy, lp, sw.baseURL, now)
		switch act.kind {
		case "create":
			if err := enqueueTicketCreate(ctx, sw.store, c.tenant, system, act.payload); err != nil {
				logWarn("ticketing", "sweep enqueue create failed",
					map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
				continue
			}
			acted = true
		case "update":
			if err := enqueueTicketUpdate(ctx, sw.store, c.tenant, system, act.payload); err != nil {
				logWarn("ticketing", "sweep enqueue update failed",
					map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
				continue
			}
			acted = true
		}
	}
	return acted
}

// sweepAction is the pure outcome of evaluating one object: enqueue nothing, a
// create, or an update — with the assembled payload for the latter two.
type sweepAction struct {
	kind    string // "" | "create" | "update"
	payload ticketPayload
}

// decideSweepAction is the I/O-free decision for one already-loaded object. A
// create when the incident policy opens a ticket; otherwise an update when an
// already-open ticket's RCA state moved on (payload hash changed) so an unchanged
// state is a no-op. Deterministic, so it is unit-tested in isolation.
func decideSweepAction(view rcaPathView, facts corrTicketFacts, policy incidentPolicy, link *ticketLink, baseURL string, now time.Time) sweepAction {
	if dec := evalTicketDecision(facts, policy, link, now); dec.Create {
		return sweepAction{kind: "create", payload: buildTicketPayload(view, facts, policy, baseURL)}
	}
	if link != nil && link.openTicket() {
		p := buildTicketPayload(view, facts, policy, baseURL)
		if payloadHash(p) != link.LastPayloadHash {
			return sweepAction{kind: "update", payload: p}
		}
	}
	return sweepAction{}
}

// policyResolution is resolvePolicyState's outcome: the governing policy plus
// HOW it came to govern, so callers (simulator, future observability) can tell
// an active configured policy from a fallback, an opt-out, or a held conflict.
// ticketSystems are the destinations the RCA policy engine can drive. Each
// system resolves its OWN governing policy (the one-enabled invariant is per
// (tenant, external_system)); ServiceNow keeps its default-on MVP fallback,
// every other system is strictly opt-in (no policy -> no delivery).
var ticketSystems = []string{"servicenow", "pagerduty"}

type policyResolution struct {
	policy incidentPolicy
	state  string // policyStateDefault | policyStateActive | policyStateOptedOut | policyStateHeld
}

const (
	policyStateDefault  = "default"   // tenant has no policy; safe MVP default governs
	policyStateActive   = "active"    // exactly one enabled configured policy governs
	policyStateOptedOut = "opted_out" // policies exist but all are disabled — tenant opted out
	policyStateHeld     = "held"      // invariant violated (multiple enabled) — ticketing held
)

// resolvePolicy returns the incident policy that governs a tenant: a configured
// enabled policy wins; an explicitly configured (but disabled) policy is honored
// so a tenant can opt OUT; only a tenant with NO policy at all falls back to the
// default-on MVP policy.
func (sw *ticketSweeper) resolvePolicy(ctx context.Context, tenant, system string) incidentPolicy {
	return sw.resolvePolicyState(ctx, tenant, system).policy
}

// resolvePolicyState is the single policy-selection brain (sweeper, manual
// path, and simulator all resolve through here — never a "first row wins").
func (sw *ticketSweeper) resolvePolicyState(ctx context.Context, tenant, system string) policyResolution {
	system = orDefault(system, "servicenow")
	all, err := sw.store.ListPolicies(ctx, tenant, false)
	var policies []incidentPolicy
	for _, p := range all {
		if orDefault(p.ExternalSystem, "servicenow") == system {
			policies = append(policies, p)
		}
	}
	if err != nil || len(policies) == 0 {
		if system == "servicenow" {
			// ServiceNow keeps the historical default-on MVP policy.
			return policyResolution{policy: defaultIncidentPolicy(tenant), state: policyStateDefault}
		}
		// Paging (and any future system) is OPT-IN: no policy, no delivery.
		off := defaultIncidentPolicy(tenant)
		off.Enabled = false
		off.ExternalSystem = system
		off.Name = "no " + system + " policy (opt-in)"
		return policyResolution{policy: off, state: policyStateOptedOut}
	}
	var enabled []incidentPolicy
	for _, p := range policies {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	switch len(enabled) {
	case 1:
		return policyResolution{policy: enabled[0], state: policyStateActive}
	case 0:
		// Explicitly configured but all disabled = the tenant opted OUT.
		return policyResolution{policy: policies[0], state: policyStateOptedOut}
	}
	// >1 enabled should be impossible (partial unique index + write-path 409) —
	// if legacy data or drift ever violates it, FAIL CLOSED: hold all ticketing
	// for the tenant and say so loudly, never silently pick a winner by row
	// order (live incident 2026-07-10: a shadowed permissive policy flooded a
	// real PDI at ~7 tickets/min while a confirmed-only policy appeared active).
	ids := make([]string, len(enabled))
	for i, p := range enabled {
		ids[i] = p.ID
	}
	logWarn("ticketing", "INVARIANT VIOLATION: multiple enabled incident policies — ticketing held (fail closed)",
		map[string]any{"tenant": tenant, "policy_ids": strings.Join(ids, ","), "system": orDefault(enabled[0].ExternalSystem, "servicenow")})
	if sw.srv != nil {
		sw.srv.tktPolicyMultiEnabled.Add(1)
	}
	held := defaultIncidentPolicy(tenant)
	held.Enabled = false
	held.Name = "HELD: conflicting enabled policies"
	return policyResolution{policy: held, state: policyStateHeld}
}
