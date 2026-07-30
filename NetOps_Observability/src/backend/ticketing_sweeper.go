package main

import (
	"context"
	"fmt"
	"netops/backend/internal/rca"
	"netops/backend/internal/ticketing"
	"os"
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
// rca.BuildPathView (the single RCA decision) via the request-free chRowsScope /
// loadCorrSlice read path, so the sweeper re-derives no RCA verdict.
//
// Tenant isolation (CLAUDE.md §3a): the candidate scan reads cross-tenant
// ("__all__") because the worker spans every tenant, but each object carries its
// own tenant_id from the corr_objects row, and EVERY downstream write (link
// lookup, outbox enqueue) is stamped + scoped to that owning tenant — never a
// request body. A tenant can only ever ticket its own correlation objects.

type policyResolution = ticketing.PolicyResolution

const (
	policyStateDefault  = ticketing.PolicyStateDefault
	policyStateActive   = ticketing.PolicyStateActive
	policyStateOptedOut = ticketing.PolicyStateOptedOut
	policyStateHeld     = ticketing.PolicyStateHeld
)

type ticketSweeper struct {
	srv     *server
	store   ticketing.Store
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

func newTicketSweeper(srv *server, store ticketing.Store) *ticketSweeper {
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
func canonicalCorrTenant(t string) string { return ticketing.CanonicalCorrTenant(t) }

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
	rca.MergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	view := rca.BuildPathView(c.id, meta, sigRows, edgeRows)
	facts := buildCorrTicketFacts(meta, sigRows, view)

	// #103: every destination system evaluates ITS OWN policy independently —
	// a ServiceNow ticket and a PagerDuty page for the same RCA object are
	// separate policy decisions, separate links, separate outbox rows.
	acted := false
	for _, system := range ticketing.TicketSystems {
		policy := sw.resolvePolicy(ctx, c.tenant, system)
		if !policy.Enabled {
			continue // opted out / held / opt-in system without a policy
		}

		// A tenant with no connection for THIS system can never send — enqueuing
		// anyway just manufactures dead letters (live 2026-07-11: 1,372 DLQ rows
		// for one unconnected tenant at ~1/min). Skip; once connected the object
		// re-enqueues naturally on the next sweep.
		if sw.srv != nil && sw.srv.itsmCfg != nil {
			if _, ok := sw.srv.itsmCfg.SystemConfigFor(c.tenant, system); !ok {
				continue
			}
		}

		link, found, err := sw.store.GetLink(ctx, c.tenant, false, c.id, system)
		if err != nil {
			logWarn("ticketing", "sweep link lookup failed",
				map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
			continue
		}
		var lp *ticketing.Link
		if found {
			lp = &link
		}

		act := decideSweepAction(view, facts, policy, lp, sw.baseURL, now)
		if act.SuppressionReason != "" {
			// NEVER a silent drop (§10): the gate's hold is observable and
			// structured; the object re-evaluates naturally on the next sweep.
			logWarn("ticketing", "RCA emitter action suppressed by consistency gate",
				map[string]any{"corr_object_id": c.id, "system": system,
					"suppression_reason": act.SuppressionReason})
			continue
		}
		switch act.Kind {
		case "create":
			if err := ticketing.EnqueueCreate(ctx, sw.store, c.tenant, system, act.Payload); err != nil {
				logWarn("ticketing", "sweep enqueue create failed",
					map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
				continue
			}
			acted = true
		case "update":
			if err := ticketing.EnqueueUpdate(ctx, sw.store, c.tenant, system, act.Payload); err != nil {
				logWarn("ticketing", "sweep enqueue update failed",
					map[string]any{"corr_object_id": c.id, "system": system, "error": err.Error()})
				continue
			}
			acted = true
		}
	}
	return acted
}

// decideSweepAction delegates to the package decision (P2 RA.5); the payload
// is assembled lazily so the package never sees main's RCA view types.
func decideSweepAction(view rcaPathView, facts ticketing.CorrFacts, policy ticketing.IncidentPolicy, link *ticketing.Link, baseURL string, now time.Time) ticketing.SweepAction {
	return ticketing.DecideSweepAction(facts, policy, link, now, func() ticketing.Payload {
		return buildTicketPayload(view, facts, policy, baseURL)
	})
}

func (sw *ticketSweeper) resolvePolicy(ctx context.Context, tenant, system string) ticketing.IncidentPolicy {
	return sw.resolvePolicyState(ctx, tenant, system).Policy
}

// resolvePolicyState delegates to the single policy-selection brain
// (ticketing.ResolvePolicyState, P2 RA.5); the invariant-violation metric bump
// stays here (it reads srv).
func (sw *ticketSweeper) resolvePolicyState(ctx context.Context, tenant, system string) policyResolution {
	return ticketing.ResolvePolicyState(ctx, sw.store, tenant, system, func() {
		if sw.srv != nil {
			sw.srv.tktPolicyMultiEnabled.Add(1)
		}
	})
}
