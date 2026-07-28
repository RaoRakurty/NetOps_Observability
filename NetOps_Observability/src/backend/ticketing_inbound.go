package main

import (
	"context"
	"netops/backend/internal/ticketing"
	"strings"
	"time"
)

// ticketing_inbound.go — the INBOUND ServiceNow state sync (#84). The outbound
// worker (ticketing_worker.go) drives Correlix→ServiceNow (create/update/resolve);
// THIS closes the loop the other way: it polls each live ticket's CURRENT state +
// lifecycle timestamps from ServiceNow and appends them to the ticket audit ledger
// as human-phase events (acknowledged / mitigation_started / mitigated / recovered
// / resolved / closed). The #84 timeline bridge (ticketing_lifecycle.go) then
// renders those phases automatically — no further wiring.
//
// Honest + idempotent: it emits an observation ONLY where ServiceNow gives a real
// timestamp, and appends each action AT MOST ONCE (deduped against the existing
// audit) so the poll loop never double-stamps a phase. Dormant unless a tenant has
// a configured connection (resolveConn ok=false → skip) and there are live links.
//
// Tenant isolation (CLAUDE.md §3a): links are listed at platform scope, but each
// carries its own tenant_id; every read (audit) + write (audit append, link
// advance) is scoped to that owning tenant — never a request body.

type ticketStateSyncer struct {
	store       ticketing.Store
	adapters    map[string]ticketing.Adapter
	resolveConn ticketing.ConnResolver
	lookback    time.Duration // bound the polled set to recently-touched links
}

func newTicketStateSyncer(store ticketing.Store, resolve ticketing.ConnResolver) *ticketStateSyncer {
	return &ticketStateSyncer{
		store:       store,
		adapters:    map[string]ticketing.Adapter{"servicenow": ticketing.NewServiceNowAdapter()},
		resolveConn: resolve,
		lookback:    14 * 24 * time.Hour,
	}
}

// Run drives tick() on an interval until ctx is cancelled. Dormant unless wired in
// (FEATURE_RCA_TICKETING) — ticketing is opt-in.
func (sy *ticketStateSyncer) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := sy.tick(ctx, time.Now().UTC()); err != nil {
				logWarn("ticketing", "inbound sync tick failed", map[string]any{"error": err.Error()})
			} else if n > 0 {
				logInfo("ticketing", "inbound sync appended lifecycle events", map[string]any{"count": n})
			}
		}
	}
}

func (sy *ticketStateSyncer) tick(ctx context.Context, now time.Time) (int, error) {
	links, err := sy.store.ListSyncableLinks(ctx, now.Add(-sy.lookback))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range links {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		n += sy.syncLink(ctx, l, now)
	}
	return n, nil
}

// syncLink polls one link's incident state and appends any newly-observed phases.
// Returns the number of audit rows appended.
func (sy *ticketStateSyncer) syncLink(ctx context.Context, l ticketing.Link, now time.Time) int {
	system := orDefault(l.ExternalSystem, "servicenow")
	adapter := sy.adapters[system]
	if adapter == nil || l.SysID == "" {
		return 0
	}
	cfg, ok, err := sy.resolveConn(ctx, l.TenantID, system)
	if err != nil || !ok || cfg.InstanceURL == "" {
		return 0 // no connection configured → dormant, not an error
	}
	inc, found, err := adapter.FetchIncident(ctx, cfg,
		ticketing.Ref{Number: l.TicketNumber, SysID: l.SysID, URL: l.InstanceURL})
	if err != nil {
		logWarn("ticketing", "inbound fetch failed",
			map[string]any{"corr_object_id": l.CorrObjectID, "error": err.Error()})
		return 0
	}
	if !found {
		return 0
	}
	obs := snowIncidentObservations(inc)

	// Dedupe against the existing (append-only) audit ledger: one row per action.
	// This dedupe needs EVERY audit row for the object, not a page: a truncated
	// read would make an already-recorded action look unrecorded and append it
	// again. One object's ledger is one row per action, so the max page is
	// ample — but if it ever were not, say so rather than silently duplicating.
	existing, existingTotal, _ := sy.store.ListAudit(ctx, l.TenantID, false, l.CorrObjectID, ticketing.MaxPage, 0)
	if existingTotal > len(existing) {
		logError("ticketing", "audit ledger truncated during inbound dedupe — duplicate audit rows possible",
			map[string]any{"corr_object_id": l.CorrObjectID, "total": existingTotal, "read": len(existing)})
	}
	seen := map[string]bool{}
	for _, e := range existing {
		if strings.EqualFold(strings.TrimSpace(e.Result), "ok") {
			seen[strings.ToLower(strings.TrimSpace(e.Action))] = true
		}
	}
	appended := 0
	for _, o := range obs {
		key := strings.ToLower(o.Action)
		if seen[key] {
			continue
		}
		if err := sy.store.AppendAudit(ctx, ticketing.AuditEntry{
			TenantID: l.TenantID, ID: randID(), CorrObjectID: l.CorrObjectID,
			ExternalSystem: system, Action: o.Action, Actor: "servicenow:sync",
			NewStatus: o.Action, Result: "ok", At: o.At,
		}); err != nil {
			continue
		}
		seen[key] = true
		appended++
	}

	sy.advanceLinkStatus(ctx, l, inc, now)
	return appended
}

// advanceLinkStatus reflects a ServiceNow resolve/close back onto the link so the
// UI status + the sweeper's open-ticket guard stay consistent with the provider.
// Only moves toward terminal — never resurrects a closed link or downgrades.
func (sy *ticketStateSyncer) advanceLinkStatus(ctx context.Context, l ticketing.Link, inc ticketing.RemoteIncident, now time.Time) {
	target := ""
	switch {
	case inc.State >= ticketing.SnowStateClosed:
		target = "closed"
	case inc.State >= ticketing.SnowStateResolved:
		target = "resolved"
	}
	if target == "" || target == l.Status || l.Status == "closed" {
		return
	}
	l.Status = target
	t := now
	l.LastSyncedAt = &t
	_ = sy.store.PutLink(ctx, l)
}

// lifecycleObservation is one (action, timestamp) the inbound sync derives from a
// fetched incident, ready to append to the audit ledger.
type lifecycleObservation struct {
	Action string
	At     time.Time
}

// snowIncidentObservations maps a fetched incident's state + timestamps onto the
// canonical lifecycle audit actions. Honest: it emits an observation ONLY where
// ServiceNow gives a real timestamp; state gates which phases are plausible. The
// optional u_correlix_* custom fields let a customer drive the Correlix-specific
// phases (mitigated/recovered) precisely; absent ⇒ that phase stays incomplete.
func snowIncidentObservations(inc ticketing.RemoteIncident) []lifecycleObservation {
	var obs []lifecycleObservation
	add := func(action string, at time.Time) {
		if !at.IsZero() {
			obs = append(obs, lifecycleObservation{Action: action, At: at.UTC()})
		}
	}
	// Acknowledged = a human engaged. Prefer an explicit ack time; else work_start;
	// else, while the ticket sits at/after In Progress (but pre-resolution), the
	// last update is the best available signal that it was picked up.
	ack := firstNonZeroTime(inc.AcknowledgedAt, inc.WorkStart)
	if ack.IsZero() && inc.State >= ticketing.SnowStateInProgress && inc.State < ticketing.SnowStateResolved {
		ack = inc.UpdatedAt
	}
	add(auditActionAcknowledged, ack)
	add(auditActionMitigationStarted, firstNonZeroTime(inc.MitigationStartedAt, inc.WorkStart))
	add(auditActionMitigated, inc.MitigatedAt)
	add(auditActionRecovered, inc.RecoveredAt)
	if inc.State >= ticketing.SnowStateResolved {
		add(auditActionResolve, firstNonZeroTime(inc.ResolvedAt, inc.UpdatedAt))
	}
	if inc.State >= ticketing.SnowStateClosed {
		add(auditActionClosed, firstNonZeroTime(inc.ClosedAt, inc.UpdatedAt))
	}
	return obs
}

func firstNonZeroTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}
