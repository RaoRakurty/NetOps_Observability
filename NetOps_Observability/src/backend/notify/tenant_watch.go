// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// tenant_watch.go — delivery of a tenant's OWN watch alerts to that tenant's
// own RCA lanes (tracker 359, owner decision 2026-11-12).
//
// What reaches a tenant lane through this file, and nothing else:
//
//   - alerts from watches the tenant set up itself — its BGP-watch prefix
//     classes (origin change, RPKI invalid, bogon, route leak, visibility loss)
//     and its cloud monitors. The CALLER decides which alerts qualify (BGP
//     peer-down does not: correlation folds that), this router only delivers.
//   - one message when the alert episode starts and one when it clears.
//     Re-fires inside an open episode (the BGP evaluator re-notifies after its
//     cool-down while an incident stays open; a monitor whose state could not
//     be persisted re-fires on every tick) are deduped here, never re-sent.
//
// WHO IT GOES TO is the tenant the SERVER stamped on the alert: the evaluator's
// own tenant, passed as an argument by the integrator. Labels, summaries and
// anything else that could carry request or device text are never consulted.
// An empty, platform ("global", the Provider) or wildcard tenant reaches no
// tenant lane (default-closed, §3a).
//
// HOW it goes is the Dispatcher's existing delivery machinery (delivery.go):
// the bounded queue, the fixed worker pool, retry with backoff + jitter, the
// per-channel sent/failed/retried/dropped counters and the structured failure
// log. The tenant lanes are NOT registered on the Dispatcher (that list is the
// platform-global audience, which keeps receiving exactly what it did); each
// send is handed to the pool as its own job. The channel names on those
// counters are the two fixed values "tenant-slack" and "tenant-pagerduty", so
// the metric cardinality does not grow with the tenant count.
//
// SECRETS: a lane's webhook URL / routing key is a bearer secret. It is held
// only inside the channel that sends, and every error leaving that channel is
// scrubbed of it before the delivery layer logs it.

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"netops/backend/internal/owner"
	"netops/backend/models"
)

// Tenant lane systems. They are the only two the RCA lanes carry.
const (
	TenantLaneSlack     = "slack"
	TenantLanePagerDuty = "pagerduty"
)

// tenantWatchMaxEpisodes bounds the open-episode register (§9). Far above any
// real number of simultaneously open watch alerts; reaching it is counted and
// logged, never silent.
const tenantWatchMaxEpisodes = 20000

// tenantWatchClosedMemory bounds how many recently cleared episodes are
// remembered for duplicate-clear detection (§9).
const tenantWatchClosedMemory = 4096

// TenantLane is one destination a tenant owns and has opted into watch alerts
// for. Secret is that tenant's own webhook URL / routing key (write-only).
type TenantLane struct {
	System string
	Secret string
}

// TenantWatchDeps are the router's injected seams (§5).
type TenantWatchDeps struct {
	// Lanes returns the lanes ONE tenant has enabled AND opted into watch
	// alerts for. It must be keyed by that tenant only; the router has already
	// refused platform/empty tenants before it asks.
	Lanes func(tenant string) []TenantLane
	// Build makes the raw sender for a lane. nil → the real Slack / PagerDuty
	// senders. Tests inject fakes so no real webhook is ever called.
	Build func(l TenantLane) Channel
	// Log receives routing events (never a secret). nil discards; the counters
	// are still kept.
	Log Logger
}

// tenantEpisode is one open watch alert and the lanes its start went to. The
// lanes are captured AT FIRE TIME: PagerDuty closes an incident by the routing
// key that opened it, so the resolve must reach the same key even if the
// tenant rotated it in between.
type tenantEpisode struct {
	seq   uint64
	lanes []TenantLane
}

type tenantEpisodeRef struct {
	key string
	seq uint64
}

// TenantWatchRouter delivers tenant-authored watch alerts to the owning
// tenant's lanes, once per episode.
type TenantWatchRouter struct {
	d    *Dispatcher
	deps TenantWatchDeps

	mu    sync.Mutex
	open  map[string]tenantEpisode
	order []tenantEpisodeRef
	seq   uint64
	// closed remembers recently CLEARED episodes (bounded FIFO), so a second
	// clear of the same episode is recognised as a duplicate rather than
	// treated as an unmatched clear and re-sent.
	closed      map[string]uint64
	closedOrder []tenantEpisodeRef

	// Routing outcomes (delivery outcomes live on the Dispatcher's counters).
	queued           atomic.Uint64 // episode start handed to ≥1 lane
	resolvedQueued   atomic.Uint64 // episode end handed to the lanes its start reached
	resolveUnmatched atomic.Uint64 // end with no recorded start (restart / eviction)
	duplicate        atomic.Uint64 // re-fire inside an open episode — not re-sent
	noLane           atomic.Uint64 // tenant has no lane opted into watch alerts
	refusedTenant    atomic.Uint64 // empty / platform / wildcard tenant
	refusedNoID      atomic.Uint64 // no stable alert id → no episode to dedupe or close
	evicted          atomic.Uint64 // register full — oldest episode forgotten
}

// NewTenantWatchRouter builds the router over the Dispatcher's delivery pool.
func NewTenantWatchRouter(d *Dispatcher, deps TenantWatchDeps) *TenantWatchRouter {
	if deps.Build == nil {
		deps.Build = buildTenantLaneSender
	}
	return &TenantWatchRouter{d: d, deps: deps, open: map[string]tenantEpisode{}, closed: map[string]uint64{}}
}

// buildTenantLaneSender is the production sender: the existing notify lanes.
func buildTenantLaneSender(l TenantLane) Channel {
	switch l.System {
	case TenantLaneSlack:
		return NewSlack(l.Secret)
	case TenantLanePagerDuty:
		return NewPagerDuty(l.Secret)
	}
	return nil
}

func (r *TenantWatchRouter) logf(level, msg string, fields map[string]any) {
	if r.deps.Log != nil {
		r.deps.Log(level, msg, fields)
	}
}

// customerTenant is the default-closed tenant check: a concrete customer id,
// never the platform realm in either spelling, never a wildcard read scope.
func customerTenant(t string) (string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || owner.IsPlatform(t) || strings.HasPrefix(t, "__") || strings.ContainsAny(t, "*\x00") {
		return "", false
	}
	return t, true
}

func episodeKey(tenant, alertID string) string { return tenant + "\x1f" + alertID }

// Fire hands the start of a watch-alert episode to the tenant's lanes. tenant
// MUST be the server-stamped owner (the evaluator's own tenant). A re-fire of
// an episode that is already open is not re-sent.
func (r *TenantWatchRouter) Fire(tenant string, a models.Alert) {
	if r == nil || r.d == nil {
		return
	}
	t, ok := customerTenant(tenant)
	if !ok {
		r.refusedTenant.Add(1)
		r.logf("info", "watch alert has no customer tenant — not delivered to any tenant lane", map[string]any{
			"alert_id": a.ID, "rule": a.Rule,
		})
		return
	}
	if a.ID == "" {
		// No stable id → no episode → no way to dedupe or close it. Refused and
		// said, rather than paging once per evaluation.
		r.refusedNoID.Add(1)
		r.logf("warn", "watch alert has no id — not delivered to the tenant lane", map[string]any{
			"tenant": t, "rule": a.Rule,
		})
		return
	}
	key := episodeKey(t, a.ID)

	r.mu.Lock()
	if _, open := r.open[key]; open {
		r.mu.Unlock()
		r.duplicate.Add(1)
		return
	}
	r.mu.Unlock()

	lanes := r.lanesFor(t)
	if len(lanes) == 0 {
		r.noLane.Add(1)
		return
	}

	r.mu.Lock()
	if _, open := r.open[key]; open { // lost a race with a concurrent Fire
		r.mu.Unlock()
		r.duplicate.Add(1)
		return
	}
	evictedKey := r.recordLocked(key, lanes)
	r.mu.Unlock()
	if evictedKey != "" {
		r.evicted.Add(1)
		r.logf("warn", "tenant watch-alert register full — the oldest open episode was forgotten; its clear will close PagerDuty but send no Slack message", map[string]any{
			"capacity": tenantWatchMaxEpisodes,
		})
	}

	for _, l := range lanes {
		r.enqueue(t, l, a, false)
	}
	r.queued.Add(1)
}

// Resolve hands the end of a watch-alert episode to the lanes its start
// reached. With no recorded start (the process restarted, or the register
// evicted it), PagerDuty still gets the close — closing an incident that was
// never opened is a no-op at the destination, and suppressing a close is never
// safe — but Slack gets nothing: a "cleared" message for an alert the channel
// was never told about is noise.
func (r *TenantWatchRouter) Resolve(tenant string, a models.Alert) {
	if r == nil || r.d == nil {
		return
	}
	t, ok := customerTenant(tenant)
	if !ok {
		r.refusedTenant.Add(1)
		return
	}
	if a.ID == "" {
		r.refusedNoID.Add(1)
		return
	}
	key := episodeKey(t, a.ID)

	r.mu.Lock()
	ep, open := r.open[key]
	if open {
		delete(r.open, key)
		r.rememberClosedLocked(key)
	} else if _, done := r.closed[key]; done {
		r.mu.Unlock()
		r.duplicate.Add(1)
		return
	}
	r.mu.Unlock()

	if open {
		for _, l := range ep.lanes {
			r.enqueue(t, l, a, true)
		}
		r.resolvedQueued.Add(1)
		return
	}
	r.resolveUnmatched.Add(1)
	for _, l := range r.lanesFor(t) {
		if l.System == TenantLanePagerDuty {
			r.enqueue(t, l, a, true)
		}
	}
}

// lanesFor asks the resolver and keeps only well-formed lanes.
func (r *TenantWatchRouter) lanesFor(tenant string) []TenantLane {
	if r.deps.Lanes == nil {
		return nil
	}
	raw := r.deps.Lanes(tenant)
	out := make([]TenantLane, 0, len(raw))
	for _, l := range raw {
		if strings.TrimSpace(l.Secret) == "" {
			continue
		}
		if l.System != TenantLaneSlack && l.System != TenantLanePagerDuty {
			continue
		}
		out = append(out, l)
	}
	return out
}

// recordLocked registers an open episode, evicting the oldest when full.
// Returns the evicted key ("" when none). Caller holds r.mu.
func (r *TenantWatchRouter) recordLocked(key string, lanes []TenantLane) string {
	evicted := ""
	if len(r.open) >= tenantWatchMaxEpisodes {
		for len(r.order) > 0 {
			ref := r.order[0]
			r.order = r.order[1:]
			if ep, ok := r.open[ref.key]; ok && ep.seq == ref.seq {
				delete(r.open, ref.key)
				evicted = ref.key
				break
			}
		}
	}
	r.seq++
	delete(r.closed, key) // a new episode of the same alert starts fresh
	r.open[key] = tenantEpisode{seq: r.seq, lanes: lanes}
	r.order = append(r.order, tenantEpisodeRef{key: key, seq: r.seq})
	// Resolved episodes leave stale refs behind; compact once they dominate so
	// the order slice stays bounded by the register, not by history.
	if len(r.order) > 2*len(r.open)+64 {
		live := r.order[:0]
		for _, ref := range r.order {
			if ep, ok := r.open[ref.key]; ok && ep.seq == ref.seq {
				live = append(live, ref)
			}
		}
		r.order = live
	}
	return evicted
}

// rememberClosedLocked records a cleared episode in the bounded FIFO. A stale
// FIFO entry (the key re-opened and re-closed since) is recognised by its seq
// and never evicts the newer record. Caller holds r.mu.
func (r *TenantWatchRouter) rememberClosedLocked(key string) {
	r.seq++
	r.closed[key] = r.seq
	r.closedOrder = append(r.closedOrder, tenantEpisodeRef{key: key, seq: r.seq})
	for len(r.closedOrder) > tenantWatchClosedMemory {
		ref := r.closedOrder[0]
		r.closedOrder = r.closedOrder[1:]
		if r.closed[ref.key] == ref.seq {
			delete(r.closed, ref.key)
		}
	}
}

// enqueue hands one send to the Dispatcher's bounded pool. Slack has no
// resolve semantics, so an episode end goes to Slack as a plain message that
// says it cleared; PagerDuty gets a real resolve (same dedup key).
func (r *TenantWatchRouter) enqueue(tenant string, l TenantLane, a models.Alert, resolve bool) {
	inner := r.deps.Build(l)
	if inner == nil {
		r.logf("error", "tenant lane sender could not be built — this message did not go out", map[string]any{
			"tenant": tenant, "lane": l.System, "alert_id": a.ID,
		})
		return
	}
	ch := &tenantLaneChannel{system: l.System, tenant: tenant, secret: l.Secret, next: inner}
	if resolve && l.System == TenantLaneSlack {
		r.d.deliverJob(sendJob{ch: ch, alert: slackClearedCopy(a)})
		return
	}
	r.d.deliverJob(sendJob{ch: ch, alert: a, resolve: resolve})
}

// slackClearedCopy makes the episode-end message read as a clear even when the
// evaluator's resolution summary does not say so (a cloud monitor's resolve
// carries its OK reading).
func slackClearedCopy(a models.Alert) models.Alert {
	c := a
	s := strings.TrimSpace(a.Summary)
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "cleared") && !strings.HasPrefix(low, "closed") && !strings.HasPrefix(low, "resolved") {
		s = "Resolved: " + s
	}
	c.Summary = s
	c.Severity = "resolved"
	return c
}

// WriteMetrics emits the routing outcomes. Delivery outcomes for the same
// sends are the Dispatcher's netops_notify_*_total{channel="tenant-…"}.
func (r *TenantWatchRouter) WriteMetrics(w io.Writer) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_notify_tenant_watch_total Tenant watch alerts (BGP-watch prefix classes, cloud monitors) by routing outcome toward the tenant's own Slack/PagerDuty lanes. Delivery success/failure of the queued sends is netops_notify_sent_total / netops_notify_failures_total with channel=\"tenant-slack\" or \"tenant-pagerduty\".\n")
	fmt.Fprintf(w, "# TYPE netops_notify_tenant_watch_total counter\n")
	for _, kv := range []struct {
		outcome string
		v       uint64
	}{
		{"queued", r.queued.Load()},
		{"resolve_queued", r.resolvedQueued.Load()},
		{"resolve_unmatched", r.resolveUnmatched.Load()},
		{"duplicate", r.duplicate.Load()},
		{"no_lane", r.noLane.Load()},
		{"refused_tenant", r.refusedTenant.Load()},
		{"refused_no_id", r.refusedNoID.Load()},
		{"evicted", r.evicted.Load()},
	} {
		fmt.Fprintf(w, "netops_notify_tenant_watch_total{outcome=%q} %d\n", kv.outcome, kv.v)
	}
	r.mu.Lock()
	n := len(r.open)
	r.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_notify_tenant_watch_open_episodes Tenant watch alerts whose start was delivered and whose clear has not arrived yet.\n")
	fmt.Fprintf(w, "# TYPE netops_notify_tenant_watch_open_episodes gauge\n")
	fmt.Fprintf(w, "netops_notify_tenant_watch_open_episodes %d\n", n)
}

// tenantLaneChannel is the per-send wrapper the pool runs: a FIXED name (so
// the delivery counters stay bounded), the tenant in the error for the log, and
// the lane secret scrubbed from anything that leaves.
type tenantLaneChannel struct {
	system string
	tenant string
	secret string
	next   Channel
}

func (c *tenantLaneChannel) Name() string { return "tenant-" + c.system }

func (c *tenantLaneChannel) Send(a models.Alert) error {
	return c.scrub(c.next.Send(a))
}

func (c *tenantLaneChannel) SendResolve(a models.Alert) error {
	rs, ok := c.next.(ResolveSender)
	if !ok {
		return nil
	}
	return c.scrub(rs.SendResolve(a))
}

// scrub returns an error that cannot carry the lane secret: a transport error
// loses its URL (an incoming-webhook URL IS the secret), and any remaining
// occurrence of the secret is replaced. The tenant rides in the text so the
// delivery layer's failure log says whose page did not go out.
func (c *tenantLaneChannel) scrub(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		inner := "request failed"
		if ue.Err != nil {
			inner = ue.Err.Error()
		}
		msg = ue.Op + " request failed: " + inner
	}
	if s := strings.TrimSpace(c.secret); s != "" {
		msg = strings.ReplaceAll(msg, s, "[redacted]")
		if u, perr := url.Parse(s); perr == nil && u.Path != "" && u.Path != "/" {
			msg = strings.ReplaceAll(msg, u.Path, "[redacted]")
		}
	}
	return fmt.Errorf("tenant %q %s lane: %s", c.tenant, c.system, msg)
}
