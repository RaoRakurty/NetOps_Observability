// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// evaluate.go — tracker row #10: the evaluator.
//
// SHAPE (the seclane precedent, §9):
//   - ONE bounded, JITTERED ticker for the whole process; each tick walks the
//     tenants in turn. No per-tenant goroutine, no unbounded fan-out.
//   - A run never overlaps itself (TryLock) — a slow upstream delays the next
//     tick, it does not stack a second one on top.
//   - Every per-tenant collection is bounded: prefixes evaluated per run,
//     alerts held in history, sightings held per tenant.
//   - Every emission is idempotent and cooled down, so a condition that stays
//     true for a week does not page anyone 10 000 times.
//
// HONESTY (§10):
//   - The evaluator alerts on TRANSITIONS, and it emits a RESOLUTION when a
//     class clears — a channel that opened an incident is told it closed.
//   - ONLY a MEASURED clean pass resolves an incident. An unmeasurable pass is
//     not a clear and never sends Resolved: true. The open incident and its
//     cool-down both survive it, and if an incident was open the operator gets
//     a separate "no longer being measured" notice that says the incident is
//     still open.
//   - An unmeasurable prefix produces ClassUnknown and NO incident alert. "We
//     could not look" is never rendered, notified or grounded as "we looked and
//     it is fine"; the failure is counted (observe_errors_total) instead.
//   - The SAME rule binds the peer lane. A peer report is a TRI-STATE (up,
//     down, unknown), and only the word "up" resolves a peer-down alert. A peer
//     reported unknown - which is what bmp.Store.Close writes for every peer of
//     a session that dropped - keeps its alert open, is counted
//     (peer_state_unmeasured_total) and, when an alert is held, produces its
//     own "no longer being measured" notice that is never Resolved.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bounds (§9).
const (
	// DefaultInterval is the shipped evaluation cadence.
	DefaultInterval = 5 * time.Minute
	// DefaultCooldown is the shipped per-(prefix,class) re-notification floor.
	DefaultCooldown = 60 * time.Minute
	// MaxPrefixesPerRun caps the outbound calls one tenant's run can make.
	MaxPrefixesPerRun = 50
	// AlertHistoryMax caps one tenant's retained alert history.
	AlertHistoryMax = 200
	// MaxTenantsPerRun caps how many tenants one tick walks.
	MaxTenantsPerRun = 500
	// evidenceAttempts / evidenceBase / evidenceMaxWait bound the bus retry.
	evidenceAttempts = 4
	evidenceBase     = 200 * time.Millisecond
	evidenceMaxWait  = 5 * time.Second
)

// Alert is this package's notification, deliberately NOT models.Alert: the
// integrator maps it in one line, which is what keeps this package a leaf that
// nothing in the core has to know about.
type Alert struct {
	// ID is the STABLE dedup key. A destination that dedups (PagerDuty) closes
	// the same incident it opened when the resolution arrives.
	ID       string            `json:"id"`
	Rule     string            `json:"rule"`
	Severity string            `json:"severity"`
	Tenant   string            `json:"-"` // never serialized: it is the reader's own
	Resource string            `json:"resource"`
	Class    IncidentClass     `json:"class"`
	Summary  string            `json:"summary"`
	Detail   string            `json:"detail,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	FiredAt  time.Time         `json:"fired_at"`
	// Resolved marks the CLEARING record kept in history.
	Resolved   bool       `json:"resolved,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// PeerObservation is one device-side/BMP BGP peer as last observed.
type PeerObservation struct {
	DeviceID  string    `json:"device_id"`
	SessionID string    `json:"session_id,omitempty"`
	Peer      string    `json:"peer"`
	PeerAS    uint32    `json:"peer_as,omitempty"`
	State     string    `json:"state"` // up | down | unknown
	Reason    string    `json:"reason,omitempty"`
	ChangedAt time.Time `json:"changed_at,omitempty"`
}

// PrefixSighting is one prefix observed on a live feed, used for the bogon
// check. Source is "feed" (the RIPEstat poller ring) or "bmp".
type PrefixSighting struct {
	Prefix string
	Peer   string
	Origin uint32
	Source string
	At     time.Time
}

// Deps are the evaluator's injected collaborators. NOTHING here is ambient:
// this package opens no socket, reads no environment variable and holds no
// global state, which is what makes the whole thing testable offline (§11).
type Deps struct {
	// Now is the clock. Required.
	Now func() time.Time
	// Interval / Cooldown are the bounded cadences (zero → the defaults).
	Interval time.Duration
	Cooldown time.Duration

	// Tenants lists the tenant ids to evaluate. Required.
	Tenants func() []string
	// Watchlist returns ONE tenant's watched PREFIXES (canonical form).
	// Required; it is the only way this package learns what to watch, and it
	// goes through the same FORCE-RLS store the watchlist API uses (§3a.4).
	Watchlist func(ctx context.Context, tenant string) ([]string, error)
	// Policies is the per-tenant declared intent. Required.
	Policies PolicyStore

	// Observe measures ONE prefix. Required. An error means "not measured" and
	// produces ClassUnknown — never a clean verdict.
	Observe func(ctx context.Context, prefix string) (Observation, error)

	// Peers returns ONE tenant's BGP peer states (BMP + device telemetry).
	// Optional: nil means the peer-down rule is simply not evaluated, which the
	// status endpoint reports rather than hiding.
	Peers func(ctx context.Context, tenant string) ([]PeerObservation, error)

	// Sightings returns prefixes ONE tenant has recently observed on its live
	// feeds, for the bogon check. Optional.
	Sightings func(ctx context.Context, tenant string) ([]PrefixSighting, error)

	// Notify / Resolve deliver through the platform's notification channels.
	// Optional (nil = no notifications; the evidence half still runs).
	Notify  func(Alert)
	Resolve func(Alert)

	// Publish is the bus transport for evidence events. Optional (nil = no
	// evidence emission; the notification half still runs).
	Publish Publisher
	// EvidenceTopic overrides DefaultEvidenceTopic.
	EvidenceTopic string

	// Bogons is the compiled bogon table. Required (NewBogonSet()).
	Bogons *BogonSet
	// BogonFeedEnabled / BogonFeedURL / BogonFetcher drive the OPTIONAL
	// full-bogons refresh. All three must be set for the fetch to happen.
	BogonFeedEnabled bool
	BogonFeedURL     string
	BogonFetcher     FeedGetter

	// LogWarn / LogError are the structured loggers (§10). Required.
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)

	// Rand supplies jitter; nil takes a per-evaluator seeded source.
	Rand func() float64
	// Sleep is the cancellable sleep; nil takes the real one.
	Sleep func(context.Context, time.Duration) error
}

func (d Deps) validate() error {
	missing := make([]string, 0, 8)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Now", d.Now != nil)
	check("Tenants", d.Tenants != nil)
	check("Watchlist", d.Watchlist != nil)
	check("Policies", d.Policies != nil)
	check("Observe", d.Observe != nil)
	check("Bogons", d.Bogons != nil)
	check("LogWarn", d.LogWarn != nil)
	check("LogError", d.LogError != nil)
	if len(missing) > 0 {
		return fmt.Errorf("bgpwatch: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// tenantState is ONE tenant's evaluator state. Every field is per-tenant by
// construction — there is no cross-tenant collection anywhere in the evaluator.
type tenantState struct {
	incidents map[string]Incident // prefix → current verdict
	// open is the prefix → incident an alert is currently OPEN for. It is NOT
	// the same thing as incidents[prefix], and the difference is the whole
	// point: incidents[prefix] is what the LAST pass measured, open[prefix] is
	// what a destination is still holding. A pass that could not measure
	// overwrites the first and must not touch the second, otherwise a failed
	// lookup closes a live hijack (found by review, 2026-09-08).
	open     map[string]Incident
	history  []Alert // bounded, newest last
	cooldown map[string]time.Time
	peerDown map[string]time.Time // "device|peer" → when it was first seen down
	lastRun  time.Time
	lastErr  string
	runs     int64
	// counters is THIS tenant's slice of the counter set. It exists because the
	// per-tenant API body must never carry process-wide aggregates: "runs" and
	// "run_errors" summed across every tenant tell a scoped reader how busy the
	// OTHER tenants are (internal/bmp/http.go's handleStats states the same rule
	// for BMP message volume). The process-wide totals still exist — they are
	// the /metrics scrape, which is platform-operator surface, not tenant API.
	// Keys come from tenantCounterNames only, so the map is bounded (§9).
	counters map[string]int64
}

// tenantCounterNames is the CLOSED set of per-tenant counters, in the order
// TenantMetrics reports them. Every name is filled in (zero when nothing has
// happened) so the response shape never changes under a reader.
var tenantCounterNames = []string{
	"runs_total",
	"run_errors_total",
	"prefixes_evaluated_total",
	"observe_errors_total",
	"peer_errors_total",
	"sighting_errors_total",
	"alerts_notified_total",
	"alerts_resolved_total",
	"alerts_suppressed_total",
	"measurement_lost_total",
	"peer_state_unmeasured_total",
	"bogon_sightings_total",
	"evidence_skipped_total",
}

// Evaluator is the runtime. One per process.
type Evaluator struct {
	deps     Deps
	interval time.Duration
	cooldown time.Duration
	topic    string
	rnd      func() float64
	sleep    func(context.Context, time.Duration) error

	mu     sync.Mutex
	state  map[string]*tenantState
	runSem chan struct{} // TryLock: one run at a time

	sightings *sightingRegister
	evidence  *evidenceProducer
	metrics   *Metrics
}

// New builds the evaluator, failing CLOSED on incomplete Deps rather than
// returning a runtime that silently evaluates nothing.
func New(d Deps) (*Evaluator, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if d.Interval <= 0 {
		d.Interval = DefaultInterval
	}
	if d.Cooldown <= 0 {
		d.Cooldown = DefaultCooldown
	}
	if d.Sleep == nil {
		d.Sleep = sleepCtx
	}
	if d.Rand == nil {
		// #nosec G404 -- jitter for a polling cadence and a retry backoff, not
		// a security decision: this value never authenticates, authorizes,
		// seeds a key or names a resource (the bgpdepth.NewRuntime precedent).
		rng := rand.New(rand.NewSource(d.Now().UnixNano()))
		var mu sync.Mutex
		d.Rand = func() float64 { mu.Lock(); defer mu.Unlock(); return rng.Float64() }
	}
	topic := strings.TrimSpace(d.EvidenceTopic)
	if topic == "" {
		topic = DefaultEvidenceTopic
	}
	e := &Evaluator{
		deps: d, interval: d.Interval, cooldown: d.Cooldown, topic: topic,
		rnd: d.Rand, sleep: d.Sleep,
		state: map[string]*tenantState{}, runSem: make(chan struct{}, 1),
		sightings: newSightingRegister(), metrics: NewMetrics(),
	}
	if d.Publish != nil {
		e.evidence = &evidenceProducer{
			pub: d.Publish, topic: topic, maxTry: evidenceAttempts,
			base: evidenceBase, maxWait: evidenceMaxWait,
			metrics: &e.metrics.Evidence, sleep: d.Sleep, jitter: d.Rand,
			logErr: d.LogError,
		}
	}
	return e, nil
}

// Metrics exposes the counter set for the /metrics writer.
func (e *Evaluator) Metrics() *Metrics {
	if e == nil {
		return nil
	}
	return e.metrics
}

// Topic is the evidence topic in force (for the status surface).
func (e *Evaluator) Topic() string {
	if e == nil {
		return ""
	}
	return e.topic
}

// jitter scales d into [0.75d, 1.25d).
func (e *Evaluator) jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.75 + 0.5*e.rnd()))
}

// Run is the evaluation loop. It returns when ctx is cancelled.
func (e *Evaluator) Run(ctx context.Context) {
	e.deps.LogWarn("BGP watchlist evaluator started", map[string]any{
		"interval": e.interval.String(), "cooldown": e.cooldown.String(),
		"evidence_topic": e.topic, "bogon_blocks": e.deps.Bogons.StaticCount(),
	})
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.jitter(e.interval)):
		}
		e.RunOnce(ctx)
	}
}

// RunOnce evaluates every tenant once. It is a NO-OP while a previous run is
// still going (TryLock) — a slow upstream delays work, it never stacks it.
func (e *Evaluator) RunOnce(ctx context.Context) {
	select {
	case e.runSem <- struct{}{}:
		defer func() { <-e.runSem }()
	default:
		e.metrics.RunsSkipped.Add(1)
		return
	}
	// The full-bogons refresh rides the same tick, bounded and jittered, and a
	// failure NEVER blocks the evaluation: the embedded set still stands.
	if e.deps.BogonFeedEnabled && e.deps.BogonFetcher != nil {
		if err := e.deps.Bogons.RefreshFeed(ctx, e.deps.BogonFetcher, e.deps.BogonFeedURL, e.deps.Now, e.sleep, e.rnd); err != nil && ctx.Err() == nil {
			e.metrics.BogonFeedErrors.Add(1)
			e.deps.LogWarn("full-bogons feed refresh failed — the embedded RFC/IANA set is still in force", map[string]any{"err": err.Error()})
		}
	}
	tenants := e.deps.Tenants()
	if len(tenants) > MaxTenantsPerRun {
		tenants = tenants[:MaxTenantsPerRun]
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return
		}
		if err := e.EvaluateTenant(ctx, t); err != nil && ctx.Err() == nil {
			e.bump(e.tenantState(t), "run_errors_total", &e.metrics.RunErrors)
			e.deps.LogError("BGP watchlist evaluation failed for a tenant", map[string]any{"err": err.Error()})
		}
	}
}

// EvaluateTenant runs ONE tenant's evaluation. Exported so the integrator can
// trigger a run and so tests drive it directly with no ticker.
func (e *Evaluator) EvaluateTenant(ctx context.Context, tenant string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	now := e.deps.Now().UTC()
	st := e.tenantState(t)

	// The bogon SIGHTING sweep runs FIRST and unconditionally, because it
	// depends on neither the policy nor the watchlist: sightings come from the
	// tenant's LIVE feeds (the BMP update ring, the near-live poller ring) and
	// are a fact about what arrived, not a verdict about what was declared.
	//
	// It used to sit at the END of this function, after two reads that both
	// `return` on error. On a stack with no relational store the watchlist read
	// failed every pass, so the sweep never ran once and /api/bgp/bogons showed
	// "none seen" while real BMP updates for a bogon prefix were sitting in the
	// store (found live, 2026-09-03). The file-backed watchlist removes that
	// particular error; this ordering removes the TRAP — no future read failure
	// upstream of it can blind the sighting register again.
	e.checkSightings(ctx, t, now)

	policy, perr := e.deps.Policies.Policy(ctx, t)
	if perr != nil {
		// Fail LOUD and STOP for this tenant: evaluating with an empty policy
		// would silently swap declared origins for learned ones and change what
		// gets alerted on. An unreadable policy is not "no policy".
		e.setLastRun(st, now, perr.Error())
		return fmt.Errorf("alert policy unreadable for this tenant: %w", perr)
	}

	prefixes, werr := e.deps.Watchlist(ctx, t)
	if werr != nil {
		e.setLastRun(st, now, werr.Error())
		return fmt.Errorf("watchlist unreadable: %w", werr)
	}
	if len(prefixes) > MaxPrefixesPerRun {
		prefixes = prefixes[:MaxPrefixesPerRun]
	}
	sort.Strings(prefixes)

	var events []Record
	var lastErr string
	for _, p := range prefixes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		obs, oerr := e.deps.Observe(ctx, p)
		if oerr != nil {
			obs = Observation{Prefix: p, Measured: false, Error: oerr.Error(), FetchedAt: now}
			e.bump(st, "observe_errors_total", &e.metrics.ObserveErrors)
			lastErr = oerr.Error()
		}
		if obs.Prefix == "" {
			obs.Prefix = p
		}
		cfg := policy.For(p)
		inc := Classify(obs, cfg, e.deps.Bogons, now)
		e.bump(st, "prefixes_evaluated_total", &e.metrics.PrefixesEvaluated)
		events = append(events, e.applyIncident(st, t, inc, cfg, now)...)
	}

	events = append(events, e.checkPeers(ctx, st, t, now)...)

	if e.evidence != nil && len(events) > 0 {
		if _, err := e.evidence.publish(ctx, events); err != nil && ctx.Err() == nil {
			// Already counted + logged by the producer; the evaluation itself
			// still succeeded and the notifications already went out.
			lastErr = "evidence publish failed: " + err.Error()
		}
	}
	e.setLastRun(st, now, lastErr)
	e.bump(st, "runs_total", &e.metrics.Runs)
	return nil
}

// applyIncident folds one verdict into the tenant's state and returns the
// evidence records the transition produced.
func (e *Evaluator) applyIncident(st *tenantState, tenant string, inc Incident, cfg PolicyConfig, now time.Time) []Record {
	e.mu.Lock()
	prev, had := st.incidents[inc.Prefix]
	if had {
		inc.FirstSeen = prev.FirstSeen
		if prev.Class == inc.Class {
			inc.Since = prev.Since // same episode — keep its start
		}
	}
	// A blind pass must not make the open incident disappear from the page.
	// The class stays "unknown" — that is honestly what this pass measured —
	// but the verdict the operator reads says what is still open.
	if op, isOpen := st.open[inc.Prefix]; isOpen && inc.Class == ClassUnknown {
		inc.Summary += fmt.Sprintf(" The %s incident opened at %s stays open: it is unproven, not cleared.",
			op.Class, op.Since.UTC().Format(time.RFC3339))
	}
	st.incidents[inc.Prefix] = inc
	e.mu.Unlock()

	// NOT MEASURED. This pass learned nothing, so it may not clear anything.
	//
	// Before 2026-09-08 this branch fell in with ClassNone and dispatched
	// Alert{Resolved: true, Summary: "Cleared: … is no longer classified
	// origin_change."}. One upstream 502 therefore closed a live hijack on
	// PagerDuty, and because resolveAlert also drops the cool-down stamp, a
	// flapping upstream produced fire / false clear / fire with the 60-minute
	// floor bypassed. The open incident and its cool-down both SURVIVE an
	// unmeasurable pass now; what goes out is a distinct notice that says we
	// stopped measuring, and it is never Resolved.
	if inc.Class == ClassUnknown {
		if op, isOpen := e.openIncident(st, inc.Prefix); isOpen {
			e.noticeMeasurementLost(st, tenant, op, inc, now)
		}
		return nil
	}

	op, isOpen := e.openIncident(st, inc.Prefix)

	// Measured and clean: the condition really did clear, so close whatever is
	// open. This is the ONLY path that resolves a prefix incident.
	if inc.Class == ClassNone {
		if isOpen {
			e.resolveAlert(st, tenant, op, now)
		}
		return nil
	}
	// The class CHANGED from one incident to another: resolve the old one first
	// so a destination is never left holding a stale open incident.
	if isOpen && op.Class != inc.Class {
		e.resolveAlert(st, tenant, op, now)
	}

	key := alertKey(tenant, inc.Prefix, inc.Class)
	if !e.coolDownPassed(st, key, now) {
		e.bump(st, "alerts_suppressed_total", &e.metrics.AlertsSuppressed)
		return nil
	}
	a := Alert{
		ID: key, Rule: "bgp_" + string(inc.Class), Severity: inc.Severity,
		Tenant: tenant, Resource: inc.Prefix, Class: inc.Class,
		Summary: inc.Summary, Detail: inc.Evidence.Detail, FiredAt: now,
		Labels: map[string]string{
			"prefix": inc.Prefix, "class": string(inc.Class), "source": "bgp-watch",
		},
	}
	if len(inc.Evidence.Vantages) > 0 {
		a.Labels["vantages"] = fmt.Sprintf("%d", len(inc.Evidence.Vantages))
	}
	e.recordAlert(st, a)
	// Remember WHAT is open before notifying: the destination now holds this
	// incident and only a measured clear (or ForgetPrefix) may close it.
	e.mu.Lock()
	st.open[inc.Prefix] = inc
	e.mu.Unlock()
	if e.deps.Notify != nil {
		e.deps.Notify(a)
		e.bump(st, "alerts_notified_total", &e.metrics.AlertsNotified)
	}

	ev, err := EventFromIncident(tenant, inc, cfg)
	if err != nil {
		e.bump(st, "evidence_skipped_total", &e.metrics.Evidence.skipped)
		e.deps.LogWarn("BGP incident could not be shaped as an evidence event — it was NOT grounded", map[string]any{
			"prefix": inc.Prefix, "class": string(inc.Class), "err": err.Error()})
		return nil
	}
	return []Record{{Key: tenant, Value: ev}}
}

// peerReport is the TRI-STATE one peer report can carry. The upstream
// (bmp.PeerView) documents exactly three values, and the store sets the third
// for EVERY peer of a session it closes. Collapsing the three into a boolean is
// what made a peer we cannot see read as up (review 2026-09-08).
type peerReport int

const (
	// peerNotMeasured: the report says "unknown" (or says nothing readable).
	// No Peer Up / Peer Down has been observed, or the BMP session carrying
	// this peer closed. It is NOT a state, it is the absence of one.
	peerNotMeasured peerReport = iota
	peerIsUp
	peerIsDown
)

// readPeerState classifies ONE peer report. Anything that is not the word "up"
// or the word "down" is NOT MEASURED — never up. An empty or unexpected string
// means the source told us nothing, and "we were told nothing" must not render
// as "we looked and it is fine" (§10).
func readPeerState(s string) peerReport {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "down":
		return peerIsDown
	case "up":
		return peerIsUp
	default:
		return peerNotMeasured
	}
}

// checkPeers evaluates the BMP/device peer-down rule.
//
// st.peerDown is the set of peers a destination is currently HOLDING a
// peer-down alert for. It is deliberately the open set and not a record of what
// the last pass measured, which is why the peer lane needs no second map the
// way the prefix lane does: a pass that could not measure simply does not touch
// it, so the alert stays open and the next MEASURED "up" still resolves it.
func (e *Evaluator) checkPeers(ctx context.Context, st *tenantState, tenant string, now time.Time) []Record {
	if e.deps.Peers == nil {
		return nil
	}
	peers, err := e.deps.Peers(ctx, tenant)
	if err != nil {
		e.bump(st, "peer_errors_total", &e.metrics.PeerErrors)
		e.deps.LogWarn("BGP peer states unreadable — the peer-down rule did not run this tick", map[string]any{"err": err.Error()})
		return nil
	}
	var out []Record
	seen := map[string]bool{}
	for _, p := range peers {
		key := clip(p.DeviceID, 128) + "|" + clip(p.Peer, 64)
		seen[key] = true
		state := readPeerState(p.State)
		e.mu.Lock()
		_, wasDown := st.peerDown[key]
		switch state {
		case peerIsDown:
			if !wasDown {
				st.peerDown[key] = now
			}
		case peerIsUp:
			if wasDown {
				delete(st.peerDown, key)
			}
		case peerNotMeasured:
			// Touch NOTHING. Before 2026-09-08 this fell in with "up": when a
			// BMP session closed, bmp.Store.Close set every one of its peers to
			// "unknown" and the very next pass dispatched "BGP peer X on Y is
			// back up" and closed the incident, for peers nobody could see.
		}
		e.mu.Unlock()

		if state == peerNotMeasured {
			e.bump(st, "peer_state_unmeasured_total", &e.metrics.PeerStateUnmeasured)
			if wasDown {
				e.noticePeerMeasurementLost(st, tenant, p, key, now)
			}
			continue
		}
		if state == peerIsDown && !wasDown {
			a := Alert{
				ID: "bgp:" + tenant + ":peer:" + key, Rule: "bgp_peer_down", Severity: SevHigh,
				Tenant: tenant, Resource: p.DeviceID, Class: ClassNone,
				Summary: fmt.Sprintf("BGP peer %s on %s is down.", clip(p.Peer, 64), clip(p.DeviceID, 128)),
				Detail:  clip(p.Reason, 200), FiredAt: now,
				Labels: map[string]string{"device": clip(p.DeviceID, 128), "peer": clip(p.Peer, 64), "source": "bgp-watch"},
			}
			if e.coolDownPassed(st, a.ID, now) {
				e.recordAlert(st, a)
				if e.deps.Notify != nil {
					e.deps.Notify(a)
					e.bump(st, "alerts_notified_total", &e.metrics.AlertsNotified)
				}
				if ev, eerr := EventFromPeerDown(tenant, p, now); eerr == nil {
					out = append(out, Record{Key: tenant, Value: ev})
				} else {
					e.bump(st, "evidence_skipped_total", &e.metrics.Evidence.skipped)
				}
			} else {
				e.bump(st, "alerts_suppressed_total", &e.metrics.AlertsSuppressed)
			}
		}
		// ONLY a measured "up" resolves. This is the peer lane's single
		// resolution path, and it is reached across any number of unmeasured
		// passes because those left st.peerDown alone.
		if state == peerIsUp && wasDown {
			alertID := "bgp:" + tenant + ":peer:" + key
			// The episode is OVER, so its cool-down stamps go with it —
			// exactly what resolveAlert does in the prefix lane. Without this
			// a peer that flapped down again inside the cool-down window
			// produced no page and no evidence record, only a suppression
			// counter, because the closed episode's stamp was still standing
			// (review 2026-09-08, 3.4-02).
			e.mu.Lock()
			delete(st.cooldown, alertID)
			delete(st.cooldown, alertID+":unmeasured")
			e.mu.Unlock()
			if e.deps.Resolve != nil {
				t := now
				e.deps.Resolve(Alert{
					ID: alertID, Rule: "bgp_peer_down", Severity: SevHigh,
					Tenant: tenant, Resource: p.DeviceID, FiredAt: now, Resolved: true, ResolvedAt: &t,
					Summary: fmt.Sprintf("BGP peer %s on %s is back up.", clip(p.Peer, 64), clip(p.DeviceID, 128)),
				})
				e.bump(st, "alerts_resolved_total", &e.metrics.AlertsResolved)
			}
		}
	}
	// A peer that VANISHED from the report is not a recovery — we stopped being
	// told about it. Drop the state without claiming it came back.
	e.mu.Lock()
	for k := range st.peerDown {
		if !seen[k] {
			delete(st.peerDown, k)
		}
	}
	e.mu.Unlock()
	return out
}

// noticePeerMeasurementLost tells the operator that a HELD peer-down alert
// stopped being measured. It mirrors noticeMeasurementLost in the prefix lane
// and is deliberately NOT a resolution:
//
//   - Resolved stays false, so a destination that dedups does not close the
//     peer-down incident. That peer is unproven, not recovered.
//   - It carries its OWN dedup id (the peer key plus ":unmeasured"), so it can
//     never overwrite or close the peer-down notification itself.
//   - It is cooled down like every other emission, so a router that stays gone
//     produces one notice per cool-down window, not one per tick.
func (e *Evaluator) noticePeerMeasurementLost(st *tenantState, tenant string, p PeerObservation, key string, now time.Time) {
	id := "bgp:" + tenant + ":peer:" + key + ":unmeasured"
	if !e.coolDownPassed(st, id, now) {
		e.bump(st, "alerts_suppressed_total", &e.metrics.AlertsSuppressed)
		return
	}
	a := Alert{
		ID: id, Rule: "bgp_peer_measurement_lost", Severity: SevWarning,
		Tenant: tenant, Resource: p.DeviceID, Class: ClassUnknown,
		Summary: fmt.Sprintf("BGP peer %s on %s is NO LONGER BEING MEASURED while it is down. "+
			"The peer-down alert stays open: this is an absent measurement, not a recovery.",
			clip(p.Peer, 64), clip(p.DeviceID, 128)),
		Detail:  clip(p.Reason, 200),
		FiredAt: now,
		Labels: map[string]string{
			"device": clip(p.DeviceID, 128), "peer": clip(p.Peer, 64),
			"state": "unmeasured", "source": "bgp-watch",
		},
	}
	e.recordAlert(st, a)
	e.bump(st, "measurement_lost_total", &e.metrics.MeasurementLost)
	if e.deps.Notify != nil {
		e.deps.Notify(a)
		e.bump(st, "alerts_notified_total", &e.metrics.AlertsNotified)
	}
}

// checkSightings records bogon sightings from the tenant's live feeds.
func (e *Evaluator) checkSightings(ctx context.Context, tenant string, now time.Time) {
	if e.deps.Sightings == nil {
		return
	}
	rows, err := e.deps.Sightings(ctx, tenant)
	if err != nil {
		e.bump(e.tenantState(tenant), "sighting_errors_total", &e.metrics.SightingErrors)
		return
	}
	for _, r := range rows {
		p, perr := parsePrefix(r.Prefix)
		if perr != nil {
			continue
		}
		entry, ok := e.deps.Bogons.Lookup(p)
		if !ok {
			continue
		}
		at := r.At
		if at.IsZero() {
			at = now
		}
		src := clip(strings.TrimSpace(r.Source), 16)
		if src == "" {
			src = "feed"
		}
		if e.sightings.note(tenant, Sighting{
			Prefix: p.String(), Entry: entry, Source: src, Peer: clip(r.Peer, 64),
			Origin: r.Origin, FirstSeen: at, LastSeen: at,
		}) {
			e.bump(e.tenantState(tenant), "bogon_sightings_total", &e.metrics.BogonSightings)
		}
	}
}

// openIncident reports the incident a destination is currently holding open for
// this prefix, if any.
func (e *Evaluator) openIncident(st *tenantState, prefix string) (Incident, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	op, ok := st.open[prefix]
	return op, ok
}

// noticeMeasurementLost tells the operator that an OPEN incident stopped being
// measured. It is deliberately NOT a resolution:
//
//   - Resolved stays false, so a destination that dedups does not close the
//     incident. The incident it names is still open and still unproven.
//   - It carries its OWN id (the prefix's "unknown" key), so it can never
//     overwrite or close the open incident's own notification.
//   - It is cooled down like any other emission, and its stamp lives exactly as
//     long as the episode: resolveAlert drops it when the incident really
//     clears, so the next outage says so again.
func (e *Evaluator) noticeMeasurementLost(st *tenantState, tenant string, open, unmeasured Incident, now time.Time) {
	key := alertKey(tenant, open.Prefix, ClassUnknown)
	if !e.coolDownPassed(st, key, now) {
		e.bump(st, "alerts_suppressed_total", &e.metrics.AlertsSuppressed)
		return
	}
	a := Alert{
		ID: key, Rule: "bgp_measurement_lost", Severity: SevWarning,
		Tenant: tenant, Resource: open.Prefix, Class: ClassUnknown,
		Summary: fmt.Sprintf("%s is NO LONGER BEING MEASURED while it is classified %s. "+
			"The incident stays open: this is an absent measurement, not a clear.",
			open.Prefix, open.Class),
		Detail:  clip(unmeasured.Error, 200),
		FiredAt: now,
		Labels: map[string]string{
			"prefix": open.Prefix, "class": string(ClassUnknown),
			"open_class": string(open.Class), "source": "bgp-watch",
		},
	}
	e.recordAlert(st, a)
	e.bump(st, "measurement_lost_total", &e.metrics.MeasurementLost)
	if e.deps.Notify != nil {
		e.deps.Notify(a)
		e.bump(st, "alerts_notified_total", &e.metrics.AlertsNotified)
	}
}

// resolveAlert closes the alert an incident class had opened. It is reached
// only from a MEASURED clean pass, a measured class change, or ForgetPrefix.
func (e *Evaluator) resolveAlert(st *tenantState, tenant string, prev Incident, now time.Time) {
	key := alertKey(tenant, prev.Prefix, prev.Class)
	a := Alert{
		ID: key, Rule: "bgp_" + string(prev.Class), Severity: prev.Severity,
		Tenant: tenant, Resource: prev.Prefix, Class: prev.Class,
		Summary:  fmt.Sprintf("Cleared: %s is no longer classified %s.", prev.Prefix, prev.Class),
		FiredAt:  prev.Since,
		Resolved: true,
	}
	t := now
	a.ResolvedAt = &t
	e.recordAlert(st, a)
	if e.deps.Resolve != nil {
		e.deps.Resolve(a)
	}
	e.bump(st, "alerts_resolved_total", &e.metrics.AlertsResolved)
	e.mu.Lock()
	delete(st.cooldown, key)
	// The episode is over, so both its stamps go: the incident's own cool-down
	// and the "we stopped measuring" notice that belongs to the same episode.
	delete(st.cooldown, alertKey(tenant, prev.Prefix, ClassUnknown))
	delete(st.open, prev.Prefix)
	e.mu.Unlock()
}

// coolDownPassed reports whether this key may notify again, stamping the time
// when it may.
func (e *Evaluator) coolDownPassed(st *tenantState, key string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := st.cooldown[key]; ok && now.Sub(last) < e.cooldown {
		return false
	}
	st.cooldown[key] = now
	return true
}

// recordAlert appends to the tenant's BOUNDED history ring.
func (e *Evaluator) recordAlert(st *tenantState, a Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st.history = append(st.history, a)
	if len(st.history) > AlertHistoryMax {
		st.history = append([]Alert(nil), st.history[len(st.history)-AlertHistoryMax:]...)
	}
}

// bump increments a counter in BOTH places it belongs: the process-wide
// atomic (the /metrics scrape) and the one tenant's own tally (the API body).
// It must never be called while e.mu is held.
func (e *Evaluator) bump(st *tenantState, name string, global *atomic.Int64) {
	if global != nil {
		global.Add(1)
	}
	if st == nil {
		return
	}
	e.mu.Lock()
	if st.counters == nil {
		st.counters = make(map[string]int64, len(tenantCounterNames))
	}
	st.counters[name]++
	e.mu.Unlock()
}

// TenantMetrics returns ONE tenant's counters. There is deliberately no
// cross-tenant read: a scoped caller asking "how is MY watchlist doing" must
// not learn how much work every other tenant generated.
func (e *Evaluator) TenantMetrics(tenant string) (map[string]int64, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(tenantCounterNames))
	for _, n := range tenantCounterNames {
		out[n] = 0
	}
	e.mu.Lock()
	if st := e.state[t]; st != nil {
		for _, n := range tenantCounterNames {
			out[n] = st.counters[n]
		}
	}
	e.mu.Unlock()
	return out, nil
}

func (e *Evaluator) setLastRun(st *tenantState, now time.Time, errText string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st.lastRun, st.lastErr, st.runs = now, errText, st.runs+1
}

// tenantState returns (creating on first use) ONE tenant's state.
func (e *Evaluator) tenantState(tenant string) *tenantState {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state[tenant]
	if st == nil {
		st = &tenantState{
			incidents: map[string]Incident{}, open: map[string]Incident{},
			cooldown: map[string]time.Time{},
			peerDown: map[string]time.Time{},
		}
		e.state[tenant] = st
	}
	return st
}

// alertKey is the stable dedup key. It carries the tenant, so two tenants
// watching the SAME prefix can never share (or close) each other's incident.
func alertKey(tenant, prefix string, class IncidentClass) string {
	return "bgp:" + tenant + ":" + prefix + ":" + string(class)
}

// ForgetPrefix drops ONE tenant's evaluator state for ONE prefix. It is what
// "stop watching this" has to mean end-to-end: without it, removing a prefix
// from the watchlist deleted the row but left its verdict behind, so the
// Prefixes view kept rendering an `incidents` entry — a live-looking hijack or
// leak classification for a resource nothing was measuring any more (found on
// the 2026-09-03 live proof).
//
// What it clears, and what it deliberately does NOT:
//
//   - incidents[prefix]      CLEARED — a verdict with no measurement behind it
//     is the definition of a stale claim (§10).
//   - cooldown for that prefix  CLEARED — otherwise re-adding the prefix inside
//     the cool-down would silently suppress its first real alert.
//   - history                KEPT — the alert ring is the record of what was
//     actually raised. Un-watching a prefix must not rewrite that.
//   - sightings              KEPT — a bogon sighting is a fact about what
//     arrived on the tenant's live feeds, not a watchlist verdict.
//
// An alert that was OPEN is resolved, because the destination that was paged
// has no other way to close it. The resolve text says the prefix was removed
// from the watchlist — it does NOT claim the condition cleared, which would be
// a false statement about the network.
func (e *Evaluator) ForgetPrefix(tenant, prefix string) (bool, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return false, err
	}
	key := strings.TrimSpace(prefix)
	if p, perr := parsePrefix(key); perr == nil {
		key = p.String() // canonical form, exactly as the evaluator stores it
	}
	if key == "" {
		return false, errors.New("bgpwatch: a prefix is required")
	}

	e.mu.Lock()
	st := e.state[t]
	if st == nil {
		e.mu.Unlock()
		return false, nil
	}
	prev, had := st.incidents[key]
	if had {
		delete(st.incidents, key)
	}
	// The OPEN incident is what a destination is still holding; an unwatched
	// prefix has none. Resolved below with the "removed from the watchlist"
	// wording, which is not a claim that the condition cleared.
	if op, isOpen := st.open[key]; isOpen {
		prev, had = op, true
	}
	delete(st.open, key)
	// classRank is the ONE enumeration of every class (classify.go), so a class
	// added later is covered here automatically rather than by a second list
	// that would silently drift out of date.
	for class := range classRank {
		delete(st.cooldown, alertKey(t, key, class))
	}
	e.mu.Unlock()

	if !had || prev.Class == ClassNone || prev.Class == ClassUnknown || e.deps.Resolve == nil {
		return had, nil
	}
	now := e.deps.Now().UTC()
	a := Alert{
		ID: alertKey(t, key, prev.Class), Rule: "bgp_" + string(prev.Class), Severity: prev.Severity,
		Tenant: t, Resource: key, Class: prev.Class,
		Summary: fmt.Sprintf("Closed: %s was removed from the watchlist while classified %s. "+
			"This is NOT a statement that the condition cleared — it is no longer being measured.",
			key, prev.Class),
		FiredAt: prev.Since, Resolved: true, ResolvedAt: &now,
	}
	e.recordAlert(st, a)
	e.deps.Resolve(a)
	e.bump(st, "alerts_resolved_total", &e.metrics.AlertsResolved)
	return had, nil
}

// ── read surfaces (per tenant, no unscoped variant) ─────────────────────────

// Incidents returns ONE tenant's current verdicts, worst first.
func (e *Evaluator) Incidents(tenant string) ([]Incident, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st := e.state[t]
	out := []Incident{}
	if st != nil {
		for _, inc := range st.incidents {
			out = append(out, inc)
		}
	}
	e.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if classRank[out[i].Class] != classRank[out[j].Class] {
			return classRank[out[i].Class] < classRank[out[j].Class]
		}
		return out[i].Prefix < out[j].Prefix
	})
	return out, nil
}

// Alerts returns ONE tenant's alert history, newest first, bounded by limit.
func (e *Evaluator) Alerts(tenant string, limit int) ([]Alert, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	st := e.state[t]
	out := []Alert{}
	if st != nil {
		for i := len(st.history) - 1; i >= 0; i-- {
			if limit > 0 && len(out) >= limit {
				break
			}
			out = append(out, st.history[i])
		}
	}
	e.mu.Unlock()
	return out, nil
}

// Sightings returns ONE tenant's bogon sightings.
func (e *Evaluator) Sightings(tenant string, limit int) ([]Sighting, error) {
	if _, err := concreteTenant(tenant); err != nil {
		return nil, err
	}
	return e.sightings.list(tenant, limit), nil
}

// NoteSighting records one externally-observed prefix (the integrator's bridge
// from the BMP store / live-feed ring). Exported so the wiring can push a
// sighting the moment it arrives instead of waiting for a tick.
func (e *Evaluator) NoteSighting(tenant string, s PrefixSighting) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	p, perr := parsePrefix(s.Prefix)
	if perr != nil {
		return perr
	}
	entry, ok := e.deps.Bogons.Lookup(p)
	if !ok {
		return nil
	}
	at := s.At
	if at.IsZero() {
		at = e.deps.Now().UTC()
	}
	if e.sightings.note(t, Sighting{
		Prefix: p.String(), Entry: entry, Source: clip(s.Source, 16),
		Peer: clip(s.Peer, 64), Origin: s.Origin, FirstSeen: at, LastSeen: at,
	}) {
		e.bump(e.tenantState(t), "bogon_sightings_total", &e.metrics.BogonSightings)
	}
	return nil
}

// Status is the per-tenant operational state of the evaluator.
type Status struct {
	Enabled       bool      `json:"enabled"`
	Interval      string    `json:"interval"`
	Cooldown      string    `json:"cooldown"`
	EvidenceTopic string    `json:"evidence_topic"`
	LastRun       time.Time `json:"last_run,omitempty"`
	Runs          int64     `json:"runs"`
	LastError     string    `json:"last_error,omitempty"`
	PeerRule      bool      `json:"peer_rule_enabled"`
	NotifyWired   bool      `json:"notify_wired"`
	EvidenceWired bool      `json:"evidence_wired"`
	Note          string    `json:"note,omitempty"`
}

// Status returns ONE tenant's evaluator status.
func (e *Evaluator) Status(tenant string) Status {
	st := Status{
		Enabled: true, Interval: e.interval.String(), Cooldown: e.cooldown.String(),
		EvidenceTopic: e.topic, PeerRule: e.deps.Peers != nil,
		NotifyWired: e.deps.Notify != nil, EvidenceWired: e.evidence != nil,
	}
	t := normTenant(tenant)
	e.mu.Lock()
	if s := e.state[t]; s != nil {
		st.LastRun, st.Runs, st.LastError = s.lastRun, s.runs, s.lastErr
	}
	e.mu.Unlock()
	if st.Runs == 0 {
		st.Note = "The evaluator has not completed a pass for this tenant yet — an empty incident list here means 'not evaluated', not 'nothing wrong'."
	}
	return st
}

// ErrDisabled is what the HTTP layer reports when the evaluator is not running.
var ErrDisabled = errors.New("bgpwatch: BGP alerting is not enabled")
