package dem

// projector.go — how the api hands the prober its work queue.
//
// The prober is a least-privilege sidecar (ADR 0001) with no database, no auth
// and no device inventory: its targets have always arrived as env lists or as a
// list the api publishes to the shared key-value channel. The DEM catalogue
// reuses the SECOND of those, exactly as the WAN circuit projector does, for
// three reasons:
//
//  1. it needs no new credential on the prober — the api already publishes and
//     the prober already reads on that channel;
//  2. the published entry carries a short TTL, so a prober that loses contact
//     with the api STOPS measuring a stale list rather than measuring forever
//     against targets the operator deleted;
//  3. it keeps the prober unable to call the api at all, which is what keeps the
//     privileged container off the authenticated surface.
//
// WireTarget is the whole contract between the two processes. It carries what a
// check needs and NOTHING else: no budgets (the prober does not score), no
// names, no created-by. That is deliberate — the work queue leaves the api and
// lands in a container that holds no secrets, so it must not carry anything a
// tenant would mind seeing there.

import (
	"context"
	"errors"
	"sort"
	"time"
)

// WireTarget is one unit of work for the prober.
type WireTarget struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	Kind        string `json:"kind"`
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	Resolver    string `json:"resolver,omitempty"`
	IntervalSec int    `json:"interval_sec"`
	Site        string `json:"site,omitempty"`
	App         string `json:"app,omitempty"`
	// ExpectStatus is the HTTP status the check must observe. 0 = any 2xx/3xx.
	ExpectStatus int `json:"expect_status,omitempty"`

	// The BUDGETS ride along so the prober can publish them as gauges beside
	// the measurements. That is what lets the experience alert rules be pure
	// PromQL comparisons — and therefore keep firing while the api, which owns
	// the catalogue, is the thing that is down (the rules-scale-slo lesson).
	// They are thresholds an operator set, not data about anyone.
	//
	// AvailBudgetPct is the EFFECTIVE budget (the declared one, or the platform
	// default), so the rule never has to know what the default is.
	AvailBudgetPct float64 `json:"avail_budget_pct,omitempty"`
	// LatencyBudgetMs is 0 when the operator declared none, and the prober then
	// publishes no latency-budget gauge at all — so the latency rule cannot fire
	// against a threshold nobody set.
	LatencyBudgetMs float64 `json:"latency_budget_ms,omitempty"`
}

// ToWire projects a catalogue row onto the prober's contract. A PAUSED target
// is never projected: pausing must stop the measurement, not merely hide it.
func ToWire(t Target) (WireTarget, bool) {
	if t.Paused {
		return WireTarget{}, false
	}
	avail, _ := t.EffectiveAvailabilityBudget()
	return WireTarget{
		ID: t.ID, Tenant: t.TenantID, Kind: t.Kind, Host: t.Host, Port: t.Port,
		Resolver: t.Resolver, IntervalSec: int(t.Interval() / time.Second),
		Site: t.Site, App: t.App, ExpectStatus: t.ExpectStatus,
		AvailBudgetPct: avail, LatencyBudgetMs: t.LatencyBudgetMs,
	}, true
}

// Publisher is the injected transport to the prober's work queue.
type Publisher interface {
	Publish(ctx context.Context, targets []WireTarget, ttlSec int) error
}

// Projector republishes the fleet's work queue on a timer.
type Projector struct {
	cat      Catalogue
	pub      Publisher
	interval time.Duration
	counters *Metrics
	logWarn  func(msg string, fields map[string]any)
}

// DefaultProjectInterval balances "a new target starts being measured soon"
// against "the queue is not a busy loop". The published TTL is three times this,
// so one missed cycle does not blank the prober's list.
const DefaultProjectInterval = 60 * time.Second

// MaxProjectedTargets bounds the whole fleet's queue. The prober runs bounded
// concurrency over it, so an unbounded queue is an unbounded work backlog on a
// 128 MiB container.
const MaxProjectedTargets = 5000

// NewProjector fails CLOSED on missing collaborators rather than silently never
// publishing (the failure mode where the prober measures nothing and nobody
// notices because there is no error anywhere).
func NewProjector(cat Catalogue, pub Publisher, interval time.Duration, counters *Metrics, logWarn func(string, map[string]any)) (*Projector, error) {
	if cat == nil || pub == nil {
		return nil, errors.New("dem: the projector needs both a catalogue and a publisher")
	}
	if logWarn == nil {
		return nil, errors.New("dem: the projector needs a logger")
	}
	if interval < 15*time.Second || interval > 15*time.Minute {
		interval = DefaultProjectInterval
	}
	if counters == nil {
		counters = NewMetrics()
	}
	return &Projector{cat: cat, pub: pub, interval: interval, counters: counters, logWarn: logWarn}, nil
}

// Interval exposes the resolved cadence (used to size the published TTL).
func (p *Projector) Interval() time.Duration { return p.interval }

// RunOnce publishes the current queue exactly once. Exported so the integrator
// can publish immediately at boot and so tests need no clock.
func (p *Projector) RunOnce(ctx context.Context) error {
	// ListAll is the ONE cross-tenant read in this package, and this is its one
	// caller: the prober measures every tenant's targets and stamps each result
	// with the tenant that owns it. It is never reachable from an HTTP handler.
	all, err := p.cat.ListAll(ctx)
	if err != nil {
		p.counters.ProjectErrors.Add(1)
		return err
	}
	queue := make([]WireTarget, 0, len(all))
	for _, t := range all {
		wt, ok := ToWire(t)
		if !ok {
			continue
		}
		if _, terr := concreteTenant(wt.Tenant); terr != nil {
			// A row with no concrete owner cannot be attributed to anyone, so
			// its measurement could not be scoped. Drop it loudly.
			p.logWarn("an experience target has no owning tenant and was NOT published to the prober",
				map[string]any{"target": wt.ID})
			continue
		}
		queue = append(queue, wt)
		if len(queue) >= MaxProjectedTargets {
			p.logWarn("the experience work queue hit its bound — the remaining targets are not being measured",
				map[string]any{"bound": MaxProjectedTargets})
			break
		}
	}
	// Deterministic order: the prober logs the queue, and a queue that
	// reshuffles every minute makes a real change invisible in the diff.
	sort.Slice(queue, func(i, j int) bool { return queue[i].ID < queue[j].ID })

	ttl := int(3 * p.interval / time.Second)
	if err := p.pub.Publish(ctx, queue, ttl); err != nil {
		p.counters.ProjectErrors.Add(1)
		return err
	}
	p.counters.TargetsProjected.Store(int64(len(queue)))
	return nil
}

// Run publishes on a ticker until ctx is done. A failed publication is LOUD
// (logged + counted) and the loop continues: the prober keeps its previous list
// until the TTL expires, which is the designed degradation.
func (p *Projector) Run(ctx context.Context) {
	if err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
		p.logWarn("the experience work queue could not be published — the prober is running on its previous list until it expires",
			map[string]any{"err": err.Error()})
	}
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
				p.logWarn("the experience work queue could not be published — the prober is running on its previous list until it expires",
					map[string]any{"err": err.Error()})
			}
		}
	}
}
