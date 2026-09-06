package storagemeter

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Meter runs the store probes and caches the platform-wide result.
//
// TWO READ PATHS, ONE PROBER. The /metrics scrape and the background sampler
// read the CACHE; the HTTP surface probes LIVE for the caller's own scope. That
// split is deliberate and is the dataprotect lesson applied here: a Prometheus
// scrape must never block on `system.parts` or `_cat/indices`, and an operator
// asking the page for their tenant's bytes must not be served a number that is
// up to a sampling interval old without being told.
type Meter struct {
	deps Deps

	mu       sync.RWMutex
	cached   []Reading
	sampleAt time.Time
	// samples counts completed sampler passes, so a never-sampled meter is
	// distinguishable from one whose last pass measured nothing.
	samples int64
}

// New builds a Meter. A zero-value Deps yields a Meter that measures nothing
// and says so on every store — never a crash and never a zero.
func New(d Deps) *Meter { return &Meter{deps: d} }

// Probe measures every store for one principal, LIVE. Each store gets its own
// bounded context so a slow ClickHouse cannot consume the OpenSearch budget,
// and the probes run concurrently because they are independent reads.
func (m *Meter) Probe(ctx context.Context, p Principal) []Reading {
	if m == nil {
		return nil
	}
	type probe struct {
		store Store
		run   func(context.Context, Principal) []Reading
	}
	probes := []probe{
		{StoreOpenSearch, m.probeOpenSearch},
		{StoreClickHouse, m.probeClickHouse},
		{StoreVictoria, m.probeVictoria},
		{StorePostgres, m.probePostgres},
		{StoreFiles, m.probeFiles},
		{StoreKafka, m.probeKafka},
	}
	out := make([][]Reading, len(probes))
	var wg sync.WaitGroup
	for i, pr := range probes {
		wg.Add(1)
		go func(i int, pr probe) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, m.deps.probeTimeout())
			defer cancel()
			out[i] = pr.run(pctx, p)
		}(i, pr)
	}
	wg.Wait()
	all := make([]Reading, 0, len(probes))
	for _, rs := range out {
		all = append(all, rs...)
	}
	sortReadings(all)
	return all
}

// Sample runs one platform-scoped pass and replaces the cache. Called by the
// background worker and, once, at boot — so the first scrape after start-up
// carries real readings rather than an empty series set.
func (m *Meter) Sample(ctx context.Context) {
	if m == nil {
		return
	}
	readings := m.Probe(ctx, Principal{Subject: "sampler", CrossTenant: true})
	now := m.deps.now()
	m.mu.Lock()
	m.cached = readings
	m.sampleAt = now
	m.samples++
	m.mu.Unlock()
	measured, total := 0, 0
	for _, r := range readings {
		total++
		if r.Measured() {
			measured++
		}
	}
	m.deps.logf("storage measurement sampled", "readings", total, "measured", measured)
}

// RunSampler is the background worker. It samples once immediately, then on the
// configured cadence, and returns when ctx is done. Nothing here retries: the
// next tick IS the retry, and a failed probe is already a visible "not
// measured" rather than a silence.
func (m *Meter) RunSampler(ctx context.Context) {
	if m == nil {
		return
	}
	m.Sample(ctx)
	t := time.NewTicker(m.deps.sampleEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sample(ctx)
		}
	}
}

// Snapshot returns the cached platform readings and when they were taken.
// sampled is the zero time when no pass has completed — which the caller MUST
// render as "never sampled", not as "now".
func (m *Meter) Snapshot() (readings []Reading, sampled time.Time, passes int64) {
	if m == nil {
		return nil, time.Time{}, 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Reading, len(m.cached))
	copy(out, m.cached)
	return out, m.sampleAt, m.samples
}

// sortReadings orders readings deterministically: store in the declared order,
// then platform first, then scope alphabetically. Deterministic output is what
// makes the wire contract diffable and the tests non-flaky.
func sortReadings(rs []Reading) {
	rank := map[Store]int{}
	for i, s := range Stores {
		rank[s] = i
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Store != rs[j].Store {
			return rank[rs[i].Store] < rank[rs[j].Store]
		}
		if (rs[i].Scope == ScopePlatform) != (rs[j].Scope == ScopePlatform) {
			return rs[i].Scope == ScopePlatform
		}
		return rs[i].Scope < rs[j].Scope
	})
}
