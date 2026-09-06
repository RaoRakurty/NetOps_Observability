// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// dem.go — the Digital Experience runner: the prober-side half of the DEM
// feature (docs/design/DEM_PLUMBING_2026-09-05.md).
//
// WHAT IS NEW HERE, AND WHAT IS NOT
// The existing `synthetics` collector already knows how to make an HTTP, TCP or
// ICMP measurement well; this file does NOT reimplement any of that — it reuses
// those exact check functions. What it adds is the three things the env-driven
// synthetics collector structurally cannot do:
//
//	1. TARGETS FROM THE CATALOGUE, NOT FROM ENV. The api publishes the fleet's
//	   work queue (dem.WireTarget) to the shared key-value channel with a short
//	   TTL, exactly as the WAN circuit projector does. That is what makes the
//	   catalogue per-tenant: an env list has no owner, so its results could never
//	   be scoped to anyone.
//	2. TENANT-LABELLED SERIES. Every sample carries tenant/target/kind/site/app
//	   and a `source` label. The legacy synthetic_*/probe_* series carry only
//	   dst+check, which is why a scoped tenant can see none of them; the dem_*
//	   series are the fix, and the API filters on the tenant label directly.
//	3. PER-TARGET SCHEDULING and a DNS check kind, which the env collector has
//	   no place to express.
//
// Zero trust / reliability (§3, §9): the work queue is UNTRUSTED input even
// though we published it — it round-trips through a shared datastore, so every
// entry is re-validated here. Every check is bounded (per-check timeout, capped
// body, bounded concurrency, no in-tick retry — the next tick is the retry).
// TLS verification is never disabled; a bad certificate is a failed check, which
// is the signal (the lab's re-signing SASE proxy is exactly why the system trust
// store, not an exception, is the right answer).

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/dem"
	"netops/backend/safego"
)

const (
	// demTick is the scheduler's resolution. Targets declare their own interval
	// (15s..1h); this is how often we ask "which of them are due".
	demTick = 15 * time.Second
	// demConcurrency bounds parallel checks. The prober is a 128 MiB container
	// and every check holds a socket.
	demConcurrency = 8
	// demDefaultTimeout bounds one check.
	demDefaultTimeout = 10 * time.Second
	// demPathMaxAge is how recent a traceroute must be to count as this
	// window's path observation. Older than this and path stability is NOT
	// MEASURED — never "stable".
	demPathMaxAge = 30 * time.Minute
	// demSourceSynthetic is the measurement source this collector produces.
	// Declared here (rather than taken from a target) because a synthetic
	// prober can only ever produce synthetic evidence.
	demSourceSynthetic = dem.SourceSynthetic
	// demRunBuffer bounds the rolling per-RUN record buffer this prober
	// republishes each tick (tracker 253). It is sized so the api's 30 s drain
	// always overlaps the previous publication — a run is never visible for
	// less than one drain — while staying a fixed, small allocation on a
	// 128 MiB container. At the 15 s tick and the default 60 s target interval
	// it covers roughly the last hour across 500 targets' worth of checks.
	demRunBuffer = 2000
)

// demTargetFetcher is the work-queue seam. Overridden in tests; in production
// it reads the list the api published.
type demTargetFetcher func(ctx context.Context) ([]dem.WireTarget, error)

// demResolver is the DNS seam so the dns check is testable without a resolver.
type demResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type demRunner struct {
	timeout time.Duration
	fetch   demTargetFetcher
	// checks reuses the synthetics collector's measurement functions verbatim.
	checks *synthetics
	// resolver is used for the `dns` kind; nil means the system resolver.
	resolver demResolver

	// publishRuns is the run-record channel seam. Overridden in tests; in
	// production it writes this prober's rolling buffer to the shared
	// key-value channel.
	publishRuns func(ctx context.Context, runs []dem.WireRun) error

	mu      sync.RWMutex
	status  Status
	lastRun map[string]time.Time
	// runs is the rolling per-RUN record buffer, oldest first. Bounded by
	// demRunBuffer: the OLDEST records are dropped, which is the right end —
	// reliability is a question about the recent past.
	runs []dem.WireRun
}

// NewDEM builds the Digital Experience runner. It is registered in the pool and
// enabled by FEATURE_DEM; with no published work queue it measures nothing and
// says so (0 targets), which is a different status from "unhealthy".
func NewDEM() Collector {
	return &demRunner{
		timeout:     envDuration("DEM_TIMEOUT", demDefaultTimeout),
		fetch:       fetchDEMWork,
		publishRuns: PublishDEMRuns,
		checks:      &synthetics{timeout: envDuration("DEM_TIMEOUT", demDefaultTimeout)},
		status:      Status{Name: "dem", Healthy: true, Kind: "metrics"},
		lastRun:     map[string]time.Time{},
	}
}

func (d *demRunner) Name() string { return "dem" }

func (d *demRunner) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.status
}

func (d *demRunner) Run(ctx context.Context) error {
	t := time.NewTicker(demTick)
	defer t.Stop()
	d.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			d.tick(ctx)
		}
	}
}

// fetchDEMWork reads the api-published work queue. An absent key is an empty
// queue (not an error): the api may simply not have published yet.
func fetchDEMWork(ctx context.Context) ([]dem.WireTarget, error) {
	return FetchDEMTargets(ctx)
}

// due reports whether a target's interval has elapsed since its last run.
func (d *demRunner) due(id string, interval time.Duration, now time.Time) bool {
	d.mu.RLock()
	last, seen := d.lastRun[id]
	d.mu.RUnlock()
	if !seen {
		return true
	}
	// Half a tick of slack: a 60s interval on a 15s scheduler must fire every
	// fourth tick, not every fifth because it missed by a millisecond.
	return now.Sub(last) >= interval-demTick/2
}

// sanitizeWork re-validates the queue. It is UNTRUSTED input: it round-tripped
// through a shared datastore, so a malformed or unowned entry must be dropped
// rather than measured and attributed to someone.
func sanitizeWork(in []dem.WireTarget) []dem.WireTarget {
	out := make([]dem.WireTarget, 0, len(in))
	for _, t := range in {
		if t.ID == "" || t.Tenant == "" || t.Host == "" || !dem.ValidKind(t.Kind) {
			continue
		}
		if t.IntervalSec <= 0 {
			t.IntervalSec = dem.DefaultIntervalSec
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// demOutcome is one target's measurement for this cycle.
type demOutcome struct {
	target  dem.WireTarget
	ran     bool
	res     synResult
	pathFP  uint32
	pathHas bool
	hops    int
}

func (d *demRunner) tick(ctx context.Context) {
	work, err := d.fetch(ctx)
	if err != nil {
		// A queue we cannot read is NOT an empty queue. Say so and keep the
		// previous status rather than reporting 0 healthy targets.
		d.mu.Lock()
		d.status.LastTick = time.Now().UTC()
		d.status.Healthy = false
		d.status.LastError = "the experience work queue could not be read: " + err.Error()
		d.mu.Unlock()
		return
	}
	work = sanitizeWork(work)
	now := time.Now().UTC()

	var dueList []dem.WireTarget
	for _, t := range work {
		if d.due(t.ID, time.Duration(t.IntervalSec)*time.Second, now) {
			dueList = append(dueList, t)
		}
	}

	outcomes := make([]demOutcome, len(dueList))
	sem := make(chan struct{}, demConcurrency)
	var wg sync.WaitGroup
	for i, tgt := range dueList {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tgt dem.WireTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			// safego (H3): a worker talking to an arbitrary remote endpoint. A
			// panic must cost that check's cycle (it reports as down), never
			// the process.
			if !safego.Run(safego.Stderr, "dem-check", func() {
				cctx, cancel := context.WithTimeout(ctx, d.timeout)
				defer cancel()
				outcomes[i] = d.runOne(cctx, tgt)
			}) {
				outcomes[i] = demOutcome{target: tgt, ran: true,
					res: synResult{failClass: "unknown"}}
			}
		}(i, tgt)
	}
	wg.Wait()

	d.publish(ctx, work, outcomes, now)
}

// runOne performs one target's check and looks up its current path.
func (d *demRunner) runOne(ctx context.Context, t dem.WireTarget) demOutcome {
	out := demOutcome{target: t, ran: true}
	st := synTarget{check: t.Kind, dst: demDestination(t)}
	switch t.Kind {
	case dem.KindHTTP:
		out.res = d.checks.checkHTTP(ctx, st)
		// A DECLARED expected status overrides the default 2xx/3xx verdict: an
		// endpoint whose health check legitimately answers 401 or 503 is not
		// "down" if the operator said that is what it should answer.
		if t.ExpectStatus != 0 {
			out.res.up = out.res.statusCode == t.ExpectStatus
			if !out.res.up && out.res.statusCode != 0 {
				out.res.failClass = "status"
			}
		}
	case dem.KindTCP:
		out.res = d.checks.checkTCP(ctx, st)
	case dem.KindICMP:
		out.res = d.checks.checkICMP(ctx, st)
	case dem.KindDNS:
		out.res = d.checkDNS(ctx, t)
	default:
		// Unreachable: sanitizeWork already refused unknown kinds. Fail closed
		// rather than reporting an unmeasured target as reachable.
		out.res = synResult{failClass: "unknown"}
	}
	out.pathFP, out.hops, out.pathHas = observedPath(demPathHost(t), time.Now().UTC())
	return out
}

// demDestination renders the check destination in the shape each reused check
// function expects.
func demDestination(t dem.WireTarget) string {
	switch t.Kind {
	case dem.KindTCP:
		if t.Port > 0 {
			return net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
		}
		return t.Host
	default:
		return t.Host
	}
}

// demPathHost is the bare host a traceroute would have been run against, so a
// path measured by the traceroute collector can be matched to this target.
func demPathHost(t dem.WireTarget) string {
	h := t.Host
	if t.Kind == dem.KindHTTP {
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}

// ── DNS ──────────────────────────────────────────────────────────────────────

// checkDNS measures name resolution: the phase every other check depends on and
// the one operators most often discover only by its symptoms.
//
// It measures the RESOLVER, not the name's owner: an NXDOMAIN is a failed check
// because a name the operator declared should resolve, and a resolver that
// answers "no such name" for it is a real experience failure.
func (d *demRunner) checkDNS(ctx context.Context, t dem.WireTarget) synResult {
	name := strings.TrimSuffix(strings.TrimSpace(t.Host), ".")
	res := synResult{target: synTarget{check: dem.KindDNS, dst: name}}
	r := d.resolver
	if r == nil {
		r = demSystemResolver(t.Resolver, d.timeout)
	}
	start := time.Now()
	addrs, err := r.LookupHost(ctx, name)
	ms := float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		res.failClass = classifyDNSErr(err)
		res.dnsMs, res.totalMs = ms, ms
		return res
	}
	if len(addrs) == 0 {
		// A resolver that answers with no addresses has not resolved the name.
		res.failClass = "no_answer"
		res.dnsMs, res.totalMs = ms, ms
		return res
	}
	res.up = true
	res.rttMs, res.dnsMs, res.totalMs = ms, ms, ms
	return res
}

// classifyDNSErr maps a resolution failure to the ProbeEvent.FailClass
// vocabulary the correlation side already understands.
func classifyDNSErr(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "nxdomain"
		case dnsErr.IsTimeout:
			return "timeout"
		}
		return "dns"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "dns"
}

// demSystemResolver returns the system resolver, or one pinned to the target's
// declared server. Pinning is what makes "our resolver is slow" separable from
// "the internet is slow".
func demSystemResolver(server string, timeout time.Duration) demResolver {
	server = strings.TrimSpace(server)
	if server == "" {
		return net.DefaultResolver
	}
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dl := net.Dialer{Timeout: timeout}
			return dl.DialContext(ctx, network, addr)
		},
	}
}

// ── path observation ─────────────────────────────────────────────────────────

// observedPath fingerprints the most recent traceroute to host, if one is fresh
// enough to be this window's path observation.
//
// Absent or stale ⇒ (0, 0, false), which the score renders as "path stability
// not measured". It must never render as "stable": we did not look.
func observedPath(host string, now time.Time) (fp uint32, hops int, ok bool) {
	if host == "" {
		return 0, 0, false
	}
	var best PathResult
	for _, p := range Paths.All() {
		if p.Dst != host {
			continue
		}
		if p.TS.After(best.TS) {
			best = p
		}
	}
	if best.Dst == "" || now.Sub(best.TS) > demPathMaxAge {
		return 0, 0, false
	}
	h := fnv.New32a()
	for _, hop := range best.Hops {
		_, _ = h.Write([]byte(hop.IP)) // hash.Hash.Write never returns an error
		_, _ = h.Write([]byte{0})
	}
	return h.Sum32(), len(best.Hops), true
}

// ── publication ──────────────────────────────────────────────────────────────

// publish turns this cycle's outcomes into VictoriaMetrics samples and bus
// events, and updates the collector's own honest status.
func (d *demRunner) publish(ctx context.Context, work []dem.WireTarget, outcomes []demOutcome, now time.Time) {
	nowMs := now.UnixMilli()
	ts := now.Format(time.RFC3339Nano)
	prober := proberID()
	decl := loadProberDeclaration()

	var lines []string
	var events []ProbeEvent
	var runs []dem.WireRun
	ran, up := 0, 0

	for _, o := range outcomes {
		if !o.ran || o.target.ID == "" {
			continue
		}
		ran++
		if o.res.up {
			up++
		}
		t := o.target
		lb := demLabels(t)
		loss := o.res.lossPct
		if !o.res.up && loss == 0 {
			loss = 100 // the check failed outright: full loss for this observation
		}
		lines = append(lines,
			fmt.Sprintf(`%s{%s} %d %d`, dem.MetricSuccess, lb, b2i(o.res.up), nowMs),
			fmt.Sprintf(`%s{%s} %.2f %d`, dem.MetricLossPct, lb, loss, nowMs),
		)
		// Latency is emitted ONLY when a timing was actually observed. A failed
		// check has no latency, and emitting 0 would drag every percentile down
		// with a number nothing measured.
		if o.res.up && o.res.rttMs > 0 {
			lines = append(lines, fmt.Sprintf(`%s{%s} %.3f %d`, dem.MetricLatencyMs, lb, o.res.rttMs, nowMs))
		}
		if o.res.ttfbMs > 0 {
			lines = append(lines, fmt.Sprintf(`%s{%s} %.3f %d`, dem.MetricTTFBMs, lb, o.res.ttfbMs, nowMs))
		}
		if o.pathHas {
			lines = append(lines,
				fmt.Sprintf(`%s{%s} %d %d`, dem.MetricPathFingerprint, lb, o.pathFP, nowMs),
				fmt.Sprintf(`%s{%s} %d %d`, dem.MetricPathHops, lb, o.hops, nowMs),
			)
		}
		// The budget gauges ride beside the measurement so the experience alert
		// rules are a pure PromQL comparison — and therefore keep firing while
		// the api, which owns the catalogue, is the thing that is down.
		if t.AvailBudgetPct > 0 {
			lines = append(lines, fmt.Sprintf(`%s{%s} %.3f %d`, dem.MetricAvailBudgetPct, lb, t.AvailBudgetPct, nowMs))
		}
		if t.LatencyBudgetMs > 0 {
			lines = append(lines, fmt.Sprintf(`%s{%s} %.3f %d`, dem.MetricLatencyBudgetMs, lb, t.LatencyBudgetMs, nowMs))
		}
		events = append(events, demEvent(t, o, prober, decl, ts, loss))
		runs = append(runs, demRun(t, o, prober, now))
		d.mu.Lock()
		d.lastRun[t.ID] = now
		d.mu.Unlock()
	}

	// The declared-target census, per tenant. It is what lets the page tell
	// "this tenant declared nothing" apart from "the prober is not reporting" —
	// two very different answers that both render as an empty table.
	for tenant, n := range demCensus(work) {
		lines = append(lines, fmt.Sprintf(`%s{tenant=%q,source=%q} %d %d`,
			dem.MetricTargets, tenant, demSourceSynthetic, n, nowMs))
	}
	// The collector's own liveness. The probe collectors historically emitted
	// none, which is why "the prober is not running" was invisible to every
	// rule (docs/runbooks/engine-liveness-matrix.md).
	lines = append(lines, collectorUpLine("dem", true, nowMs))

	if len(lines) > 0 {
		emitMetrics(ctx, strings.Join(lines, "\n"))
	}
	forwardProbeEvents(ctx, events)
	d.publishRunRecords(ctx, runs)

	d.mu.Lock()
	d.status.LastTick = now
	d.status.Targets = len(work)
	d.status.Reachable = up
	if ran == 0 {
		// Nothing was DUE this tick. That is normal scheduling, not a fault —
		// the last cycle's verdict stands.
		d.status.Healthy = true
		d.status.LastError = ""
	} else {
		d.status.Healthy = cycleHealthy(ran, up)
		d.status.LastError = cycleError(ran, up, "")
	}
	d.mu.Unlock()
}

// publishRunRecords appends this cycle's immutable run records to the rolling
// buffer and republishes the whole buffer.
//
// The WHOLE buffer, not the delta: the channel is a TTL'd key, not a queue, so
// a republication is how a record stays visible across the api's next drain.
// The api dedupes by run id, so re-publishing costs nothing but bytes.
//
// A failed publication is counted and reported by the shared publish path; it
// is NEVER fatal to the cycle — the measurements and their series have already
// been emitted, and losing a reliability sample must not cost a measurement.
func (d *demRunner) publishRunRecords(ctx context.Context, fresh []dem.WireRun) {
	d.mu.Lock()
	if len(fresh) > 0 {
		d.runs = append(d.runs, fresh...)
		if len(d.runs) > demRunBuffer {
			d.runs = append([]dem.WireRun(nil), d.runs[len(d.runs)-demRunBuffer:]...)
		}
	}
	buf := append([]dem.WireRun(nil), d.runs...)
	d.mu.Unlock()
	if len(buf) == 0 || d.publishRuns == nil {
		return
	}
	if err := d.publishRuns(ctx, buf); err != nil && ctx.Err() == nil {
		// §16.1/§10: never swallowed. Without run records every check grades
		// `unknown`, and an ungraded check is one the incident detector will
		// not let raise a high-severity incident — a silent loss of severity.
		log.Printf("dem: the per-run records could not be published; check reliability will read as ungraded: %v", err)
	}
}

// demRun shapes one immutable per-RUN record for the reliability grader.
//
// It carries an OUTCOME, not a score: `error` means this prober's own machinery
// failed, and grading that as a target failure is exactly the confusion the
// reliability model exists to prevent. Today's runner never retries in-tick
// (the next tick is the retry), so Retries is 0 and honestly so.
func demRun(t dem.WireTarget, o demOutcome, prober string, now time.Time) dem.WireRun {
	r := dem.WireRun{
		ID:         newExecutionID(),
		Tenant:     t.Tenant,
		TargetID:   t.ID,
		Kind:       t.Kind,
		Vantage:    prober,
		StartedAt:  now,
		EndedAt:    now,
		Outcome:    dem.RunFailure,
		FailReason: o.res.failClass,
		DurationMs: o.res.totalMs,
		TTFBMs:     o.res.ttfbMs,
		StatusCode: o.res.statusCode,
	}
	switch {
	case o.res.up:
		r.Outcome, r.FailReason = dem.RunSuccess, ""
	case o.res.failClass == "unknown":
		// The check function itself could not produce a verdict (a panic caught
		// by safego, or an unreachable kind). That is a RUNNER fault.
		r.Outcome = dem.RunError
	case o.res.failClass == "" && o.res.statusCode > 0:
		// The request completed and the SERVER answered something the operator
		// did not want. The transport classes leave failClass empty for that
		// case; naming it here keeps "the service answered 500" separable from
		// "we never reached the service", which is the difference between an
		// application fault and a path fault.
		r.FailReason = "status"
	}
	if r.DurationMs == 0 && o.res.rttMs > 0 {
		r.DurationMs = o.res.rttMs
	}
	return r
}

// demLabels renders the series labels. Every value is %q-quoted, so no label
// value can terminate the label set and forge another.
func demLabels(t dem.WireTarget) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "tenant=%q,target=%q,kind=%q", t.Tenant, t.ID, t.Kind)
	if t.Site != "" {
		fmt.Fprintf(b, ",site=%q", t.Site)
	}
	if t.App != "" {
		fmt.Fprintf(b, ",app=%q", t.App)
	}
	fmt.Fprintf(b, ",source=%q", demSourceSynthetic)
	return b.String()
}

// demCensus counts declared targets per tenant.
func demCensus(work []dem.WireTarget) map[string]int {
	out := map[string]int{}
	for _, t := range work {
		if t.Tenant != "" {
			out[t.Tenant]++
		}
	}
	return out
}

// demEvent shapes one bus event. The DEM additions (tenant, target_id, source,
// app) are ADDITIVE and omitempty, so the existing probe-lane contract — and
// every correlation-side consumer reading it — is unchanged.
func demEvent(t dem.WireTarget, o demOutcome, prober string, decl proberDeclaration, ts string, loss float64) ProbeEvent {
	return ProbeEvent{
		Kind: t.Kind, Prober: prober, Target: demDestination(t),
		OK: o.res.up, RTTms: o.res.rttMs, LossPct: loss, TS: ts,
		SiteID: t.Site, FailClass: o.res.failClass, StatusCode: o.res.statusCode,
		Method: o.res.method, Path: o.res.path,
		DNSMs: o.res.dnsMs, TCPConnectMs: o.res.connectMs, TLSMs: o.res.tlsMs,
		TTFBMs: o.res.ttfbMs, TotalMs: o.res.totalMs,
		CertDaysToExpiry: o.res.certDays, CertSubject: o.res.certSubject, CertIssuer: o.res.certIssuer,
		ExecutionID: newExecutionID(),
		// The recurring test's stable identity is now the CATALOGUE id, which
		// survives a rename of the host and cannot collide across tenants.
		ScheduleID:  t.ID,
		ProbeIntent: decl.Intent, VantageType: decl.Vantage,
		Environment: decl.Environment, SignalPurpose: decl.Purpose,
		Tenant: t.Tenant, TargetID: t.ID, AppID: t.App, Source: demSourceSynthetic,
	}
}

// demHTTPTransport is the test seam for the reused HTTP check.
func (d *demRunner) setTransport(rt http.RoundTripper) { d.checks.transport = rt }
