package bgpdepth

// feed.go — the near-live BGP update feed.
//
// ── Why a poller (the §6 decision, recorded on purpose) ─────────────────────
//
// RIPE's RIS Live is WebSocket-only. A WebSocket client is NOT in the Go
// standard library, and the CLAUDE.md §6 allowlist (pgx, x/crypto ssh,
// x/net ipv4+icmp) does not include one; hand-rolling RFC 6455 framing is
// exactly the class of wire code that rule exists to keep out of this codebase.
// So the producer is a BOUNDED, JITTERED POLLER over the plain-HTTP RIPEstat
// "bgp-updates" data call. The result is near-live (one interval behind), not
// live, and the API says so. Everything downstream — the ring, the cursor, the
// UI — is producer-agnostic: swapping in a vetted stream later touches only
// poller.run.
//
// ── Shape ───────────────────────────────────────────────────────────────────
//
//   - ONE ring per tenant, CONSTANT size (RingSize), overwrite-oldest. Memory
//     is O(tenants × RingSize) and nothing about the upstream can grow it.
//   - ONE poller per tenant, started lazily on the tenant's first read and
//     stopped after PollerIdle without a read. A GLOBAL cap (MaxPollers) means
//     a thousand tenants cannot become a thousand outbound pollers; a tenant
//     over the cap is told so, honestly, instead of being served stale silence.
//   - Backoff with jitter on upstream error, capped; every poll is context-
//     bounded through the Fetcher's own timeout.
//   - Counters for everything an operator would ask about.
//
// The whole subsystem is dormant unless FEATURE_BGP_LIVE_FEED=true.

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// RingSize is the constant per-tenant buffer depth (the item spec's 2 000).
	RingSize = 2000
	// MaxPollers caps concurrent per-tenant pollers process-wide.
	MaxPollers = 8
	// MaxFeedResources caps how many watchlist resources one tenant's poller
	// follows — the outbound call count per interval.
	MaxFeedResources = 12
	// DefaultPollInterval is the base cadence; real jitter is added per poll.
	DefaultPollInterval = 60 * time.Second
	// DefaultPollerIdle stops a poller nobody is reading.
	DefaultPollerIdle = 15 * time.Minute
	// maxBackoff caps the error backoff.
	maxBackoff = 10 * time.Minute
	// feedLookback is the first poll's window.
	feedLookback = 30 * time.Minute
	// maxUpdatesPerPoll bounds what one poll may append per resource.
	maxUpdatesPerPoll = 500
	// FeedPageMax bounds one API page.
	FeedPageMax = 500
)

// ErrFeedDisabled is returned when the feature flag is off.
var ErrFeedDisabled = errors.New("bgpdepth: BGP live feed is not enabled")

// Update is one buffered BGP update, already normalized and bounded.
type Update struct {
	// Seq is the RING's own monotonic cursor — the client's "since" token. It
	// is NOT the upstream sequence number (which is not monotonic per tenant).
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // "A" (announce) | "W" (withdraw)
	Resource string    `json:"resource"`
	Prefix   string    `json:"prefix"`
	Peer     string    `json:"peer"`
	Path     []uint32  `json:"path,omitempty"`
	Origin   uint32    `json:"origin,omitempty"`
}

// ring is a fixed-size overwrite-oldest buffer. Constant memory by construction.
type ring struct {
	mu      sync.Mutex
	buf     [RingSize]Update
	n       int    // entries written (saturates conceptually at seq)
	next    uint64 // next Seq to assign; also the count ever written
	dropped uint64 // entries overwritten before a reader saw them
}

func (r *ring) append(u Update) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == RingSize {
		r.dropped++
	} else {
		r.n++
	}
	u.Seq = r.next
	r.buf[r.next%RingSize] = u
	r.next++
}

// since returns entries with Seq >= from, oldest first, plus the next cursor
// and whether the reader MISSED entries (its cursor fell out of the window).
func (r *ring) since(from uint64, limit int) (out []Update, next uint64, gap bool) {
	if limit <= 0 || limit > FeedPageMax {
		limit = FeedPageMax
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	oldest := uint64(0)
	if r.next > RingSize {
		oldest = r.next - RingSize
	}
	if from < oldest {
		from, gap = oldest, from != 0 || r.dropped > 0
	}
	for s := from; s < r.next && len(out) < limit; s++ {
		out = append(out, r.buf[s%RingSize])
	}
	next = r.next
	if len(out) > 0 {
		next = out[len(out)-1].Seq + 1
	}
	return out, next, gap
}

func (r *ring) stats() (buffered int, written, dropped uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n, r.next, r.dropped
}

// Options configures a Runtime. Zero values take the defaults.
type Options struct {
	Enabled  bool
	Interval time.Duration
	Idle     time.Duration
	Now      func() time.Time
	// Rand supplies jitter. Injectable so tests are deterministic.
	Rand func() float64
	// Log receives structured poller events; nil is silent.
	Log func(msg string, fields map[string]any)
}

// Runtime owns every ring and poller. One per process.
type Runtime struct {
	f        Fetcher
	enabled  bool
	interval time.Duration
	idle     time.Duration
	now      func() time.Time
	rnd      func() float64
	log      func(string, map[string]any)

	mu      sync.Mutex
	rings   map[string]*ring
	pollers map[string]*poller
	slots   int // free poller slots (global cap)

	// counters (§10: every service emits metrics)
	polls      atomic.Int64
	pollErrors atomic.Int64
	buffered   atomic.Int64
	started    atomic.Int64
	capped     atomic.Int64
	stopped    atomic.Int64
}

type poller struct {
	cancel    context.CancelFunc
	lastRead  atomic.Int64 // unix nanos
	resources atomic.Pointer[[]string]
}

// NewRuntime builds the feed runtime. It starts NOTHING; pollers appear on
// demand and only when Enabled.
func NewRuntime(f Fetcher, o Options) *Runtime {
	if o.Interval <= 0 {
		o.Interval = DefaultPollInterval
	}
	if o.Idle <= 0 {
		o.Idle = DefaultPollerIdle
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		// #nosec G404 -- jitter for a polling cadence, not a security decision:
		// this value never authenticates, authorizes, seeds a key or names a
		// resource. crypto/rand here would buy nothing and cost syscalls on
		// every poll (CLAUDE.md §9 asks for jitter, §8 asks for no fake crypto).
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		var mu sync.Mutex
		o.Rand = func() float64 { mu.Lock(); defer mu.Unlock(); return rng.Float64() }
	}
	return &Runtime{
		f: f, enabled: o.Enabled && f != nil,
		interval: o.Interval, idle: o.Idle, now: o.Now, rnd: o.Rand, log: o.Log,
		rings: map[string]*ring{}, pollers: map[string]*poller{}, slots: MaxPollers,
	}
}

// Enabled reports the feature-flag state.
func (rt *Runtime) Enabled() bool { return rt.enabled }

// Metrics is the counter snapshot (§10).
func (rt *Runtime) Metrics() map[string]int64 {
	rt.mu.Lock()
	pollers, rings, slots := len(rt.pollers), len(rt.rings), rt.slots
	rt.mu.Unlock()
	return map[string]int64{
		"polls_total":            rt.polls.Load(),
		"poll_errors_total":      rt.pollErrors.Load(),
		"updates_buffered_total": rt.buffered.Load(),
		"pollers_started_total":  rt.started.Load(),
		"pollers_stopped_total":  rt.stopped.Load(),
		"pollers_capped_total":   rt.capped.Load(),
		"pollers_active":         int64(pollers),
		"poller_slots_free":      int64(slots),
		"rings":                  int64(rings),
	}
}

// FeedStatus is the per-tenant status the API returns alongside a page.
type FeedStatus struct {
	Enabled   bool      `json:"enabled"`
	Polling   bool      `json:"polling"`
	Capped    bool      `json:"capped"`
	Resources []string  `json:"resources"`
	Buffered  int       `json:"buffered"`
	Written   uint64    `json:"written"`
	Dropped   uint64    `json:"dropped"`
	RingSize  int       `json:"ring_size"`
	Interval  string    `json:"interval"`
	Producer  string    `json:"producer"`
	Note      string    `json:"note,omitempty"`
	Now       time.Time `json:"now"`
}

// FeedPage is one read of a tenant's ring.
type FeedPage struct {
	Updates []Update   `json:"updates"`
	Next    uint64     `json:"next"`
	Gap     bool       `json:"gap"`
	Status  FeedStatus `json:"status"`
}

// NormalizeFeedResources bounds and canonicalizes the resource set a tenant's
// poller follows. Input is the tenant's own watchlist — still validated (§3).
func NormalizeFeedResources(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] || len(r) > 64 {
			continue
		}
		seen[r] = true
		out = append(out, r)
		if len(out) >= MaxFeedResources {
			break
		}
	}
	sort.Strings(out)
	return out
}

// Page returns the tenant's buffered updates after `since`, starting or
// refreshing that tenant's poller. tenant MUST already be a concrete tenant.
func (rt *Runtime) Page(ctx context.Context, tenant string, resources []string, since uint64, limit int) (FeedPage, error) {
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	if tenant == "" || tenant == "*" {
		return FeedPage{}, errors.New("bgpdepth: feed requires a concrete tenant")
	}
	res := NormalizeFeedResources(resources)
	st := FeedStatus{
		Enabled: rt.enabled, Resources: res, RingSize: RingSize,
		Interval: rt.interval.String(), Producer: "ripestat-poll", Now: rt.now(),
	}
	if !rt.enabled {
		st.Note = "The near-live feed is off. Set " + EnvFeatureFlag + "=true to enable it."
		return FeedPage{Updates: []Update{}, Status: st}, ErrFeedDisabled
	}
	if len(res) == 0 {
		st.Note = "Add prefixes or ASNs to this tenant's watchlist — the feed follows the watchlist."
		return FeedPage{Updates: []Update{}, Status: st}, nil
	}

	r, capped := rt.ensure(tenant, res)
	st.Capped = capped
	st.Polling = !capped
	if capped {
		st.Note = "The global poller cap is reached; this tenant's feed is not being polled right now."
	}
	if r == nil {
		return FeedPage{Updates: []Update{}, Status: st}, nil
	}
	ups, next, gap := r.since(since, limit)
	buffered, written, dropped := r.stats()
	st.Buffered, st.Written, st.Dropped = buffered, written, dropped
	if ups == nil {
		ups = []Update{}
	}
	return FeedPage{Updates: ups, Next: next, Gap: gap, Status: st}, nil
}

// ensure starts or refreshes the tenant's poller. Returns the ring and whether
// the global cap prevented polling.
func (rt *Runtime) ensure(tenant string, res []string) (*ring, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	r := rt.rings[tenant]
	if r == nil {
		r = &ring{}
		rt.rings[tenant] = r
	}
	if p := rt.pollers[tenant]; p != nil {
		p.lastRead.Store(rt.now().UnixNano())
		cp := append([]string(nil), res...)
		p.resources.Store(&cp)
		return r, false
	}
	if rt.slots <= 0 {
		rt.capped.Add(1)
		return r, true
	}
	rt.slots--
	ctx, cancel := context.WithCancel(context.Background())
	p := &poller{cancel: cancel}
	p.lastRead.Store(rt.now().UnixNano())
	cp := append([]string(nil), res...)
	p.resources.Store(&cp)
	rt.pollers[tenant] = p
	rt.started.Add(1)
	go rt.run(ctx, tenant, p, r)
	return r, false
}

// jitter returns d scaled into [0.75d, 1.25d).
func (rt *Runtime) jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.75 + 0.5*rt.rnd()))
}

// run is the poll loop for ONE tenant.
func (rt *Runtime) run(ctx context.Context, tenant string, p *poller, r *ring) {
	defer func() {
		rt.mu.Lock()
		if rt.pollers[tenant] == p {
			delete(rt.pollers, tenant)
			rt.slots++
		}
		rt.mu.Unlock()
		rt.stopped.Add(1)
	}()
	cursor := map[string]time.Time{}
	backoff := time.Duration(0)
	for {
		wait := rt.jitter(rt.interval)
		if backoff > 0 {
			wait = rt.jitter(backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if rt.now().Sub(time.Unix(0, p.lastRead.Load())) > rt.idle {
			if rt.log != nil {
				rt.log("bgp feed poller idle — stopping", map[string]any{"tenant": tenant})
			}
			return
		}
		resPtr := p.resources.Load()
		if resPtr == nil {
			continue
		}
		failed := false
		for _, res := range *resPtr {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rt.polls.Add(1)
			n, err := rt.pollOne(ctx, res, cursor, r)
			if err != nil {
				failed = true
				rt.pollErrors.Add(1)
				if rt.log != nil {
					rt.log("bgp feed poll failed", map[string]any{"tenant": tenant, "resource": res, "err": err.Error()})
				}
				continue
			}
			rt.buffered.Add(int64(n))
		}
		if failed {
			if backoff == 0 {
				backoff = rt.interval
			} else if backoff < maxBackoff {
				backoff *= 2
			}
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = 0
		}
	}
}

// pollOne fetches one resource's updates since the cursor and appends the new
// ones. Returns how many entries were appended.
func (rt *Runtime) pollOne(ctx context.Context, resource string, cursor map[string]time.Time, r *ring) (int, error) {
	from, ok := cursor[resource]
	if !ok {
		from = rt.now().UTC().Add(-feedLookback)
	}
	extra := "starttime=" + urlEscape(from.UTC().Format("2006-01-02T15:04:05"))
	// TTL 0: the feed must not be served a cached window, or it would stall.
	data, err := rt.f.RIPEstat(ctx, "bgp-updates", resource, extra, 0)
	if err != nil {
		return 0, err
	}
	ups, newest := ParseBGPUpdates(data, resource, from, maxUpdatesPerPoll)
	for _, u := range ups {
		r.append(u)
	}
	if newest.After(from) {
		cursor[resource] = newest
	}
	return len(ups), nil
}

// ParseBGPUpdates normalizes a RIPEstat bgp-updates payload into ring entries
// strictly newer than `after`, bounded to `limit`. Verified shape (2026-09-02):
//
//	data.updates[] = {"seq":…, "timestamp":"2026-08-31T14:07:34", "type":"A",
//	                  "attrs":{"source_id":"15-187.16.222.156",
//	                           "target_prefix":"193.0.0.0/21","path":[…]}}
func ParseBGPUpdates(data json.RawMessage, resource string, after time.Time, limit int) ([]Update, time.Time) {
	var body struct {
		Updates []struct {
			Timestamp string `json:"timestamp"`
			Type      string `json:"type"`
			Attrs     struct {
				SourceID     string            `json:"source_id"`
				TargetPrefix string            `json:"target_prefix"`
				Path         []json.RawMessage `json:"path"`
			} `json:"attrs"`
		} `json:"updates"`
	}
	if json.Unmarshal(data, &body) != nil {
		return nil, after
	}
	newest := after
	out := make([]Update, 0, min(len(body.Updates), limit))
	for _, e := range body.Updates {
		if len(out) >= limit {
			break
		}
		ts, err := time.Parse("2006-01-02T15:04:05", strings.TrimSpace(e.Timestamp))
		if err != nil {
			continue
		}
		ts = ts.UTC()
		if !ts.After(after) {
			continue // already buffered on an earlier poll
		}
		typ := strings.ToUpper(clip(strings.TrimSpace(e.Type), 1))
		if typ != "A" && typ != "W" {
			continue
		}
		u := Update{
			Time: ts, Type: typ, Resource: clip(resource, 64),
			Prefix: clip(strings.TrimSpace(e.Attrs.TargetPrefix), 64),
			Peer:   clip(strings.TrimSpace(e.Attrs.SourceID), 48),
		}
		for _, n := range e.Attrs.Path {
			if len(u.Path) >= maxPathLen {
				break
			}
			v, ok := ParseASNValue(n)
			if !ok {
				continue // conservative: drop the hop, never guess it
			}
			u.Path = append(u.Path, v)
		}
		u.Path = CompressPath(u.Path)
		if len(u.Path) > 0 {
			u.Origin = u.Path[len(u.Path)-1]
		}
		out = append(out, u)
		if ts.After(newest) {
			newest = ts
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, newest
}

// Stop cancels every poller. Called on shutdown.
func (rt *Runtime) Stop() {
	rt.mu.Lock()
	ps := make([]*poller, 0, len(rt.pollers))
	for _, p := range rt.pollers {
		ps = append(ps, p)
	}
	rt.mu.Unlock()
	for _, p := range ps {
		p.cancel()
	}
}
