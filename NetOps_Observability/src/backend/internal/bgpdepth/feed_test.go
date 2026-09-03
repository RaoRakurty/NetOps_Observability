package bgpdepth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// realUpdates is the verbatim shape of RIPEstat's bgp-updates data call
// (captured 2026-09-02 for 193.0.0.0/21).
const realUpdates = `{"resource":"193.0.0.0/21","updates":[
 {"seq":506308772364294,"timestamp":"2026-08-31T14:07:34","type":"A","attrs":{"source_id":"15-187.16.222.156","target_prefix":"193.0.0.0/21","path":[264479,20562,1103,1103,3333],"community":[]}},
 {"seq":316014865743882,"timestamp":"2026-08-31T16:03:24","type":"W","attrs":{"source_id":"10-217.29.67.54","target_prefix":"193.0.0.0/21"}},
 {"seq":316017778622466,"timestamp":"2026-08-31T16:03:50","type":"A","attrs":{"source_id":"10-217.29.67.54","target_prefix":"193.0.0.0/21","path":[20912,9002,3333],"community":[]}}]}`

func TestParseBGPUpdatesNormalizesTheRealPayload(t *testing.T) {
	parsed := ParseBGPUpdates(json.RawMessage(realUpdates), "193.0.0.0/21", time.Time{}, 100)
	ups, newest := parsed.Updates, parsed.Cursor
	if len(ups) != 3 {
		t.Fatalf("got %d updates", len(ups))
	}
	if ups[0].Type != "A" || ups[0].Prefix != "193.0.0.0/21" || ups[0].Peer != "15-187.16.222.156" {
		t.Fatalf("update 0 = %+v", ups[0])
	}
	// 1103 is prepended upstream; the ring stores the compressed path.
	if len(ups[0].Path) != 4 || ups[0].Origin != 3333 {
		t.Fatalf("path/origin = %v / %d", ups[0].Path, ups[0].Origin)
	}
	if ups[1].Type != "W" || len(ups[1].Path) != 0 || ups[1].Origin != 0 {
		t.Fatalf("a withdrawal must carry no path: %+v", ups[1])
	}
	if !newest.Equal(time.Date(2026, 8, 31, 16, 3, 50, 0, time.UTC)) {
		t.Fatalf("newest = %v", newest)
	}
	if !parsed.UpstreamNewest.Equal(time.Date(2026, 8, 31, 16, 3, 50, 0, time.UTC)) {
		t.Fatalf("upstream newest = %v", parsed.UpstreamNewest)
	}
	// Chronological order is the ring's contract.
	for i := 1; i < len(ups); i++ {
		if ups[i].Time.Before(ups[i-1].Time) {
			t.Fatal("updates are not chronological")
		}
	}
}

// The cursor is what stops a poll re-buffering the window it already saw.
func TestParseBGPUpdatesSkipsWhatTheCursorAlreadyCovered(t *testing.T) {
	after := time.Date(2026, 8, 31, 16, 3, 24, 0, time.UTC)
	parsed := ParseBGPUpdates(json.RawMessage(realUpdates), "193.0.0.0/21", after, 100)
	if len(parsed.Updates) != 1 || parsed.Updates[0].Type != "A" {
		t.Fatalf("re-buffered old updates: %+v", parsed.Updates)
	}
	// The cursor filter must NOT blind the upstream-age measurement: the
	// skipped records still prove how current the archive is. This is the
	// 2026-09-03 dead-feed lesson in one assertion.
	if !parsed.UpstreamNewest.Equal(time.Date(2026, 8, 31, 16, 3, 50, 0, time.UTC)) {
		t.Fatalf("the cursor filter swallowed the upstream age: %v", parsed.UpstreamNewest)
	}
}

// The case that was live on 2026-09-03: EVERY record is older than the window,
// so nothing is buffered — and the parser must still report how far behind the
// archive is, or the caller has nothing to explain the silence with.
func TestParseBGPUpdatesReportsUpstreamAgeWhenEverythingIsStale(t *testing.T) {
	after := time.Date(2026, 9, 3, 5, 17, 0, 0, time.UTC) // long past every record
	parsed := ParseBGPUpdates(json.RawMessage(realUpdates), "193.0.0.0/21", after, 100)
	if len(parsed.Updates) != 0 {
		t.Fatalf("stale records were buffered: %+v", parsed.Updates)
	}
	if !parsed.Cursor.Equal(after) {
		t.Fatalf("cursor moved on a payload that contributed nothing: %v", parsed.Cursor)
	}
	if !parsed.UpstreamNewest.Equal(time.Date(2026, 8, 31, 16, 3, 50, 0, time.UTC)) {
		t.Fatalf("upstream age unknown on the poll that most needed it: %v", parsed.UpstreamNewest)
	}
}

func TestParseBGPUpdatesIsBoundedAndDropsGarbage(t *testing.T) {
	ups := ParseBGPUpdates(json.RawMessage(realUpdates), "x", time.Time{}, 1).Updates
	if len(ups) != 1 {
		t.Fatalf("limit ignored: %d", len(ups))
	}
	bad := `{"updates":[{"timestamp":"not-a-time","type":"A","attrs":{}},{"timestamp":"2026-08-31T14:07:34","type":"X","attrs":{}},{"timestamp":"2026-08-31T14:07:34","type":"A","attrs":{"path":[0,-5,"x",3333]}}]}`
	ups = ParseBGPUpdates(json.RawMessage(bad), "x", time.Time{}, 100).Updates
	if len(ups) != 1 {
		t.Fatalf("garbage rows were not dropped: %+v", ups)
	}
	if len(ups[0].Path) != 1 || ups[0].Path[0] != 3333 {
		t.Fatalf("invalid ASNs survived the path: %v", ups[0].Path)
	}
	if got := ParseBGPUpdates(json.RawMessage(`nope`), "x", time.Time{}, 10); got.Updates != nil {
		t.Fatal("unparsable payload yielded updates")
	}
}

// The ring is the memory bound. This is the test that would fail if someone
// ever made it grow.
func TestRingIsConstantSizeAndOverwritesOldest(t *testing.T) {
	r := &ring{}
	for i := 0; i < RingSize*3; i++ {
		r.append(Update{Prefix: itoa(i)})
	}
	buffered, written, dropped := r.stats()
	if buffered != RingSize {
		t.Fatalf("buffered = %d, want the constant %d", buffered, RingSize)
	}
	if written != uint64(RingSize*3) {
		t.Fatalf("written = %d", written)
	}
	if dropped != uint64(RingSize*2) {
		t.Fatalf("dropped = %d, want %d", dropped, RingSize*2)
	}
	// A reader starting at 0 gets the OLDEST SURVIVING entry and is told it
	// missed data — never a silent hole.
	got, next, gap := r.since(0, 10)
	if !gap {
		t.Fatal("a reader whose cursor fell out of the window was not told")
	}
	if len(got) != 10 || got[0].Seq != uint64(RingSize*2) {
		t.Fatalf("first entry = %+v", got[0])
	}
	if next != got[len(got)-1].Seq+1 {
		t.Fatalf("cursor = %d", next)
	}
}

func TestRingSinceIsAWorkingCursor(t *testing.T) {
	r := &ring{}
	for i := 0; i < 5; i++ {
		r.append(Update{Prefix: itoa(i)})
	}
	got, next, gap := r.since(0, 100)
	if gap || len(got) != 5 || next != 5 {
		t.Fatalf("first page: %d entries, next=%d gap=%v", len(got), next, gap)
	}
	got, next2, _ := r.since(next, 100)
	if len(got) != 0 || next2 != next {
		t.Fatalf("an idle re-read returned %d entries and moved the cursor to %d", len(got), next2)
	}
	r.append(Update{Prefix: "new"})
	got, _, _ = r.since(next, 100)
	if len(got) != 1 || got[0].Prefix != "new" {
		t.Fatalf("incremental read = %+v", got)
	}
}

func TestRingSincePageIsCapped(t *testing.T) {
	r := &ring{}
	for i := 0; i < FeedPageMax+50; i++ {
		r.append(Update{})
	}
	if got, _, _ := r.since(0, 100000); len(got) != FeedPageMax {
		t.Fatalf("page = %d, cap is %d", len(got), FeedPageMax)
	}
}

func TestNormalizeFeedResourcesBoundsAndDedupes(t *testing.T) {
	in := []string{"AS3333", "AS3333", " ", "", "203.0.113.0/24", strings.Repeat("x", 200)}
	for i := 0; i < 40; i++ {
		in = append(in, "203.0."+itoa(i)+".0/24")
	}
	got := NormalizeFeedResources(in)
	if len(got) > MaxFeedResources {
		t.Fatalf("resources = %d, cap is %d", len(got), MaxFeedResources)
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r] {
			t.Fatalf("duplicate resource %q", r)
		}
		if r == "" || len(r) > 64 {
			t.Fatalf("garbage resource survived: %q", r)
		}
		seen[r] = true
	}
}

// Flag off = nothing runs, nothing is claimed.
func TestFeedDisabledIsHonestAndStartsNothing(t *testing.T) {
	f := newFake()
	rt := NewRuntime(f, Options{Enabled: false, Now: fixedNow()})
	if rt.Enabled() {
		t.Fatal("runtime reports enabled with the flag off")
	}
	page, err := rt.Page(context.Background(), "acme", []string{"AS3333"}, 0, 100)
	if !errors.Is(err, ErrFeedDisabled) {
		t.Fatalf("err = %v, want ErrFeedDisabled", err)
	}
	if page.Status.Enabled || !strings.Contains(page.Status.Note, EnvFeatureFlag) {
		t.Fatalf("the off-state does not name the flag: %+v", page.Status)
	}
	if page.Updates == nil {
		t.Fatal("Updates must be an empty array, never null")
	}
	if rt.Metrics()["pollers_started_total"] != 0 || f.calls.Load() != 0 {
		t.Fatal("a disabled feed touched the upstream")
	}
}

func TestFeedRefusesANonConcreteTenant(t *testing.T) {
	rt := NewRuntime(newFake(), Options{Enabled: true, Now: fixedNow()})
	defer rt.Stop()
	for _, tenant := range []string{"", "  ", "*", " * "} {
		if _, err := rt.Page(context.Background(), tenant, []string{"AS1"}, 0, 10); err == nil {
			t.Errorf("Page(%q) was accepted — the ring must never be keyed by a wildcard", tenant)
		}
	}
}

func TestFeedWithAnEmptyWatchlistSaysSoAndPollsNothing(t *testing.T) {
	f := newFake()
	rt := NewRuntime(f, Options{Enabled: true, Now: fixedNow()})
	defer rt.Stop()
	page, err := rt.Page(context.Background(), "acme", nil, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if page.Status.Polling || !strings.Contains(page.Status.Note, "watchlist") {
		t.Fatalf("status = %+v", page.Status)
	}
	if rt.Metrics()["pollers_started_total"] != 0 {
		t.Fatal("a poller was started for an empty watchlist")
	}
}

// Each tenant gets its OWN ring: one tenant's updates must never appear in
// another's page (§3a — the ring is per-tenant data).
func TestFeedRingsAreIsolatedPerTenant(t *testing.T) {
	rt := NewRuntime(newFake(), Options{Enabled: true, Now: fixedNow()})
	defer rt.Stop()
	ctx := context.Background()
	acme, _ := rt.ensure("acme", []string{"AS1"})
	globex, _ := rt.ensure("globex", []string{"AS2"})
	if acme == globex {
		t.Fatal("two tenants share one ring — a cross-tenant leak by construction")
	}
	acme.append(Update{Prefix: "acme-only"})
	page, err := rt.Page(ctx, "globex", []string{"AS2"}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range page.Updates {
		if u.Prefix == "acme-only" {
			t.Fatal("CROSS-TENANT LEAK: globex read acme's buffered update")
		}
	}
	page, _ = rt.Page(ctx, "acme", []string{"AS1"}, 0, 100)
	if len(page.Updates) != 1 || page.Updates[0].Prefix != "acme-only" {
		t.Fatalf("acme lost its own update: %+v", page.Updates)
	}
}

// The global poller cap is the whole point of "one poller per tenant with a
// global concurrency cap": tenant N+1 is told honestly, not served silence.
func TestFeedGlobalPollerCapIsEnforcedAndDeclared(t *testing.T) {
	rt := NewRuntime(newFake(), Options{Enabled: true, Now: fixedNow(), Interval: time.Hour, Idle: time.Hour})
	defer rt.Stop()
	for i := 0; i < MaxPollers; i++ {
		if _, capped := rt.ensure("t"+itoa(i), []string{"AS1"}); capped {
			t.Fatalf("tenant %d capped below the cap", i)
		}
	}
	page, err := rt.Page(context.Background(), "one-too-many", []string{"AS1"}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Status.Capped || page.Status.Polling {
		t.Fatalf("the cap was not declared: %+v", page.Status)
	}
	if !strings.Contains(page.Status.Note, "cap") {
		t.Fatalf("note does not explain the cap: %q", page.Status.Note)
	}
	if rt.Metrics()["pollers_capped_total"] < 1 {
		t.Fatal("the cap was not counted")
	}
	if free := rt.Metrics()["poller_slots_free"]; free != 0 {
		t.Fatalf("slots free = %d, want 0", free)
	}
}

// The poller actually fills the ring, and the flag-gated loop is observable
// through the counters (§10). Interval is tiny so this stays a fast unit test.
func TestPollerFillsTheRingAndCounts(t *testing.T) {
	f := newFake()
	f.put("bgp-updates", "193.0.0.0/21", realUpdates)
	// Now is pinned INSIDE the fixture's window: the poller's first lookback is
	// now-30m, so a real clock would filter the (dated) fixture out entirely.
	rt := NewRuntime(f, Options{
		Enabled: true, Interval: time.Millisecond, Idle: time.Hour,
		Now:  func() time.Time { return time.Date(2026, 8, 31, 14, 5, 0, 0, time.UTC) },
		Rand: func() float64 { return 0.5 },
	})
	defer rt.Stop()
	ctx := context.Background()
	if _, err := rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 100); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var page FeedPage
	for time.Now().Before(deadline) {
		page, _ = rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 100)
		if len(page.Updates) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(page.Updates) == 0 {
		t.Fatalf("the poller buffered nothing; metrics=%v", rt.Metrics())
	}
	if page.Updates[0].Resource != "193.0.0.0/21" {
		t.Fatalf("update not tagged with its resource: %+v", page.Updates[0])
	}
	m := rt.Metrics()
	if m["polls_total"] < 1 || m["updates_buffered_total"] < 1 || m["pollers_started_total"] != 1 {
		t.Fatalf("metrics = %v", m)
	}
	// The cursor stops re-buffering: a second poll of the same window adds
	// nothing, so the ring must not grow without bound on a static upstream.
	time.Sleep(50 * time.Millisecond)
	page2, _ := rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 500)
	if len(page2.Updates) != len(page.Updates) {
		t.Fatalf("the same upstream window was re-buffered: %d → %d", len(page.Updates), len(page2.Updates))
	}
}

// An upstream that always fails must back off and must never be counted as
// buffered work — and it must not spin.
func TestPollerBacksOffOnUpstreamErrors(t *testing.T) {
	f := newFake()
	f.putErr("bgp-updates", "AS3333", errors.New("upstream 503"))
	rt := NewRuntime(f, Options{
		Enabled: true, Interval: time.Millisecond, Idle: time.Hour,
		Rand: func() float64 { return 0.5 },
	})
	defer rt.Stop()
	ctx := context.Background()
	if _, err := rt.Page(ctx, "acme", []string{"AS3333"}, 0, 10); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rt.Metrics()["poll_errors_total"] > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m := rt.Metrics()
	if m["poll_errors_total"] < 1 {
		t.Fatalf("errors were not counted: %v", m)
	}
	if m["updates_buffered_total"] != 0 {
		t.Fatalf("a failing upstream buffered %d updates", m["updates_buffered_total"])
	}
	// Backoff: after the first failure the loop must not have burned hundreds of
	// polls in the time a 1ms interval would allow.
	time.Sleep(200 * time.Millisecond)
	if polls := rt.Metrics()["polls_total"]; polls > 50 {
		t.Fatalf("no backoff — %d polls against a failing upstream", polls)
	}
}

func TestPollerStopsWhenIdleAndReleasesItsSlot(t *testing.T) {
	rt := NewRuntime(newFake(), Options{
		Enabled: true, Interval: time.Millisecond, Idle: time.Nanosecond,
		Rand: func() float64 { return 0.5 },
	})
	defer rt.Stop()
	if _, err := rt.Page(context.Background(), "acme", []string{"AS3333"}, 0, 10); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rt.Metrics()["pollers_stopped_total"] > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m := rt.Metrics()
	if m["pollers_stopped_total"] < 1 {
		t.Fatalf("an idle poller never stopped: %v", m)
	}
	if m["poller_slots_free"] != int64(MaxPollers) {
		t.Fatalf("the stopped poller did not release its slot: %v", m)
	}
}

func TestJitterStaysInBand(t *testing.T) {
	rt := NewRuntime(newFake(), Options{Enabled: true})
	base := time.Minute
	for i := 0; i < 200; i++ {
		d := rt.jitter(base)
		if d < time.Duration(float64(base)*0.75) || d >= time.Duration(float64(base)*1.25) {
			t.Fatalf("jitter %v outside [0.75, 1.25) × %v", d, base)
		}
	}
}

// TestPeekReadsWithoutStartingOrRefreshingAPoller pins the property Peek exists
// for: a background consumer must not be able to keep a poller alive.
func TestPeekReadsWithoutStartingOrRefreshingAPoller(t *testing.T) {
	rt := NewRuntime(newFake(), Options{Enabled: true, Now: fixedNow(), Rand: func() float64 { return 0.5 }})
	if got := rt.Peek("acme", 10); len(got) != 0 {
		t.Fatalf("a tenant with no ring must Peek empty, got %d", len(got))
	}
	if len(rt.pollers) != 0 || len(rt.rings) != 0 {
		t.Fatal("Peek must not create a ring or start a poller")
	}
	// Seed a ring directly and read it back newest-first.
	r := &ring{}
	rt.rings["acme"] = r
	for i := 0; i < 5; i++ {
		r.append(Update{Prefix: "10.0.0.0/8", Peer: "p"})
	}
	got := rt.Peek("acme", 3)
	if len(got) != 3 {
		t.Fatalf("Peek(3) returned %d", len(got))
	}
	if got[0].Seq != 4 || got[2].Seq != 2 {
		t.Fatalf("Peek must return newest-first, got seqs %d..%d", got[0].Seq, got[2].Seq)
	}
	// Scopeless / wildcard reads return nothing, never everything.
	for _, bad := range []string{"", "*", "  "} {
		if len(rt.Peek(bad, 10)) != 0 {
			t.Fatalf("Peek(%q) must return nothing", bad)
		}
	}
	if len(rt.Peek("globex", 10)) != 0 {
		t.Fatal("Peek must not cross tenants")
	}
}

// ── per-tenant feed counters (§3a) ─────────────────────────────────────────
//
// The feed response is a PER-TENANT body, so the counters in it must be the
// caller's own. The process-wide snapshot used to ride there and it carried
// `rings` — literally the number of tenants using the feed — plus every
// tenant's poll totals. TenantMetrics reports one tenant and nothing else; the
// aggregates are WriteMetrics/​/metrics, which is operator surface.
func TestTenantMetricsRevealNothingAboutOtherTenants(t *testing.T) {
	f := newFake()
	f.put("bgp-updates", "193.0.0.0/21", realUpdates)
	rt := NewRuntime(f, Options{
		Enabled: true, Interval: time.Millisecond, Idle: time.Hour,
		Now:  func() time.Time { return time.Date(2026, 8, 31, 14, 5, 0, 0, time.UTC) },
		Rand: func() float64 { return 0.5 },
	})
	defer rt.Stop()
	ctx := context.Background()

	// Only acme uses the feed.
	if _, err := rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 100); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rt.TenantMetrics("acme")["updates_buffered_total"] > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	acme := rt.TenantMetrics("acme")
	if acme["updates_buffered_total"] == 0 || acme["polls_total"] == 0 {
		t.Fatalf("acme's own counters never moved: %v", acme)
	}
	if acme["poller_active"] != 1 {
		t.Fatalf("acme's own poller state = %d, want 1", acme["poller_active"])
	}

	// A tenant that has never touched the feed sees ZEROS — not acme's numbers,
	// and no hint that acme's ring exists.
	globex := rt.TenantMetrics("globex")
	for k, v := range globex {
		if k == "ring_size" {
			continue
		}
		if v != 0 {
			t.Errorf("globex, which never used the feed, sees %s = %d — that is acme's activity", k, v)
		}
	}
	// The keys that describe the PROCESS must not exist in a tenant body at all.
	for _, leaked := range []string{"rings", "pollers_active", "poller_slots_free",
		"pollers_started_total", "pollers_stopped_total", "pollers_capped_total"} {
		if _, ok := globex[leaked]; ok {
			t.Errorf("%q is a process-wide fact and must not be in a per-tenant body", leaked)
		}
	}
	// A non-concrete tenant reads nothing rather than everything.
	for _, bad := range []string{"", "  ", "*"} {
		m := rt.TenantMetrics(bad)
		for k, v := range m {
			if k != "ring_size" && v != 0 {
				t.Errorf("TenantMetrics(%q) leaked %s = %d", bad, k, v)
			}
		}
	}

	// The aggregates still exist for the operator, on the scrape surface.
	var buf strings.Builder
	rt.WriteMetrics(&buf)
	out := buf.String()
	for _, want := range []string{"netops_bgpfeed_rings", "netops_bgpfeed_polls_total", "# TYPE netops_bgpfeed_rings gauge"} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics exposition is missing %q:\n%s", want, out)
		}
	}
}

// ── L-03: the window must cover the upstream's publishing lag ──────────────

func TestFeedLookbackDefaultsAndClamps(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"unset takes the code default", 0, DefaultFeedLookback},
		{"negative takes the code default", -time.Hour, DefaultFeedLookback},
		{"too small is pulled up", time.Second, MinFeedLookback},
		{"too large is pulled down", 72 * time.Hour, MaxFeedLookback},
		{"in range is honoured", 8 * time.Hour, 8 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := NewRuntime(newFake(), Options{Enabled: true, Lookback: tc.in})
			defer rt.Stop()
			if got := rt.Lookback(); got != tc.want {
				t.Fatalf("lookback = %v, want %v", got, tc.want)
			}
		})
	}
	// The default must actually cover the lag measured on the live host
	// (3 h 15 m on 2026-09-03) — the whole reason it is not 30m any more.
	if DefaultFeedLookback < 4*time.Hour {
		t.Fatalf("DefaultFeedLookback = %v; the measured upstream lag was 3h15m and a "+
			"window that does not cover it makes the feed structurally unable to emit",
			DefaultFeedLookback)
	}
}

// feedRuntimeAt builds a runtime whose clock is pinned to `now`, polls once for
// acme, and returns the status the API would serve.
func feedRuntimeAt(t *testing.T, now time.Time, lookback time.Duration) FeedStatus {
	t.Helper()
	f := newFake()
	f.put("bgp-updates", "193.0.0.0/21", realUpdates)
	rt := NewRuntime(f, Options{
		Enabled: true, Interval: time.Millisecond, Idle: time.Hour, Lookback: lookback,
		Now:  func() time.Time { return now },
		Rand: func() float64 { return 0.5 },
	})
	t.Cleanup(rt.Stop)
	ctx := context.Background()
	if _, err := rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 100); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rt.TenantMetrics("acme")["polls_total"] > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	page, err := rt.Page(ctx, "acme", []string{"193.0.0.0/21"}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return page.Status
}

// The upstream's own currency is REPORTED, so a page can say "feed on, upstream
// N behind" instead of rendering an empty list with no explanation.
func TestFeedStatusReportsUpstreamLag(t *testing.T) {
	// The fixture's newest record is 2026-08-31T16:03:50Z; pin the clock 3 h
	// later, which is the lag actually measured on the live host.
	now := time.Date(2026, 8, 31, 19, 3, 50, 0, time.UTC)
	st := feedRuntimeAt(t, now, DefaultFeedLookback)

	if st.Lookback != DefaultFeedLookback.String() {
		t.Fatalf("status does not publish the window in force: %q", st.Lookback)
	}
	if st.UpstreamNewest == nil || st.UpstreamLagSeconds == nil {
		t.Fatal("the upstream age is not reported — an empty feed would be unexplainable")
	}
	if !st.UpstreamNewest.Equal(time.Date(2026, 8, 31, 16, 3, 50, 0, time.UTC)) {
		t.Fatalf("upstream_newest_ts = %v", st.UpstreamNewest)
	}
	if *st.UpstreamLagSeconds != int64(3*time.Hour/time.Second) {
		t.Fatalf("upstream_lag_seconds = %d, want %d", *st.UpstreamLagSeconds, int64(3*time.Hour/time.Second))
	}
	// A lag INSIDE the window is not a problem and must not be narrated as one.
	if st.Note != "" {
		t.Fatalf("a lag inside the window produced an alarming note: %q", st.Note)
	}
	// …and the window covering the lag means the feed actually buffers.
	if st.Written == 0 {
		t.Fatal("nothing was buffered even though the window covers the upstream lag")
	}
}

// The live 2026-09-03 shape: lag beyond the window, nothing buffered, 0 errors.
// The status must SAY why, name the knob, and not blame the operator's network.
func TestFeedStatusExplainsALagBeyondTheWindow(t *testing.T) {
	now := time.Date(2026, 9, 3, 5, 17, 0, 0, time.UTC) // ~2.5 days past the fixture
	st := feedRuntimeAt(t, now, 6*time.Hour)

	if st.Written != 0 {
		t.Fatalf("records older than the window were buffered: %d", st.Written)
	}
	if st.UpstreamLagSeconds == nil || *st.UpstreamLagSeconds < int64(6*time.Hour/time.Second) {
		t.Fatalf("the lag that explains the empty feed was not reported: %+v", st.UpstreamLagSeconds)
	}
	if st.Note == "" {
		t.Fatal("an enabled, error-free, permanently EMPTY feed said nothing — the exact 2026-09-03 defect")
	}
	for _, want := range []string{EnvFeedLookback, "behind", "upstream"} {
		if !strings.Contains(st.Note, want) {
			t.Errorf("the note does not mention %q; it must name the cause and the knob:\n%s", want, st.Note)
		}
	}
	if !strings.Contains(st.Note, "NOT an outage on your network") {
		t.Errorf("the note must not let an operator read an upstream delay as their own outage:\n%s", st.Note)
	}
}

// Before any poll completes, the upstream age is UNKNOWN and must be omitted —
// never rendered as a lag of zero, which would read as "perfectly current".
func TestFeedStatusOmitsUpstreamAgeBeforeTheFirstPoll(t *testing.T) {
	rt := NewRuntime(newFake(), Options{
		Enabled: true, Interval: time.Hour, Idle: time.Hour,
		Now: fixedNow(), Rand: func() float64 { return 0.5 },
	})
	defer rt.Stop()
	page, err := rt.Page(context.Background(), "acme", []string{"193.0.0.0/21"}, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if page.Status.UpstreamNewest != nil || page.Status.UpstreamLagSeconds != nil {
		t.Fatalf("an unmeasured upstream was reported as measured: %+v", page.Status)
	}
	body, err := json.Marshal(page.Status)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"upstream_newest_ts", "upstream_lag_seconds"} {
		if strings.Contains(string(body), key) {
			t.Errorf("%s is serialized before it was ever measured: %s", key, body)
		}
	}
}
