package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
)

// devstore_compact_test.go — tracker 175: tombstone growth must be BOUNDED,
// and bounding it must not resurrect a deleted device.
//
// The defect these pin: a lab that had run the scale ladder for weeks held
// 35,427 tombstones / 142 MB for ZERO real devices, because every
// DELETE /api/devices/{id} wrote a suppression record that nothing ever
// removed. At the 5k/10k ladder (2–4x the churn) that is a run-blocker.
//
// These are deterministic accounting tests on an injected clock — NEVER timing
// tests. Nothing here sleeps.

// fakeClock is the injected time source. Advance is called from the test
// goroutine only, but reads happen from the store under its own lock, so it is
// mutex-guarded.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)}
}
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// tombstoneBytes is the on-record footprint of the suppression set: the sum of
// the stored record bytes under the suppressed/ prefix. The lab's 142 MB was
// this multiplied by the filesystem's 4 KiB block; bounding the record count
// bounds both.
func tombstoneBytes(kv *recKV, st *DevStore) (count, bytes int) {
	for key, b := range kv.m {
		if strings.HasPrefix(key, st.suppressedPrefix()) {
			count++
			bytes += len(b)
		}
	}
	return count, bytes
}

// churn runs one scale-run's worth of create+delete against the store: N
// devices onboarded through Put and then deleted through RemoveOwned, exactly
// as scripts/scale-miniladder.py drives the API. Ids are unique per run, so the
// tombstones ACCUMULATE — that is the growth being bounded.
func churn(t *testing.T, st *DevStore, tenant string, run, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-run%d-dev%04d", tenant, run, i)
		if err := st.Put(models.Device{ID: id, Name: id, Address: fmt.Sprintf("10.%d.%d.%d", run, i/254, i%254), TenantID: tenant, Source: "manual"}); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
		if err := st.RemoveOwned(tenant, id); err != nil {
			t.Fatalf("remove %s: %v", id, err)
		}
	}
}

// TestTombstoneGrowthIsBoundedUnderTenRunChurn is the tracker-175 regression:
// ten 5,000-device create+delete runs — 50,000 tombstones under the old code,
// which is 1.4x the residue that wedged the lab — must leave the store under
// its hard cap, in RAM and on the backend.
//
// MUTANT: comment out the compactLocked call in RemoveOwned and this fails with
// 50,000.
func TestTombstoneGrowthIsBoundedUnderTenRunChurn(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	const max = 2000
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		Max: max,
		Now: clk.now,
		// Zero uptime is not enough for the cap tier (a source may not have
		// polled yet); the ladder runs for hours, so start past the window.
		HitObservationWindow: time.Minute,
	})
	if err := st.Unreadable(); err != nil {
		t.Fatalf("boot: %v", err)
	}
	clk.advance(2 * time.Minute)

	const runs, perRun = 10, 5000
	peak := 0
	for run := 0; run < runs; run++ {
		churn(t, st, "t_scale", run, perRun)
		if c, _ := tombstoneBytes(kv, st); c > peak {
			peak = c
		}
		// Each run is well inside the retention horizon, so this is the CAP
		// tier doing the work, not expiry.
		clk.advance(20 * time.Minute)
	}

	count, bytes := tombstoneBytes(kv, st)
	t.Logf("after %d runs x %d devices (%d deletes): stored tombstones=%d bytes=%d peak=%d (unbounded would be %d)",
		runs, perRun, runs*perRun, count, bytes, peak, runs*perRun)
	if count > max {
		t.Fatalf("stored tombstones = %d, over the cap of %d — growth is not bounded", count, max)
	}
	if got := st.Tombstones().Count; got > max {
		t.Fatalf("in-memory tombstones = %d, over the cap of %d", got, max)
	}
	if peak > max+defaultEvictBudget {
		t.Fatalf("peak tombstones = %d — compaction is not keeping up incrementally (cap %d, per-pass budget %d)", peak, max, defaultEvictBudget)
	}
	if st.Tombstones().EvictedCap == 0 {
		t.Fatal("nothing was cap-evicted — the bound never engaged, so this test proves nothing")
	}
}

// TestDeletedDeviceDoesNotResurrectInsideTheHorizon is the correctness half:
// compaction must not undo F-69. A device deleted inside the retention horizon
// stays suppressed when its source replays it.
func TestDeletedDeviceDoesNotResurrectInsideTheHorizon(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		TTL: 24 * time.Hour, Max: 5000, Now: clk.now, HitObservationWindow: time.Minute,
	})
	const id = "snmp-core-sw01"
	if err := st.RemoveOwned("t_a", id); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Minute)

	// Ordinary churn well under the cap: every compaction pass that runs here
	// is the EXPIRED tier, and nothing is expired, so the suppression must
	// survive every one of them. Replay the source between runs the way
	// pollOnce does.
	for run := 0; run < 4; run++ {
		churn(t, st, "t_a", run, 200)
		clk.advance(5 * time.Hour)
		if !st.IsSuppressed(id) {
			t.Fatalf("deleted device resurrected after run %d — compaction dropped a live suppression (F-69)", run)
		}
	}
	if st.Tombstones().EvictedCap != 0 {
		t.Fatalf("cap tier ran (%d) — this test is meant to exercise the horizon, not the cap", st.Tombstones().EvictedCap)
	}
	// 20 h of replays keep pushing lastActivity forward, so the suppression is
	// still inside its horizon even though the DELETE is now 20 h old.
	if !st.IsSuppressed(id) {
		t.Fatal("deleted device resurrected inside the retention horizon")
	}
	if _, ok := kv.m[st.suppressedKey(id)]; !ok {
		t.Fatal("the suppression record was compacted inside its horizon")
	}
}

// TestActivelySuppressedTombstoneIsNeverCapEvicted is the invariant that makes
// the cap tier safe: a tombstone that a source keeps hitting refreshes itself
// and is never evicted to make room, no matter how much churn piles up behind
// it. Without it, a still-live NetBox device would reappear the moment a scale
// run pushed the store over its cap.
func TestActivelySuppressedTombstoneIsNeverCapEvicted(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		TTL: 24 * time.Hour, Max: 200, Now: clk.now, HitObservationWindow: time.Minute,
	})
	const live = "netbox-dc1-fw01"
	if err := st.RemoveOwned("t_a", live); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Minute)

	// The tombstone is the OLDEST in the store, so oldest-first eviction aims
	// straight at it — only the hit protection saves it.
	for run := 0; run < 6; run++ {
		clk.advance(2 * time.Hour) // ... and it keeps ageing past every rival
		if !st.IsSuppressed(live) {
			t.Fatalf("live suppression evicted before run %d", run)
		}
		churn(t, st, "t_a", run, 400)
	}
	if !st.IsSuppressed(live) {
		t.Fatal("an actively-hit suppression was cap-evicted — a live source device would resurrect")
	}
	if _, ok := kv.m[st.suppressedKey(live)]; !ok {
		t.Fatal("the live suppression's record was deleted from the backend")
	}
	if st.Tombstones().EvictedCap == 0 {
		t.Fatal("no cap eviction happened — the protection was never actually tested")
	}
}

// TestExpiredTombstonesAreCompacted is the expired tier: a suppression nothing
// has needed for a full retention horizon is collected, and this is the tier
// that runs at boot (where the cap tier is deliberately inert).
func TestExpiredTombstonesAreCompacted(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	lim := TombstoneLimits{TTL: 24 * time.Hour, Max: 100000, Now: clk.now}
	st := NewDevStoreWithLimits("devices.json", kv, nil, lim)
	for i := 0; i < 50; i++ {
		if err := st.RemoveOwned("t_a", fmt.Sprintf("old-%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := tombstoneBytes(kv, st); c != 50 {
		t.Fatalf("setup: %d tombstones, want 50", c)
	}

	// Well under the cap, so ONLY expiry can evict here.
	clk.advance(25 * time.Hour)
	if err := st.RemoveOwned("t_a", "fresh"); err != nil {
		t.Fatal(err)
	}
	if got := st.Tombstones().Count; got != 1 {
		t.Fatalf("after expiry: %d tombstones, want 1 (the fresh one)", got)
	}
	if !st.IsSuppressed("fresh") {
		t.Fatal("compaction evicted the tombstone that was just written")
	}
	if st.Tombstones().EvictedExpired != 50 {
		t.Fatalf("evicted_expired = %d, want 50", st.Tombstones().EvictedExpired)
	}

	// The same expiry runs at BOOT, off the durable deleted_at — the path that
	// drains an already-accumulated residue.
	kv2 := newRecKV()
	st2 := NewDevStoreWithLimits("devices.json", kv2, nil, lim)
	for i := 0; i < 30; i++ {
		if err := st2.RemoveOwned("t_a", fmt.Sprintf("stale-%02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(48 * time.Hour)
	st3 := NewDevStoreWithLimits("devices.json", kv2, nil, lim)
	if err := st3.Unreadable(); err != nil {
		t.Fatalf("reboot: %v", err)
	}
	if got := st3.Tombstones().Count; got != 0 {
		t.Fatalf("boot compaction left %d expired tombstones", got)
	}
	if c, _ := tombstoneBytes(kv2, st3); c != 0 {
		t.Fatalf("boot compaction left %d expired records on the backend", c)
	}
}

// TestCompactionDoesNotCrossTenants — §3a. The cap tier is a degradation, so it
// must be aimed at the tenant that caused it: a churning tenant can never evict
// a quiet tenant's suppressions.
func TestCompactionDoesNotCrossTenants(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	const max = 300
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		TTL: 24 * time.Hour, Max: max, Now: clk.now, HitObservationWindow: time.Minute,
	})
	// The quiet tenant deletes a handful of devices FIRST, so every one of them
	// is older than everything the noisy tenant will write — oldest-first
	// eviction would take them first if it were tenant-blind.
	quiet := []string{"q-fw01", "q-fw02", "q-fw03", "q-sw01", "q-sw02"}
	for _, id := range quiet {
		if err := st.RemoveOwned("t_quiet", id); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(2 * time.Minute)

	for run := 0; run < 5; run++ {
		churn(t, st, "t_noisy", run, 400)
		clk.advance(10 * time.Minute)
	}

	if st.Tombstones().EvictedCap == 0 {
		t.Fatal("no cap eviction — the tenant scoping was never exercised")
	}
	for _, id := range quiet {
		if !st.IsSuppressed(id) {
			t.Fatalf("quiet tenant's suppression %q was evicted by another tenant's churn (§3a cross-tenant effect)", id)
		}
		if _, ok := kv.m[st.suppressedKey(id)]; !ok {
			t.Fatalf("quiet tenant's record for %q was deleted from the backend", id)
		}
	}
	if got := st.Tombstones().Count; got > max {
		t.Fatalf("count = %d, over cap %d", got, max)
	}
}

// TestTombstoneTenantAndHitSurviveAReload: retention state is durable, so a
// restart cannot make a load-bearing tombstone look like garbage. The hit is
// persisted lazily (rate-limited), which is why the reload asserts it after a
// compaction pass has had the chance to flush it.
func TestTombstoneTenantAndHitSurviveAReload(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	lim := TombstoneLimits{TTL: 24 * time.Hour, Max: 10, Now: clk.now, HitPersistInterval: time.Minute, HitObservationWindow: time.Minute}
	st := NewDevStoreWithLimits("devices.json", kv, nil, lim)
	for _, id := range []string{"keeper", "other"} {
		if err := st.RemoveOwned("t_a", id); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(20 * time.Hour)
	if !st.IsSuppressed("keeper") { // the hit that makes it load-bearing
		t.Fatal("setup: not suppressed")
	}
	clk.advance(2 * time.Minute)
	// Any later write triggers the pass that flushes the hit.
	if err := st.RemoveOwned("t_a", "trigger"); err != nil {
		t.Fatal(err)
	}

	// Now 25 h after both DELETEs, but only 5 h after keeper's hit. Expiry is
	// measured from lastActivity, so the reloaded store must hold keeper and
	// drop other — which differ ONLY in that a source still wants keeper's id.
	clk.advance(5 * time.Hour)
	st2 := NewDevStoreWithLimits("devices.json", kv, nil, lim)
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !st2.IsSuppressed("keeper") {
		t.Fatal("a tombstone hit 23 h ago was expired on its 25-h-old deleted_at — last_hit did not survive the reload")
	}
	if ts := st2.suppressed["keeper"]; ts == nil || ts.tenant != "t_a" {
		t.Fatalf("tenant lost across reload: %+v", ts)
	}
	if st2.IsSuppressed("other") {
		t.Fatal("a never-hit tombstone 25 h past its horizon survived the reload")
	}
}

// TestBootWithAFullStoreStaysBounded: the 6b79ea58 wedge must not come back
// through the compaction door. A boot facing a full store's worth of expired
// tombstones does ONE bounded pass — it never tries to unlink all 35k inline —
// and successive boots drain the rest.
func TestBootWithAFullStoreStaysBounded(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	const budget = 256
	lim := TombstoneLimits{TTL: 24 * time.Hour, Max: 100000, BootBudget: budget, Now: clk.now}
	st := NewDevStoreWithLimits("devices.json", kv, nil, lim)
	const total = 3000
	for i := 0; i < total; i++ {
		if err := st.RemoveOwned("t_a", fmt.Sprintf("residue-%05d", i)); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(72 * time.Hour) // every one of them is now expired

	before := kv.deletes
	st2 := NewDevStoreWithLimits("devices.json", kv, nil, lim)
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("boot: %v", err)
	}
	spent := kv.deletes - before
	if spent > budget {
		t.Fatalf("boot spent %d record deletes, over its budget of %d — that is the 6b79ea58 wedge class", spent, budget)
	}
	if spent != budget {
		t.Fatalf("boot spent %d deletes, want the full budget %d (compaction did not engage)", spent, budget)
	}
	if got := st2.Tombstones().Count; got != total-budget {
		t.Fatalf("after one bounded boot pass: %d tombstones, want %d", got, total-budget)
	}
	// Successive boots drain it — bounded work each time, not one stall.
	for boot := 0; boot < 4; boot++ {
		st2 = NewDevStoreWithLimits("devices.json", kv, nil, lim)
		if err := st2.Unreadable(); err != nil {
			t.Fatalf("boot %d: %v", boot, err)
		}
	}
	if got := st2.Tombstones().Count; got != total-5*budget {
		t.Fatalf("after 5 bounded boots: %d tombstones, want %d", got, total-5*budget)
	}
}

// TestCapTierWaitsForSourcesToPoll: right after boot the in-memory hit picture
// is empty, so cap-evicting then would drop suppressions a source is about to
// hit. The cap tier stays inert until the store has been up long enough for
// every configured source to have polled (15 min > the 5 min SNMP interval).
func TestCapTierWaitsForSourcesToPoll(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		TTL: 24 * time.Hour, Max: 10, Now: clk.now, HitObservationWindow: 15 * time.Minute,
	})
	for i := 0; i < 200; i++ {
		if err := st.RemoveOwned("t_a", fmt.Sprintf("d-%03d", i)); err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Second) // 200 s of uptime: inside the observation window
	}
	if got := st.Tombstones().EvictedCap; got != 0 {
		t.Fatalf("cap tier evicted %d tombstones before any source could have polled", got)
	}
	if got := st.Tombstones().Count; got != 200 {
		t.Fatalf("count = %d, want 200 held during the observation window", got)
	}

	clk.advance(20 * time.Minute)
	if err := st.RemoveOwned("t_a", "trigger"); err != nil {
		t.Fatal(err)
	}
	if st.Tombstones().EvictedCap == 0 {
		t.Fatal("cap tier never engaged once the observation window had passed")
	}
}

// TestPollDoesNotResurrectACompactedFleetsSurvivor wires the store to the real
// aggregator and the real pollOnce path: the end-to-end statement of what all
// of the above is protecting. A source replays a deleted device; it must stay
// deleted while its neighbours' tombstones are being compacted around it.
func TestPollDoesNotResurrectACompactedFleetsSurvivor(t *testing.T) {
	clk := newFakeClock()
	kv := newRecKV()
	st := NewDevStoreWithLimits("devices.json", kv, nil, TombstoneLimits{
		TTL: 24 * time.Hour, Max: 150, Now: clk.now, HitObservationWindow: time.Minute,
	})
	a := NewDiscoveryAggregator()
	a.SetStore(st)

	live := models.Device{ID: ScanDeviceID("dc1-core-sw01", "10.9.9.1"), Name: "dc1-core-sw01", Address: "10.9.9.1", Source: "snmp"}
	src := &fakeSource{name: "snmp", devices: []models.Device{live}}
	a.PollOnceForTest(context.Background(), src)
	if _, ok := a.Get(live.ID); !ok {
		t.Fatal("setup: source device not in cache")
	}
	if err := a.Delete(live.ID); err != nil {
		t.Fatal(err)
	}
	clk.advance(2 * time.Minute)

	for run := 0; run < 4; run++ {
		// The source keeps listing the device on every poll — that is what a
		// live NetBox/SNMP source does, and it is what keeps the suppression
		// load-bearing while a scale run churns thousands of ids past it.
		a.PollOnceForTest(context.Background(), src)
		churn(t, st, "", run, 200)
		clk.advance(90 * time.Minute)
		a.PollOnceForTest(context.Background(), src) // the source replays it
		if _, ok := a.Get(live.ID); ok {
			t.Fatalf("deleted device resurrected on the poll after run %d (F-69)", run)
		}
	}
	if st.Tombstones().EvictedCap == 0 {
		t.Fatal("no compaction pressure was applied — the test proves nothing")
	}
	if got := st.Tombstones().Count; got > 150+defaultEvictBudget {
		t.Fatalf("count = %d, unbounded despite compaction", got)
	}
}
