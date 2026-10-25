// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// found_persist_test.go — tracker 366: the SNMP scanner's memory persists, is
// restored through the normal admission path, and ages ONLY on the evidence of
// completed sweeps.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// prefixMemKV is a PrefixKV with failure injection.
type prefixMemKV struct {
	mu       sync.Mutex
	m        map[string][]byte
	failLoad bool
	failSave bool
}

func newPrefixMemKV() *prefixMemKV { return &prefixMemKV{m: map[string][]byte{}} }

func (k *prefixMemKV) Load(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.m[key]
	if !ok {
		return nil, fmt.Errorf("load %s: %w", key, os.ErrNotExist)
	}
	return b, nil
}

func (k *prefixMemKV) Save(key string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failSave {
		return errors.New("disk full")
	}
	k.m[key] = append([]byte(nil), data...)
	return nil
}

func (k *prefixMemKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failLoad {
		return nil, errors.New("io error")
	}
	out := map[string][]byte{}
	for key, v := range k.m {
		if strings.HasPrefix(key, prefix) {
			out[key] = v
		}
	}
	return out, nil
}

func (k *prefixMemKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failSave {
		return errors.New("disk full")
	}
	delete(k.m, key)
	return nil
}

func (k *prefixMemKV) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

// countingStore wraps a FoundStore and records every Apply.
type countingStore struct {
	FoundStore
	mu      sync.Mutex
	applies int
	ups     []FoundRecord
	prunes  []FoundKey
	fail    bool
}

func (c *countingStore) Apply(ctx context.Context, ups []FoundRecord, prunes []FoundKey) error {
	c.mu.Lock()
	c.applies++
	c.ups = append(c.ups, ups...)
	c.prunes = append(c.prunes, prunes...)
	fail := c.fail
	c.mu.Unlock()
	if fail {
		return errors.New("store down")
	}
	return c.FoundStore.Apply(ctx, ups, prunes)
}

func (c *countingStore) reset() (int, []FoundRecord, []FoundKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, u, p := c.applies, c.ups, c.prunes
	c.applies, c.ups, c.prunes = 0, nil, nil
	return n, u, p
}

type scanClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *scanClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *scanClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// liveSet is the set of addresses that answer, switchable mid-test.
type liveSet struct {
	mu     sync.Mutex
	alive  map[string]string // address → sysName
	probes atomic.Int64
}

func (l *liveSet) set(alive map[string]string) { l.mu.Lock(); l.alive = alive; l.mu.Unlock() }
func (l *liveSet) probe(_ context.Context, tg collectors.Target) (string, string, string, bool) {
	l.probes.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	name, ok := l.alive[tg.Address]
	if !ok {
		return "", "", "", false
	}
	return name, "cisco", "Cisco IOS XE 17.9", true
}

var testCreds = []ScanCredential{{ProfileID: "lab-ro", Target: collectors.Target{Community: "lab"}}}

type scanRig struct {
	src   *SNMPSource
	clock *scanClock
	live  *liveSet
	kv    *prefixMemKV
	store *countingStore
	cfg   *atomic.Pointer[ScanSettings]
}

func newScanRig(t *testing.T, kv *prefixMemKV) *scanRig {
	t.Helper()
	r := &scanRig{clock: &scanClock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}, live: &liveSet{}, kv: kv,
		cfg: &atomic.Pointer[ScanSettings]{}}
	r.cfg.Store(&ScanSettings{Enabled: true, Ranges: []string{"10.66.0.0/29"}, Credentials: testCreds})
	r.src = NewSNMPSource(func() ScanSettings { return *r.cfg.Load() }, nil)
	r.src.SetProbeForTest(r.live.probe)
	r.src.SetClockForTest(r.clock.now)
	r.store = &countingStore{FoundStore: NewFileFoundStore("/data/discovered_devices.json", kv)}
	return r
}

// sweep advances past the cooldown and runs one poll.
func (r *scanRig) sweep(t *testing.T) []models.Device {
	t.Helper()
	r.clock.advance(ScanCooldown + time.Second)
	devs, err := r.src.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	return devs
}

func byAddr(devs []models.Device) map[string]models.Device {
	out := map[string]models.Device{}
	for _, d := range devs {
		out[d.Address] = d
	}
	return out
}

var threeAlive = map[string]string{"10.66.0.1": "edge-1", "10.66.0.2": "edge-2", "10.66.0.3": "edge-3"}

// seedStore runs a first life: three devices found and persisted.
func seedStore(t *testing.T, kv *prefixMemKV) []models.Device {
	t.Helper()
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatalf("restore on an empty store: %v", err)
	}
	r.live.set(threeAlive)
	devs := r.sweep(t)
	if len(devs) != 3 {
		t.Fatalf("first life found %d devices, want 3", len(devs))
	}
	if n := kv.count(); n != 3 {
		t.Fatalf("first life persisted %d records, want 3", n)
	}
	return devs
}

// ── restore through the admission path ───────────────────────────────────────

func TestRestoreThenFirstPollDoesNotPrune(t *testing.T) {
	kv := newPrefixMemKV()
	first := seedStore(t, kv)

	// Second life: the network is down (nothing answers).
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatalf("restore: %v", err)
	}
	a := NewDiscoveryAggregator()
	a.Register(r.src)
	if a.Ready("snmp") {
		t.Fatal("a registered source must not be ready before its restore is ingested")
	}
	a.RestoreForTest()
	if !a.Ready("snmp") {
		t.Fatal("a successful restore must make the source ready")
	}
	got := a.Devices()
	if len(got) != 3 {
		t.Fatalf("restored inventory holds %d devices before any poll, want 3: %+v", len(got), got)
	}
	want := map[string]bool{}
	for _, d := range first {
		want[d.ID] = true
	}
	for _, d := range got {
		if !want[d.ID] || d.TenantID != "" || d.Source != "snmp" {
			t.Fatalf("restored device changed identity: %+v", d)
		}
	}

	// The first poll after a restart, with nothing answering, prunes nothing.
	r.clock.advance(ScanCooldown + time.Second)
	a.PollOnceForTest(context.Background(), r.src)
	if n := len(a.Devices()); n != 3 {
		t.Fatalf("first silent poll after restore left %d devices, want 3", n)
	}
	for _, d := range a.Devices() {
		if d.DiscoveryStale {
			t.Fatalf("one missed sweep made %s stale", d.ID)
		}
	}
}

func TestRestoredButTombstonedDeviceStaysSuppressed(t *testing.T) {
	kv := newPrefixMemKV()
	first := seedStore(t, kv)
	victim := first[1]

	dev := NewDevStore("/data/devices.json", newPrefixMemKV(), nil)
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(dev)
	a.Register(r.src)
	// The operator deleted it in the previous life (tombstone persisted).
	if err := dev.Remove(victim.ID); err != nil {
		t.Fatal(err)
	}
	a.RestoreForTest()
	for _, d := range a.Devices() {
		if d.ID == victim.ID {
			t.Fatalf("a restored device resurrected over its tombstone: %+v", d)
		}
	}
	if n := len(a.Devices()); n != 2 {
		t.Fatalf("want the 2 untombstoned devices, got %d", n)
	}
	r.live.set(threeAlive)
	r.clock.advance(ScanCooldown + time.Second)
	a.PollOnceForTest(context.Background(), r.src)
	for _, d := range a.Devices() {
		if d.ID == victim.ID {
			t.Fatal("the tombstoned device came back on the first poll after restore")
		}
	}
}

// ── ageing: only completed sweeps count ──────────────────────────────────────

func missesOf(s *SNMPSource, addr string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.found[addr]
	if !ok {
		return 0, false
	}
	return e.misses, !e.staleSince.IsZero()
}

func TestNonCompletedSweepsCountNoMisses(t *testing.T) {
	kv := newPrefixMemKV()
	seedStore(t, kv)
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(nil) // nothing answers from here on

	base := *r.cfg.Load()
	kinds := map[string]func(){
		"disabled": func() {
			c := base
			c.Enabled = false
			r.cfg.Store(&c)
			r.clock.advance(ScanCooldown + time.Second)
			if devs, err := r.src.Poll(context.Background()); err != nil || len(devs) != 0 {
				t.Fatalf("a disabled source reports nothing: %v %d", err, len(devs))
			}
		},
		"refused-range": func() {
			c := base
			c.Ranges = []string{"10.0.0.0/8"}
			r.cfg.Store(&c)
			r.clock.advance(ScanCooldown + time.Second)
			if _, err := r.src.Poll(context.Background()); err == nil {
				t.Fatal("oversized range must be refused")
			}
		},
		"no-credentials": func() {
			c := base
			c.Credentials = nil
			r.cfg.Store(&c)
			r.clock.advance(ScanCooldown + time.Second)
			if _, err := r.src.Poll(context.Background()); err == nil {
				t.Fatal("no credentials must be refused")
			}
		},
		"cooldown": func() {
			r.cfg.Store(&base)
			r.clock.advance(ScanCooldown + time.Second)
			if _, err := r.src.Poll(context.Background()); err != nil { // a real sweep: one miss
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ { // inside the cooldown: serve the cache, count nothing
				if _, err := r.src.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
		},
		"cancelled": func() {
			r.cfg.Store(&base)
			r.clock.advance(ScanCooldown + time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := r.src.Poll(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("a cancelled sweep must report cancellation, got %v", err)
			}
		},
	}
	order := []string{"disabled", "refused-range", "no-credentials", "cancelled", "cooldown"}
	for _, k := range order {
		for i := 0; i < 4; i++ {
			if k == "cooldown" && i > 0 {
				break // the cooldown case runs one real sweep by construction
			}
			kinds[k]()
		}
		m, stale := missesOf(r.src, "10.66.0.1")
		wantMisses := 0
		if k == "cooldown" {
			wantMisses = 1
		}
		if m != wantMisses || stale {
			t.Fatalf("after %q polls: misses=%d stale=%v, want misses=%d stale=false", k, m, stale, wantMisses)
		}
	}
}

func TestThreeMissedSweepsMakeStaleNeverDeleted(t *testing.T) {
	kv := newPrefixMemKV()
	seedStore(t, kv)
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(map[string]string{"10.66.0.1": "edge-1", "10.66.0.2": "edge-2"}) // .3 is down
	for i := 1; i <= 2; i++ {
		devs := byAddr(r.sweep(t))
		if devs["10.66.0.3"].DiscoveryStale {
			t.Fatalf("stale after %d misses, want 3", i)
		}
	}
	devs := byAddr(r.sweep(t))
	if !devs["10.66.0.3"].DiscoveryStale {
		t.Fatal("three missed completed sweeps must mark the device stale")
	}
	if devs["10.66.0.1"].DiscoveryStale {
		t.Fatal("an answering device was marked stale")
	}
	// Many more misses, well short of the prune period: still there.
	for i := 0; i < 20; i++ {
		devs = byAddr(r.sweep(t))
	}
	if _, ok := devs["10.66.0.3"]; !ok {
		t.Fatal("a device was deleted for missed sweeps alone")
	}
	// The stale mark is durable.
	recs, err := r.store.Load(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Address == "10.66.0.3" && rec.StaleSince.IsZero() {
			t.Fatal("stale_since was not persisted")
		}
	}
	// It answers again: no longer stale, same id.
	r.live.set(threeAlive)
	devs = byAddr(r.sweep(t))
	if devs["10.66.0.3"].DiscoveryStale {
		t.Fatal("a device that answered again is still stale")
	}
	if devs["10.66.0.3"].ID != ScanDeviceID("edge-3", "10.66.0.3") {
		t.Fatalf("id changed: %s", devs["10.66.0.3"].ID)
	}
}

func TestStalePruneNeedsSevenDaysAndAnAnswer(t *testing.T) {
	kv := newPrefixMemKV()
	seedStore(t, kv)
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(nil) // whole-site outage
	for i := 0; i < staleAfterMisses; i++ {
		r.sweep(t)
	}
	for _, d := range r.src.snapshot() {
		if !d.DiscoveryStale {
			t.Fatalf("%s not stale after the outage", d.Address)
		}
	}
	r.clock.advance(pruneAfterStale + time.Hour)
	if n := len(r.sweep(t)); n != 3 {
		t.Fatalf("an all-silent sweep pruned: %d devices left, want 3", n)
	}
	if n := kv.count(); n != 3 {
		t.Fatalf("an all-silent sweep deleted stored records: %d left", n)
	}
	// One device answers: the others, stale ≥ 7 days, are pruned — from memory
	// and from the store.
	r.live.set(map[string]string{"10.66.0.1": "edge-1"})
	devs := r.sweep(t)
	if len(devs) != 1 || devs[0].Address != "10.66.0.1" {
		t.Fatalf("want only the answering device after the prune, got %+v", devs)
	}
	recs, err := r.store.Load(context.Background(), "", true)
	if err != nil || len(recs) != 1 || recs[0].Address != "10.66.0.1" {
		t.Fatalf("store after prune: %v %+v", err, recs)
	}
}

func TestReprobeUpdatesLivenessNeverIdentity(t *testing.T) {
	r := newScanRig(t, newPrefixMemKV())
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(map[string]string{"10.66.0.1": "edge-1"})
	first := byAddr(r.sweep(t))["10.66.0.1"]
	r.live.set(map[string]string{"10.66.0.1": "renamed-by-someone"})
	again := byAddr(r.sweep(t))["10.66.0.1"]
	if again.ID != first.ID || again.Name != first.Name {
		t.Fatalf("a re-probe rewrote identity: %+v → %+v", first, again)
	}
	if !again.LastSeen.After(first.LastSeen) {
		t.Fatal("a re-probe that answered did not advance liveness")
	}
}

func TestCredOrderTriesTheBoundProfileFirst(t *testing.T) {
	creds := []ScanCredential{{ProfileID: "a"}, {ProfileID: "b"}, {ProfileID: "c"}}
	ids := func(cs []ScanCredential) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ProfileID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(credOrder(creds, "c")); got != "c,a,b" {
		t.Fatalf("bound first: %s", got)
	}
	if got := ids(credOrder(creds, "")); got != "a,b,c" {
		t.Fatalf("unbound: %s", got)
	}
	if got := ids(credOrder(creds, "gone")); got != "a,b,c" {
		t.Fatalf("ineligible bound profile: %s", got)
	}
}

// ── the unreadable store ─────────────────────────────────────────────────────

func TestUnreadableStoreRefusesWritesAndIsNotReady(t *testing.T) {
	kv := newPrefixMemKV()
	seedStore(t, kv)
	kv.failLoad = true
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err == nil {
		t.Fatal("an unreadable store must fail the restore")
	}
	if _, ok := r.src.Restored(); ok {
		t.Fatal("an unreadable store must not report a restore")
	}
	a := NewDiscoveryAggregator()
	a.Register(r.src)
	a.RestoreForTest()
	if a.Ready("snmp") {
		t.Fatal("an unreadable store must leave the source not ready")
	}
	if n := len(a.Devices()); n != 0 {
		t.Fatalf("nothing was restored, yet %d devices are in the inventory", n)
	}
	kv.failLoad = false
	r.live.set(map[string]string{"10.66.0.9": "newcomer"}) // outside the seed
	r.cfg.Store(&ScanSettings{Enabled: true, Ranges: []string{"10.66.0.8/29"}, Credentials: testCreds})
	r.clock.advance(ScanCooldown + time.Second)
	a.PollOnceForTest(context.Background(), r.src)
	if n, _, _ := r.store.reset(); n != 0 {
		t.Fatalf("an unreadable store accepted %d writes — it would overwrite what it could not read", n)
	}
	if !a.Ready("snmp") {
		t.Fatal("a completed sweep must make the source ready even when the memory was unreadable")
	}
	var buf bytes.Buffer
	r.src.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_discovery_found_store_loaded{source="snmp"} 0`) {
		t.Fatalf("the unreadable state is not observable:\n%s", buf.String())
	}
}

// ── write discipline ─────────────────────────────────────────────────────────

func TestOnlyChangedRecordsAreWrittenAndAFailedWriteIsRetried(t *testing.T) {
	r := newScanRig(t, newPrefixMemKV())
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(map[string]string{"10.66.0.1": "edge-1", "10.66.0.2": "edge-2"})
	r.sweep(t)
	if _, ups, _ := r.store.reset(); len(ups) != 2 {
		t.Fatalf("first sweep wrote %d records, want the 2 new ones", len(ups))
	}
	r.sweep(t) // both answer again, a minute later: nothing changed worth writing
	if n, ups, _ := r.store.reset(); n != 0 || len(ups) != 0 {
		t.Fatalf("an unchanged sweep wrote %d records in %d calls", len(ups), n)
	}
	r.clock.advance(answeredPersistEvery)
	r.sweep(t) // an hour on: last_answered is refreshed, once
	if _, ups, _ := r.store.reset(); len(ups) != 2 {
		t.Fatalf("hourly liveness refresh wrote %d records, want 2", len(ups))
	}

	// A failed write keeps the change and the next poll retries it.
	r.store.fail = true
	r.live.set(map[string]string{"10.66.0.1": "edge-1", "10.66.0.2": "edge-2", "10.66.0.3": "edge-3"})
	r.sweep(t)
	var buf bytes.Buffer
	r.src.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_discovery_found_store_errors_total{source="snmp"} 1`) {
		t.Fatalf("the failed write is not counted:\n%s", buf.String())
	}
	r.store.reset()
	r.store.fail = false
	// A cooled-down poll is enough to retry: the write does not wait for evidence.
	if _, err := r.src.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, ups, _ := r.store.reset()
	if len(ups) != 1 || ups[0].Address != "10.66.0.3" {
		t.Fatalf("retry wrote %+v, want exactly the record that failed", ups)
	}
	recs, err := r.store.Load(context.Background(), "", true)
	if err != nil || len(recs) != 3 {
		t.Fatalf("store after retry: %v %d records", err, len(recs))
	}
}

func TestScanMemoryIsBounded(t *testing.T) {
	kv := newPrefixMemKV()
	st := NewFileFoundStore("/data/discovered_devices.json", kv)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	recs := make([]FoundRecord, 0, maxFound+1)
	for i := 0; i < maxFound+1; i++ {
		addr := []byte{172, 16, byte(i >> 8), byte(i)}
		a := fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
		recs = append(recs, FoundRecord{Source: "snmp", Address: a, DeviceID: "d-" + a,
			FirstFound: base, LastAnswered: base.Add(time.Duration(i) * time.Second)})
	}
	if err := st.Apply(context.Background(), recs, nil); err != nil {
		t.Fatal(err)
	}
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	devs, _ := r.src.Restored()
	if len(devs) != maxFound {
		t.Fatalf("restored %d devices, want the bound %d", len(devs), maxFound)
	}
	for _, d := range devs {
		if d.Address == recs[0].Address {
			t.Fatal("the bound dropped a recently answered device instead of the least recent")
		}
	}
	// A full memory does not grow from a sweep either.
	r.live.set(map[string]string{"10.66.0.1": "newcomer"})
	if n := len(r.sweep(t)); n != maxFound {
		t.Fatalf("a full memory grew to %d", n)
	}
	var buf bytes.Buffer
	r.src.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `netops_discovery_found_dropped_total{source="snmp"} 2`) {
		t.Fatalf("drops not counted:\n%s", buf.String())
	}
}

// ── the file backend ─────────────────────────────────────────────────────────

func TestFileFoundStoreRefusesACorruptLoad(t *testing.T) {
	good := FoundRecord{Source: "snmp", Address: "10.66.0.1", DeviceID: "edge-1-x"}
	cases := map[string]func(kv *prefixMemKV, st *FileFoundStore){
		"undecodable": func(kv *prefixMemKV, st *FileFoundStore) {
			kv.m[st.prefix+"deadbeef"] = []byte("{not json")
		},
		"name-content-mismatch": func(kv *prefixMemKV, st *FileFoundStore) {
			b, _ := json.Marshal(good)
			kv.m[st.keyFor(FoundKey{Source: "snmp", Address: "10.66.0.2"})] = b
		},
		"tenant-forged-under-another-name": func(kv *prefixMemKV, st *FileFoundStore) {
			forged := good
			forged.TenantID = "t_acme"
			b, _ := json.Marshal(forged)
			kv.m[st.keyFor(good.Key())] = b // the '' partition's name, acme's content
		},
		"invalid-address": func(kv *prefixMemKV, st *FileFoundStore) {
			bad := good
			bad.Address = "not-an-ip"
			b, _ := json.Marshal(bad)
			kv.m[st.keyFor(bad.Key())] = b
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			kv := newPrefixMemKV()
			st := NewFileFoundStore("/data/discovered_devices.json", kv)
			if err := st.Apply(context.Background(), []FoundRecord{good}, nil); err != nil {
				t.Fatal(err)
			}
			corrupt(kv, st)
			if recs, err := st.Load(context.Background(), "", true); err == nil {
				t.Fatalf("a corrupt store loaded %d records instead of refusing", len(recs))
			}
		})
	}
	// And a record that is not valid is refused on the way in.
	st := NewFileFoundStore("/data/discovered_devices.json", newPrefixMemKV())
	if err := st.Apply(context.Background(), []FoundRecord{{Source: "snmp", Address: "x", DeviceID: "d"}}, nil); err == nil {
		t.Fatal("an invalid record was written")
	}
}

// §3a: the file store itself scopes every read by tenant.
func TestFileFoundStoreIsTenantScoped(t *testing.T) {
	st := NewFileFoundStore("/data/discovered_devices.json", newPrefixMemKV())
	recs := []FoundRecord{
		{TenantID: "", Source: "snmp", Address: "10.66.0.1", DeviceID: "plat"},
		{TenantID: "T_Acme", Source: "snmp", Address: "10.66.0.1", DeviceID: "acme"}, // same address, other tenant
		{TenantID: "t_globex", Source: "snmp", Address: "10.66.0.2", DeviceID: "globex"},
	}
	if err := st.Apply(context.Background(), recs, nil); err != nil {
		t.Fatal(err)
	}
	ids := func(tenant string, cross bool) string {
		got, err := st.Load(context.Background(), tenant, cross)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range got {
			out = append(out, r.DeviceID)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := ids("t_acme", false); got != "acme" {
		t.Fatalf("acme sees %q, want only its own row", got)
	}
	if got := ids("t_globex", false); got != "globex" {
		t.Fatalf("globex sees %q", got)
	}
	if got := ids("", false); got != "plat" {
		t.Fatalf("the platform partition sees %q — '' is a partition, not a wildcard", got)
	}
	if got := ids("t_nobody", false); got != "" {
		t.Fatalf("an unknown tenant sees %q", got)
	}
	if got := ids("t_acme", true); got != "acme,globex,plat" {
		t.Fatalf("the cross-tenant read sees %q", got)
	}
	// A prune is scoped by its key's tenant: acme's prune leaves the platform row.
	if err := st.Apply(context.Background(), nil, []FoundKey{{TenantID: "t_acme", Source: "snmp", Address: "10.66.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if got := ids("", true); got != "globex,plat" {
		t.Fatalf("after acme's prune: %q", got)
	}
}

func TestMergedRecordIsStaleOnlyIfEveryRecordIs(t *testing.T) {
	stale := models.Device{ID: "snmp-a", Source: "snmp", Address: "10.1.1.1", DiscoveryStale: true}
	live := models.Device{ID: "static-a", Source: "static", Address: "10.1.1.1"}
	if mergeDevices(stale, live).DiscoveryStale || mergeDevices(live, stale).DiscoveryStale {
		t.Fatal("one source still hearing the device must keep the merged record live")
	}
	other := models.Device{ID: "netbox-a", Source: "netbox", Address: "10.1.1.1", DiscoveryStale: true}
	if !mergeDevices(stale, other).DiscoveryStale {
		t.Fatal("every record stale must merge stale")
	}
}

func TestIngestKeepsAStaleDevicesLastAnswer(t *testing.T) {
	kv := newPrefixMemKV()
	seedStore(t, kv)
	r := newScanRig(t, kv)
	if err := r.src.Restore(context.Background(), r.store); err != nil {
		t.Fatal(err)
	}
	r.live.set(nil)
	for i := 0; i < staleAfterMisses; i++ {
		r.sweep(t)
	}
	a := NewDiscoveryAggregator()
	a.Register(r.src)
	r.clock.advance(ScanCooldown + time.Second)
	a.PollOnceForTest(context.Background(), r.src)
	reported := map[string]time.Time{}
	for _, d := range r.src.snapshot() {
		reported[d.ID] = d.LastSeen
	}
	for _, d := range a.Devices() {
		if !d.DiscoveryStale {
			t.Fatalf("%s lost its stale mark in the aggregator", d.ID)
		}
		if !d.LastSeen.Equal(reported[d.ID]) {
			t.Fatalf("a stale device was stamped seen %v, but it last answered %v", d.LastSeen, reported[d.ID])
		}
	}
}
