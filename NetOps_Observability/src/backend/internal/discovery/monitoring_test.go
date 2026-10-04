// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery_test

// monitoring_test.go — the device registry's monitoring model (owner decision
// 2026-10-03): every addressable inventory device is monitored, up to the
// licence ceiling, in FIRST-SEEN order.
//
// What this file proves is what nothing above the registry can: the first-seen
// order is the registry's own and survives a restart, one physical device takes
// one slot however many sources report it, and a freed slot (a delete, a device
// leaving its source, a bigger licence) promotes the next device in line with no
// operator action.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// memLedger is an in-memory FirstSeenStore.
type memLedger struct {
	mu      sync.Mutex
	recs    []discovery.FirstSeenRecord
	saves   int
	saveErr error
}

func (m *memLedger) FirstSeenRecords() []discovery.FirstSeenRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]discovery.FirstSeenRecord(nil), m.recs...)
}

func (m *memLedger) SaveFirstSeen(recs []discovery.FirstSeenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saves++
	m.recs = append([]discovery.FirstSeenRecord(nil), recs...)
	return nil
}

func (m *memLedger) at(id string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.recs {
		if r.DeviceID == id {
			return r.FirstSeen, true
		}
	}
	return time.Time{}, false
}

// fixedSource reports a fixed device list under a chosen source name.
type fixedSource struct {
	name    string
	devices []models.Device
}

func (f *fixedSource) Name() string            { return f.name }
func (f *fixedSource) Interval() time.Duration { return time.Minute }
func (f *fixedSource) Poll(context.Context) ([]models.Device, error) {
	return append([]models.Device(nil), f.devices...), nil
}

// limitOf returns a fixed ceiling.
func limitOf(n int) func() int { return func() int { return n } }

// seededLedger pre-records first-seen times so a test controls the licence
// order exactly: ids[0] was seen first, ids[1] a minute later, and so on.
func seededLedger(ids ...string) *memLedger {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := &memLedger{}
	for i, id := range ids {
		l.recs = append(l.recs, discovery.FirstSeenRecord{DeviceID: id, FirstSeen: base.Add(time.Duration(i) * time.Minute)})
	}
	return l
}

func dev(id, addr string) models.Device {
	return models.Device{ID: id, Name: id, Address: addr}
}

func states(a *discovery.DiscoveryAggregator) map[string]models.Device {
	out := map[string]models.Device{}
	for _, d := range a.Devices() {
		out[d.ID] = d
	}
	return out
}

func monitoredIDs(a *discovery.DiscoveryAggregator) []string {
	var out []string
	for _, d := range a.Devices() {
		if d.Monitored {
			out = append(out, d.ID)
		}
	}
	return out
}

func TestEveryAddressableDeviceIsMonitoredWhateverItsSource(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	scan := &fixedSource{name: devmon.SourceSubnetScan}
	declared := &fixedSource{name: devmon.SourceStatic}
	for i := 0; i < 5; i++ {
		scan.devices = append(scan.devices, dev("scan-"+strconv.Itoa(i), "10.1.0."+strconv.Itoa(i+1)))
		declared.devices = append(declared.devices, dev("static-"+strconv.Itoa(i), "10.2.0."+strconv.Itoa(i+1)))
	}
	a.PollOnceForTest(context.Background(), scan)
	a.PollOnceForTest(context.Background(), declared)

	if got := a.MonitoredCount(); got != 10 {
		t.Fatalf("monitored = %d, want all 10 — a device found by a subnet scan is monitored like any other", got)
	}
	for _, d := range a.Devices() {
		if !d.Monitored || d.MonitorState != devmon.StateMonitored || d.MonitorReason != devmon.ReasonMonitored {
			t.Fatalf("%s: monitored=%v state=%q reason=%q", d.ID, d.Monitored, d.MonitorState, d.MonitorReason)
		}
		if len(d.MonitorMethods) == 0 {
			t.Fatalf("%s is monitored but names no telemetry", d.ID)
		}
	}
}

func TestAnAddresslessDeviceIsNeverMonitoredAndTakesNoSlot(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetFirstSeenStore(seededLedger("ghost", "real"))
	a.SetMonitorLimit(limitOf(1))
	a.PollOnceForTest(context.Background(), &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "ghost", Name: "ghost"}, // seen FIRST, but nothing can reach it
		dev("real", "10.0.0.1"),
	}})
	s := states(a)
	if g := s["ghost"]; g.Monitored || g.MonitorState != devmon.StateNoAddress || g.MonitorReason != devmon.ReasonNoAddress {
		t.Fatalf("addressless device: %+v", g)
	}
	if r := s["real"]; !r.Monitored {
		t.Fatalf("the addressless device must not consume the only slot: %+v", r)
	}
	if a.MonitoringWithheldCount() != 0 {
		t.Fatal("an addressless device is not 'over the limit' — it is unreachable")
	}
}

func TestTheFirstNByFirstSeenAreMonitoredAndTheRestAreOverTheLimit(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	// Seen order d3, d1, d4, d0, d2 — deliberately not the id order.
	a.SetFirstSeenStore(seededLedger("d3", "d1", "d4", "d0", "d2"))
	a.SetMonitorLimit(limitOf(3))
	src := &fixedSource{name: devmon.SourceSubnetScan}
	for i := 0; i < 5; i++ {
		src.devices = append(src.devices, dev("d"+strconv.Itoa(i), "10.0.0."+strconv.Itoa(i+1)))
	}
	a.PollOnceForTest(context.Background(), src)

	if got := strings.Join(monitoredIDs(a), ","); !sameSet(got, "d3,d1,d4") {
		t.Fatalf("monitored = %s, want the first three seen: d3,d1,d4", got)
	}
	s := states(a)
	for _, id := range []string{"d0", "d2"} {
		d := s[id]
		if d.Monitored || d.MonitorState != devmon.StateOverLimit || d.MonitorLimit != 3 {
			t.Fatalf("%s must be over the limit of 3: %+v", id, d)
		}
		if !strings.Contains(d.MonitorReason, "licence limit of 3") || len(d.MonitorMethods) != 0 {
			t.Fatalf("%s reason/methods: %q %v", id, d.MonitorReason, d.MonitorMethods)
		}
	}
	// Nothing was dropped: all five are in the inventory.
	if got := len(a.Devices()); got != 5 {
		t.Fatalf("inventory = %d, want 5 — over-limit devices stay", got)
	}
	if a.MonitoredCount() != 3 || a.MonitoringWithheldCount() != 2 {
		t.Fatalf("counts: monitored=%d over=%d", a.MonitoredCount(), a.MonitoringWithheldCount())
	}
}

func sameSet(csv, want string) bool {
	got := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		got[s] = true
	}
	w := strings.Split(want, ",")
	if len(got) != len(w) {
		return false
	}
	for _, s := range w {
		if !got[s] {
			return false
		}
	}
	return true
}

func TestDeletingAMonitoredDevicePromotesTheNextInLine(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetFirstSeenStore(seededLedger("m1", "m2", "m3"))
	a.SetMonitorLimit(limitOf(2))
	for _, d := range []models.Device{dev("m1", "10.0.0.1"), dev("m2", "10.0.0.2"), dev("m3", "10.0.0.3")} {
		if err := a.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	if s := states(a); s["m3"].Monitored {
		t.Fatal("precondition: m3 is third in line and over a limit of 2")
	}
	if err := a.Delete("m1"); err != nil {
		t.Fatal(err)
	}
	s := states(a)
	if !s["m3"].Monitored || !s["m2"].Monitored {
		t.Fatalf("m1's slot must pass to m3 automatically: %+v", s)
	}
	if a.MonitoringWithheldCount() != 0 {
		t.Fatal("nothing is over the limit any more")
	}
}

func TestADeviceLeavingItsSourceFreesItsSlotAndRejoinsAtTheBack(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	ledger := seededLedger("a", "b")
	a.SetFirstSeenStore(ledger)
	a.SetMonitorLimit(limitOf(1))
	src := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{dev("a", "10.0.0.1"), dev("b", "10.0.0.2")}}
	a.PollOnceForTest(context.Background(), src)
	if got := monitoredIDs(a); len(got) != 1 || got[0] != "a" {
		t.Fatalf("precondition: a is first, got %v", got)
	}
	src.devices = []models.Device{dev("b", "10.0.0.2")}
	a.PollOnceForTest(context.Background(), src)
	if got := monitoredIDs(a); len(got) != 1 || got[0] != "b" {
		t.Fatalf("b must take a's freed slot, got %v", got)
	}
	if _, ok := ledger.at("a"); ok {
		t.Fatal("a device that left the inventory must leave the persisted ledger")
	}
	// a returns: it is a NEW arrival now and must not displace b.
	src.devices = []models.Device{dev("a", "10.0.0.1"), dev("b", "10.0.0.2")}
	a.PollOnceForTest(context.Background(), src)
	if got := monitoredIDs(a); len(got) != 1 || got[0] != "b" {
		t.Fatalf("a returning must join the back of the line, got %v", got)
	}
}

func TestLicenceGrowthPromotesWithoutAnyOperatorAction(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	limit := 1
	var mu sync.Mutex
	a.SetMonitorLimit(func() int { mu.Lock(); defer mu.Unlock(); return limit })
	a.SetFirstSeenStore(seededLedger("x", "y", "z"))
	a.PollOnceForTest(context.Background(), &fixedSource{name: devmon.SourceSubnetScan, devices: []models.Device{
		dev("x", "10.0.0.1"), dev("y", "10.0.0.2"), dev("z", "10.0.0.3"),
	}})
	if a.MonitoredCount() != 1 || a.MonitoringWithheldCount() != 2 {
		t.Fatalf("precondition: 1 monitored, 2 over; got %d, %d", a.MonitoredCount(), a.MonitoringWithheldCount())
	}
	mu.Lock()
	limit = 2
	mu.Unlock()
	if s := states(a); !s["y"].Monitored || s["z"].Monitored {
		t.Fatalf("growing the licence to 2 must promote y (next in line) and only y: %+v", s)
	}
	mu.Lock()
	limit = devmon.NoLimit
	mu.Unlock()
	if a.MonitoredCount() != 3 || a.MonitoringWithheldCount() != 0 {
		t.Fatal("an unlimited licence monitors every addressable device")
	}
}

func TestTheOrderSurvivesARestartWhicheverSourcePollsFirst(t *testing.T) {
	ledger := &memLedger{}
	early := &fixedSource{name: devmon.SourceStatic, devices: []models.Device{dev("early", "10.0.0.1")}}
	late := &fixedSource{name: devmon.SourceSubnetScan, devices: []models.Device{dev("late", "10.0.0.2")}}

	a := discovery.NewDiscoveryAggregator()
	a.SetFirstSeenStore(ledger)
	a.SetMonitorLimit(limitOf(1))
	a.PollOnceForTest(context.Background(), early)
	time.Sleep(2 * time.Millisecond) // distinct first-seen instants
	a.PollOnceForTest(context.Background(), late)
	if got := monitoredIDs(a); len(got) != 1 || got[0] != "early" {
		t.Fatalf("precondition: early holds the slot, got %v", got)
	}

	// Restart: a fresh registry over the same ledger, and this time the scan
	// happens to poll first. It must NOT take the slot.
	b := discovery.NewDiscoveryAggregator()
	b.SetFirstSeenStore(ledger)
	b.SetMonitorLimit(limitOf(1))
	b.PollOnceForTest(context.Background(), late)
	b.PollOnceForTest(context.Background(), early)
	if got := monitoredIDs(b); len(got) != 1 || got[0] != "early" {
		t.Fatalf("after a restart the licence order must be the persisted one, got %v", got)
	}
}

func TestALedgerWriteFailureIsNotFatal(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetFirstSeenStore(&memLedger{saveErr: errStr("disk full")})
	if err := a.Upsert(dev("d1", "10.0.0.1")); err != nil {
		t.Fatalf("the device was stored; a ledger failure must not refuse it: %v", err)
	}
	if a.MonitoredCount() != 1 {
		t.Fatal("the in-memory order still applies")
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

func TestOneDeviceReportedByTwoSourcesTakesOneSlot(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorLimit(limitOf(1))
	// The SAME box: a NetBox record and the SNMP scan that found it. They share
	// a management address, so dedupe folds them into one device.
	a.PollOnceForTest(context.Background(), &fixedSource{name: devmon.SourceNetbox, devices: []models.Device{
		{ID: "netbox-1", Name: "leaf1", Address: "10.0.0.1"},
	}})
	a.PollOnceForTest(context.Background(), &fixedSource{name: devmon.SourceSubnetScan, devices: []models.Device{
		{ID: "snmp-leaf1", Name: "leaf1", Address: "10.0.0.1"},
	}})
	if got := len(a.Devices()); got != 1 {
		t.Fatalf("the two records are one device, got %d", got)
	}
	if a.MonitoredCount() != 1 || a.MonitoringWithheldCount() != 0 {
		t.Fatalf("one physical device is one slot: monitored=%d over=%d", a.MonitoredCount(), a.MonitoringWithheldCount())
	}
	// The same hostname and address in ANOTHER tenant is a different device and
	// does take a slot of its own (here: over the limit of 1).
	a.PollOnceForTest(context.Background(), &fixedSource{name: devmon.SourceStatic, devices: []models.Device{
		{ID: "other-leaf1", Name: "leaf1", Address: "10.0.0.1", TenantID: "globex"},
	}})
	if a.MonitoredCount() != 1 || a.MonitoringWithheldCount() != 1 {
		t.Fatalf("another tenant's same-named box is a second device: monitored=%d over=%d", a.MonitoredCount(), a.MonitoringWithheldCount())
	}
}

func TestACreatePastTheCeilingIsStoredAndMarkedOverTheLimit(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorLimit(limitOf(0))
	d, created, err := a.CreateOrResolve(dev("new", "10.9.9.9"))
	if err != nil || !created {
		t.Fatalf("a create is never refused by the licence: created=%v err=%v", created, err)
	}
	if d.Monitored || d.MonitorState != devmon.StateOverLimit {
		t.Fatalf("the create must report the device's real state: %+v", d)
	}
}

func TestClientSuppliedMonitoringStateIsDiscarded(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorLimit(limitOf(0))
	// A device that claims to be monitored, the way a crafted POST body would.
	err := a.Upsert(models.Device{
		ID: "scan-1", Name: "scan-1", Address: "10.0.0.1", Source: "snmp",
		Monitored: true, MonitorState: devmon.StateMonitored, MonitorReason: "trust me", MonitorMethods: []string{"snmp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.MonitoredCount() != 0 {
		t.Fatal("monitoring is server state; a caller's claim must be discarded")
	}
	d, ok := a.Get("scan-1")
	if !ok {
		t.Fatal("the device must exist")
	}
	if d.Monitored || d.MonitorReason == "trust me" || d.MonitorState != devmon.StateOverLimit {
		t.Fatalf("the claim leaked into the registry: %+v", d)
	}
}

// TestMonitoredOverCeiling is the SOFT-overage listing (paid tiers, where the
// registry has no ceiling and every device is collected from): which monitored
// devices are beyond the allowance — the ones first seen after the first N,
// newest first.
func TestMonitoredOverCeiling(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	ids := []string{"dev-0", "dev-1", "dev-2", "dev-3", "dev-4", "dev-5"}
	a.SetFirstSeenStore(seededLedger(ids...))
	for i, id := range ids {
		if err := a.Upsert(models.Device{ID: id, Name: id, Address: "10.20.0." + strconv.Itoa(i+1), Source: devmon.SourceStatic}); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.MonitoredCount(); got != 6 {
		t.Fatalf("harness: %d monitored, want 6", got)
	}
	if rows := a.MonitoredOverCeiling(6); len(rows) != 0 {
		t.Fatalf("exactly at the allowance nothing is over: %+v", rows)
	}
	if rows := a.MonitoredOverCeiling(-1); len(rows) != 0 {
		t.Fatal("there is no `beyond` an unlimited allowance")
	}
	rows := a.MonitoredOverCeiling(4)
	if len(rows) != 2 || rows[0].DeviceID != "dev-5" || rows[1].DeviceID != "dev-4" {
		t.Fatalf("want the two last-seen devices, newest first, got %+v", rows)
	}
	if got := a.MonitoredCount(); got != 6 {
		t.Fatalf("listing must not disable anything: %d monitored, want 6", got)
	}
}
