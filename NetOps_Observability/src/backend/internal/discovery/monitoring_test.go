// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery_test

// monitoring_test.go — the device registry's monitoring state machine.
//
// The registry is where the monitoring decision LIVES, so this file proves the
// three properties nothing above it can: a decision survives a restart, a
// device that two sources report is ONE monitored device, and the ceiling is
// asked once, at the transition, under the same lock as the write.

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// memMonitorStore is an in-memory MonitorStore.
type memMonitorStore struct {
	mu      sync.Mutex
	records map[string]devmon.Record
	putErr  error
	puts    int
}

func newMemMonitorStore() *memMonitorStore {
	return &memMonitorStore{records: map[string]devmon.Record{}}
}

func (m *memMonitorStore) MonitorRecords() []devmon.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]devmon.Record, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	return out
}

func (m *memMonitorStore) PutMonitor(r devmon.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.puts++
	m.records[r.DeviceID] = r
	return nil
}

func (m *memMonitorStore) DeleteMonitor(_, deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, deviceID)
	return nil
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

func TestMonitoringDecisionSurvivesARestart(t *testing.T) {
	store := newMemMonitorStore()
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorStore(store)
	if err := a.Upsert(models.Device{ID: "d1", Name: "d1", Address: "10.0.0.1", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if a.MonitoredCount() != 1 {
		t.Fatal("a declared device is monitored by default")
	}
	if _, err := a.SetMonitoring("d1", false, "op"); err != nil {
		t.Fatal(err)
	}
	if a.MonitoredCount() != 0 {
		t.Fatal("the decision must take effect")
	}

	// A second aggregator over the same store is the restart.
	b := discovery.NewDiscoveryAggregator()
	b.SetMonitorStore(store)
	if err := b.Upsert(models.Device{ID: "d1", Name: "d1", Address: "10.0.0.1", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if b.MonitoredCount() != 0 {
		t.Fatal("a decision that does not survive a restart is a device silently monitored again")
	}
	rec, ok := b.MonitoringDecision("d1")
	if !ok || rec.Enabled || rec.UpdatedBy != "op" {
		t.Fatalf("the stored decision must carry who made it: %+v ok=%v", rec, ok)
	}
}

func TestMonitoringIsNotClaimedWhenItDoesNotPersist(t *testing.T) {
	store := newMemMonitorStore()
	a := discovery.NewDiscoveryAggregator()
	a.SetMonitorStore(store)
	if err := a.Upsert(models.Device{ID: "d1", Address: "10.0.0.1", Source: "snmp"}); err != nil {
		t.Fatal(err)
	}
	store.putErr = errNotPersisted
	if _, err := a.SetMonitoring("d1", true, "op"); err == nil {
		t.Fatal("a decision that did not persist must be reported as a failure, not answered 200")
	}
	if a.MonitoredCount() != 0 {
		t.Fatal("the in-memory state must not claim what the store refused")
	}
}

var errNotPersisted = errStr("disk full")

type errStr string

func (e errStr) Error() string { return string(e) }

func TestOneDeviceReportedByTwoSourcesIsOneMonitoredDevice(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	// The SAME box: a NetBox record and the SNMP scan that found it. They share
	// a management address, so dedupe folds them into one device.
	netbox := &fixedSource{name: "netbox", devices: []models.Device{
		{ID: "netbox-1", Name: "leaf1", Address: "10.0.0.1"},
	}}
	scan := &fixedSource{name: "snmp", devices: []models.Device{
		{ID: "snmp-leaf1", Name: "leaf1", Address: "10.0.0.1"},
	}}
	a.PollOnceForTest(context.Background(), netbox)
	a.PollOnceForTest(context.Background(), scan)

	if got := len(a.Devices()); got != 1 {
		t.Fatalf("the two records are one device, got %d", got)
	}
	if got := a.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — never one per source record", got)
	}
}

func TestSourceReportedDevicesTakeTheirSourcesDefault(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	scan := &fixedSource{name: "snmp"}
	declared := &fixedSource{name: "static"}
	for i := 0; i < 5; i++ {
		scan.devices = append(scan.devices, models.Device{
			ID: "scan-" + strconv.Itoa(i), Name: "scan-" + strconv.Itoa(i),
			Address: "10.1.0." + strconv.Itoa(i),
		})
		declared.devices = append(declared.devices, models.Device{
			ID: "static-" + strconv.Itoa(i), Name: "static-" + strconv.Itoa(i),
			Address: "10.2.0." + strconv.Itoa(i),
		})
	}
	a.PollOnceForTest(context.Background(), scan)
	a.PollOnceForTest(context.Background(), declared)

	if got := len(a.Devices()); got != 10 {
		t.Fatalf("inventory = %d, want 10", got)
	}
	if got := a.MonitoredCount(); got != 5 {
		t.Fatalf("monitored = %d, want the 5 DECLARED ones — a scan result is a candidate", got)
	}
	for _, d := range a.Devices() {
		if d.MonitorReason == "" {
			t.Fatalf("%s has no reason for its state", d.ID)
		}
		if d.Monitored && len(d.MonitorMethods) == 0 {
			t.Fatalf("%s is monitored but names no telemetry", d.ID)
		}
	}
}

func TestTheCeilingIsAskedOnlyAtTheTransition(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	asked := 0
	a.SetMonitorGate(func(current int) error {
		asked++
		if current >= 2 {
			return errNotPersisted // any refusal
		}
		return nil
	})
	dev := models.Device{ID: "d1", Name: "d1", Address: "10.0.0.1", Source: "manual"}
	if err := a.Upsert(dev); err != nil {
		t.Fatal(err)
	}
	first := asked
	if first == 0 {
		t.Fatal("creating a monitored device must ask the ceiling")
	}
	// Re-writing the SAME device, and adding telemetry to it, asks nothing: it
	// is already counted.
	dev.CredentialRef = "lab"
	dev.Labels = map[string]string{"gnmi": "true"}
	if err := a.Upsert(dev); err != nil {
		t.Fatal(err)
	}
	if asked != first {
		t.Fatalf("the ceiling was asked again for a device already monitored (%d → %d)", first, asked)
	}
	// Turning monitoring OFF can only free capacity: it must not be gated.
	if _, err := a.SetMonitoring("d1", false, "op"); err != nil {
		t.Fatal(err)
	}
	if asked != first {
		t.Fatalf("turning monitoring off must never be refused by a ceiling (%d → %d)", first, asked)
	}
}

func TestWithheldMonitoringIsListedAndReleasable(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	limit := 2
	a.SetMonitorGate(func(current int) error {
		if current >= limit {
			return errNotPersisted
		}
		return nil
	})
	src := &fixedSource{name: "static"}
	for i := 0; i < 5; i++ {
		src.devices = append(src.devices, models.Device{
			ID: "s" + strconv.Itoa(i), Name: "s" + strconv.Itoa(i), Address: "10.3.0." + strconv.Itoa(i),
		})
	}
	a.PollOnceForTest(context.Background(), src)

	if got := len(a.Devices()); got != 5 {
		t.Fatalf("every device must be in the inventory, got %d — the ceiling never blocks discovery", got)
	}
	if got := a.MonitoredCount(); got != 2 {
		t.Fatalf("monitored = %d, want 2", got)
	}
	withheld := a.MonitoringWithheld()
	if len(withheld) != 3 || a.MonitoringWithheldCount() != 3 {
		t.Fatalf("3 devices must be listed as withheld, got %d", len(withheld))
	}
	for _, w := range withheld {
		if w.Reason == "" || w.Name == "" {
			t.Fatalf("a withheld device must be identifiable and explained: %+v", w)
		}
	}
	// The withheld devices are visible and carry the reason on the device row.
	for _, d := range a.Devices() {
		if !d.Monitored && d.MonitorReason == "" {
			t.Fatalf("%s is not monitored and does not say why", d.ID)
		}
	}

	// Raising the ceiling starts collecting from them on the next poll, with no
	// operator action.
	limit = 5
	a.PollOnceForTest(context.Background(), src)
	if got := a.MonitoredCount(); got != 5 {
		t.Fatalf("monitored = %d, want 5 after the ceiling rose", got)
	}
	if got := a.MonitoringWithheldCount(); got != 0 {
		t.Fatalf("withheld = %d, want 0", got)
	}
}

func TestSetMonitoringOnAnUnknownDevice(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	if _, err := a.SetMonitoring("nope", true, "op"); err == nil {
		t.Fatal("an unknown device must be refused, never created")
	} else if !errors.Is(err, devmon.ErrUnknownDevice) {
		t.Fatalf("err = %v, want the shared sentinel so a caller can answer 404", err)
	}
}

func TestClientSuppliedMonitoringStateIsDiscarded(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	// A scan result that claims to be monitored, the way a crafted POST body
	// would.
	err := a.Upsert(models.Device{
		ID: "scan-1", Name: "scan-1", Address: "10.0.0.1", Source: "snmp",
		Monitored: true, MonitorReason: "trust me", MonitorMethods: []string{"snmp"},
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
	if d.Monitored || d.MonitorReason == "trust me" {
		t.Fatalf("the claim leaked into the registry: %+v", d)
	}
}

// TestMonitoredOverCeiling is the SOFT-overage listing: which monitored devices
// are beyond the allowance, most recently enabled first.
//
// The ordering is presentational and the API says so in words; what this test
// pins is that it is DETERMINISTIC (two reads never disagree) and that nothing
// about appearing on the list changes a device's state.
func TestMonitoredOverCeiling(t *testing.T) {
	a := discovery.NewDiscoveryAggregator()
	// Six DECLARED devices: monitored by provenance, no explicit decision.
	for i := 0; i < 6; i++ {
		if err := a.Upsert(models.Device{
			ID: "dev-" + strconv.Itoa(i), Name: "dev-" + strconv.Itoa(i),
			Address: "10.20.0." + strconv.Itoa(i+1), Source: devmon.SourceStatic,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.MonitoredCount(); got != 6 {
		t.Fatalf("harness: %d monitored, want 6", got)
	}

	if rows := a.MonitoredOverCeiling(6); len(rows) != 0 {
		t.Fatalf("exactly at the allowance nothing is over: %+v", rows)
	}
	if rows := a.MonitoredOverCeiling(10); len(rows) != 0 {
		t.Fatalf("under the allowance nothing is over: %+v", rows)
	}
	if rows := a.MonitoredOverCeiling(-1); len(rows) != 0 {
		t.Fatal("there is no `beyond` an unlimited allowance")
	}

	rows := a.MonitoredOverCeiling(4)
	if len(rows) != 2 {
		t.Fatalf("6 monitored against an allowance of 4 is 2 over, got %d: %+v", len(rows), rows)
	}
	// Deterministic: the same read twice gives the same answer, or the page
	// reshuffles under the operator every poll.
	again := a.MonitoredOverCeiling(4)
	for i := range rows {
		if rows[i].DeviceID != again[i].DeviceID {
			t.Fatalf("the ordering must be stable: %v then %v", rows, again)
		}
	}
	// With no explicit decisions the fallback is the device id, descending, so
	// the highest-numbered devices are the ones shown as "beyond".
	if rows[0].DeviceID != "dev-5" || rows[1].DeviceID != "dev-4" {
		t.Fatalf("want the last-added devices listed first, got %+v", rows)
	}

	// An OPERATOR decision is newer than any provenance default, so a device
	// enabled by hand sorts to the front.
	if _, err := a.SetMonitoring("dev-0", true, "operator@example.test"); err != nil {
		t.Fatal(err)
	}
	rows = a.MonitoredOverCeiling(4)
	if len(rows) != 2 || rows[0].DeviceID != "dev-0" {
		t.Fatalf("the most recently ENABLED device leads the list, got %+v", rows)
	}

	// Nothing about the listing changes any device's state: all six are still
	// monitored, and none was withheld.
	if got := a.MonitoredCount(); got != 6 {
		t.Fatalf("listing must not disable anything: %d monitored, want 6", got)
	}
	if got := a.MonitoringWithheldCount(); got != 0 {
		t.Fatalf("a soft overage withholds nothing: %d withheld", got)
	}
}
