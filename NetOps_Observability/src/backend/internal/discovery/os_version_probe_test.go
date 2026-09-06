package discovery

// os_version_probe_test.go — the OS-VERSION SOURCE LADDER as the enrichment tick
// runs it: which devices get probed, what lands on the row, and what is
// persisted.
//
// The scenario throughout is the reference lab's: a MANUAL row carrying
// `vendor: nokia`, `os: "SR Linux"` and no version, on a device whose SNMP agent
// does not exist and whose SSH answers `show version`.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/osprobe"
	"netops/backend/models"
)

// probeStore is an in-memory DeviceStore that records what was persisted.
type probeStore struct {
	mu      sync.Mutex
	rows    map[string]models.Device
	putErr  error
	putCall int
}

func newProbeStore(seed ...models.Device) *probeStore {
	st := &probeStore{rows: map[string]models.Device{}}
	for _, d := range seed {
		st.rows[d.ID] = d
	}
	return st
}

func (s *probeStore) IsSuppressed(string) bool { return false }
func (s *probeStore) Put(d models.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putCall++
	if s.putErr != nil {
		return s.putErr
	}
	s.rows[d.ID] = d
	return nil
}
func (s *probeStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}
func (s *probeStore) Devices() []models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.Device, 0, len(s.rows))
	for _, d := range s.rows {
		out = append(out, d)
	}
	return out
}
func (s *probeStore) get(id string) models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[id]
}

// scriptedSource is a rung whose answer the test dictates, per device.
type scriptedSource struct {
	method  osprobe.Method
	answers map[string]string
	err     error

	mu    sync.Mutex
	calls []string
}

func (s *scriptedSource) Method() osprobe.Method { return s.method }
func (s *scriptedSource) Probe(_ context.Context, t osprobe.Target) (string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, t.DeviceID)
	s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	return s.answers[t.DeviceID], nil
}
func (s *scriptedSource) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func ladderOf(t *testing.T, sources ...osprobe.Source) *osprobe.Ladder {
	t.Helper()
	l, err := osprobe.NewLadder(func(string, map[string]any) {}, sources...)
	if err != nil {
		t.Fatalf("NewLadder: %v", err)
	}
	return l
}

const srlProbed = "SRLinux-v26.3.2"

// spineRow is the lab row this whole feature exists for.
func spineRow() models.Device {
	return models.Device{
		ID: "spine1", Name: "spine1", Address: "172.40.40.11",
		Vendor: "nokia", OS: "SR Linux", Source: "manual", TenantID: "acme",
	}
}

// TestEnrichmentLearnsTheVersionAndItsProvenance — the headline: a row that was
// permanently unassessable acquires a version, a source and a timestamp.
func TestEnrichmentLearnsTheVersionAndItsProvenance(t *testing.T) {
	store := newProbeStore(spineRow())
	a := NewDiscoveryAggregator()
	a.SetStore(store)
	snmp := &scriptedSource{method: osprobe.MethodSNMP, answers: map[string]string{}}
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}
	a.SetOSVersionLadder(ladderOf(t, snmp, ssh))

	a.enrichOSVersions(context.Background())

	got, ok := a.Get("spine1")
	if !ok {
		t.Fatal("device vanished")
	}
	if got.OSVersion != srlProbed {
		t.Errorf("os_version = %q, want %q", got.OSVersion, srlProbed)
	}
	if got.OSVersionSource != string(osprobe.MethodSSH) {
		t.Errorf("os_version_source = %q, want %q — a version with no stated source cannot be audited",
			got.OSVersionSource, osprobe.MethodSSH)
	}
	if got.OSVersionAt.IsZero() {
		t.Error("os_version_at was not stamped")
	}
	if snmp.called() == nil {
		t.Error("the top rung was skipped on an empty row")
	}
	// The row is OPERATOR-OWNED, so what was learned must survive a restart.
	if persisted := store.get("spine1"); persisted.OSVersion != srlProbed || persisted.OSVersionSource != "ssh" {
		t.Errorf("persisted row = %+v, want the learned version and its source", persisted)
	}
	// Tenancy travels with the row and is never rewritten by the probe.
	if got.TenantID != "acme" || store.get("spine1").TenantID != "acme" {
		t.Error("the probe changed the row's owning tenant")
	}
}

// TestEnrichmentLeavesAnUnanswerableDeviceAlone — the honest non-answer. A
// device no rung can read must keep an EMPTY version, not acquire an invented
// one, and must stay reported as unassessed downstream.
func TestEnrichmentLeavesAnUnanswerableDeviceAlone(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(spineRow()))
	a.SetOSVersionLadder(ladderOf(t,
		&scriptedSource{method: osprobe.MethodSNMP, err: errors.New("i/o timeout")},
		&scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{}},
	))

	a.enrichOSVersions(context.Background())

	got, _ := a.Get("spine1")
	if got.OSVersion != "" || got.OSVersionSource != "" {
		t.Errorf("invented %q via %q for a device nothing could read", got.OSVersion, got.OSVersionSource)
	}
}

// TestEnrichmentNeverErasesAWithATransientEmptyRead — overwrite rule 1, through
// the tick. A probe that answers with nothing must not blank a device's version
// and drop it back to unassessed.
func TestEnrichmentNeverErasesAWithATransientEmptyRead(t *testing.T) {
	row := spineRow()
	row.OSVersion, row.OSVersionSource = srlProbed, "ssh"
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	a.SetOSVersionLadder(ladderOf(t, &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{}}))

	a.enrichOSVersions(context.Background())

	if got, _ := a.Get("spine1"); got.OSVersion != srlProbed {
		t.Errorf("os_version = %q, want the earlier reading kept", got.OSVersion)
	}
}

// TestEnrichmentNeverProbesAnOperatorsRow — an operator-pinned version means the
// device is never dialled at all, because no answer could be used.
func TestEnrichmentNeverProbesAnOperatorsRow(t *testing.T) {
	row := spineRow()
	row.OSVersion, row.OSVersionSource = "SRLinux-v25.10.1", string(osprobe.MethodManual)
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}
	a.SetOSVersionLadder(ladderOf(t, ssh))

	a.enrichOSVersions(context.Background())

	if got := ssh.called(); len(got) != 0 {
		t.Errorf("dialled %v for an answer that could never be written", got)
	}
	if got, _ := a.Get("spine1"); got.OSVersion != "SRLinux-v25.10.1" {
		t.Errorf("os_version = %q, want the operator's value untouched", got.OSVersion)
	}
}

// TestEnrichmentRefreshesOnlyTheRungThatOwnsTheRow — overwrite rules 2 and 3
// through the tick.
func TestEnrichmentRefreshesOnlyTheRungThatOwnsTheRow(t *testing.T) {
	row := spineRow()
	row.OSVersion, row.OSVersionSource = srlProbed, string(osprobe.MethodSSH)
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	snmp := &scriptedSource{method: osprobe.MethodSNMP, answers: map[string]string{"spine1": "SRLinux-v27.0.0 sysdescr"}}
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": "SRLinux-v26.4.0"}}
	a.SetOSVersionLadder(ladderOf(t, snmp, ssh))

	a.enrichOSVersions(context.Background())

	got, _ := a.Get("spine1")
	if got.OSVersion != "SRLinux-v26.4.0" || got.OSVersionSource != "ssh" {
		t.Errorf("row = (%q via %q), want the SSH rung's refreshed reading", got.OSVersion, got.OSVersionSource)
	}
	if called := snmp.called(); len(called) != 0 {
		t.Errorf("the SNMP rung ran for a row it could not have written: %v", called)
	}
}

// TestEnrichmentSkipsDevicesItCannotProbe — no address is nothing to dial, and
// no vendor is nothing to resolve a profile with.
func TestEnrichmentSkipsDevicesItCannotProbe(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(
		models.Device{ID: "no-addr", Name: "no-addr", Vendor: "nokia", OS: "SR Linux", Source: "manual"},
		models.Device{ID: "no-vendor", Name: "no-vendor", Address: "10.0.0.9", OS: "SR Linux", Source: "manual"},
		spineRow(),
	))
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}
	a.SetOSVersionLadder(ladderOf(t, ssh))

	a.enrichOSVersions(context.Background())

	called := strings.Join(ssh.called(), ",")
	if called != "spine1" {
		t.Errorf("probed %q, want only spine1", called)
	}
}

// TestEnrichmentHonoursTheCoolDown — a fleet that cannot answer must not turn
// the two-minute enrichment tick into a permanent dial storm.
func TestEnrichmentHonoursTheCoolDown(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(spineRow()))
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{}}
	a.SetOSVersionLadder(ladderOf(t, ssh))

	a.enrichOSVersions(context.Background())
	a.enrichOSVersions(context.Background())
	if got := ssh.called(); len(got) != 1 {
		t.Fatalf("dialled %d times across two ticks, want 1 — the cool-down is not applied", len(got))
	}

	// Wind the clock back past the retry window: the device is due again.
	a.mu.Lock()
	a.osProbeAt["spine1"] = time.Now().UTC().Add(-osProbeRetryInterval - time.Minute)
	a.mu.Unlock()
	a.enrichOSVersions(context.Background())
	if got := ssh.called(); len(got) != 2 {
		t.Errorf("dialled %d times, want a retry once the cool-down expired", len(got))
	}
}

// TestEnrichmentBoundsOneTick — §9.
func TestEnrichmentBoundsOneTick(t *testing.T) {
	seed := make([]models.Device, 0, osProbeMaxPerTick*2)
	for i := 0; i < osProbeMaxPerTick*2; i++ {
		d := spineRow()
		d.ID = "spine" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		d.Name = d.ID
		seed = append(seed, d)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(seed...))
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{}}
	a.SetOSVersionLadder(ladderOf(t, ssh))

	a.enrichOSVersions(context.Background())
	if got := len(ssh.called()); got != osProbeMaxPerTick {
		t.Errorf("probed %d devices in one tick, want the bound of %d", got, osProbeMaxPerTick)
	}
}

// TestEnrichmentWalksTheFleetFairly — a fleet larger than the per-tick bound
// must not leave the tail permanently unprobed.
func TestEnrichmentWalksTheFleetFairly(t *testing.T) {
	total := osProbeMaxPerTick + 3
	seed := make([]models.Device, 0, total)
	for i := 0; i < total; i++ {
		d := spineRow()
		d.ID = "spine" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		d.Name = d.ID
		seed = append(seed, d)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(seed...))
	ssh := &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{}}
	a.SetOSVersionLadder(ladderOf(t, ssh))

	a.enrichOSVersions(context.Background())
	// Age every probe past the retry window so the second tick is free to pick,
	// then confirm the ones already probed sort LAST and the untouched tail runs.
	a.mu.Lock()
	for id := range a.osProbeAt {
		a.osProbeAt[id] = time.Now().UTC().Add(-osProbeRetryInterval - time.Hour)
	}
	a.mu.Unlock()
	a.enrichOSVersions(context.Background())

	seen := map[string]bool{}
	for _, id := range ssh.called() {
		seen[id] = true
	}
	if len(seen) <= osProbeMaxPerTick {
		t.Errorf("two ticks reached %d distinct devices out of %d — the tail is starved", len(seen), total)
	}
}

// TestEnrichmentDoesNotPersistASourceReportedDevice — a source-reported device's
// source is its authority; persisting a shadow would resurrect what pollOnce
// legitimately prunes.
func TestEnrichmentDoesNotPersistASourceReportedDevice(t *testing.T) {
	row := spineRow()
	row.Source = "netbox"
	store := newProbeStore()
	a := NewDiscoveryAggregator()
	a.SetStore(store)
	a.mu.Lock()
	a.cache[row.ID] = row
	a.mu.Unlock()
	a.SetOSVersionLadder(ladderOf(t, &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}))

	a.enrichOSVersions(context.Background())

	if got, _ := a.Get("spine1"); got.OSVersion != srlProbed {
		t.Errorf("the cache did not learn the version: %q", got.OSVersion)
	}
	if store.putCall != 0 {
		t.Errorf("a source-reported device was persisted (%d writes)", store.putCall)
	}
}

// TestEnrichmentKeepsTheReadingWhenPersistenceFails — the store is not allowed
// to lose the reading from RAM; the next boot re-probes.
func TestEnrichmentKeepsTheReadingWhenPersistenceFails(t *testing.T) {
	store := newProbeStore(spineRow())
	store.putErr = errors.New("disk full")
	a := NewDiscoveryAggregator()
	a.SetStore(store)
	a.SetOSVersionLadder(ladderOf(t, &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}))

	a.enrichOSVersions(context.Background())

	if got, _ := a.Get("spine1"); got.OSVersion != srlProbed {
		t.Errorf("os_version = %q, want the reading kept in RAM despite the store failing", got.OSVersion)
	}
}

// TestEnrichmentIsANoOpWithoutALadder — the feature is additive: a build that
// wired no transport behaves exactly as it did before.
func TestEnrichmentIsANoOpWithoutALadder(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(spineRow()))
	a.enrichOSVersions(context.Background())
	if got, _ := a.Get("spine1"); got.OSVersion != "" {
		t.Errorf("os_version = %q with no ladder wired", got.OSVersion)
	}
}

// TestEnrichmentExposesItsMetrics — §10.
func TestEnrichmentExposesItsMetrics(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(spineRow()))
	a.SetOSVersionLadder(ladderOf(t, &scriptedSource{method: osprobe.MethodSSH, answers: map[string]string{"spine1": srlProbed}}))
	a.enrichOSVersions(context.Background())

	var b strings.Builder
	a.WriteOSVersionMetrics(&b)
	if !strings.Contains(b.String(), `netops_device_osversion_probe_total{method="ssh",outcome="learned"} 1`) {
		t.Errorf("metrics:\n%s", b.String())
	}
	// Nil-safe: an aggregator with no ladder must still scrape.
	var empty strings.Builder
	NewDiscoveryAggregator().WriteOSVersionMetrics(&empty)
}

// TestMergeMovesTheVersionAndItsProvenanceTogether — a merge that took one and
// left the other would produce a row claiming a version was learned by a source
// that never read it.
func TestMergeMovesTheVersionAndItsProvenanceTogether(t *testing.T) {
	at := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	netbox := models.Device{ID: "spine1", Source: "netbox", Vendor: "nokia", OS: "SR Linux"}
	live := models.Device{ID: "spine1", Source: "static", OSVersion: srlProbed, OSVersionSource: "ssh", OSVersionAt: at}

	got := mergeDevices(netbox, live)
	if got.OSVersion != srlProbed || got.OSVersionSource != "ssh" || !got.OSVersionAt.Equal(at) {
		t.Errorf("merged = (%q via %q at %v), want all three carried across",
			got.OSVersion, got.OSVersionSource, got.OSVersionAt)
	}
}

// ─── provenance is server state, never request input ─────────────────────────

// TestUpsertRefusesAClientAssertedProbeProvenance — a caller may SET a version
// (the documented manual path) but may not claim a probe learned it. A faked
// `os_version_source: "ssh"` would both invent an audit trail and change which
// rung of the ladder is allowed to refresh the row.
func TestUpsertRefusesAClientAssertedProbeProvenance(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore())
	body := models.Device{
		ID: "spine1", Name: "spine1", Address: "172.40.40.11", Vendor: "nokia", OS: "SR Linux",
		OSVersion: srlProbed, OSVersionSource: "ssh",
		OSVersionAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := a.Upsert(body); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := a.Get("spine1")
	if got.OSVersion != srlProbed {
		t.Errorf("os_version = %q, want the operator's value kept", got.OSVersion)
	}
	if got.OSVersionSource != string(osprobe.MethodManual) {
		t.Errorf("os_version_source = %q, want it stamped manual — a client cannot claim a probe read it",
			got.OSVersionSource)
	}
	if got.OSVersionAt.Year() == 1999 {
		t.Error("the client's timestamp was accepted")
	}
}

// TestUpsertKeepsAProbedProvenanceOnAnUnchangedVersion — a UI that round-trips
// the device object (to add a label, say) must not relabel a probed version as
// hand-written, which would freeze the ladder off that row forever.
func TestUpsertKeepsAProbedProvenanceOnAnUnchangedVersion(t *testing.T) {
	at := time.Date(2026, 9, 6, 7, 0, 0, 0, time.UTC)
	row := spineRow()
	row.OSVersion, row.OSVersionSource, row.OSVersionAt = srlProbed, "ssh", at
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))

	echoed := row
	echoed.OSVersionSource, echoed.OSVersionAt = "manual", time.Time{} // what a client might send back
	echoed.Labels = map[string]string{"site": "dc1"}
	if err := a.Upsert(echoed); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := a.Get("spine1")
	if got.OSVersionSource != "ssh" || !got.OSVersionAt.Equal(at) {
		t.Errorf("provenance = (%q at %v), want the row's own (ssh at %v) kept",
			got.OSVersionSource, got.OSVersionAt, at)
	}
	if got.Labels["site"] != "dc1" {
		t.Error("the rest of the update was lost")
	}
}

// TestUpsertClearsProvenanceWithNoVersion — there is no provenance to state for
// a version that is not there.
func TestUpsertClearsProvenanceWithNoVersion(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore())
	d := spineRow()
	d.OSVersionSource, d.OSVersionAt = "snmp", time.Now().UTC()
	if err := a.Upsert(d); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := a.Get("spine1")
	if got.OSVersionSource != "" || !got.OSVersionAt.IsZero() {
		t.Errorf("provenance = (%q at %v) on a row with no version", got.OSVersionSource, got.OSVersionAt)
	}
}
