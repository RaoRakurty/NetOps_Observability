// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// tenant_scope_test.go — tenant-owned discovery scopes (2026-11-10): the scope
// is the channel, a device found through a tenant's scope is that tenant's,
// and one box found by two owners is two devices that never touch each other.

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

const retail = "t_retail"

var (
	platformCreds = []ScanCredential{{ProfileID: "plat-ro", Target: collectors.Target{Community: "plat"}}}
	retailCreds   = []ScanCredential{{ProfileID: "retail-ro", Target: collectors.Target{Community: "retail"}}}
)

// credProbe answers for an address only with the community that address
// accepts, and records every (address, community) it was tried with.
type credProbe struct {
	mu     sync.Mutex
	accept map[string]string // address → the community it answers to
	names  map[string]string // address → sysName
	tried  map[string][]string
}

func newCredProbe() *credProbe {
	return &credProbe{accept: map[string]string{}, names: map[string]string{}, tried: map[string][]string{}}
}

func (p *credProbe) set(addr, community, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accept[addr], p.names[addr] = community, name
}

func (p *credProbe) probe(_ context.Context, t collectors.Target) (string, string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tried[t.Address] = append(p.tried[t.Address], t.Community)
	if c, ok := p.accept[t.Address]; ok && (c == "*" || c == t.Community) {
		return p.names[t.Address], "cisco", "Cisco IOS XE 17.9", true
	}
	return "", "", "", false
}

func (p *credProbe) triedWith(addr string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tried[addr]...)
}

type scopeRig struct {
	src   *SNMPSource
	probe *credProbe
	clock *scanClock
	cfg   *atomic.Pointer[ScanSettings]
	known *atomic.Pointer[[]models.Device]
}

func newScopeRig(t *testing.T, scopes ...ScanScope) *scopeRig {
	t.Helper()
	r := &scopeRig{probe: newCredProbe(), clock: &scanClock{t: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)},
		cfg: &atomic.Pointer[ScanSettings]{}, known: &atomic.Pointer[[]models.Device]{}}
	r.cfg.Store(&ScanSettings{Enabled: true, Scopes: scopes})
	empty := []models.Device{}
	r.known.Store(&empty)
	r.src = NewSNMPSource(func() ScanSettings { return *r.cfg.Load() }, func() []models.Device { return *r.known.Load() })
	r.src.SetProbeForTest(r.probe.probe)
	r.src.SetClockForTest(r.clock.now)
	return r
}

func (r *scopeRig) sweep(t *testing.T) []models.Device {
	t.Helper()
	r.clock.advance(ScanCooldown + time.Second)
	devs, err := r.src.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	return devs
}

func platformScope(ranges ...string) ScanScope {
	return ScanScope{ID: PlatformScopeID, Ranges: ranges, Credentials: platformCreds}
}

func retailScope(ranges ...string) ScanScope {
	return ScanScope{ID: "scope-retail", TenantID: retail, Ranges: ranges, Credentials: retailCreds}
}

// byOwner indexes devices by (tenant, address).
func byOwner(devs []models.Device) map[string]models.Device {
	out := map[string]models.Device{}
	for _, d := range devs {
		out[d.TenantID+"|"+d.Address] = d
	}
	return out
}

func TestScanDeviceIDForKeepsPlatformIDsAndSaltsTenants(t *testing.T) {
	plat := ScanDeviceID("cEDGE-81", "10.70.0.81")
	for _, tn := range []string{"", "  ", "global", "GLOBAL"} {
		if got := ScanDeviceIDFor(tn, "cEDGE-81", "10.70.0.81"); got != plat {
			t.Fatalf("platform owner %q: id %q, want the unchanged platform id %q", tn, got, plat)
		}
	}
	sib := ScanDeviceIDFor(retail, "cEDGE-81", "10.70.0.81")
	if sib == plat {
		t.Fatalf("a tenant's id must differ from the platform's for the same box: %q", sib)
	}
	if !strings.HasPrefix(sib, "cedge-81-") || len(sib) != len(plat) {
		t.Fatalf("a tenant id keeps the platform shape (name-<8 hex>): %q vs %q", sib, plat)
	}
	if again := ScanDeviceIDFor(" T_RETAIL ", "cEDGE-81", "10.70.0.81"); again != sib {
		t.Fatalf("the id must be stable per (tenant, device), case/space-insensitive: %q vs %q", again, sib)
	}
	if other := ScanDeviceIDFor("t_other", "cEDGE-81", "10.70.0.81"); other == sib || other == plat {
		t.Fatalf("two tenants on one address must get two ids: %q", other)
	}
	if moved := ScanDeviceIDFor(retail, "cEDGE-81", "10.70.0.82"); moved == sib {
		t.Fatal("the address is part of a tenant id, as it is of the platform id")
	}
	if got := ScanDeviceIDFor(retail, "", "10.70.0.81"); !strings.HasPrefix(got, "10.70.0.81-") {
		t.Fatalf("a nameless tenant device falls back to its address, salted: %q", got)
	}
}

func TestTwoOwnersScopesOnOneAddressAreTwoDevices(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	r.probe.set("10.70.0.81", "*", "cEDGE-81") // answers both communities
	devs := byOwner(r.sweep(t))
	p, okP := devs["|10.70.0.81"]
	s, okS := devs[retail+"|10.70.0.81"]
	if !okP || !okS || len(devs) != 2 {
		t.Fatalf("want the platform record AND the tenant record, got %+v", devs)
	}
	if p.ID == s.ID {
		t.Fatalf("two owners must never share an id: %q", p.ID)
	}
	if p.ID != ScanDeviceID("cEDGE-81", "10.70.0.81") || s.ID != ScanDeviceIDFor(retail, "cEDGE-81", "10.70.0.81") {
		t.Fatalf("ids: platform %q, tenant %q", p.ID, s.ID)
	}
	if p.CredentialRef != "plat-ro" || s.CredentialRef != "retail-ro" {
		t.Fatalf("each record is bound to its own owner's profile: %q / %q", p.CredentialRef, s.CredentialRef)
	}

	// Through the aggregator: two inventory rows, never merged across owners
	// (identityTokens partitions by tenant), and neither replaces the other.
	a := NewDiscoveryAggregator()
	a.Register(r.src)
	r.clock.advance(ScanCooldown + time.Second)
	a.PollOnceForTest(context.Background(), r.src)
	inv := byOwner(a.Devices())
	if len(inv) != 2 || inv["|10.70.0.81"].ID != p.ID || inv[retail+"|10.70.0.81"].ID != s.ID {
		t.Fatalf("the inventory must hold both owners' devices, unmerged: %+v", inv)
	}
}

func TestTenantScopeTriesOnlyItsOwnCredentials(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.1.0/30"), retailScope("10.70.2.0/30"))
	r.probe.set("10.70.1.1", "plat", "plat-box")
	r.probe.set("10.70.2.1", "plat", "retail-box") // answers ONLY the platform community
	devs := byOwner(r.sweep(t))
	if _, ok := devs[retail+"|10.70.2.1"]; ok {
		t.Fatal("a tenant scope must not find a box that answers only to a platform profile")
	}
	for _, c := range r.probe.triedWith("10.70.2.1") {
		if c != "retail" {
			t.Fatalf("a platform secret was sprayed at a tenant scope's address: tried %v", r.probe.triedWith("10.70.2.1"))
		}
	}
	for _, c := range r.probe.triedWith("10.70.1.1") {
		if c != "plat" {
			t.Fatalf("a tenant secret was sprayed at a platform address: tried %v", r.probe.triedWith("10.70.1.1"))
		}
	}
	if _, ok := devs["|10.70.1.1"]; !ok {
		t.Fatal("the platform scope still finds its own box")
	}
}

func TestTenantScopeKnownSetIsItsOwnPartition(t *testing.T) {
	// The lab case: the platform already has the edge (any source). The tenant
	// scope must still probe it, or the customer's channel never finds it.
	r := newScopeRig(t, retailScope("10.70.3.0/30"))
	r.probe.set("10.70.3.1", "retail", "cEDGE-83")
	known := []models.Device{
		{ID: "cedge-83-platform", Name: "cEDGE-83", Address: "10.70.3.1", Source: "snmp"},                // the platform's copy
		{ID: "other-tenant-box", Name: "x", Address: "10.70.3.2", Source: "manual", TenantID: "t_other"}, // another customer
	}
	r.known.Store(&known)
	devs := byOwner(r.sweep(t))
	if _, ok := devs[retail+"|10.70.3.1"]; !ok {
		t.Fatal("another owner's device at the address must not count as known for a tenant scope")
	}
	if len(r.probe.triedWith("10.70.3.2")) == 0 {
		t.Fatal("another tenant's address must be probed by this tenant's scope")
	}

	// The tenant's OWN device from another source IS known: not probed.
	r2 := newScopeRig(t, retailScope("10.70.4.0/30"))
	r2.probe.set("10.70.4.1", "retail", "own")
	own := []models.Device{{ID: "retail-manual", Name: "own", Address: "10.70.4.1", Source: "manual", TenantID: "T_Retail"}}
	r2.known.Store(&own)
	r2.sweep(t)
	if n := len(r2.probe.triedWith("10.70.4.1")); n != 0 {
		t.Fatalf("the tenant's own manual device must stay known (probed %d times)", n)
	}

	// The platform scope keeps its rule: ANY owner's device is known.
	r3 := newScopeRig(t, platformScope("10.70.5.0/30"))
	r3.probe.set("10.70.5.1", "plat", "tenant-box")
	tb := []models.Device{{ID: "t-box", Name: "tenant-box", Address: "10.70.5.1", Source: "manual", TenantID: retail}}
	r3.known.Store(&tb)
	r3.sweep(t)
	if n := len(r3.probe.triedWith("10.70.5.1")); n != 0 {
		t.Fatalf("the platform scope must not add a copy of a box a customer already has (probed %d times)", n)
	}
}

func TestRestoreKeepsEveryOwnersRecordForOneAddress(t *testing.T) {
	kv := newPrefixMemKV()
	store := NewFileFoundStore("/data/discovered_devices.json", kv)
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	if err := r.src.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	r.probe.set("10.70.0.81", "*", "cEDGE-81")
	first := byOwner(r.sweep(t))
	if kv.count() != 2 {
		t.Fatalf("persisted %d records, want 2 (one per owner)", kv.count())
	}

	// Restart. The platform record answered LATER than the tenant one: before
	// tenant scopes the restore kept only the freshest record per address.
	r2 := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	if err := r2.src.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	restored, ok := r2.src.Restored()
	if !ok {
		t.Fatal("restore must succeed")
	}
	got := byOwner(restored)
	if len(got) != 2 || got["|10.70.0.81"].ID != first["|10.70.0.81"].ID ||
		got[retail+"|10.70.0.81"].ID != first[retail+"|10.70.0.81"].ID {
		t.Fatalf("restore collapsed the two owners' records: %+v", got)
	}
	if got[retail+"|10.70.0.81"].TenantID != retail {
		t.Fatalf("the tenant record lost its owner: %+v", got[retail+"|10.70.0.81"])
	}
}

func TestPlatformDeleteNeverSuppressesTheTenantSibling(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	r.probe.set("10.70.0.81", "*", "cEDGE-81")
	dev := NewDevStore("/data/devices.json", newPrefixMemKV(), nil)
	a := NewDiscoveryAggregator()
	a.SetStore(dev)
	a.Register(r.src)
	poll := func() map[string]models.Device {
		r.clock.advance(ScanCooldown + time.Second)
		a.PollOnceForTest(context.Background(), r.src)
		return byOwner(a.Devices())
	}
	inv := poll()
	platID, sibID := inv["|10.70.0.81"].ID, inv[retail+"|10.70.0.81"].ID
	if platID == "" || sibID == "" {
		t.Fatalf("both owners' devices must exist first: %+v", inv)
	}

	// The runbook's retire step: the operator deletes the PLATFORM row (same
	// name, same address as the sibling — every bare-id derivation matches).
	if err := a.Delete(platID); err != nil {
		t.Fatal(err)
	}
	inv = poll()
	if _, ok := inv["|10.70.0.81"]; ok {
		t.Fatal("the deleted platform row came back")
	}
	if inv[retail+"|10.70.0.81"].ID != sibID {
		t.Fatalf("deleting the platform row suppressed the customer's sibling: %+v", inv)
	}

	// A tombstone of the sibling's id stamped with ANOTHER owner does not
	// suppress it either: only a delete in the sibling's own scope does.
	if err := dev.RemoveOwned("t_other", sibID); err != nil {
		t.Fatal(err)
	}
	if inv = poll(); inv[retail+"|10.70.0.81"].ID != sibID {
		t.Fatal("another owner's tombstone suppressed the sibling")
	}
	if err := a.Delete(sibID); err != nil {
		t.Fatal(err)
	}
	if inv = poll(); len(inv) != 0 {
		t.Fatalf("a delete in the sibling's own scope must stick: %+v", inv)
	}
}

// ownerFlipSource reports whatever records it is handed, under the name "snmp".
type ownerFlipSource struct {
	mu   sync.Mutex
	devs []models.Device
}

func (s *ownerFlipSource) Name() string            { return "snmp" }
func (s *ownerFlipSource) Interval() time.Duration { return time.Hour }
func (s *ownerFlipSource) Poll(context.Context) ([]models.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.Device(nil), s.devs...), nil
}
func (s *ownerFlipSource) set(d ...models.Device) { s.mu.Lock(); s.devs = d; s.mu.Unlock() }

// TestSiblingNeverOverwritesAnotherOwnersRow is THE cross-tenant overwrite
// hazard: the aggregator cache is keyed by id, and before the guard a record of
// one owner carrying an id another owner's row held simply replaced it
// (ingestLocked's a.cache[d.ID] = d). Forced here with a colliding id, which
// tenant salting makes a hash collision or a stamping bug — exactly the cases
// the guard exists for.
func TestSiblingNeverOverwritesAnotherOwnersRow(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second models.Device
	}{
		{"tenant record cannot replace the platform row",
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1"},
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1", TenantID: retail}},
		{"platform record cannot replace a tenant row",
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1", TenantID: retail},
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1"}},
		{"one tenant cannot replace another's row",
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1", TenantID: "t_a"},
			models.Device{ID: "edge-1", Name: "edge-1", Address: "10.70.9.1", TenantID: "t_b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &ownerFlipSource{}
			a := NewDiscoveryAggregator()
			a.Register(src)
			src.set(tc.first)
			a.PollOnceForTest(context.Background(), src)
			// The same poll reports the incumbent AND the intruder, in both orders.
			for _, batch := range [][]models.Device{{tc.first, tc.second}, {tc.second, tc.first}} {
				src.set(batch...)
				a.PollOnceForTest(context.Background(), src)
				got, ok := a.Get("edge-1")
				if !ok || deviceTenantKey(got) != deviceTenantKey(tc.first) {
					t.Fatalf("CROSS-TENANT OVERWRITE: the row of %q now belongs to %q", tc.first.TenantID, got.TenantID)
				}
			}
			if n := a.CrossOwnerRefusals(); n != 2 {
				t.Fatalf("each refused overwrite is counted: %d, want 2", n)
			}
			var buf bytes.Buffer
			a.WriteMetrics(&buf)
			if !strings.Contains(buf.String(), "netops_discovery_cross_owner_refused_total 2") {
				t.Fatalf("the guard must be observable:\n%s", buf.String())
			}
			// The same owner still updates its own row.
			upd := tc.first
			upd.Vendor = "cisco"
			src.set(upd)
			a.PollOnceForTest(context.Background(), src)
			if got, _ := a.Get("edge-1"); got.Vendor != "cisco" {
				t.Fatal("the owner's own refresh must still land")
			}
		})
	}
}

func TestEachScopeIsRefusedOnItsOwn(t *testing.T) {
	bad := retailScope("8.8.8.0/30") // public, not acknowledged
	r := newScopeRig(t, platformScope("10.70.6.0/30"), bad)
	r.probe.set("10.70.6.1", "plat", "plat-box")
	devs := byOwner(r.sweep(t)) // the platform scope still runs: no poll error
	if _, ok := devs["|10.70.6.1"]; !ok {
		t.Fatal("a refused tenant scope must not stop the platform scope")
	}
	st := statusOf(t, r.src, "scope-retail")
	if !strings.Contains(st.LastError, "not private") || !strings.Contains(st.LastError, "scope scope-retail") {
		t.Fatalf("the refusal is the scope's own status: %q", st.LastError)
	}
	if plat := statusOf(t, r.src, PlatformScopeID); plat.LastError != "" || plat.Answering != 1 || plat.LastSweep.IsZero() {
		t.Fatalf("platform status: %+v", plat)
	}

	// No credential: refused, said so.
	noCred := retailScope("10.70.7.0/30")
	noCred.Credentials = nil
	r.cfg.Store(&ScanSettings{Enabled: true, Scopes: []ScanScope{platformScope("10.70.6.0/30"), noCred}})
	r.sweep(t)
	if st := statusOf(t, r.src, "scope-retail"); !strings.Contains(st.LastError, "own SNMP profiles") {
		t.Fatalf("no-credential refusal: %q", st.LastError)
	}

	// Every scope refused: the poll is an error, as the single scope always was.
	r.cfg.Store(&ScanSettings{Enabled: true, Scopes: []ScanScope{bad}})
	r.clock.advance(ScanCooldown + time.Second)
	if _, err := r.src.Poll(context.Background()); err == nil {
		t.Fatal("a poll whose every scope is refused must return the refusal")
	}
}

func TestScopesShareOneSweepBudgetPlatformFirst(t *testing.T) {
	big := platformScope("10.80.0.0/20") // 4096 = the whole budget
	r := newScopeRig(t, retailScope("10.81.0.0/30"), big)
	r.probe.set("10.81.0.1", "retail", "x")
	if _, err := r.src.Poll(context.Background()); err != nil {
		t.Fatalf("the platform scope fits and runs: %v", err)
	}
	if st := statusOf(t, r.src, "scope-retail"); !strings.Contains(st.LastError, "more than 4096 addresses") {
		t.Fatalf("the scope past the shared budget is refused, platform first: %q", st.LastError)
	}
	if n := len(r.probe.triedWith("10.81.0.1")); n != 0 {
		t.Fatalf("a refused scope probes nothing (probed %d times)", n)
	}
}

func TestAPartitionWithoutAScopeIsNotReported(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	r.probe.set("10.70.0.81", "*", "cEDGE-81")
	if n := len(r.sweep(t)); n != 2 {
		t.Fatalf("want both owners' devices, got %d", n)
	}
	// The customer's scope is turned off: its devices leave the inventory
	// (the pre-scope "discovery disabled" rule, per owner); the platform's stay.
	r.cfg.Store(&ScanSettings{Enabled: true, Scopes: []ScanScope{platformScope("10.70.0.80/30")}})
	devs := byOwner(r.sweep(t))
	if len(devs) != 1 || devs["|10.70.0.81"].ID == "" {
		t.Fatalf("only the platform partition is reported now: %+v", devs)
	}
	// Turned back on: the same id comes back (the memory was kept).
	r.cfg.Store(&ScanSettings{Enabled: true, Scopes: []ScanScope{platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30")}})
	devs = byOwner(r.sweep(t))
	if devs[retail+"|10.70.0.81"].ID != ScanDeviceIDFor(retail, "cEDGE-81", "10.70.0.81") {
		t.Fatalf("the tenant device returns under its stable id: %+v", devs)
	}
}

func TestOneOwnersSilentSweepPrunesNothingOfItsOwn(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.88/30"))
	r.probe.set("10.70.0.81", "plat", "plat-box")
	r.probe.set("10.70.0.89", "retail", "retail-box")
	r.sweep(t)
	// The customer's site goes dark; the platform's keeps answering.
	r.probe.mu.Lock()
	delete(r.probe.accept, "10.70.0.89")
	r.probe.mu.Unlock()
	for i := 0; i < staleAfterMisses; i++ {
		r.sweep(t)
	}
	r.clock.advance(pruneAfterStale)
	devs := byOwner(r.sweep(t))
	if d, ok := devs[retail+"|10.70.0.89"]; !ok || !d.DiscoveryStale {
		t.Fatalf("an all-silent partition prunes nothing, even while another owner's scope answers: %+v", devs)
	}
}

func TestScopeMetricsNameTheScopeNotTheTenant(t *testing.T) {
	r := newScopeRig(t, platformScope("10.70.0.80/30"), retailScope("10.70.0.80/30"))
	r.probe.set("10.70.0.81", "*", "cEDGE-81")
	r.sweep(t)
	var buf bytes.Buffer
	r.src.WriteMetrics(&buf)
	out := buf.String()
	for _, want := range []string{
		`netops_discovery_scope_found_devices{source="snmp",scope="platform",state="answering"} 1`,
		`netops_discovery_scope_found_devices{source="snmp",scope="scope-retail",state="answering"} 1`,
		`netops_discovery_scope_refused{source="snmp",scope="scope-retail"} 0`,
		`netops_discovery_found_devices{source="snmp",state="answering"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, retail) {
		t.Fatal("a tenant id leaked into a metric label")
	}
}

func statusOf(t *testing.T, s *SNMPSource, id string) ScopeStatus {
	t.Helper()
	for _, st := range s.ScopeStatuses() {
		if st.ScopeID == id {
			return st
		}
	}
	t.Fatalf("no status for scope %q", id)
	return ScopeStatus{}
}
