// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/devidentity"
	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/nms"
)

// Tracker 371: a controller-only device (an integration reports it; no collector
// of ours polls it) got no registry row of any kind, so its traps, syslog and
// flows reached the engine unattributed. These tests pin the narrow fix
// (internal/devidentity) and, above all, that it costs no existing row anything.

func ctlDevice(id, name, addr, owner string) models.Device {
	return models.Device{ID: id, Name: name, Address: addr, TenantID: owner, Source: devmon.SourceController, Vendor: "cisco"}
}

// controllerIsoDevices are two tenants' controller-only devices and the
// platform's, chosen to collide with isoDevices() and with each other.
func controllerIsoDevices() []models.Device {
	return []models.Device{
		// Tenant A's controller-only box: unique name and address.
		ctlDevice("ctl-vmanage-a01", "acme-branch", "172.16.1.1", isoTenantA),
		// Tenant B's controller-only box, NAMED like the platform's controller box.
		ctlDevice("ctl-vmanage-b01", "plat-branch", "172.16.2.1", isoTenantB),
		// The platform's controller-only boxes:
		ctlDevice("ctl-vmanage-p01", "plat-branch", "172.16.9.1", "global"), // name shared with B's box
		ctlDevice("ctl-vmanage-p02", "plat-edge", "10.0.0.2", ""),           // address = tenant B's DIRECT device
		ctlDevice("ctl-vmanage-p03", "plat-solo", "172.16.9.3", "global"),   // nothing shared
	}
}

func controllerIsoIfAddr() map[string]map[string]string {
	return map[string]map[string]string{
		"ctl-vmanage-p03": {"192.168.222.107": "Lo200", "198.51.100.3": "Gi1"},
		"ctl-vmanage-p01": {"192.168.50.1": "Gi2"},
		// Tenant A's SNMP device carries the same interface address as p01.
		"acme-1": {"192.168.50.1": "Vlan10"},
		// Tenant A's controller box's interfaces never become rows (tenant = channel).
		"ctl-vmanage-a01": {"192.168.60.1": "Gi1"},
	}
}

func TestControllerRowsLeaveEveryDirectRowByteIdentical(t *testing.T) {
	base, _, _ := buildEnrichmentRowsIdentity(isoDevices(), nil, nil, nil)
	all := append(isoDevices(), controllerIsoDevices()...)
	with, _, _ := buildEnrichmentRowsIdentity(all, nil, nil, controllerIsoIfAddr())
	got := rowsByIdentity(with)
	for _, r := range base {
		if got[r.Identity] != r {
			t.Fatalf("a direct row changed when controller devices were added:\n before %+v\n  after %+v", r, got[r.Identity])
		}
	}
	// And a direct identity that was ambiguous (two owners) stays out.
	if _, ok := got["edge-1"]; ok {
		t.Fatal("the ambiguous direct identity edge-1 was claimed by a controller row")
	}
	if _, ok := got["192.0.2.9"]; ok {
		t.Fatal("the ambiguous NAT address was claimed by a controller row")
	}
}

func TestControllerRowsNeverCrossATenant(t *testing.T) {
	all := append(isoDevices(), controllerIsoDevices()...)
	rows, _, stats := buildEnrichmentRowsIdentity(all, nil, nil, controllerIsoIfAddr())
	got := rowsByIdentity(rows)

	// Every owner's id row, under that owner (platform as "").
	for id, tenant := range map[string]string{
		"ctl-vmanage-a01": isoTenantA, "ctl-vmanage-b01": isoTenantB,
		"ctl-vmanage-p01": "", "ctl-vmanage-p02": "", "ctl-vmanage-p03": "",
	} {
		r, ok := got[id]
		if !ok || r.Tenant != tenant || r.DeviceID != id {
			t.Fatalf("id row %s: got %+v ok=%v, want tenant %q", id, r, ok, tenant)
		}
	}
	// A tenant-owned controller device: nothing from a name or an address.
	for _, ident := range []string{"acme-branch", "172.16.1.1", "172.16.2.1", "192.168.60.1"} {
		if r, ok := got[ident]; ok {
			t.Fatalf("a tenant-owned controller device derived a tenant from %q: %+v", ident, r)
		}
	}
	// The platform's unshared identities are written under the platform.
	for _, ident := range []string{"plat-solo", "172.16.9.3", "192.168.222.107", "198.51.100.3", "172.16.9.1", "plat-edge"} {
		if r, ok := got[ident]; !ok || r.Tenant != "" {
			t.Fatalf("platform identity %q: got %+v ok=%v", ident, r, ok)
		}
	}
	// A name the platform box shares with tenant B's box names nobody.
	if r, ok := got["plat-branch"]; ok {
		t.Fatalf("a name two controller devices hold must name nobody: %+v", r)
	}
	// An interface address the platform box shares with tenant A's SNMP device.
	if r, ok := got["192.168.50.1"]; ok {
		t.Fatalf("an address another device's interface carries must name nobody: %+v", r)
	}
	// The platform box's address equals tenant B's DIRECT device: B's row stands.
	if r := got["10.0.0.2"]; r.Tenant != isoTenantB || r.DeviceID != "globex-1" {
		t.Fatalf("a controller claim displaced a direct row: %+v", r)
	}
	if stats[devidentity.StatKey{Tier: devidentity.TierPlatform, Outcome: devidentity.OutcomeDirectStands}] == 0 ||
		stats[devidentity.StatKey{Tier: devidentity.TierPlatform, Outcome: devidentity.OutcomeShared}] == 0 {
		t.Fatalf("the withheld claims were not counted: %v", stats)
	}
}

// fakeControllerSource is a discovery source named like the real controller
// source ("api"), so the not-ready hold sees it.
type fakeControllerSource struct{ devs []models.Device }

func (f *fakeControllerSource) Name() string            { return nms.ControllerSourceName }
func (f *fakeControllerSource) Interval() time.Duration { return time.Hour }
func (f *fakeControllerSource) Poll(context.Context) ([]models.Device, error) {
	return f.devs, nil
}

func TestTenantEnrichmentHeldUntilTheControllerInventoryIsRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, enrichmentFileName)
	prev := []byte("identity,tenant_id\nkept,t_acme\n")
	if err := os.WriteFile(path, prev, 0o644); err != nil {
		t.Fatal(err)
	}
	ctl := &fakeControllerSource{devs: []models.Device{ctlDevice("ctl-vmanage-a01", "acme-branch", "172.16.1.1", isoTenantA)}}
	agg := discovery.NewDiscoveryAggregator()
	agg.Register(ctl) // no SNMP source registered: nothing to wait for there
	s := &server{discovery: agg, devIdentityMetrics: devidentity.NewMetrics()}
	if s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("the export was written before the controller inventory was read")
	}
	if b, _ := os.ReadFile(path); string(b) != string(prev) {
		t.Fatalf("the previous file changed while not ready: %q", b)
	}
	agg.PollOnceForTest(context.Background(), ctl)
	if !s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("after the controller source answered, the export must be written")
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "ctl-vmanage-a01,"+isoTenantA) {
		t.Fatalf("the controller-only device's id row is missing: %q", b)
	}
}

func TestNMSOnlyInstallWithSNMPDiscoveryOffWritesTheRegistry(t *testing.T) {
	dir := t.TempDir()
	// The real SNMP source, switched off (no platform range, no tenant scope).
	snmp := discovery.NewSNMPSource(func() discovery.ScanSettings { return discovery.ScanSettings{} }, nil)
	ctl := &fakeControllerSource{devs: []models.Device{ctlDevice("ctl-vmanage-p03", "plat-solo", "172.16.9.3", "global")}}
	agg := discovery.NewDiscoveryAggregator()
	agg.Register(snmp)
	agg.Register(ctl)
	s := &server{discovery: agg, devIdentityMetrics: devidentity.NewMetrics(),
		enrichIfAddr: func(context.Context) (map[string]map[string]string, error) {
			return map[string]map[string]string{"ctl-vmanage-p03": {"192.168.222.107": "Lo200"}}, nil
		}}
	agg.PollOnceForTest(context.Background(), snmp)
	agg.PollOnceForTest(context.Background(), ctl)
	if !agg.Ready("snmp") {
		t.Fatal("a switched-off SNMP scanner must read as ready after its poll")
	}
	if !s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("an NMS-only install with SNMP discovery off must still write the registry")
	}
	b, err := os.ReadFile(filepath.Join(dir, enrichmentFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ctl-vmanage-p03,,", "plat-solo,,", "172.16.9.3,,", "192.168.222.107,,"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in the registry:\n%s", want, b)
		}
	}
	if s.devIdentityMetrics.Rows(devidentity.TierPlatform, devidentity.OutcomeWritten) != 3 {
		t.Fatalf("gauge: platform rows written = %d", s.devIdentityMetrics.Rows(devidentity.TierPlatform, devidentity.OutcomeWritten))
	}
}

func TestTenantEnrichmentHeldWhileTheInterfaceMapIsUnread(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, enrichmentFileName)
	prev := []byte("identity,tenant_id\nkept,\n")
	if err := os.WriteFile(path, prev, 0o644); err != nil {
		t.Fatal(err)
	}
	ctl := &fakeControllerSource{devs: []models.Device{ctlDevice("ctl-vmanage-p03", "plat-solo", "172.16.9.3", "global")}}
	agg := discovery.NewDiscoveryAggregator()
	agg.Register(ctl)
	agg.PollOnceForTest(context.Background(), ctl)
	read := errors.New("kv read timeout")
	s := &server{discovery: agg, devIdentityMetrics: devidentity.NewMetrics(),
		enrichIfAddr: func(context.Context) (map[string]map[string]string, error) { return nil, read }}
	if s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("platform interface rows would flap: the tick must keep the previous file")
	}
	if b, _ := os.ReadFile(path); string(b) != string(prev) {
		t.Fatalf("the previous file changed while the interface map was unread: %q", b)
	}
	// No sharing channel configured at all is not a failure: no interface rows, truthfully.
	s.enrichIfAddr = func(context.Context) (map[string]map[string]string, error) {
		return nil, collectors.ErrNotConfigured
	}
	if !s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("with no sharing channel configured the export must be written")
	}
	// Only TENANT-owned controller devices: the interface map is never read.
	tenantOnly := &fakeControllerSource{devs: []models.Device{ctlDevice("ctl-vmanage-a01", "acme-branch", "172.16.1.1", isoTenantA)}}
	agg2 := discovery.NewDiscoveryAggregator()
	agg2.Register(tenantOnly)
	agg2.PollOnceForTest(context.Background(), tenantOnly)
	s2 := &server{discovery: agg2, devIdentityMetrics: devidentity.NewMetrics(),
		enrichIfAddr: func(context.Context) (map[string]map[string]string, error) {
			t.Fatal("the interface map was read although no platform controller device exists")
			return nil, nil
		}}
	if !s2.writeTenantEnrichmentOnce(t.TempDir()) {
		t.Fatal("tenant-only controller devices: the export must be written")
	}
}
