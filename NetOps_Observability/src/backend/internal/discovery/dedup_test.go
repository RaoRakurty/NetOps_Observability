// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

import (
	"context"
	"testing"
	"time"

	"netops/backend/models"
)

// The same physical device seen by SNMP discovery AND NetBox must show ONCE,
// merged (NetBox metadata + SNMP live fields), not as two rows.
func TestDevicesDedupAcrossSources(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-10.0.0.1", Name: "leaf1", Address: "10.0.0.1", Vendor: "Arista", Source: "snmp", CredentialRef: "arista-v2c"})
	a.Upsert(models.Device{ID: "netbox-42", Name: "leaf1", Address: "10.0.0.1", Source: "netbox", Labels: map[string]string{"site": "dc1"}})

	devs := a.Devices()
	if len(devs) != 1 {
		t.Fatalf("same device from two sources should merge to 1, got %d", len(devs))
	}
	d := devs[0]
	if d.Source != "netbox" {
		t.Errorf("merged base should prefer the NetBox record, got source %q", d.Source)
	}
	if d.Vendor != "Arista" {
		t.Errorf("should fold in SNMP-learned vendor, got %q", d.Vendor)
	}
	if d.CredentialRef != "arista-v2c" {
		t.Errorf("should keep the SNMP credential_ref for polling, got %q", d.CredentialRef)
	}
	if d.Labels["site"] != "dc1" {
		t.Errorf("should keep the NetBox site label, got %q", d.Labels["site"])
	}
	if d.Labels["sources"] != "netbox+snmp" {
		t.Errorf("should record both sources, got %q", d.Labels["sources"])
	}

	// A genuinely different device stays separate.
	a.Upsert(models.Device{ID: "snmp-10.0.0.2", Name: "leaf2", Address: "10.0.0.2", Source: "snmp"})
	if got := len(a.Devices()); got != 2 {
		t.Errorf("distinct devices must not merge, got %d", got)
	}
}

// The reported duplicate: an SNMP device (keyed by mgmt IP) and its synced
// NetBox twin (create-only → NO primary IP) share no IP, but DO share the name
// (and, now that NetboxSource reads it, the serial). Multi-identity union must
// still collapse them — a single-key (IP-first) scheme would not.
func TestDedupeNetboxTwinNoSharedIP(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-leaf1", Name: "leaf1", Address: "10.70.0.1", Source: "snmp",
		CredentialRef: "v3-arista", Labels: map[string]string{"serial": "ABC123"}})
	a.Upsert(models.Device{ID: "netbox-7", Name: "leaf1", Source: "netbox", Model: "DCS-7050",
		Labels: map[string]string{"site": "dallas", "serial": "ABC123"}}) // IP-less twin

	devs := a.Devices()
	if len(devs) != 1 {
		t.Fatalf("IP-less NetBox twin must merge with its SNMP record, got %d: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.Address != "10.70.0.1" {
		t.Errorf("merged must keep the SNMP mgmt IP, got %q", d.Address)
	}
	if d.CredentialRef != "v3-arista" {
		t.Errorf("merged must keep the SNMP credential for polling, got %q", d.CredentialRef)
	}
	if d.Model != "DCS-7050" || d.Labels["site"] != "dallas" {
		t.Errorf("merged must keep NetBox metadata, got %+v", d)
	}
}

func TestDedupeBySerialDifferentNames(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-x", Name: "10.0.0.5", Address: "10.0.0.5", Source: "snmp",
		Labels: map[string]string{"serial": "SN-9"}})
	a.Upsert(models.Device{ID: "netbox-2", Name: "core-sw-1", Source: "netbox",
		Labels: map[string]string{"serial": "SN-9"}})
	if got := len(a.Devices()); got != 1 {
		t.Fatalf("serial-based merge expected 1, got %d", got)
	}
}

// Transitive: A shares IP with B, B shares name with C → all one device.
func TestDedupeTransitive(t *testing.T) {
	cache := map[string]models.Device{
		"a": {ID: "a", Name: "r1", Address: "10.0.0.9", Source: "snmp"},
		"b": {ID: "b", Name: "r1-mgmt", Address: "10.0.0.9", Source: "static"},
		"c": {ID: "c", Name: "r1-mgmt", Source: "netbox"},
	}
	if got := len(dedupeDevices(cache)); got != 1 {
		t.Fatalf("transitive union expected 1, got %d", got)
	}
}

// Blank identity fields must never union unrelated devices.
func TestDedupeBlankFieldsDontUnion(t *testing.T) {
	cache := map[string]models.Device{
		"a": {ID: "a", Name: "", Address: "10.0.0.1", Source: "snmp"},
		"b": {ID: "b", Name: "", Address: "10.0.0.2", Source: "snmp"},
	}
	if got := len(dedupeDevices(cache)); got != 2 {
		t.Fatalf("blank names unioned distinct devices: got %d, want 2", got)
	}
}

func TestDeviceIdentities(t *testing.T) {
	got := DeviceIdentities(models.Device{Address: "10.0.0.1", Name: "Leaf1", Labels: map[string]string{"serial": "ABC123"}})
	want := map[string]bool{"ip:10.0.0.1": true, "sn:abc123": true, "name:leaf1": true}
	if len(got) != len(want) {
		t.Fatalf("identities = %v, want keys %v", got, want)
	}
	for _, tok := range got {
		if !want[tok] {
			t.Errorf("unexpected identity token %q", tok)
		}
	}
	// No identities at all → empty (can't accidentally union).
	if ids := DeviceIdentities(models.Device{}); len(ids) != 0 {
		t.Errorf("empty device should yield no identities, got %v", ids)
	}
}

// fakeSource is a controllable DiscoverySource for reconciliation tests.
type fakeSource struct {
	name    string
	devices []models.Device
	err     error
}

func (f *fakeSource) Name() string                                  { return f.name }
func (f *fakeSource) Interval() time.Duration                       { return time.Minute }
func (f *fakeSource) Poll(context.Context) ([]models.Device, error) { return f.devices, f.err }

// The direction-switch case: a source reports devices, then (switched to
// write-only / disabled) returns nothing on a SUCCESSFUL poll → its records are
// pruned, not left lingering as duplicates.
func TestPollOncePrunesOnEmptySuccess(t *testing.T) {
	a := NewDiscoveryAggregator()
	src := &fakeSource{name: "netbox", devices: []models.Device{
		{ID: "netbox-1", Name: "leaf1"}, {ID: "netbox-2", Name: "leaf2"},
	}}
	a.pollOnce(context.Background(), src)
	if got := len(a.RawDevices()); got != 2 {
		t.Fatalf("after first poll want 2 raw devices, got %d", got)
	}
	// Source now returns nothing (e.g. NetBox sync flipped read→write).
	src.devices = nil
	a.pollOnce(context.Background(), src)
	if got := len(a.RawDevices()); got != 0 {
		t.Fatalf("empty successful poll must prune the source's devices, got %d", got)
	}
}

// A poll ERROR must NOT prune — a transient outage can't wipe the inventory.
func TestPollOnceErrorRetains(t *testing.T) {
	a := NewDiscoveryAggregator()
	src := &fakeSource{name: "netbox", devices: []models.Device{{ID: "netbox-1", Name: "leaf1"}}}
	a.pollOnce(context.Background(), src)
	src.devices = nil
	src.err = context.DeadlineExceeded // poll failed
	a.pollOnce(context.Background(), src)
	if got := len(a.RawDevices()); got != 1 {
		t.Fatalf("poll error must retain prior devices, got %d", got)
	}
}

// Pruning is source-scoped: one source going empty doesn't touch another
// source's devices.
func TestPollOncePruneIsSourceScoped(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.pollOnce(context.Background(), &fakeSource{name: "static", devices: []models.Device{{ID: "static-1", Name: "core1"}}})
	nb := &fakeSource{name: "netbox", devices: []models.Device{{ID: "netbox-1", Name: "leaf1"}}}
	a.pollOnce(context.Background(), nb)
	nb.devices = nil
	a.pollOnce(context.Background(), nb) // netbox empties
	devs := a.RawDevices()
	if len(devs) != 1 || devs[0].ID != "static-1" {
		t.Fatalf("static device must survive netbox pruning, got %+v", devs)
	}
}

// mergeDevices must be PURE: base/other carry the LIVE cached Labels maps
// (Devices() returns struct copies that still share them), and dedupeDevices
// runs under an RLock — an in-place label write is a concurrent map read/write
// that crashes the whole API (observed in production: two records merging on
// one IP + a collector reading dev.Labels).
func TestMergeDevicesDoesNotMutateInputs(t *testing.T) {
	x := models.Device{ID: "manual-1", Name: "app-host", Address: "10.60.10.10",
		Source: "manual", Labels: map[string]string{"role": "cloud-app-host"}}
	y := models.Device{ID: "cloud-1", Name: "app-host", Address: "10.60.10.10",
		Source: "cloud", Labels: map[string]string{"provider": "aws"}}

	got := mergeDevices(x, y)

	if len(x.Labels) != 1 || x.Labels["role"] != "cloud-app-host" {
		t.Errorf("mergeDevices mutated x.Labels: %v", x.Labels)
	}
	if len(y.Labels) != 1 || y.Labels["provider"] != "aws" {
		t.Errorf("mergeDevices mutated y.Labels: %v", y.Labels)
	}
	if got.Labels["role"] != "cloud-app-host" || got.Labels["provider"] != "aws" {
		t.Errorf("merge result must union labels, got %v", got.Labels)
	}
	if got.Labels["sources"] == "" {
		t.Errorf("cross-source merge must record the sources label, got %v", got.Labels)
	}
}

// Regression for the production crash: concurrent Devices() calls (dedupe/merge
// under RLock) racing readers of the returned Labels maps. Run with -race (the
// CI gate does): the pre-fix code fails here with a data-race report.
func TestDevicesConcurrentMergeIsRaceFree(t *testing.T) {
	a := NewDiscoveryAggregator()
	// Two records that merge on the shared IP → every Devices() call folds labels.
	a.Upsert(models.Device{ID: "manual-1", Name: "app-host", Address: "10.60.10.10",
		Source: "manual", Labels: map[string]string{"role": "cloud-app-host"}})
	a.Upsert(models.Device{ID: "cloud-1", Name: "app-host", Address: "10.60.10.10",
		Source: "cloud", Labels: map[string]string{"provider": "aws"}})

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				for _, d := range a.Devices() {
					_ = d.Labels["gnmi"] // the exact read that crashed (main.go target builder)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
