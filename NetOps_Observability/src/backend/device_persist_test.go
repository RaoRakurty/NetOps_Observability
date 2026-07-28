package main

import (
	"netops/backend/internal/discovery"
	"testing"

	"netops/backend/models"
)

// device_persist_test.go — devices created through the API must survive a
// restart, and a deleted device must stay deleted.
//
// The defect these pin: discovery.DiscoveryAggregator.Upsert wrote to an in-memory map
// with no persistence anywhere, so POST /api/devices returned 201 Created for a
// device that evaporated on the next restart, container recreate, crash, deploy
// or documented UPGRADE.md upgrade. On the lab stack a single API restart
// destroyed 500 operator-created devices across 10 tenants. Only devices a
// SOURCE could rediscover came back.
//
// A restart is simulated the honest way: build a second aggregator over the same
// kv backend, exactly as a fresh process would.

func TestManualDeviceSurvivesRestart(t *testing.T) {
	withBackend(t, newMemKV())

	a := discovery.NewDiscoveryAggregator()
	a.SetStore(newDeviceStore(devicesPath()))

	d := models.Device{ID: "walmart-br1-core-sw01", Name: "walmart-br1-core-sw01",
		Address: "10.101.1.22", TenantID: "t_walmart"}
	if err := a.Upsert(d); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// --- process restart ---
	b := discovery.NewDiscoveryAggregator()
	b.SetStore(newDeviceStore(devicesPath()))

	got := b.Devices()
	if len(got) != 1 {
		t.Fatalf("after restart the inventory has %d devices, want 1.\n"+
			"POST /api/devices returned 201 for a device that did not survive the "+
			"process — a 2xx for a write that was never persisted.", len(got))
	}
	if got[0].ID != d.ID || got[0].TenantID != "t_walmart" {
		t.Fatalf("recovered device = %+v, want id %s owned by t_walmart. Tenant "+
			"ownership must survive too, or the device comes back unattributed.", got[0], d.ID)
	}
}

// TestDeletedDeviceStaysDeleted is audit F-69: DELETE returned 204 and the
// device reappeared within 60s because the owning source re-added it on the
// next poll. The operator was told it was gone and it was not.
func TestDeletedDeviceStaysDeleted(t *testing.T) {
	withBackend(t, newMemKV())

	a := discovery.NewDiscoveryAggregator()
	st := newDeviceStore(devicesPath())
	a.SetStore(st)

	const id = "snmp-10.70.245.120"
	if err := a.Upsert(models.Device{ID: id, Name: "lab-sw", Address: "10.70.245.120"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(a.Devices()) != 0 {
		t.Fatal("device still present immediately after delete")
	}

	// The tombstone is what stops the next source poll resurrecting it.
	if !st.IsSuppressed(id) {
		t.Fatal("delete recorded no tombstone — the owning source will re-add this " +
			"device on its next poll and the 204 was a lie (F-69)")
	}

	// And it survives a restart: a tombstone that forgets is a tombstone that
	// lets the device return on the next deploy.
	b := newDeviceStore(devicesPath())
	if !b.IsSuppressed(id) {
		t.Fatal("tombstone did not persist — the device returns after a restart")
	}
}

// TestRecreatingADeletedDeviceClearsTheTombstone: a suppression must not become
// a permanent blocklist, or an operator who deletes a device can never add it
// back and has no way to see why.
func TestRecreatingADeletedDeviceClearsTheTombstone(t *testing.T) {
	withBackend(t, newMemKV())

	a := discovery.NewDiscoveryAggregator()
	st := newDeviceStore(devicesPath())
	a.SetStore(st)

	const id = "core-sw01"
	if err := a.Upsert(models.Device{ID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
	if err := a.Delete(id); err != nil {
		t.Fatal(err)
	}
	if err := a.Upsert(models.Device{ID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
	if st.IsSuppressed(id) {
		t.Fatal("re-creating a deleted device left its tombstone in place — the " +
			"device is invisible and the operator has no way to know why")
	}
	if len(a.Devices()) != 1 {
		t.Fatal("re-created device is not in the inventory")
	}
}

// TestUpsertReportsPersistFailure is the FAILURE path: when the store cannot
// write, the caller must be told rather than handed a 201 and an in-memory
// device that disappears at the next restart.
func TestUpsertReportsPersistFailure(t *testing.T) {
	withBackend(t, newMemKV())
	a := discovery.NewDiscoveryAggregator()
	a.SetStore(newDeviceStore(devicesPath()))

	withFailingKV(t) // every Save now fails

	err := a.Upsert(models.Device{ID: "d1", Name: "d1"})
	if err == nil {
		t.Fatal("upsert reported success while the store was unwritable — this is " +
			"the 201-without-persistence defect")
	}
	// RAM must not claim a device the store rejected.
	for _, d := range a.Devices() {
		if d.ID == "d1" {
			t.Fatal("device is in the in-memory inventory but was never persisted — " +
				"it will silently vanish at the next restart")
		}
	}
}

// TestSourceDevicesAreNotPersisted: a source-reported device must NOT be written
// to the manual store. Its source is its authority — persisting a shadow copy
// would resurrect devices that pollOnce legitimately prunes when the source
// stops reporting them (a disabled NetBox sync, a decommissioned subnet).
func TestSourceDevicesAreNotPersisted(t *testing.T) {
	withBackend(t, newMemKV())
	a := discovery.NewDiscoveryAggregator()
	st := newDeviceStore(devicesPath())
	a.SetStore(st)

	if err := a.Upsert(models.Device{ID: "netbox-1", Name: "netbox-1", Source: "netbox"}); err != nil {
		t.Fatal(err)
	}
	if got := st.Devices(); len(got) != 0 {
		t.Fatalf("source-owned device was persisted (%+v) — it would outlive its "+
			"source and reappear as a ghost after the source drops it", got)
	}
}

// TestManualDevicesAreTenantScoped: ownership is part of the persisted record,
// so a restart must not collapse devices into the global/Provider tenant. The
// static YAML source cannot express tenant at all, which is exactly why this
// store has to.
func TestManualDevicesAreTenantScoped(t *testing.T) {
	withBackend(t, newMemKV())
	a := discovery.NewDiscoveryAggregator()
	a.SetStore(newDeviceStore(devicesPath()))

	if err := a.Upsert(models.Device{ID: "a1", Name: "a1", TenantID: "t_a"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Upsert(models.Device{ID: "b1", Name: "b1", TenantID: "t_b"}); err != nil {
		t.Fatal(err)
	}

	b := discovery.NewDiscoveryAggregator()
	b.SetStore(newDeviceStore(devicesPath()))

	owners := map[string]string{}
	for _, d := range b.Devices() {
		owners[d.ID] = d.TenantID
	}
	if owners["a1"] != "t_a" || owners["b1"] != "t_b" {
		t.Fatalf("tenant ownership after restart = %v, want a1->t_a b1->t_b", owners)
	}
}
