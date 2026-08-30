package discovery

import (
	"testing"

	"netops/backend/models"
)

// TRACKER 181, storage layer. CreateOrResolve is the operator-create seam: it
// resolves the identity BEFORE writing, so a create that dedupe absorbs never
// becomes a persisted-but-unlistable SHADOW row. These tests pin the store's
// own contract, independent of the HTTP handler.

func rawIDs(a *DiscoveryAggregator) map[string]bool {
	out := map[string]bool{}
	for _, d := range a.RawDevices() {
		out[d.ID] = true
	}
	return out
}

func TestCreateOrResolveNewIdentityPersists(t *testing.T) {
	a := NewDiscoveryAggregator()
	got, created, err := a.CreateOrResolve(models.Device{ID: "leaf-1", Name: "leaf-1", Address: "10.0.0.1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created {
		t.Fatal("a genuinely new identity must be reported as created")
	}
	if got.ID != "leaf-1" {
		t.Fatalf("created device must own its requested identity, got %q", got.ID)
	}
	if raw := rawIDs(a); len(raw) != 1 || !raw["leaf-1"] {
		t.Fatalf("exactly one row must persist, got %v", raw)
	}
}

func TestCreateOrResolveAbsorbedWritesNothing(t *testing.T) {
	a := NewDiscoveryAggregator()
	if _, created, err := a.CreateOrResolve(
		models.Device{ID: "aaa-keeper", Name: "aaa-keeper", Address: "10.0.0.2"}); err != nil || !created {
		t.Fatalf("seed: created=%v err=%v", created, err)
	}
	got, created, err := a.CreateOrResolve(
		models.Device{ID: "zzz-absorbed", Name: "zzz-absorbed", Address: "10.0.0.2"})
	if err != nil {
		t.Fatalf("absorbed create: %v", err)
	}
	if created {
		t.Fatal("a create absorbed by dedupe must not be reported as created")
	}
	if got.ID != "aaa-keeper" {
		t.Fatalf("absorbed create must return the canonical device, got %q", got.ID)
	}
	raw := rawIDs(a)
	if raw["zzz-absorbed"] {
		t.Fatal("SHADOW ROW: the absorbed create was persisted under its own id (tracker 181)")
	}
	if len(raw) != 1 {
		t.Fatalf("one identity must persist exactly one row, got %v", raw)
	}
	// The raw rows (what Delete addresses) and the projection (what the read
	// path lists) must describe the same fleet.
	if devs := a.Devices(); len(devs) != len(raw) {
		t.Fatalf("projection lists %d device(s) but %d row(s) are persisted", len(devs), len(raw))
	}
}

// Re-onboarding the same device is an update of the same row, not a new one.
func TestCreateOrResolveIsIdempotentForTheSameRow(t *testing.T) {
	a := NewDiscoveryAggregator()
	d := models.Device{ID: "leaf-3", Name: "leaf-3", Address: "10.0.0.3"}
	if _, created, err := a.CreateOrResolve(d); err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}
	d.Vendor = "Arista"
	got, _, err := a.CreateOrResolve(d)
	if err != nil {
		t.Fatalf("re-onboard: %v", err)
	}
	if got.ID != "leaf-3" || got.Vendor != "Arista" {
		t.Fatalf("re-onboard must update the same row, got %+v", got)
	}
	if raw := rawIDs(a); len(raw) != 1 {
		t.Fatalf("re-onboard must not add a row, got %v", raw)
	}
}

// §3a: dedupe is tenant-partitioned. The same management address and hostname
// in two tenants are two DIFFERENT devices; merging them would fold one
// tenant's inventory into the other's (the merged record carries a single
// TenantID, so the loser's owner sees a device that is not theirs — or loses
// sight of their own).
func TestDedupeNeverMergesAcrossTenants(t *testing.T) {
	a := NewDiscoveryAggregator()
	if err := a.Upsert(models.Device{ID: "acme-core", Name: "core-sw01", Address: "10.10.0.1", TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Upsert(models.Device{ID: "globex-core", Name: "core-sw01", Address: "10.10.0.1", TenantID: "globex"}); err != nil {
		t.Fatal(err)
	}
	devs := a.Devices()
	if len(devs) != 2 {
		t.Fatalf("CROSS-TENANT MERGE: two tenants' devices collapsed into %d row(s): %+v", len(devs), devs)
	}
	seen := map[string]bool{}
	for _, d := range devs {
		seen[d.TenantID] = true
	}
	if !seen["acme"] || !seen["globex"] {
		t.Fatalf("each tenant must keep its own record, got %v", seen)
	}
	// Untagged (platform-scoped) records keep merging with each other.
	if err := a.Upsert(models.Device{ID: "snmp-a", Name: "edge-1", Address: "10.20.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Upsert(models.Device{ID: "netbox-a", Name: "edge-1", Source: "netbox"}); err != nil {
		t.Fatal(err)
	}
	if got := len(a.Devices()); got != 3 {
		t.Fatalf("platform-scoped records must still merge with each other, got %d rows", got)
	}
}

// A create in another tenant that derives the SAME id must not overwrite the
// incumbent: it gets its own key and both rows survive.
func TestCreateOrResolveNeverOverwritesAnotherTenantsRow(t *testing.T) {
	a := NewDiscoveryAggregator()
	id := ScanDeviceID("core-sw01", "10.10.0.1")
	acme := models.Device{ID: id, Name: "core-sw01", Address: "10.10.0.1", TenantID: "acme"}
	globex := models.Device{ID: id, Name: "core-sw01", Address: "10.10.0.1", TenantID: "globex"}
	if _, created, err := a.CreateOrResolve(acme); err != nil || !created {
		t.Fatalf("acme create: created=%v err=%v", created, err)
	}
	got, created, err := a.CreateOrResolve(globex)
	if err != nil {
		t.Fatalf("globex create: %v", err)
	}
	if !created {
		t.Fatalf("globex's own device must create independently, got canonical %+v", got)
	}
	if got.ID == id {
		t.Fatalf("CROSS-TENANT WRITE: globex took over acme's row %q", id)
	}
	raw := rawIDs(a)
	if len(raw) != 2 || !raw[id] || !raw[got.ID] {
		t.Fatalf("both tenants must keep a row, got %v", raw)
	}
	if d, ok := a.Get(id); !ok || d.TenantID != "acme" {
		t.Fatalf("acme's row must be untouched, got %+v (present=%v)", d, ok)
	}
	// And globex re-onboarding the same device stays on its own row.
	if _, _, err := a.CreateOrResolve(globex); err != nil {
		t.Fatalf("globex re-onboard: %v", err)
	}
	if raw := rawIDs(a); len(raw) != 2 {
		t.Fatalf("a re-onboard must not fragment into a third row, got %v", raw)
	}
}
