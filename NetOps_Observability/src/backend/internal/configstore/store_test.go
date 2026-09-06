// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// store_test.go — §3a rule 4: the STORE is the isolation boundary. Every method
// is exercised from a foreign tenant's scope and must behave as if the row does
// not exist.

func seedRow(t *testing.T, s Store, tenant, device, seed string, at time.Time) Version {
	t.Helper()
	v := Version{
		TenantID: tenant, DeviceID: device, SHA: SHA256Hex(seed), CapturedAt: at,
		SizeBytes: int64(len(seed)), BlobRef: tenant + "/" + device + "/" + SHA256Hex(seed),
		Vendor: string(VendorCisco), Status: StatusOK, Drift: DriftUnknown,
	}
	if err := s.Put(context.Background(), tenant, false, v); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return v
}

func TestStoreOwnOnlyListing(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	own := seedRow(t, s, "acme", "d1", "acme-cfg", base)
	foreign := seedRow(t, s, "globex", "d2", "globex-cfg", base)
	// Same DEVICE ID in two tenants — the nastiest shape, and the one a
	// device-id-keyed store gets wrong.
	collide := seedRow(t, s, "globex", "d1", "globex-same-id", base.Add(time.Hour))

	rows, err := s.List(ctx, "acme", false, "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SHA != own.SHA {
		t.Fatalf("acme sees %d rows for d1, want only its own: %+v", len(rows), rows)
	}
	if rows, _ := s.List(ctx, "acme", false, "d2"); len(rows) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme lists %d rows on globex's device", len(rows))
	}
	if _, err := s.Get(ctx, "acme", false, "d1", collide.SHA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("colliding device id leaked across tenants: %v", err)
	}
	if _, err := s.Get(ctx, "acme", false, "d2", foreign.SHA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get = %v, want ErrNotFound", err)
	}
	// Cross-tenant callers DO see everything — isolation is scope-based.
	if rows, _ := s.List(ctx, "", true, "d1"); len(rows) != 2 {
		t.Fatalf("cross-tenant list = %d rows, want 2", len(rows))
	}
}

func TestStoreCrossTenantWritesAreRefused(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	foreign := seedRow(t, s, "globex", "d2", "globex-cfg", base)

	if err := s.SetGolden(ctx, "acme", false, "d2", foreign.SHA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant SetGolden = %v, want ErrNotFound", err)
	}
	if err := s.RecordDrift(ctx, "acme", false, "d2", foreign.SHA, DriftDrifted, 1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant RecordDrift = %v, want ErrNotFound", err)
	}
	// …and nothing was changed under the covers.
	got, err := s.Get(ctx, "globex", false, "d2", foreign.SHA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Golden || got.Drift != DriftUnknown {
		t.Fatalf("a refused cross-tenant write still mutated the row: %+v", got)
	}
	if pruned, err := s.Prune(ctx, "acme", false, "d2", 2); err != nil || len(pruned) != 0 {
		t.Fatalf("cross-tenant Prune touched %d rows (err %v)", len(pruned), err)
	}
}

func TestStoreGoldenIsSingular(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	a := seedRow(t, s, "acme", "d1", "cfg-a", base)
	b := seedRow(t, s, "acme", "d1", "cfg-b", base.Add(time.Hour))

	if err := s.SetGolden(ctx, "acme", false, "d1", a.SHA); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGolden(ctx, "acme", false, "d1", b.SHA); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.List(ctx, "acme", false, "d1")
	golds := 0
	for _, r := range rows {
		if r.Golden {
			golds++
			if r.SHA != b.SHA {
				t.Errorf("wrong golden: %s", r.SHA)
			}
		}
	}
	if golds != 1 {
		t.Fatalf("%d golden versions, want exactly 1", golds)
	}
	g, ok, err := s.Golden(ctx, "acme", false, "d1")
	if err != nil || !ok || g.SHA != b.SHA {
		t.Fatalf("Golden() = %+v ok=%v err=%v", g, ok, err)
	}
}

func TestStoreLatestSkipsFailedCaptures(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	good := seedRow(t, s, "acme", "d1", "cfg-good", base)
	// A LATER failed capture must not become "the latest configuration" — that
	// would hand the hardening engine an empty config and turn every rule green.
	fail := Version{TenantID: "acme", DeviceID: "d1", SHA: failureSHA("d1", base.Add(time.Hour)),
		CapturedAt: base.Add(time.Hour), Status: StatusFailed, Error: "unreachable", Drift: DriftUnknown}
	if err := s.Put(ctx, "acme", false, fail); err != nil {
		t.Fatal(err)
	}
	latest, ok, err := s.Latest(ctx, "acme", false, "d1")
	if err != nil || !ok {
		t.Fatalf("Latest = ok %v err %v", ok, err)
	}
	if latest.SHA != good.SHA {
		t.Fatalf("Latest returned the failed row: %+v", latest)
	}
}

func TestStoreKeepClamping(t *testing.T) {
	for in, want := range map[int]int{0: minKeepVersions, 1: minKeepVersions, 30: 30, 100000: maxKeepVersions, -5: minKeepVersions} {
		if got := clampKeep(in); got != want {
			t.Errorf("clampKeep(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestStoreRejectsMalformedVersion(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	if err := s.Put(ctx, "acme", false, Version{TenantID: "acme", Status: StatusOK, SHA: SHA256Hex("x")}); err == nil {
		t.Error("a version with no device id must be refused")
	}
	if err := s.Put(ctx, "acme", false, Version{TenantID: "acme", DeviceID: "d1", Status: StatusOK, SHA: "short"}); err == nil {
		t.Error("a version with an invalid sha must be refused")
	}
}

func TestSegIsBoundedAndSafe(t *testing.T) {
	if Seg("") != "global" || Seg("   ") != "global" {
		t.Error("empty tenant must render as the global segment")
	}
	if got := Seg("ACME Corp/../etc"); got != "acme-corp----etc" {
		t.Errorf("Seg = %q; path separators must not survive", got)
	}
	long := Seg(string(make([]byte, 200)))
	if len(long) > 64 {
		t.Errorf("Seg is unbounded: %d chars", len(long))
	}
}

// TestFileStorePersistsEveryFieldItNeeds guards the state file's round trip. A
// row that reloads without its tenant, blob reference or vendor is worse than no
// row: the blob becomes unreachable garbage and the tenant filter loses its
// owner (the failure mode a `json:"-"` on a STORE row would have caused).
func TestFileStorePersistsEveryFieldItNeeds(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config_backup_versions.json"
	s := NewFileStore(path)
	at := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	want := Version{
		TenantID: "acme", DeviceID: "d1", SHA: SHA256Hex("cfg"), CapturedAt: at,
		SizeBytes: 42, BlobRef: "acme/d1/" + SHA256Hex("cfg"), Vendor: string(VendorCisco),
		Status: StatusOK, Drift: DriftChanged, Added: 3, Removed: 1,
	}
	if err := s.Put(context.Background(), "acme", false, want); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGolden(context.Background(), "acme", false, "d1", want.SHA); err != nil {
		t.Fatal(err)
	}

	reloaded := NewFileStore(path)
	got, err := reloaded.Get(context.Background(), "acme", false, "d1", want.SHA)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.TenantID != "acme" || got.BlobRef != want.BlobRef || got.Vendor != want.Vendor {
		t.Fatalf("reloaded row lost fields: %+v", got)
	}
	if !got.Golden || got.Drift != DriftChanged || got.Added != 3 || got.Removed != 1 {
		t.Fatalf("reloaded row = %+v", got)
	}
	if !got.CapturedAt.Equal(at) {
		t.Errorf("captured_at = %v, want %v", got.CapturedAt, at)
	}
	// And the tenant filter still holds after a reload.
	if rows, _ := reloaded.List(context.Background(), "globex", false, "d1"); len(rows) != 0 {
		t.Fatal("CROSS-TENANT LEAK after reload")
	}
}
