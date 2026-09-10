// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"context"
	"errors"
	"fmt"
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

// TestPruneCountsFailureRowsSeparately is the store-level half of the retention
// rule: failure rows are a capture-outage timeline, not configuration history.
// They must never consume the budget that protects a captured version, and
// pruning one must never hand the caller a blob reference to delete.
func TestPruneCountsFailureRowsSeparately(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	kept := []Version{}
	for i := 0; i < 3; i++ {
		kept = append(kept, seedRow(t, s, "acme", "d1", fmt.Sprintf("cfg-%d", i), base.Add(time.Duration(i)*time.Hour)))
	}
	// The outage lands AFTER every real version, so a newest-first budget fills
	// with failures first. That ordering is the whole bug.
	for i := 0; i < 4*maxFailedVersions; i++ {
		at := base.Add(24*time.Hour + time.Duration(i)*15*time.Minute)
		row := Version{TenantID: "acme", DeviceID: "d1", SHA: failureSHA("d1", at),
			CapturedAt: at, Status: StatusFailed, Error: "unreachable", Drift: DriftUnknown}
		if err := s.Put(ctx, "acme", false, row); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.Prune(ctx, "acme", false, "d1", 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range removed {
		if r.Status == StatusOK {
			t.Errorf("HISTORY LOST: retention removed captured version %s", r.SHA)
		}
		if r.BlobRef != "" {
			t.Errorf("a pruned failure row carried a blob reference (%q); the caller deletes those", r.BlobRef)
		}
	}
	rows, err := s.List(ctx, "acme", false, "d1")
	if err != nil {
		t.Fatal(err)
	}
	alive := map[string]bool{}
	okRows, failRows := 0, 0
	for _, r := range rows {
		alive[r.SHA] = true
		if r.Status == StatusOK {
			okRows++
		} else {
			failRows++
		}
	}
	for _, v := range kept {
		if !alive[v.SHA] {
			t.Errorf("HISTORY LOST: version %s is gone from the register", v.SHA)
		}
	}
	if okRows != 3 {
		t.Errorf("register holds %d captured versions, want 3", okRows)
	}
	if failRows == 0 || failRows > maxFailedVersions {
		t.Errorf("register holds %d failure rows, want 1..%d", failRows, maxFailedVersions)
	}
}

// TestPruneDoesNotLoseRowsWhenTheFlushFails: the file register applied the prune
// to its in-memory map and only then tried to persist it. On a flush failure the
// blobs were correctly kept — Prune returns an error and the caller deletes
// nothing — but the rows were already gone from memory, so the register silently
// disagreed with the disk and the next successful write made that loss permanent
// (§10, no silent failures).
//
// The disk is the assertion that matters: a reload has to find every row.
func TestPruneDoesNotLoseRowsWhenTheFlushFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/versions.json"
	s := NewFileStore(path)
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	seeded := []Version{}
	for i := 0; i < 6; i++ {
		seeded = append(seeded, seedRow(t, s, "acme", "d1", fmt.Sprintf("cfg-%d", i),
			base.Add(time.Duration(i)*time.Hour)))
	}

	// Break the write. The register's directory is now a FILE, so the atomic
	// write cannot create its temp file — the same shape as a full or read-only
	// volume, without needing either.
	s.path = path + "/versions.json"

	if _, err := s.Prune(ctx, "acme", false, "d1", 2); err == nil {
		t.Fatal("Prune must report a flush it could not complete")
	}

	// Nothing was durably removed, so nothing may be missing from the register.
	rows, err := s.List(ctx, "acme", false, "d1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(seeded) {
		t.Errorf("METADATA LOST in memory: register holds %d rows after a failed prune, want %d",
			len(rows), len(seeded))
	}
	// Not just the count. A rollback that puts back a slice header can put back
	// a MUTATED backing array, so check the rows are the ones that were seeded,
	// each with the blob reference it was stored with.
	alive := map[string]string{}
	for _, r := range rows {
		alive[r.SHA] = r.BlobRef
	}
	for i, v := range seeded {
		if ref, ok := alive[v.SHA]; !ok {
			t.Errorf("METADATA LOST in memory: version %d (%s) is gone", i, v.SHA)
		} else if ref != v.BlobRef {
			t.Errorf("version %d came back pointing at %q, want %q", i, ref, v.BlobRef)
		}
	}

	// The next successful write must not persist the loss either. This is where
	// an in-memory-only loss becomes permanent.
	s.path = path
	if err := s.Put(ctx, "acme", false, seedRow(t, NewFileStore(""), "acme", "d1", "cfg-later",
		base.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	reloaded := NewFileStore(path)
	for i, v := range seeded {
		if _, err := reloaded.Get(ctx, "acme", false, "d1", v.SHA); err != nil {
			t.Errorf("METADATA LOST from disk: version %d (%s) is gone after a failed prune: %v", i, v.SHA, err)
		}
	}
}

// TestStoreSetGoldenKeepsTheMarkWhenTheTargetIsAbsent — REGRESSION (review
// 3.5-01). The golden mark is OPERATOR INTENT: nothing recomputes it, and the
// only way back is for a human to set it again on a version they have to find.
// A SetGolden that cannot find its target must therefore be a pure refusal —
// the device keeps the baseline it had. The scan used to clear every row first
// and only discover the miss afterwards, so a mistyped sha, a pruned one, or the
// synthetic sha of a FAILED capture (well-formed, so it passes validation, but
// never eligible) left the device with no baseline at all and every later drift
// verdict measured against nothing.
func TestStoreSetGoldenKeepsTheMarkWhenTheTargetIsAbsent(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	// Each case is a sha that is well-formed but not a version this device can
	// be golden on.
	cases := map[string]func(t *testing.T, s Store) string{
		"unknown sha": func(*testing.T, Store) string { return SHA256Hex("never-captured") },
		"pruned sha": func(t *testing.T, s Store) string {
			// A REAL prune: seed past the retention budget and use the sha
			// retention actually removed.
			seedRow(t, s, "acme", "d1", "cfg-c", base.Add(2*time.Hour))
			seedRow(t, s, "acme", "d1", "cfg-d", base.Add(3*time.Hour))
			removed, err := s.Prune(ctx, "acme", false, "d1", minKeepVersions)
			if err != nil || len(removed) != 1 {
				t.Fatalf("prune to mint a dead sha: removed %d err %v", len(removed), err)
			}
			return removed[0].SHA
		},
		"failed capture row": func(t *testing.T, s Store) string {
			sha := failureSHA("d1", base.Add(2*time.Hour))
			row := Version{TenantID: "acme", DeviceID: "d1", SHA: sha,
				CapturedAt: base.Add(2 * time.Hour), Status: StatusFailed,
				Error: "unreachable", Drift: DriftUnknown}
			if err := s.Put(ctx, "acme", false, row); err != nil {
				t.Fatalf("seed failed row: %v", err)
			}
			return sha
		},
	}
	for name, mint := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewFileStore("")
			good := seedRow(t, s, "acme", "d1", "cfg-a", base)
			seedRow(t, s, "acme", "d1", "cfg-b", base.Add(time.Hour))
			if err := s.SetGolden(ctx, "acme", false, "d1", good.SHA); err != nil {
				t.Fatalf("seed golden: %v", err)
			}
			miss := mint(t, s)

			if err := s.SetGolden(ctx, "acme", false, "d1", miss); !errors.Is(err, ErrNotFound) {
				t.Fatalf("SetGolden(%s) = %v, want ErrNotFound", name, err)
			}
			g, ok, err := s.Golden(ctx, "acme", false, "d1")
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("a refused SetGolden LEFT THE DEVICE WITH NO GOLDEN: the operator's baseline is gone and nothing recomputes it")
			}
			if g.SHA != good.SHA {
				t.Fatalf("golden moved to %s, want the untouched %s", g.SHA, good.SHA)
			}
		})
	}
}
