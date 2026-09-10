// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// store_test.go — §3a rule 4: isolation is enforced IN the store, so the store
// is tested WITHOUT the handlers. Every assertion here would still hold if a
// handler forgot its filter.

func storeRow(tenant, device, id string, at time.Time) Capture {
	return Capture{
		TenantID: tenant, DeviceID: device, ID: id, Interface: "Ethernet1/1",
		StartedAt: at, ExpiresAt: at.Add(time.Minute), Status: StatusStored,
		BlobRef: tenant + "/" + device + "/" + id + ".sealed",
	}
}

func TestFileStoreIsTenantFiltered(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	if err := s.Put(ctx, "acme", false, storeRow("acme", "shared-id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", at)); err != nil {
		t.Fatal(err)
	}
	// The SAME device id owned by another tenant — the shape a duplicated
	// inventory id takes, and the one a naive "filter by device" would leak.
	if err := s.Put(ctx, "globex", false, storeRow("globex", "shared-id", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2", at)); err != nil {
		t.Fatal(err)
	}

	rows, err := s.List(ctx, "acme", false, "shared-id", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "acme" {
		t.Fatalf("acme's list = %+v, want only its own row", rows)
	}
	if _, err := s.Get(ctx, "acme", false, "shared-id", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acme read globex's row: %v", err)
	}
	if _, err := s.Delete(ctx, "acme", false, "shared-id", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acme DELETED globex's row: %v", err)
	}
	// A cross-tenant caller sees both.
	rows, err = s.List(ctx, "", true, "shared-id", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("cross-tenant list = %d rows, want 2", len(rows))
	}
}

func TestFileStoreRefusesAWriteOutsideTheCallersScope(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	err := s.Put(ctx, "acme", false, storeRow("globex", "globex-core", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2", time.Now().UTC()))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("the store accepted a write stamped for ANOTHER tenant: %v", err)
	}
}

func TestFileStoreRefusesAnUnmintedCaptureID(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	bad := storeRow("acme", "acme-core", "../../etc/passwd", time.Now().UTC())
	if err := s.Put(ctx, "acme", false, bad); err == nil {
		t.Fatal("the store accepted a capture id that is not a minted 32-hex id")
	}
}

func TestFileStoreActiveForAndPruneRespectRunning(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	running := storeRow("acme", "acme-core", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9", at.Add(-time.Hour))
	running.Status = StatusRunning
	if err := s.Put(ctx, "acme", false, running); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.ActiveFor(ctx, "acme", false, "acme-core")
	if err != nil || !found || got.ID != running.ID {
		t.Fatalf("ActiveFor = (%+v, %v, %v)", got, found, err)
	}
	// globex must not see acme's running capture.
	if _, found, _ := s.ActiveFor(ctx, "globex", false, "acme-core"); found {
		t.Fatal("TENANT LEAK: globex saw acme's running capture")
	}
	for i := 0; i < 5; i++ {
		id := "cccccccccccccccccccccccccccccc" + string(rune('a'+i)) + "0"
		if err := s.Put(ctx, "acme", false, storeRow("acme", "acme-core", id, at.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.Prune(ctx, "acme", false, "acme-core", 2)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := s.List(ctx, "acme", false, "acme-core", 0)
	for _, r := range rows {
		if r.Status == StatusRunning {
			goto foundRunning
		}
	}
	t.Fatal("retention pruned the RUNNING capture — its device is still working")
foundRunning:
	if len(removed) == 0 {
		t.Fatal("retention removed nothing")
	}
	if len(rows) != 3 { // keep=2 finished + the running one
		t.Fatalf("kept %d rows, want 3 (2 finished + 1 running)", len(rows))
	}
}

func TestFileStorePersistsAcrossInstances(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/captures.json"
	s := NewFileStore(path)
	row := storeRow("acme", "acme-core", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", time.Now().UTC())
	if err := s.Put(ctx, "acme", false, row); err != nil {
		t.Fatal(err)
	}
	again := NewFileStore(path)
	got, err := again.Get(ctx, "acme", false, "acme-core", row.ID)
	if err != nil {
		t.Fatalf("the register did not survive a restart: %v", err)
	}
	if got.BlobRef != row.BlobRef {
		t.Fatalf("blob ref = %q, want %q", got.BlobRef, row.BlobRef)
	}
	// …and the tenant filter still holds after a reload.
	if _, err := again.Get(ctx, "globex", false, "acme-core", row.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TENANT LEAK after reload: %v", err)
	}
}

func TestBlobStoreRefusesUnsealedAndEscapingReferences(t *testing.T) {
	root := t.TempDir() + "/blobs"
	b, err := NewFileBlobStore(root, "v1:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Put("acme", "acme-core", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "plaintext"); err == nil {
		t.Fatal("the blob store accepted an UNSEALED capture")
	}
	if _, err := b.Put("acme", "acme-core", "../../etc/passwd", "v1:x"); err == nil {
		t.Fatal("the blob store accepted an unminted capture id")
	}
	for _, ref := range []string{"../../../etc/passwd", "/etc/passwd", "a/../../../etc/passwd"} {
		if _, err := b.Get(ref); err == nil {
			t.Errorf("the blob store served an escaping reference %q", ref)
		}
	}
}

// TestPruneCountsFailedCapturesSeparately is the store-level half of the
// retention rule: failed captures are an attempt timeline, not an artifact.
// They must never consume the budget that protects a stored capture, and
// pruning one must never hand the caller a blob reference to delete.
func TestPruneCountsFailedCapturesSeparately(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	kept := []Capture{}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("%032x", i+1)
		row := storeRow("acme", "acme-core", id, base.Add(time.Duration(i)*time.Minute))
		if err := s.Put(ctx, "acme", false, row); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, row)
	}
	// The failures land AFTER every real capture, so a newest-first budget
	// fills with them first. That ordering is the whole bug.
	for i := 0; i < 4*maxFailedCaptures; i++ {
		at := base.Add(24*time.Hour + time.Duration(i)*time.Minute)
		row := storeRow("acme", "acme-core", fmt.Sprintf("%032x", 1000+i), at)
		row.Status = StatusFailed
		row.Error = "connection refused"
		row.BlobRef = "" // a failed capture stores no packets, so it owns no blob
		if err := s.Put(ctx, "acme", false, row); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.Prune(ctx, "acme", false, "acme-core", 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range removed {
		if r.Status == StatusStored {
			t.Errorf("CAPTURE LOST: retention removed stored capture %s", r.ID)
		}
		if r.BlobRef != "" {
			t.Errorf("a pruned failed capture carried a blob reference (%q); the caller deletes those", r.BlobRef)
		}
	}
	rows, err := s.List(ctx, "acme", false, "acme-core", MaxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	alive := map[string]bool{}
	storedRows, failedRows := 0, 0
	for _, r := range rows {
		alive[r.ID] = true
		if r.Status == StatusStored {
			storedRows++
		} else {
			failedRows++
		}
	}
	for _, c := range kept {
		if !alive[c.ID] {
			t.Errorf("CAPTURE LOST: %s is gone from the register", c.ID)
		}
	}
	if storedRows != 3 {
		t.Errorf("register holds %d stored captures, want 3", storedRows)
	}
	if failedRows == 0 || failedRows > maxFailedCaptures {
		t.Errorf("register holds %d failed captures, want 1..%d", failedRows, maxFailedCaptures)
	}
}

// TestPruneDoesNotLoseCapturesWhenTheFlushFails is the configstore rule applied
// to this register, which has the same shape. Prune applied the retention to its
// in-memory map and only then tried to persist it. On a flush failure the sealed
// blobs were correctly kept — Prune returns an error and the caller deletes
// nothing — but the rows were already gone from memory, so the register silently
// disagreed with the disk and the next successful write made that loss permanent
// (§10). The captures would then be on disk with nothing able to reach them.
func TestPruneDoesNotLoseCapturesWhenTheFlushFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/captures.json"
	s := NewFileStore(path)
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	seeded := []Capture{}
	for i := 0; i < 6; i++ {
		row := storeRow("acme", "acme-core", fmt.Sprintf("%032x", i+1), base.Add(time.Duration(i)*time.Minute))
		if err := s.Put(ctx, "acme", false, row); err != nil {
			t.Fatal(err)
		}
		seeded = append(seeded, row)
	}

	// Break the write: the register's directory is now a FILE, so the atomic
	// write cannot create its temp file — a full or read-only volume without
	// needing either.
	s.path = path + "/captures.json"

	if _, err := s.Prune(ctx, "acme", false, "acme-core", 2); err == nil {
		t.Fatal("Prune must report a flush it could not complete")
	}

	rows, err := s.List(ctx, "acme", false, "acme-core", MaxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	alive := map[string]string{}
	for _, r := range rows {
		alive[r.ID] = r.BlobRef
	}
	for i, c := range seeded {
		if ref, ok := alive[c.ID]; !ok {
			t.Errorf("METADATA LOST in memory: capture %d (%s) is gone after a failed prune", i, c.ID)
		} else if ref != c.BlobRef {
			t.Errorf("capture %d came back pointing at %q, want %q", i, ref, c.BlobRef)
		}
	}

	// The next successful write must not persist the loss either.
	s.path = path
	later := storeRow("acme", "acme-core", fmt.Sprintf("%032x", 99), base.Add(time.Hour))
	if err := s.Put(ctx, "acme", false, later); err != nil {
		t.Fatal(err)
	}
	reloaded := NewFileStore(path)
	for i, c := range seeded {
		if _, err := reloaded.Get(ctx, "acme", false, "acme-core", c.ID); err != nil {
			t.Errorf("METADATA LOST from disk: capture %d (%s) is gone after a failed prune: %v", i, c.ID, err)
		}
	}
}

// TestDeleteDoesNotLoseTheRowWhenTheFlushFails is the same rule applied to the
// single-capture delete, which Prune's fix left behind.
//
// Delete removed the row from the register and only then wrote the file. On a
// write failure it returned an error, so the caller correctly deleted no blob —
// but the row was already gone from memory, and the next successful write made
// that permanent. The sealed capture would then sit on the volume with nothing
// able to list it, open it or delete it, and the operator who was told the
// delete FAILED could never retry it: the retry answers not found.
func TestDeleteDoesNotLoseTheRowWhenTheFlushFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := dir + "/captures.json"
	s := NewFileStore(path)
	base := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

	doomed := storeRow("acme", "acme-core", fmt.Sprintf("%032x", 1), base)
	keeper := storeRow("acme", "acme-core", fmt.Sprintf("%032x", 2), base.Add(time.Minute))
	for _, row := range []Capture{doomed, keeper} {
		if err := s.Put(ctx, "acme", false, row); err != nil {
			t.Fatal(err)
		}
	}

	// Break the write: the register's directory is now a FILE.
	s.path = path + "/captures.json"
	if _, err := s.Delete(ctx, "acme", false, "acme-core", doomed.ID); err == nil {
		t.Fatal("Delete must report a flush it could not complete")
	}

	got, err := s.Get(ctx, "acme", false, "acme-core", doomed.ID)
	if err != nil {
		t.Fatalf("METADATA LOST in memory: the capture is gone after a delete that failed: %v", err)
	}
	if got.BlobRef != doomed.BlobRef {
		t.Fatalf("the capture came back pointing at %q, want %q", got.BlobRef, doomed.BlobRef)
	}

	// The next successful write must not persist the loss either.
	s.path = path
	later := storeRow("acme", "acme-core", fmt.Sprintf("%032x", 99), base.Add(time.Hour))
	if err := s.Put(ctx, "acme", false, later); err != nil {
		t.Fatal(err)
	}
	reloaded := NewFileStore(path)
	if _, err := reloaded.Get(ctx, "acme", false, "acme-core", doomed.ID); err != nil {
		t.Fatalf("METADATA LOST from disk: the capture is gone after a delete that failed: %v", err)
	}

	// And a delete that CAN write still deletes.
	if _, err := s.Delete(ctx, "acme", false, "acme-core", doomed.ID); err != nil {
		t.Fatalf("Delete on a working write path: %v", err)
	}
	if _, err := NewFileStore(path).Get(ctx, "acme", false, "acme-core", doomed.ID); err == nil {
		t.Fatal("on disk: the capture survived a delete that did persist")
	}
	if _, err := NewFileStore(path).Get(ctx, "acme", false, "acme-core", keeper.ID); err != nil {
		t.Fatalf("on disk: the delete took the wrong row with it: %v", err)
	}
}
