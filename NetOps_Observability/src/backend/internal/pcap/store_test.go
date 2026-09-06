// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
	"errors"
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
