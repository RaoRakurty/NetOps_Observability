// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_first_seen_store_test.go — the persistence half of the 2026-10-03
// monitoring rule: the first-seen ledger survives a round trip, an absent
// ledger is a first boot, an unparseable one fails the boot (never a silent
// fresh start that would hand the licence slots to whichever source polls
// first), and the per-device decisions of an older build are removed.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/discovery"
)

func TestFirstSeenStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_first_seen.json")
	st, err := newDeviceFirstSeenStore(path)
	if err != nil {
		t.Fatalf("an absent ledger is a first boot, not an error: %v", err)
	}
	if got := st.FirstSeenRecords(); len(got) != 0 {
		t.Fatalf("absent ledger seeded %v", got)
	}
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := st.SaveFirstSeen([]discovery.FirstSeenRecord{{TenantID: "acme", DeviceID: "d1", FirstSeen: at}}); err != nil {
		t.Fatal(err)
	}
	again, err := newDeviceFirstSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.FirstSeenRecords()
	if len(got) != 1 || got[0].DeviceID != "d1" || got[0].TenantID != "acme" || !got[0].FirstSeen.Equal(at) {
		t.Fatalf("round trip = %+v", got)
	}
}

func TestFirstSeenStoreRefusesAnUnparseableLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_first_seen.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newDeviceFirstSeenStore(path); err == nil {
		t.Fatal("a corrupt ledger must fail loudly, never start a fresh licence order silently")
	}
}

func TestRetireDeviceMonitoringDecisionsRemovesTheOldBlob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_monitoring.json")
	if err := os.WriteFile(path, []byte(`[{"tenant_id":"acme","device_id":"d1","enabled":false}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	retireDeviceMonitoringDecisions(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the retired decisions must be removed, stat err = %v", err)
	}
	// Absent is a no-op, and calling it again must not fail or recreate it.
	retireDeviceMonitoringDecisions(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a second run must leave nothing behind")
	}
}
