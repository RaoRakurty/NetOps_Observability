// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

// notifystate_isolation_test.go — CLAUDE.md §3a for the durable notified set.
//
// The store keys every record by the tenant its alert's DEVICE belongs to, and
// this file is the proof that the key is load-bearing rather than decorative.
// The cross-tenant harm here is not a data leak in the usual sense — it is a
// SUPPRESSED PAGE: if tenant B's engine could see tenant A's record for the
// same alert id (rule names and device ids repeat across tenants — every tenant
// has a "DeviceUnreachable|device=core1"), B's genuinely-new firing would be
// treated as already-notified and nobody would be told. A notification silently
// not sent for the wrong tenant is exactly the class of failure the alerting
// work of 2026-09-02/03 exists to end.
//
// Asserted, mirroring org_isolation_test.go's shape:
//
//	own-only list                      List(A) never contains B's records
//	cross-tenant get → absent          Notified(B, idOfA) is false
//	cross-tenant delete → no-op        Clear(B, idOfA) leaves A's record intact
//	owner from the caller, not payload a tenant label in the alert is ignored
//	eviction is per tenant             A at its cap never displaces B

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netops/backend/models"
)

const (
	tenantA = "t_acme"
	tenantB = "t_globex"
)

// sameID is one alert id that legitimately exists in BOTH tenants — the same
// rule firing on a same-named device. This is the collision the tenant key has
// to survive, and it is not hypothetical.
const sameID = "DeviceUnreachable|device=core1"

func newIsolationStore(t *testing.T) *NotifyStateStore {
	t.Helper()
	st, err := NewNotifyStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err)
	}
	clock := &fakeClock{t: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)}
	st.SetNowForTest(clock.now)
	return st
}

func TestNotifyStateIsTenantIsolated(t *testing.T) {
	st := newIsolationStore(t)
	st.MarkNotified(tenantA, models.Alert{ID: sameID, Rule: "DeviceUnreachable", DeviceID: "core1", Severity: "critical"})

	// own-only list
	if got := st.List(tenantA); len(got) != 1 || got[0].Alert.ID != sameID {
		t.Fatalf("List(A) = %+v, want exactly A's record", got)
	}
	if got := st.List(tenantB); len(got) != 0 {
		t.Fatalf("List(B) leaked %d of A's records: %+v", len(got), got)
	}
	if got := st.List(""); len(got) != 0 {
		t.Fatalf("the platform bucket leaked a tenant's records: %+v", got)
	}

	// cross-tenant get: absent, not merely filtered
	if _, ok := st.Notified(tenantB, sameID); ok {
		t.Fatal("tenant B can see tenant A's notified record — B's real page would be suppressed")
	}

	// cross-tenant delete: a no-op, never a delete
	st.Clear(tenantB, sameID)
	if _, ok := st.Notified(tenantA, sameID); !ok {
		t.Fatal("tenant B's Clear removed tenant A's record")
	}
	// Own-tenant delete works, so the no-op above is isolation and not inertia.
	st.Clear(tenantA, sameID)
	if _, ok := st.Notified(tenantA, sameID); ok {
		t.Fatal("own-tenant Clear did not remove the record")
	}

	// cross-tenant touch: also a no-op
	st.MarkNotified(tenantA, models.Alert{ID: sameID, Rule: "DeviceUnreachable"})
	before, _ := st.Notified(tenantA, sameID)
	st.Touch(tenantB, sameID)
	after, _ := st.Notified(tenantA, sameID)
	if !after.LastSeen.Equal(before.LastSeen) {
		t.Fatal("tenant B's Touch mutated tenant A's record")
	}
}

// §3a rule 2: the OWNER is stamped from the caller's derivation (the alert's
// device → tenant), never from anything carried in the alert itself. A rule bug
// — or a device label an operator controls — must not be able to file a record
// under someone else's tenant.
func TestNotifyStateOwnerComesFromTheCallerNotTheAlert(t *testing.T) {
	st := newIsolationStore(t)
	st.MarkNotified(tenantA, models.Alert{
		ID:   sameID,
		Rule: "DeviceUnreachable",
		// A payload that asks to be filed under another tenant. It is data.
		Labels: map[string]string{"tenant": tenantB, "tenant_id": tenantB, "org": "global"},
	})
	if got := st.List(tenantB); len(got) != 0 {
		t.Fatalf("a tenant label in the alert placed the record in tenant B: %+v", got)
	}
	if got := st.List(tenantA); len(got) != 1 {
		t.Fatalf("the record was not filed under the CALLER's tenant: %+v", got)
	}
	if got := st.List(tenantA)[0].TenantID; got != tenantA {
		t.Fatalf("stored TenantID = %q, want the caller's %q", got, tenantA)
	}
}

// Two tenants' records survive a restart independently, each still keyed to its
// owner — the round trip is where a tenant key is most easily lost.
func TestNotifyStateTenantKeySurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := NewNotifyStateStore(path)
	if err != nil {
		t.Fatalf("NewNotifyStateStore: %v", err)
	}
	st.MarkNotified(tenantA, models.Alert{ID: sameID, Rule: "DeviceUnreachable"})
	st.MarkNotified(tenantB, models.Alert{ID: sameID, Rule: "DeviceUnreachable"})
	st.MarkNotified("", models.Alert{ID: "IngestPipelineSilent", Rule: "IngestPipelineSilent"})
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	back, err := NewNotifyStateStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, tn := range []string{tenantA, tenantB} {
		got := back.List(tn)
		if len(got) != 1 || got[0].TenantID != tn || got[0].Alert.ID != sameID {
			t.Fatalf("after reload List(%q) = %+v, want exactly that tenant's own record", tn, got)
		}
	}
	if got := back.List(""); len(got) != 1 || got[0].Alert.ID != "IngestPipelineSilent" {
		t.Fatalf("the platform-owned record did not round-trip: %+v", got)
	}
	if got := back.Tenants(); len(got) != 3 {
		t.Fatalf("Tenants() = %v, want the three namespaces", got)
	}
	// Case and padding are one namespace, not three (the key is normalized).
	if _, ok := back.Notified("  T_ACME ", sameID); !ok {
		t.Fatal("a differently-cased tenant id missed its own record")
	}
}

// The per-tenant cap is exactly that: a tenant filling its own quota must never
// evict another tenant's state and cause a duplicate page in that namespace.
func TestNotifyStateEvictionIsPerTenant(t *testing.T) {
	st := newIsolationStore(t)
	st.MarkNotified(tenantB, models.Alert{ID: "quiet-tenant-alert", Rule: "R"})
	for i := 0; i < notifyStateMaxPerTenant+100; i++ {
		st.MarkNotified(tenantA, models.Alert{ID: "R|n=" + strconv.Itoa(i), Rule: "R"})
	}
	if got := len(st.List(tenantA)); got != notifyStateMaxPerTenant {
		t.Fatalf("tenant A holds %d records, want the cap %d", got, notifyStateMaxPerTenant)
	}
	if _, ok := st.Notified(tenantB, "quiet-tenant-alert"); !ok {
		t.Fatal("a noisy tenant evicted a quiet tenant's record — that is a duplicate page in another namespace")
	}
}

// The engine's own derivation: with no TenantOf hook every alert is
// platform-owned, and with one the record lands in that tenant. This is the
// seam that connects server.alertTenant to the store, so it is asserted rather
// than assumed.
func TestEngineFilesNotifiedRecordsUnderTheDerivedTenant(t *testing.T) {
	st := newIsolationStore(t)
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) {
		return []Sample{{Labels: map[string]string{"device": "core1"}, Value: 1}}, nil
	})
	e.SetNotifyState(st)
	e.TenantOf = func(a models.Alert) string {
		if a.DeviceID == "core1" {
			return tenantA
		}
		return ""
	}
	e.AddRule(Rule{Name: "DeviceUnreachable", Expr: "x > 0", Severity: "critical"})
	e.evaluateAll()

	if got := st.List(tenantA); len(got) != 1 {
		t.Fatalf("the engine did not file the record under the derived tenant: %+v", got)
	}
	if got := st.List(""); len(got) != 0 {
		t.Fatalf("a device-owned alert was filed as platform-owned: %+v", got)
	}
}
