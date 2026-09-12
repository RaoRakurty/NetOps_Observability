// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/rca"
	"strings"
	"sync"
	"testing"
)

// settings_persist_failure_test.go — THE FAILURE PATH for every file/kv-backed
// settings store (audit F-62/F-63/F-64 class).
//
// Why this file exists. The happy path for these stores was already tested and
// green. What was never tested was the only path that actually mattered: what
// the API does when the WRITE DOES NOT LAND. The answer used to be "return 200
// and log a warning", because `saveLocked()` returned nothing at all — the
// handler was structurally incapable of noticing. Every one of those green
// happy-path tests stayed green through the entire defect.
//
// So these tests inject a failing kv backend and assert the three properties a
// write path must have when its store is broken:
//
//   1. STATUS      — the caller is told (5xx), never a 2xx for an unpersisted write.
//   2. ROLLBACK    — in-memory state matches the store; a rejected write does not
//                    keep applying in RAM until the next restart.
//   3. NO COLLATERAL — one tenant's failing write never destroys another
//                      tenant's persisted data (F-64).
//
// The backend is a process-wide var, so nothing here may run in parallel.

// faultyKV fails Save for every key, and counts attempts. Load delegates to the
// real file backend so store construction still works.
type faultyKV struct {
	mu       sync.Mutex
	saves    int
	failWith error
}

func (f *faultyKV) Load(key string) ([]byte, error) { return platformdb.FileKV{}.Load(key) }

func (f *faultyKV) Save(key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves++
	if f.failWith != nil {
		return f.failWith
	}
	return platformdb.FileKV{}.Save(key, data)
}

func (f *faultyKV) attempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

// withFailingKV swaps the process-wide backend for one that refuses every write
// (the realistic shapes: EACCES on a wrong-UID container, ENOSPC on a full
// disk, or Postgres down). Restored on cleanup.
func withFailingKV(t *testing.T) *faultyKV {
	t.Helper()
	f := &faultyKV{failWith: errors.New("kv unavailable: permission denied")}
	t.Cleanup(platformdb.SwapBackendForTest(f))
	return f
}

// TestSettingsWritesFailLoudlyWhenTheStoreIsBroken is the class guard: every
// tenant-settings mutator must surface a persist failure rather than swallow it.
// A new store added to this family must be added here — that is the point.
func TestSettingsWritesFailLoudlyWhenTheStoreIsBroken(t *testing.T) {
	dir := t.TempDir()

	gov := newTenantGovernanceStore(dir + "/gov.json")
	disp := newTenantDisplayStore(dir + "/disp.json")
	slo := newCloudSLOStore(dir + "/slo.json")
	promo := newRcaPromotionStore(dir + "/promo.json")

	f := withFailingKV(t)

	cases := []struct {
		name string
		call func() error
	}{
		{"governance.setRequiredTags", func() error { return gov.SetRequiredTags("t-a", []string{"app"}) }},
		{"governance.setRcaWindowHours", func() error { return gov.SetRcaWindowHours("t-a", 72) }},
		{"governance.setAttributionPrecedence", func() error {
			return gov.SetAttributionPrecedence("t-a", []string{"operator_override"})
		}},
		{"governance.setSeamOwners", func() error {
			return gov.SetSeamOwners("t-a", map[string]seamOwnerEntry{"isp": {Name: "Lumen"}})
		}},
		{"display.setTimeDisplay", func() error { _, err := disp.setTimeDisplay("t-a", "utc"); return err }},
		{"slo.set", func() error { return slo.Set("t-a", []cloudSLO{{AppName: "checkout", TargetPct: 99.9, WindowDays: 7}}) }},
		{"promotion.set", func() error { return promo.Set("t-a", "c-1", rca.PromotionRecord{PromotedBy: "ops"}) }},
		{"promotion.remove", func() error { return promo.Remove("t-a", "c-1") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := f.attempts()
			if err := tc.call(); err == nil {
				t.Fatal("persist failed but the mutator reported success — this is the F-62 defect class: " +
					"a write path that cannot fail is a write path that is not writing")
			}
			if f.attempts() == before {
				t.Fatal("mutator never attempted a save — the test is not exercising the persist path")
			}
		})
	}
}

// TestSettingsRollBackInMemoryStateOnFailedPersist: a refused write must not
// keep applying in RAM. Otherwise the process serves a value that does not
// exist in the store — the same "looks applied, isn't" shape, just relocated,
// and it silently repairs itself on restart which makes it very hard to debug.
func TestSettingsRollBackInMemoryStateOnFailedPersist(t *testing.T) {
	dir := t.TempDir()
	gov := newTenantGovernanceStore(dir + "/gov.json")

	// Seed a good value through a WORKING backend.
	if err := gov.SetRcaWindowHours("t-a", 24); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	if h, custom := gov.RcaWindowHours("t-a"); h != 24 || !custom {
		t.Fatalf("seed = (%d,%v), want (24,true)", h, custom)
	}

	withFailingKV(t)

	if err := gov.SetRcaWindowHours("t-a", 96); err == nil {
		t.Fatal("write on a broken store must fail")
	}
	if h, custom := gov.RcaWindowHours("t-a"); h != 24 || !custom {
		t.Fatalf("after a REFUSED write the store reads (%d,%v) — want the pre-write (24,true). "+
			"In-memory state diverged from the store.", h, custom)
	}

	// A refused CREATE must leave no phantom record either.
	if err := gov.SetRcaWindowHours("t-new", 48); err == nil {
		t.Fatal("create on a broken store must fail")
	}
	if _, custom := gov.RcaWindowHours("t-new"); custom {
		t.Fatal("a tenant whose creating write was refused now reads as configured — phantom record")
	}
}

// TestRcaWindowPutReportsPersistFailure is the SEED DEFECT, end to end at the
// HTTP boundary: "PUT /api/settings/rca-window returns 200 without persisting;
// the UI shows the new value and a reload shows the old one."
func TestRcaWindowPutReportsPersistFailure(t *testing.T) {
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	au, err := newAuditStore(dir + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{roles: rs, audit: au, governance: newTenantGovernanceStore(dir + "/gov.json")}
	adm := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}

	withFailingKV(t)

	r := httptest.NewRequest(http.MethodPut, "/api/settings/rca-window", strings.NewReader(`{"rca_window_hours":72}`))
	rec := httptest.NewRecorder()
	s.handleRcaWindowSettings(rec, claimsCtx(r, adm))

	if rec.Code == http.StatusOK {
		t.Fatalf("PUT returned 200 while the store was unwritable — the seed defect. body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT = %d, want 500", rec.Code)
	}

	// And the read-back agrees: the operator is not shown a value that is not stored.
	r = httptest.NewRequest(http.MethodGet, "/api/settings/rca-window", nil)
	rec = httptest.NewRecorder()
	s.handleRcaWindowSettings(rec, claimsCtx(r, adm))
	if strings.Contains(rec.Body.String(), `"rca_window_hours":72`) {
		t.Fatalf("GET reports the value the failed PUT tried to set: %s", rec.Body.String())
	}
}

// TestAITenantConfigFailedSaveDoesNotDestroyOtherTenants is F-64 (Critical):
// the store rewrites ONE whole file for ALL tenants, so a per-record failure
// used to be "resolved" by dropping that record and writing the rest — tenant
// B's save silently deleted tenant A's stored provider key, and both callers
// got 200. Cross-tenant data destruction (CLAUDE.md §3a).
func TestAITenantConfigFailedSaveDoesNotDestroyOtherTenants(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ai.json"

	// Tenant A stores a BYO provider key through a healthy vault + backend.
	sealer := &failingVault{}
	stA := newAITenantConfigStore(path, sealer)
	if _, err := stA.SetTenantSettings("t-a", "anthropic", "claude-opus-4-8", "sk-tenant-a-secret", false, false); err != nil {
		t.Fatalf("tenant A seed write: %v", err)
	}

	// Now tenant B writes while the vault refuses to seal. The old code
	// `continue`d past the unsealable record and persisted the rest.
	sealer.fail = true
	if _, err := stA.SetTenantSettings("t-b", "openai", "", "sk-tenant-b", false, false); err == nil {
		t.Fatal("a save that could not seal every record must fail, not persist a partial map")
	}

	// Tenant A's key must still be on disk and readable by a fresh store.
	sealer.fail = false
	reloaded := newAITenantConfigStore(path, &failingVault{})
	if got := reloaded.Get("t-a"); got.Key != "sk-tenant-a-secret" {
		t.Fatalf("tenant A's stored key after tenant B's failed write = %q, want it intact. "+
			"One tenant's write destroyed another tenant's data.", got.Key)
	}
}

// failingVault is a passthrough sealer with a switch, so a per-record seal
// failure can be provoked deterministically.
type failingVault struct{ fail bool }

func (v *failingVault) Encrypt(tenant, field, plaintext string) (string, error) {
	if v.fail {
		return "", errors.New("seal unavailable")
	}
	return plaintext, nil
}

func (v *failingVault) Decrypt(tenant, field, ciphertext string) (string, error) {
	return ciphertext, nil
}
