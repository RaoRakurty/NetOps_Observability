package configdrift

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// http_test.go — the bulk drift list contract and its §3a obligations.

func seedState(t *testing.T, f *fixture, tenant, device, state string) {
	t.Helper()
	sha := "sha-" + device
	err := f.store.Put(context.Background(), tenant, false, State{
		TenantID: tenant, DeviceID: device, State: state,
		LastSHA: sha, LastCapture: f.now, UpdatedAt: f.now,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// TestDriftListContract pins the shape the inventory badge consumes.
func TestDriftListContract(t *testing.T) {
	f := newFixture(t, nil)
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	seedState(t, f, "acme", "d1", StateDrifted)

	w := f.do(http.MethodGet, "/api/config/drift")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := f.decode(w)
	if body["next_cursor"] != nil {
		t.Errorf("next_cursor = %v, want null on a single page", body["next_cursor"])
	}
	if body["total"] != float64(1) {
		t.Errorf("total = %v, want 1", body["total"])
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", body["items"])
	}
	item := items[0].(map[string]any)
	for _, key := range []string{"device_id", "device_name", "state", "last_sha", "golden_sha", "last_capture_at"} {
		if _, present := item[key]; !present {
			t.Errorf("item is missing %q: %v", key, item)
		}
	}
	if item["device_name"] != "acme-edge-01" {
		t.Errorf("device_name = %v", item["device_name"])
	}
	if item["state"] != StateDrifted {
		t.Errorf("state = %v", item["state"])
	}
	if item["golden_sha"] != nil {
		t.Errorf("an unset golden must be null, got %v", item["golden_sha"])
	}
}

// TestDriftListIsOwnOnly is the §3a rule 1 obligation on a LIST surface.
func TestDriftListIsOwnOnly(t *testing.T) {
	f := newFixture(t, nil)
	seedState(t, f, "acme", "d1", StateDrifted)
	seedState(t, f, "globex", "d2", StateDrifted)
	seedState(t, f, "globex", "d3", StateChanged)

	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	body := f.decode(f.do(http.MethodGet, "/api/config/drift"))
	items := body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["device_id"] != "d1" {
		t.Fatalf("CROSS-TENANT LEAK: acme sees %v", items)
	}
	if body["total"] != float64(1) {
		t.Errorf("total leaked other tenants' rows: %v", body["total"])
	}

	// A cursor naming a foreign device cannot page into that tenant.
	body = f.decode(f.do(http.MethodGet, "/api/config/drift?cursor=d0"))
	for _, it := range body["items"].([]any) {
		if id := it.(map[string]any)["device_id"]; id != "d1" {
			t.Fatalf("CROSS-TENANT LEAK via cursor: %v", id)
		}
	}

	// The platform owner (cross) sees everything — isolation is scope-based.
	f.principal = Principal{Cross: true, Subject: "platform"}
	body = f.decode(f.do(http.MethodGet, "/api/config/drift"))
	if len(body["items"].([]any)) != 3 {
		t.Fatalf("cross-tenant list = %v", body["items"])
	}
}

// TestDriftListStateFilterIsValidated: an unknown state is a 400, never a
// silently unfiltered list that reads as "nothing is drifted".
func TestDriftListStateFilterIsValidated(t *testing.T) {
	f := newFixture(t, nil)
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	seedState(t, f, "acme", "d1", StateDrifted)
	seedState(t, f, "acme", "d2", StateInSync)

	body := f.decode(f.do(http.MethodGet, "/api/config/drift?state=drifted"))
	if len(body["items"].([]any)) != 1 || body["total"] != float64(1) {
		t.Fatalf("state filter did not apply: %v", body)
	}
	if w := f.do(http.MethodGet, "/api/config/drift?state=drifting"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown state = %d, want 400", w.Code)
	}
	if w := f.do(http.MethodGet, "/api/config/drift?states=drifted"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown query parameter = %d, want 400", w.Code)
	}
	if w := f.do(http.MethodGet, "/api/config/drift?limit=0"); w.Code != http.StatusBadRequest {
		t.Fatalf("limit=0 = %d, want 400", w.Code)
	}
}

// TestDriftListPagesAndIsBounded (§9).
func TestDriftListPagesAndIsBounded(t *testing.T) {
	f := newFixture(t, nil)
	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}
	for i := 0; i < 5; i++ {
		seedState(t, f, "acme", fmt.Sprintf("d%02d", i), StateChanged)
	}
	body := f.decode(f.do(http.MethodGet, "/api/config/drift?limit=2"))
	if len(body["items"].([]any)) != 2 {
		t.Fatalf("page size not honoured: %v", body["items"])
	}
	cursor, _ := body["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("a truncated page must return a cursor")
	}
	seen := map[string]bool{}
	for _, it := range body["items"].([]any) {
		seen[it.(map[string]any)["device_id"].(string)] = true
	}
	body2 := f.decode(f.do(http.MethodGet, "/api/config/drift?limit=2&cursor="+cursor))
	for _, it := range body2["items"].([]any) {
		id := it.(map[string]any)["device_id"].(string)
		if seen[id] {
			t.Fatalf("cursor paging repeated %q", id)
		}
	}
	// An oversized limit is clamped, not honoured.
	if _, _, _, err := f.store.List(context.Background(), "acme", false, "", "", 100000); err != nil {
		t.Fatal(err)
	}
	if got := clampLimit(100000); got != MaxListLimit {
		t.Errorf("clampLimit = %d, want %d", got, MaxListLimit)
	}
}

// TestStatusForIsScoped: the per-device badge read the configstore route calls.
func TestStatusForIsScoped(t *testing.T) {
	f := newFixture(t, nil)
	seedState(t, f, "globex", "d2", StateDrifted)

	if _, ok, err := f.eval.StatusFor(context.Background(), "acme", false, "d2"); ok || err != nil {
		t.Fatalf("CROSS-TENANT LEAK: acme read globex's badge (ok=%v err=%v)", ok, err)
	}
	st, ok, err := f.eval.StatusFor(context.Background(), "globex", false, "d2")
	if err != nil || !ok {
		t.Fatalf("owner read failed: ok=%v err=%v", ok, err)
	}
	if st.State != StateDrifted || st.LastSHA == nil || *st.LastSHA != "sha-d2" {
		t.Fatalf("status = %+v", st)
	}
	if st.GoldenSHA != nil {
		t.Errorf("an unset golden must be nil, got %v", *st.GoldenSHA)
	}
}

// TestDriftListMethodAndAuthzGuards.
func TestDriftListMethodAndAuthzGuards(t *testing.T) {
	f := newFixture(t, nil)
	f.principal = Principal{Tenant: "acme"}
	if w := f.do(http.MethodPost, "/api/config/drift"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", w.Code)
	}
	f.authzOK = false
	if w := f.do(http.MethodGet, "/api/config/drift"); w.Code != http.StatusForbidden {
		t.Errorf("unauthorized = %d, want 403", w.Code)
	}
}

// TestFileStorePersistsAndReloads.
func TestFileStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config_drift_state.json"
	s := NewFileStore(path)
	at := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	if err := s.Put(context.Background(), "acme", false, State{
		TenantID: "acme", DeviceID: "d1", State: StateDrifted, LastSHA: "abc",
		LastCapture: at, UpdatedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := NewFileStore(path)
	st, ok, err := reloaded.Get(context.Background(), "acme", false, "d1")
	if err != nil || !ok {
		t.Fatalf("reload: ok=%v err=%v", ok, err)
	}
	if st.State != StateDrifted || st.LastSHA != "abc" {
		t.Fatalf("reloaded row = %+v", st)
	}
	if _, ok, _ := reloaded.Get(context.Background(), "globex", false, "d1"); ok {
		t.Fatal("CROSS-TENANT LEAK after reload")
	}
}

// TestDriftListAcceptsAsTenantAndStillScopesToThePrincipal pins the ONE
// exception to the strict unknown-parameter rule.
//
// as_tenant is the platform-wide acting-tenant switcher. It is applied UPSTREAM
// of this handler — the auth middleware folds it into the claims Deps.Authz
// resolves — so this package's only job is to not 400 on it. What it must NEVER
// do is let the parameter influence the scope from inside the handler: the rows
// served are the ones Deps.Authz's principal is entitled to, whatever the query
// string says. Both halves are asserted here, plus the fact that every OTHER
// unknown parameter is still refused (the exception did not become a hole).
func TestDriftListAcceptsAsTenantAndStillScopesToThePrincipal(t *testing.T) {
	f := newFixture(t, nil)
	seedState(t, f, "acme", "d1", StateDrifted)
	seedState(t, f, "globex", "d2", StateDrifted)

	f.principal = Principal{Tenant: "acme", Subject: "ops@acme"}

	// Accepted, not refused: the drift page is reachable with the selector on.
	w := f.do(http.MethodGet, "/api/config/drift?as_tenant=globex")
	if w.Code != http.StatusOK {
		t.Fatalf("?as_tenant = %d, want 200 (%s)", w.Code, w.Body)
	}
	// …and INERT here: the principal, not the query string, decides the scope.
	items := f.decode(w)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["device_id"] != "d1" {
		t.Fatalf("CROSS-TENANT LEAK: ?as_tenant widened the list from inside the handler: %v", items)
	}
	if strings.Contains(w.Body.String(), "d2") {
		t.Fatalf("CROSS-TENANT LEAK: the body carried another tenant's device: %s", w.Body)
	}

	// A principal the middleware ALREADY narrowed sees exactly that tenant — the
	// handler reads the resolved principal and nothing else.
	f.principal = Principal{Tenant: "globex", Subject: "root"}
	items = f.decode(f.do(http.MethodGet, "/api/config/drift?as_tenant=globex"))["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["device_id"] != "d2" {
		t.Fatalf("a narrowed principal must read that tenant: %v", items)
	}

	// The exception is exactly one parameter wide.
	for _, bad := range []string{"as_tenants", "tenant", "states", "offset"} {
		if w := f.do(http.MethodGet, "/api/config/drift?"+bad+"=x"); w.Code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400 — the as_tenant exception must not widen", bad, w.Code)
		}
	}
}
