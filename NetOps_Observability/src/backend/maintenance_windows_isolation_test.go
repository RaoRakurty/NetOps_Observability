package backend

// maintenance_windows_isolation_test.go — §3a cross-org isolation guard for
// the maintenance-window surface (item 121), exercised through the REAL router
// + auth middleware (org_isolation_test.go template): own-only list,
// cross-tenant get/put/delete → 404 (id existence never revealed),
// acting-tenant override into another org ignored, platform owner sees all.
// Also proves the suppression seam end-to-end: a covering window pauses the
// NOTIFICATION for a newly-firing alert of its own tenant and never another's.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/maintenance"
	"netops/backend/models"
)

func TestMaintenanceWindowCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.maintWindows = maintenance.NewFileStore(filepath.Join(t.TempDir(), "windows.json"))

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "mw-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	now := time.Now().UTC()
	windowBody := func(name string) map[string]any {
		return map[string]any{
			"name":      name,
			"starts_at": now.Add(-time.Hour).Format(time.RFC3339),
			"ends_at":   now.Add(time.Hour).Format(time.RFC3339),
		}
	}

	// ── create: each org declares one active tenant-wide window ────────────────
	st, body := do(t, srv, "POST", "/api/alerts/maintenance-windows", a.token, windowBody("A change"))
	if st != 201 {
		t.Fatalf("org-A create window: %d %s", st, body)
	}
	var wA maintenance.Window
	if err := json.Unmarshal(body, &wA); err != nil || wA.ID == "" {
		t.Fatalf("create must return the window: %s", body)
	}
	if wA.TenantID != a.tenantID {
		t.Fatalf("owner must be stamped from the token, got %q want %q", wA.TenantID, a.tenantID)
	}
	if !wA.Enabled {
		t.Fatalf("enabled must default to true when omitted: %+v", wA)
	}
	st, body = do(t, srv, "POST", "/api/alerts/maintenance-windows", b.token, windowBody("B change"))
	if st != 201 {
		t.Fatalf("org-B create window: %d %s", st, body)
	}
	var wB maintenance.Window
	_ = json.Unmarshal(body, &wB)

	// A payload trying to claim another tenant is ignored for a scoped caller.
	forged := windowBody("forged")
	forged["tenant_id"] = b.tenantID
	st, body = do(t, srv, "POST", "/api/alerts/maintenance-windows", a.token, forged)
	if st != 201 {
		t.Fatalf("forged-tenant create: %d %s", st, body)
	}
	var wForged maintenance.Window
	_ = json.Unmarshal(body, &wForged)
	if wForged.TenantID != a.tenantID {
		t.Fatalf("§3a.2: body tenant must be ignored, got %q", wForged.TenantID)
	}

	// ── own-only list ──────────────────────────────────────────────────────────
	type listResp struct {
		Windows []maintenance.Window `json:"windows"`
		Count   int                  `json:"count"`
	}
	list := func(token string) listResp {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/alerts/maintenance-windows", token, nil)
		if st != 200 {
			t.Fatalf("list windows: %d %s", st, body)
		}
		var lr listResp
		if err := json.Unmarshal(body, &lr); err != nil {
			t.Fatal(err)
		}
		return lr
	}
	for _, w := range list(a.token).Windows {
		if w.TenantID == b.tenantID {
			t.Fatalf("TENANT LEAK: org-A listed org-B's window: %+v", w)
		}
	}
	if got := list(admin).Count; got != 3 {
		t.Fatalf("platform owner must see all windows, got %d", got)
	}

	// ── cross-tenant get/put/delete → 404, row untouched ───────────────────────
	if st, _ := do(t, srv, "GET", "/api/alerts/maintenance-windows/"+wB.ID, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("cross-tenant GET must 404, got %d", st)
	}
	if st, _ := do(t, srv, "PUT", "/api/alerts/maintenance-windows/"+wB.ID, a.token, windowBody("hijack")); st != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT must 404, got %d", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/alerts/maintenance-windows/"+wB.ID, a.token, nil); st != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE must 404, got %d", st)
	}
	if st, body := do(t, srv, "GET", "/api/alerts/maintenance-windows/"+wB.ID, b.token, nil); st != 200 {
		t.Fatalf("org-B's window must survive cross-tenant attempts: %d %s", st, body)
	}

	// ── acting-tenant override into another org is ignored for a non-owner ─────
	{
		bts, _ := json.Marshal(windowBody("via header"))
		req, err := http.NewRequest("DELETE", srv.URL+"/api/alerts/maintenance-windows/"+wB.ID, bytes.NewReader(bts))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("acting-tenant override must not widen a scoped caller: %d", resp.StatusCode)
		}
	}

	// ── suppression seam: a covering window pauses notifications for ITS tenant
	// only. Device tenancy drives the lookup, exactly like the episode fold. ────
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "dev-c", Name: "dev-c", TenantID: "untouched-tenant"})
	if !s.alertNotifySuppressed(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: "dev-a"}) {
		t.Fatal("a newly-firing alert inside a covering window must be suppressed")
	}
	if s.alertNotifySuppressed(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: "dev-c"}) {
		t.Fatal("TENANT LEAK: another tenant's window suppressed an unrelated alert")
	}

	// ── update round-trip keeps server-owned stamps ────────────────────────────
	upd := windowBody("A change renamed")
	upd["enabled"] = false
	st, body = do(t, srv, "PUT", "/api/alerts/maintenance-windows/"+wA.ID, a.token, upd)
	if st != 200 {
		t.Fatalf("own-tenant PUT: %d %s", st, body)
	}
	var got maintenance.Window
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "A change renamed" || got.Enabled || got.CreatedBy != a.user || got.TenantID != a.tenantID {
		t.Fatalf("update must replace mutable fields and keep stamps: %+v", got)
	}
	// wForged (enabled, tenant A, tenant-wide) still covers dev-a — remove it so
	// the disabled wA is tenant A's only window, then suppression must stop.
	if st, _ := do(t, srv, "DELETE", "/api/alerts/maintenance-windows/"+wForged.ID, a.token, nil); st != 200 {
		t.Fatalf("own-tenant DELETE failed: %d", st)
	}
	if s.alertNotifySuppressed(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: "dev-a"}) {
		t.Fatal("a disabled window must stop suppressing")
	}
}
