// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// maintenance_windows_restriction_test.go — the CLAUDE.md §3a rule-5 isolation
// test for the operator-visibility restriction (Tenant.OperatorRestricted) on
// /api/alerts/maintenance-windows and its by-id sibling (tracker 305).
//
// A declared maintenance window is when a customer's network is deliberately
// down and who is touching it: the device ids and site slugs under work, the
// rules being paused, the operator's own description of the change, and the
// schedule it runs on. It is the same class of disclosure as the site list and
// the fleet count the owner has already ruled are per-tenant — so a tenant that
// platform staff may administer but not READ does not appear in the operator's
// Global window list either.
//
// WHY THE FIX IS AT THE HANDLER AND NOT IN THE STORE — checked, not assumed.
// The episode list needed the store because its `total` is computed inside
// EpisodeStore.List, over the visible set, before the limit. maintenance.Store
// has no such number: List takes no limit, returns whole rows, and the `count`
// beside the list is len(out) computed in the handler AFTER the filter. So the
// filter and the count are already the same pass. This test asserts the count
// anyway, in both halves, because that is the assertion that would catch it if
// the store ever grew a bound.
//
// The WRITE half is covered too. A window platform staff may not read is not one
// they may overwrite or delete: a 200 from PUT/DELETE on an id whose GET answers
// 404 confirms the id exists just as loudly as a 403 would.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/maintenance"
	"netops/backend/models"
)

// The values that must not reach the platform operator once tenant B asks not
// to be readable.
const (
	mwBDevice = "mw-acme-core-sw1"
	mwBSite   = "acme-hq-datacentre"
	mwBDesc   = "replacing the failed line card in rack 4 with the vendor on site"
	mwBName   = "Acme line-card swap"
	mwADevice = "mw-globex-core-sw1"
	mwPName   = "Platform control-plane upgrade"
)

type mwFixture struct {
	t             *testing.T
	srv           *httptest.Server
	s             *server
	adm           string
	a, b          *orgFixture
	aWin, bWin    string
	platformWinID string
}

type mwList struct {
	Windows []maintenance.Window `json:"windows"`
	Count   int                  `json:"count"`
	raw     string
}

func (l mwList) names() []string {
	out := make([]string, 0, len(l.Windows))
	for _, w := range l.Windows {
		out = append(out, w.Name)
	}
	return out
}

func (f *mwFixture) list(token, asTenant string) mwList {
	f.t.Helper()
	path := withAsTenant("/api/alerts/maintenance-windows", asTenant)
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out mwList
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode windows: %v (%s)", err, body)
	}
	out.raw = string(body)
	return out
}

func (f *mwFixture) byID(method, token, id, asTenant string, body any) (int, []byte) {
	f.t.Helper()
	return do(f.t, f.srv, method, withAsTenant("/api/alerts/maintenance-windows/"+id, asTenant), token, body)
}

func newMwFixture(t *testing.T) *mwFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	s.maintWindows = maintenance.NewFileStore(filepath.Join(t.TempDir(), "windows.json"))
	adm := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", adm, map[string]any{"name": "MwOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", adm, map[string]any{"name": "MwTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "mw-restrict-user-" + name
		st, b = do(t, srv, "POST", "/api/users", adm, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	now := time.Now().UTC()
	window := func(name, desc, device, site string) map[string]any {
		return map[string]any{
			"name": name, "description": desc,
			"device_ids": []string{device}, "sites": []string{site},
			"rules":     []string{"HighCPU"},
			"starts_at": now.Add(-time.Hour).Format(time.RFC3339),
			"ends_at":   now.Add(time.Hour).Format(time.RFC3339),
		}
	}
	create := func(token string, body map[string]any) string {
		t.Helper()
		st, resp := do(t, srv, "POST", "/api/alerts/maintenance-windows", token, body)
		if st != http.StatusCreated {
			t.Fatalf("create window: %d %s", st, resp)
		}
		var w maintenance.Window
		if err := json.Unmarshal(resp, &w); err != nil || w.ID == "" {
			t.Fatalf("create must return the window: %s", resp)
		}
		return w.ID
	}

	aWin := create(a.token, window("Globex switch reload", "rebooting the core switch", mwADevice, "globex-hq"))
	bWin := create(b.token, window(mwBName, mwBDesc, mwBDevice, mwBSite))
	// A genuinely PLATFORM-owned window (the operator declaring work on the
	// stack itself): it belongs to no tenant and must survive every filter.
	pWin := create(adm, window(mwPName, "upgrading the control plane", "stack-jump", "core-dc"))

	// Tenant B's device and its site binding, so the suppression seam can be
	// shown to keep working for a restricted tenant — the restriction governs
	// operator READS, never what the platform collects or suppresses on a
	// tenant's behalf. The binding is what resolves the alert's site, which the
	// window's `sites` scope is matched against.
	if err := s.discovery.Upsert(models.Device{ID: mwBDevice, Name: mwBDevice, TenantID: b.tenantID}); err != nil {
		t.Fatalf("upsert %s: %v", mwBDevice, err)
	}
	ds, err := newDeviceSiteStore(filepath.Join(t.TempDir(), "device_sites.json"))
	if err != nil {
		t.Fatalf("deviceSiteStore: %v", err)
	}
	s.deviceSites = ds
	if err := ds.Set(DeviceSiteBinding{TenantID: b.tenantID, DeviceID: mwBDevice, Device: mwBDevice, Site: mwBSite}); err != nil {
		t.Fatalf("bind %s to %s: %v", mwBDevice, mwBSite, err)
	}

	return &mwFixture{t: t, srv: srv, s: s, adm: adm, a: a, b: b, aWin: aWin, bWin: bWin, platformWinID: pWin}
}

func (f *mwFixture) restrictB() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted(f.b.tenantID, true); err != nil {
		f.t.Fatalf("restrict tenant B: %v", err)
	}
}

// TestMaintenanceWindowsHonourTheOperatorVisibilityRestriction — both halves,
// the count alongside the rows, the write path, and the restricted tenant's own
// view captured before the switch and compared after.
func TestMaintenanceWindowsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newMwFixture(t)

	// ── baseline ──
	base := f.list(f.adm, "")
	if base.Count != 3 || len(base.Windows) != 3 {
		t.Fatalf("baseline: the owner should read 3 windows with count 3, got %d rows / count %d (%v)",
			len(base.Windows), base.Count, base.names())
	}
	for _, want := range []string{mwBName, mwBDesc, mwBDevice, mwBSite} {
		if !strings.Contains(base.raw, want) {
			t.Fatalf("baseline: the owner's window list does not carry tenant B's %q — the fixture proves nothing:\n%s", want, base.raw)
		}
	}
	if st, body := f.byID("GET", f.adm, f.bWin, "", nil); st != http.StatusOK {
		t.Fatalf("baseline: the owner should read tenant B's window by id: %d %s", st, body)
	}
	// Tenant B's OWN view, captured BEFORE the switch.
	bBefore := f.list(f.b.token, "")
	if bBefore.Count != 1 || bBefore.Windows[0].Name != mwBName {
		t.Fatalf("baseline: tenant B should read its own single window, got %d (%v)", bBefore.Count, bBefore.names())
	}
	// And the suppression seam works for tenant B's device.
	if !f.s.alertNotifySuppressed(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: mwBDevice}) {
		t.Fatalf("baseline: tenant B's covering window must suppress its own alert")
	}

	f.restrictB()

	// ── half 1: the operator's GLOBAL view drops tenant B — rows AND count. ──
	global := f.list(f.adm, "")
	for _, leak := range []string{mwBName, mwBDesc, mwBDevice, mwBSite, f.bWin} {
		if strings.Contains(global.raw, leak) {
			t.Errorf("RESTRICTION LEAK: the owner's Global window list carries tenant B's %q:\n%s", leak, global.raw)
		}
	}
	if global.Count != 2 || len(global.Windows) != 2 {
		t.Errorf("THE COUNT DISCLOSES: the owner's Global window list is %d rows / count %d, want 2 and 2 (%v)",
			len(global.Windows), global.Count, global.names())
	}
	seen := map[string]bool{}
	for _, n := range global.names() {
		seen[n] = true
	}
	if !seen["Globex switch reload"] || !seen[mwPName] {
		t.Errorf("restricting tenant B also removed tenant A's window or the PLATFORM's own: %v", global.names())
	}

	// ── by id: 404, never 403 — a 403 confirms the id exists. Read AND write. ──
	for _, asTenant := range []string{"", f.b.tenantID} {
		for _, m := range []struct {
			method string
			body   any
		}{
			{"GET", nil},
			{"PUT", map[string]any{
				"name":      "hijacked",
				"starts_at": time.Now().UTC().Format(time.RFC3339),
				"ends_at":   time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			}},
			{"DELETE", nil},
		} {
			st, body := f.byID(m.method, f.adm, f.bWin, asTenant, m.body)
			if st != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: owner %s of tenant B's window (as_tenant=%q) = %d, want 404: %s",
					m.method, asTenant, st, body)
			}
			if strings.Contains(string(body), mwBDesc) || strings.Contains(string(body), mwBDevice) {
				t.Errorf("the %s response names tenant B's planned work:\n%s", m.method, body)
			}
		}
	}

	// ── half 2: ?as_tenant into the restricted tenant reads nothing, and counts
	//    nothing — not even the platform's own window under that tenant's name. ──
	into := f.list(f.adm, f.b.tenantID)
	if into.Count != 0 || len(into.Windows) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantB windows returned %d rows / count %d: %s",
			len(into.Windows), into.Count, into.raw)
	}
	for _, leak := range []string{mwBName, mwBDesc, mwBDevice, mwBSite} {
		if strings.Contains(into.raw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→tenantB window body contains %q:\n%s", leak, into.raw)
		}
	}

	// ── the owner scoped into the UNRESTRICTED tenant is unmoved. ──
	intoA := f.list(f.adm, f.a.tenantID)
	if intoA.Count != 1 || !strings.Contains(intoA.raw, mwADevice) {
		t.Errorf("restricting tenant B moved the owner→tenantA window view: count %d (%v)", intoA.Count, intoA.names())
	}
	if st, _ := f.byID("GET", f.adm, f.aWin, "", nil); st != http.StatusOK {
		t.Errorf("restricting tenant B broke the owner's read of tenant A's window: %d", st)
	}
	// The platform's own window is still readable and still writable by the owner.
	if st, _ := f.byID("GET", f.adm, f.platformWinID, "", nil); st != http.StatusOK {
		t.Errorf("the restriction swallowed the PLATFORM's own window: %d", st)
	}

	// ── half 3: the restricted tenant's OWN view is unchanged — rows and count.
	//    The switch hides a tenant from the PLATFORM, never from itself. ──
	bAfter := f.list(f.b.token, "")
	if bAfter.Count != bBefore.Count || strings.Join(bAfter.names(), ",") != strings.Join(bBefore.names(), ",") {
		t.Errorf("the restriction changed tenant B's OWN window view: %d/%v before, %d/%v after",
			bBefore.Count, bBefore.names(), bAfter.Count, bAfter.names())
	}
	if !strings.Contains(bAfter.raw, mwBDesc) {
		t.Errorf("tenant B lost its own planned work from its own list:\n%s", bAfter.raw)
	}
	if strings.Contains(bAfter.raw, mwADevice) {
		t.Errorf("CROSS-TENANT LEAK: tenant B's window list names tenant A's device:\n%s", bAfter.raw)
	}
	if st, body := f.byID("GET", f.b.token, f.bWin, "", nil); st != http.StatusOK {
		t.Errorf("the restriction took tenant B's own window away from it: %d %s", st, body)
	}
	// The refused writes above must not have landed: the window is intact and
	// tenant B can still update it itself.
	st, body := f.byID("PUT", f.b.token, f.bWin, "", map[string]any{
		"name": mwBName, "description": mwBDesc,
		"device_ids": []string{mwBDevice}, "sites": []string{mwBSite},
		"starts_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		"ends_at":   time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if st != http.StatusOK {
		t.Errorf("tenant B can no longer update its own window: %d %s", st, body)
	}
	// ── and the restriction is a rule about operator READS, not a collection
	//    rule: the window still suppresses tenant B's own alerts. ──
	if !f.s.alertNotifySuppressed(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: mwBDevice}) {
		t.Errorf("the restriction stopped a restricted tenant's own maintenance window from suppressing its alerts")
	}
}
