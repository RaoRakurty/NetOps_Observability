// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// saved_objects_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for the operator-visibility restriction (Tenant.OperatorRestricted) on the
// SAVED-OBJECT surfaces: GET/POST /api/saved, GET/PUT/DELETE /api/saved/{id},
// and the `saved` branch of the omnibox (/api/search/global). Tracker 306.
//
// A saved object is not a label. Its BODY is the customer's own work: a saved
// search carries the query string (index names, device names, the text an
// analyst greps for), a dashboard carries its panel definitions, and a REPORT
// carries a delivery instruction — the schedule and the contact points a
// rendered report is mailed to. visibleSaved returned the whole store to any
// cross-tenant caller, so a tenant that platform staff may administer but not
// READ handed them all three, plus the report ids that /api/reports/run takes.
//
// THREE tenants, and the operator is restricted out of exactly ONE of them, so
// the test can tell "hides the restricted tenant" apart from "hides everything
// but my own" — the failure mode a two-tenant fixture cannot see.
//
// The WRITE half is covered for the same reason it was covered for the
// maintenance windows (tracker 305), where the row was filed read-only and the
// writes turned out open: an object platform staff may not read is not one they
// may rename, overwrite or delete, and a 200 from PUT/DELETE on an id whose GET
// answers 404 confirms the id exists just as loudly as a 403 would. CREATE is
// covered too, and it is the sharpest of the three: a saved `report` planted in
// a restricted tenant is rendered BY THE PLATFORM, on a timer, against that
// tenant's data, and delivered to the contact points in the body.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/alerts"
	"netops/backend/internal/saved"
)

// The bytes that must not reach the platform operator once tenant C asks not to
// be readable. A name, a query body, and the recipient a report is delivered to.
const (
	savedCName      = "Acme executive weekly"
	savedCQuery     = "index=acme-billing error"
	savedCRecipient = "noc-lead@acme.example"
	savedAName      = "Globex link errors"
	savedBName      = "Bravo capacity board"
	savedPName      = "Platform fleet weekly"
)

type savedFixture struct {
	t          *testing.T
	srv        *httptest.Server
	s          *server
	adm        string
	a, b, c    *orgFixture
	aID        string
	bID        string
	cID        string
	platformID string
}

// list runs the real GET /api/saved and returns the decoded rows plus the raw
// body, so an assertion can grep BYTES (the recipient inside an opaque body)
// and not only the typed fields.
func (f *savedFixture) list(token, asTenant string) ([]saved.Object, string) {
	f.t.Helper()
	path := withAsTenant("/api/saved", asTenant)
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out []saved.Object
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode saved list: %v (%s)", err, body)
	}
	return out, string(body)
}

func savedNames(rows []saved.Object) []string {
	out := make([]string, 0, len(rows))
	for _, o := range rows {
		out = append(out, o.Name)
	}
	return out
}

// omniboxSaved runs the real GET /api/search/global and returns the ids of the
// `saved` hits plus the raw body.
func (f *savedFixture) omniboxSaved(token, q, asTenant string) (map[string]bool, string) {
	f.t.Helper()
	path := withAsTenant("/api/search/global?q="+q, asTenant)
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out struct {
		Results []globalResult `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode omnibox: %v (%s)", err, body)
	}
	ids := map[string]bool{}
	for _, r := range out.Results {
		if r.Kind == "saved" {
			ids[r.ID] = true
		}
	}
	return ids, string(body)
}

func (f *savedFixture) byID(method, token, id, asTenant string, body any) (int, []byte) {
	f.t.Helper()
	return do(f.t, f.srv, method, withAsTenant("/api/saved/"+id, asTenant), token, body)
}

func (f *savedFixture) restrictC() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted(f.c.tenantID, true); err != nil {
		f.t.Fatalf("restrict tenant C: %v", err)
	}
}

func newSavedFixture(t *testing.T) *savedFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	// The omnibox reads the active alert set; the shared harness leaves the
	// engine nil, and this test is not about alerts.
	s.alerts = alerts.NewEngine("", nil)
	adm := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B", "C"} {
		st, b := do(t, srv, "POST", "/api/orgs", adm, map[string]any{"name": "SavedOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", adm, map[string]any{"name": "SavedTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "saved-restrict-user-" + strings.ToLower(name)
		st, b = do(t, srv, "POST", "/api/users", adm, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b, c := fix["A"], fix["B"], fix["C"]

	create := func(token string, req map[string]any) string {
		t.Helper()
		st, resp := do(t, srv, "POST", "/api/saved", token, req)
		if st != http.StatusCreated {
			t.Fatalf("create saved %v: %d %s", req["name"], st, resp)
		}
		var o saved.Object
		if err := json.Unmarshal(resp, &o); err != nil || o.ID == "" {
			t.Fatalf("create must return the object: %s", resp)
		}
		return o.ID
	}

	aID := create(a.token, map[string]any{
		"type": "saved_search", "name": savedAName,
		"body": map[string]any{"query": "index=globex iface_errors>0"},
	})
	bID := create(b.token, map[string]any{
		"type": "dashboard", "name": savedBName,
		"body": map[string]any{"panels": []string{"cpu", "iface"}},
	})
	// Tenant C's REPORT: the sharpest body in the store — a query, a schedule,
	// and the contact point the rendered report is delivered to.
	cID := create(c.token, map[string]any{
		"type": "report", "name": savedCName,
		"body": map[string]any{
			"query": savedCQuery, "schedule": "weekly",
			"recipients": []string{savedCRecipient},
		},
	})
	// A genuinely PLATFORM-owned object (tenant_id ""): it belongs to no tenant
	// and must survive every filter, read and write alike.
	platformID := create(adm, map[string]any{
		"type": "report", "name": savedPName, "tenant_id": "",
		"body": map[string]any{"query": "index=stack", "schedule": "weekly"},
	})

	return &savedFixture{t: t, srv: srv, s: s, adm: adm, a: a, b: b, c: c,
		aID: aID, bID: bID, cID: cID, platformID: platformID}
}

// TestSavedObjectsHonourTheOperatorVisibilityRestriction — the list, the
// omnibox, the by-id read, and all three writes, with tenant C's own view
// captured BEFORE the switch and compared after.
func TestSavedObjectsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newSavedFixture(t)

	// ── baseline: the operator reads all four, C's body included. Without this
	//    half the test could pass by hiding everything. ──
	base, baseRaw := f.list(f.adm, "")
	if len(base) != 4 {
		t.Fatalf("baseline: the owner should read 4 saved objects, got %d (%v)", len(base), savedNames(base))
	}
	for _, want := range []string{savedCName, savedCQuery, savedCRecipient, f.cID} {
		if !strings.Contains(baseRaw, want) {
			t.Fatalf("baseline: the owner's saved list does not carry tenant C's %q — the fixture proves nothing:\n%s", want, baseRaw)
		}
	}
	if st, body := f.byID("GET", f.adm, f.cID, "", nil); st != http.StatusOK {
		t.Fatalf("baseline: the owner should read tenant C's saved object by id: %d %s", st, body)
	}
	if ids, raw := f.omniboxSaved(f.adm, "acme-billing", ""); !ids[f.cID] {
		t.Fatalf("baseline: the omnibox does not offer tenant C's saved object for its own query text:\n%s", raw)
	}
	// Tenant C's OWN view, captured BEFORE the switch.
	cBefore, cBeforeRaw := f.list(f.c.token, "")
	if len(cBefore) != 1 || cBefore[0].Name != savedCName {
		t.Fatalf("baseline: tenant C should read its own single object, got %d (%v)", len(cBefore), savedNames(cBefore))
	}
	if !strings.Contains(cBeforeRaw, savedCRecipient) {
		t.Fatalf("baseline: tenant C's own list lost its own recipient:\n%s", cBeforeRaw)
	}

	f.restrictC()

	// ── half 1: the operator's GLOBAL list drops tenant C — name, body, id. ──
	global, globalRaw := f.list(f.adm, "")
	for _, leak := range []string{savedCName, savedCQuery, savedCRecipient, f.cID} {
		if strings.Contains(globalRaw, leak) {
			t.Errorf("RESTRICTION LEAK: the owner's Global saved list carries tenant C's %q:\n%s", leak, globalRaw)
		}
	}
	if len(global) != 3 {
		t.Errorf("the owner's Global saved list is %d rows, want 3 (%v)", len(global), savedNames(global))
	}
	seen := map[string]bool{}
	for _, n := range savedNames(global) {
		seen[n] = true
	}
	if !seen[savedAName] || !seen[savedBName] || !seen[savedPName] {
		t.Errorf("restricting tenant C also removed tenant A's or B's object, or the PLATFORM's own: %v", savedNames(global))
	}

	// ── the omnibox is the same store through a second door. ──
	if ids, raw := f.omniboxSaved(f.adm, "acme-billing", ""); ids[f.cID] {
		t.Errorf("RESTRICTION LEAK: the omnibox still offers tenant C's saved object %q as a jump target:\n%s", f.cID, raw)
	} else if strings.Contains(raw, savedCName) || strings.Contains(raw, savedCRecipient) {
		t.Errorf("RESTRICTION LEAK: the omnibox body names tenant C's saved object:\n%s", raw)
	}

	// ── by id: 404, never 403 — read AND write, Global and ?as_tenant. ──
	for _, asTenant := range []string{"", f.c.tenantID} {
		for _, m := range []struct {
			method string
			body   any
		}{
			{"GET", nil},
			{"PUT", map[string]any{"name": "hijacked", "body": map[string]any{"query": "index=*"}}},
			{"DELETE", nil},
		} {
			st, body := f.byID(m.method, f.adm, f.cID, asTenant, m.body)
			if st != http.StatusNotFound {
				t.Errorf("RESTRICTION LEAK: owner %s of tenant C's saved object (as_tenant=%q) = %d, want 404: %s",
					m.method, asTenant, st, body)
			}
			for _, leak := range []string{savedCName, savedCQuery, savedCRecipient} {
				if strings.Contains(string(body), leak) {
					t.Errorf("the %s response names tenant C's %q:\n%s", m.method, leak, body)
				}
			}
		}
	}

	// ── CREATE: the operator may not plant a saved report IN the restricted
	//    tenant either. The platform renders it on a timer, against that
	//    tenant's data, and delivers it to the body's own contact points. ──
	st, body := do(t, f.srv, "POST", "/api/saved", f.adm, map[string]any{
		"type": "report", "name": "planted", "tenant_id": f.c.tenantID,
		"body": map[string]any{"query": "index=*", "recipients": []string{"attacker@example.net"}},
	})
	if st != http.StatusForbidden {
		t.Errorf("RESTRICTION LEAK: the owner planted a saved report in the restricted tenant: %d, want 403: %s", st, body)
	}
	// And ?as_tenant into the restricted tenant is the same refusal.
	st, body = do(t, f.srv, "POST", withAsTenant("/api/saved", f.c.tenantID), f.adm, map[string]any{
		"type": "report", "name": "planted-as-tenant",
		"body": map[string]any{"query": "index=*"},
	})
	if st != http.StatusForbidden {
		t.Errorf("RESTRICTION LEAK: as_tenant=C created a saved report inside the restricted tenant: %d, want 403: %s", st, body)
	}

	// ── half 2: ?as_tenant into the restricted tenant reads nothing — not even
	//    the platform's own object under that tenant's name. ──
	into, intoRaw := f.list(f.adm, f.c.tenantID)
	if len(into) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantC saved list returned %d rows: %s", len(into), intoRaw)
	}
	for _, leak := range []string{savedCName, savedCQuery, savedCRecipient} {
		if strings.Contains(intoRaw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→tenantC saved body contains %q:\n%s", leak, intoRaw)
		}
	}
	if ids, raw := f.omniboxSaved(f.adm, "acme-billing", f.c.tenantID); len(ids) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantC omnibox offered %d saved hits:\n%s", len(ids), raw)
	}

	// ── the operator's reach into the OTHER two tenants is unmoved: this is a
	//    restriction on one tenant, not a collapse to own-tenant-only. ──
	intoA, intoARaw := f.list(f.adm, f.a.tenantID)
	if len(intoA) != 1 || !strings.Contains(intoARaw, savedAName) {
		t.Errorf("restricting tenant C moved the owner→tenantA saved view: %d (%v)", len(intoA), savedNames(intoA))
	}
	for _, id := range []string{f.aID, f.bID, f.platformID} {
		if st, body := f.byID("GET", f.adm, id, "", nil); st != http.StatusOK {
			t.Errorf("restricting tenant C broke the owner's read of %q: %d %s", id, st, body)
		}
	}
	// The platform's own object is still writable by the owner.
	if st, body := f.byID("PUT", f.adm, f.platformID, "", map[string]any{
		"name": savedPName, "body": map[string]any{"query": "index=stack"},
	}); st != http.StatusOK {
		t.Errorf("the restriction swallowed the PLATFORM's own saved object: %d %s", st, body)
	}

	// ── half 3: tenant C's OWN view is unchanged, and the refused writes above
	//    landed NOTHING — the object is intact, not renamed and not deleted. ──
	cAfter, cAfterRaw := f.list(f.c.token, "")
	if len(cAfter) != len(cBefore) || strings.Join(savedNames(cAfter), ",") != strings.Join(savedNames(cBefore), ",") {
		t.Errorf("the restriction changed tenant C's OWN saved view: %d/%v before, %d/%v after",
			len(cBefore), savedNames(cBefore), len(cAfter), savedNames(cAfter))
	}
	if !strings.Contains(cAfterRaw, savedCRecipient) || !strings.Contains(cAfterRaw, savedCQuery) {
		t.Errorf("tenant C lost its own report body from its own list:\n%s", cAfterRaw)
	}
	if strings.Contains(cAfterRaw, "hijacked") || strings.Contains(cAfterRaw, "planted") {
		t.Errorf("a REFUSED write landed in tenant C's store anyway:\n%s", cAfterRaw)
	}
	if strings.Contains(cAfterRaw, savedAName) || strings.Contains(cAfterRaw, savedPName) {
		t.Errorf("CROSS-TENANT LEAK: tenant C's saved list names another owner's object:\n%s", cAfterRaw)
	}
	if st, body := f.byID("GET", f.c.token, f.cID, "", nil); st != http.StatusOK {
		t.Errorf("the restriction took tenant C's own saved object away from it: %d %s", st, body)
	}
	// And tenant C can still update its own object.
	if st, body := f.byID("PUT", f.c.token, f.cID, "", map[string]any{
		"name": savedCName,
		"body": map[string]any{"query": savedCQuery, "recipients": []string{savedCRecipient}},
	}); st != http.StatusOK {
		t.Errorf("tenant C can no longer update its own saved object: %d %s", st, body)
	}
}
