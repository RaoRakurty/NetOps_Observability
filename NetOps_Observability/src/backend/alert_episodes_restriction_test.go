// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alert_episodes_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test
// for the operator-visibility restriction (Tenant.OperatorRestricted) on
// /api/alerts/episodes (tracker 301).
//
// An episode is the folded form of a customer's live incident: the device it
// fired on, the rule, the summary that names both, and how many times it has
// happened. GET /api/alerts and its four sibling surfaces stopped serving a
// restricted tenant's alerts; this route kept serving the same incidents in
// their grouped form, and its triage actions let platform staff ack, assign,
// mute and annotate them.
//
// WHY THE FIX IS IN THE STORE AND NOT HERE. `total` is computed inside
// EpisodeStore.List, over the visible set, BEFORE the limit is applied. A filter
// at the handler would drop the hidden rows from the page and hand back a count
// of how many episodes the hidden tenant has — "acme has 47 open episodes" is
// precisely the fact the restriction exists to withhold, and it is no less a
// disclosure for arriving as an integer. So the scope is threaded INTO the store
// (alerts.EpisodeScope) and the filter and the count are the same loop.
//
// This test therefore asserts the COUNT as well as the rows, in both halves, and
// drives the real router + auth middleware so ?as_tenant is validated and
// stamped the way production stamps it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

// epRestrictFixture is two tenants, one device and one episode each, plus a
// genuinely platform-owned device-less episode that must survive every filter.
type epRestrictFixture struct {
	t              *testing.T
	srv            *httptest.Server
	s              *server
	admin          string // the platform owner's token
	a, b           *orgFixture
	aEpID, bEpID   string
	platformEpID   string
	aSummary, bSum string
}

const (
	epAcmeDevice  = "ep-acme-core"
	epAcmeSummary = "OSPF adjacency to 198.51.100.9 is down on ep-acme-core"
	epGlobexDev   = "ep-globex-core"
	epGlobexSum   = "OSPF adjacency is down on ep-globex-core"
	epStackSum    = "platform disk is filling"
)

// epList is one GET /api/alerts/episodes, decoded — rows, the store's total, and
// the raw body so a leak assertion can grep bytes rather than only typed fields.
type epList struct {
	Episodes []AlertEpisode `json:"episodes"`
	Total    int            `json:"total"`
	raw      string
}

func (l epList) resources() []string {
	out := make([]string, 0, len(l.Episodes))
	for _, ep := range l.Episodes {
		out = append(out, ep.Resource)
	}
	return out
}

func (f *epRestrictFixture) list(token, asTenant string) epList {
	f.t.Helper()
	path := "/api/alerts/episodes?status=all"
	if asTenant != "" {
		path += "&as_tenant=" + asTenant
	}
	st, body := do(f.t, f.srv, "GET", path, token, nil)
	if st != http.StatusOK {
		f.t.Fatalf("GET %s = %d: %s", path, st, body)
	}
	var out epList
	if err := json.Unmarshal(body, &out); err != nil {
		f.t.Fatalf("decode episodes: %v (%s)", err, body)
	}
	out.raw = string(body)
	return out
}

// ack drives POST /api/alerts/episodes/{id}/ack and returns the status only —
// a cross-tenant or restricted id must come back 404, never 403.
func (f *epRestrictFixture) ack(token, id, asTenant string) int {
	f.t.Helper()
	path := "/api/alerts/episodes/" + id + "/ack"
	if asTenant != "" {
		path += "?as_tenant=" + asTenant
	}
	st, _ := do(f.t, f.srv, "POST", path, token, map[string]any{"acknowledged": true})
	return st
}

func newEpRestrictFixture(t *testing.T) *epRestrictFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	store := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	store.SetNowForTest(func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) })
	s.alertEpisodes = store

	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "EpOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "EpTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "ep-restrict-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// One device per tenant; the engine adapter derives each episode's tenant
	// from its DEVICE, never from a payload.
	for _, d := range []models.Device{
		{ID: epAcmeDevice, Name: epAcmeDevice, TenantID: a.tenantID},
		{ID: epGlobexDev, Name: epGlobexDev, TenantID: b.tenantID},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatalf("upsert %s: %v", d.ID, err)
		}
	}
	s.observeAlertTransition(models.Alert{Rule: "OSPFAdjacencyDown", Severity: "critical", DeviceID: epAcmeDevice, Summary: epAcmeSummary}, true)
	s.observeAlertTransition(models.Alert{Rule: "OSPFAdjacencyDown", Severity: "critical", DeviceID: epGlobexDev, Summary: epGlobexSum}, true)
	s.observeAlertTransition(models.Alert{Rule: "StackDisk", Severity: "warning", Summary: epStackSum}, true)

	f := &epRestrictFixture{t: t, srv: srv, s: s, admin: admin, a: a, b: b, aSummary: epAcmeSummary, bSum: epGlobexSum}
	for _, ep := range f.list(admin, "").Episodes {
		switch ep.Resource {
		case epAcmeDevice:
			f.aEpID = ep.ID
		case epGlobexDev:
			f.bEpID = ep.ID
		case "":
			f.platformEpID = ep.ID
		}
	}
	if f.aEpID == "" || f.bEpID == "" || f.platformEpID == "" {
		t.Fatalf("fixture did not fold three episodes: %v", f.list(admin, "").resources())
	}
	return f
}

func (f *epRestrictFixture) restrictB() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted(f.b.tenantID, true); err != nil {
		f.t.Fatalf("restrict tenant B: %v", err)
	}
}

// TestAlertEpisodesHonourTheOperatorVisibilityRestriction — both halves, the
// count as well as the rows, and the restricted tenant's own view before/after.
func TestAlertEpisodesHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newEpRestrictFixture(t)

	// ── baseline: the platform owner reads all three, and the COUNT says three.
	//    Without this the assertions below could pass on a route serving nothing. ──
	base := f.list(f.admin, "")
	if base.Total != 3 || len(base.Episodes) != 3 {
		t.Fatalf("baseline: owner should read 3 episodes with total 3, got %d rows / total %d (%v)", len(base.Episodes), base.Total, base.resources())
	}
	if !strings.Contains(base.raw, f.bSum) || !strings.Contains(base.raw, epGlobexDev) {
		t.Fatalf("baseline: the owner's episode list does not name tenant B's incident:\n%s", base.raw)
	}
	// The owner can triage tenant B's episode today.
	if st := f.ack(f.admin, f.bEpID, ""); st != http.StatusOK {
		t.Fatalf("baseline: owner ack of tenant B's episode = %d, want 200", st)
	}
	// Tenant B's OWN view, captured BEFORE the switch: its own episode plus the
	// platform's device-less one.
	bBefore := f.list(f.b.token, "")
	if bBefore.Total != 2 {
		t.Fatalf("baseline: tenant B should read its own episode + the platform's, total 2, got %d (%v)", bBefore.Total, bBefore.resources())
	}

	f.restrictB()

	// ── half 1: the owner's GLOBAL view drops tenant B — rows AND count. ──
	global := f.list(f.admin, "")
	for _, leak := range []string{epGlobexDev, f.bSum, f.bEpID} {
		if strings.Contains(global.raw, leak) {
			t.Errorf("RESTRICTION LEAK: the owner's Global episode list carries tenant B's %q:\n%s", leak, global.raw)
		}
	}
	if global.Total != 2 {
		t.Errorf("THE COUNT DISCLOSES: the owner's Global episode total is %d, want 2 — a count of the hidden tenant's episodes is the fact the restriction withholds (%v)", global.Total, global.resources())
	}
	if len(global.Episodes) != 2 {
		t.Errorf("the owner's Global episode list returned %d rows, want 2: %v", len(global.Episodes), global.resources())
	}
	// An unrestricted tenant and the platform's own episode survive.
	got := map[string]bool{}
	for _, r := range global.resources() {
		got[r] = true
	}
	if !got[epAcmeDevice] || !got[""] {
		t.Errorf("restricting tenant B also removed tenant A's episode or the platform's own: %v", global.resources())
	}

	// ── half 2: ?as_tenant into the restricted tenant reads nothing, and counts
	//    nothing. Not even the platform's own device-less episode — a scope that
	//    may read none of a tenant is not served the rest under its name. ──
	into := f.list(f.admin, f.b.tenantID)
	if into.Total != 0 || len(into.Episodes) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→tenantB episodes returned %d rows / total %d: %s", len(into.Episodes), into.Total, into.raw)
	}
	for _, leak := range []string{epGlobexDev, f.bSum} {
		if strings.Contains(into.raw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→tenantB episode body contains %q:\n%s", leak, into.raw)
		}
	}
	// And the WRITE half: triage of a restricted tenant's episode is 404 — never
	// 403, which would confirm the id exists.
	for _, asTenant := range []string{"", f.b.tenantID} {
		if st := f.ack(f.admin, f.bEpID, asTenant); st != http.StatusNotFound {
			t.Errorf("owner ack of a restricted tenant's episode (as_tenant=%q) = %d, want 404", asTenant, st)
		}
	}

	// ── the owner scoped into the UNRESTRICTED tenant is unmoved. ──
	intoA := f.list(f.admin, f.a.tenantID)
	if intoA.Total != 2 || !strings.Contains(intoA.raw, epAcmeDevice) {
		t.Errorf("restricting tenant B moved the owner→tenantA view: total %d (%v)", intoA.Total, intoA.resources())
	}

	// ── half 3: the restricted tenant's OWN view is unchanged — rows and count.
	//    The switch hides a tenant from the PLATFORM, never from itself. ──
	bAfter := f.list(f.b.token, "")
	if bAfter.Total != bBefore.Total || strings.Join(bAfter.resources(), ",") != strings.Join(bBefore.resources(), ",") {
		t.Errorf("the restriction changed tenant B's OWN episode view: %d/%v before, %d/%v after",
			bBefore.Total, bBefore.resources(), bAfter.Total, bAfter.resources())
	}
	if !strings.Contains(bAfter.raw, f.bSum) {
		t.Errorf("tenant B lost its own incident from its own episode list:\n%s", bAfter.raw)
	}
	if strings.Contains(bAfter.raw, epAcmeDevice) {
		t.Errorf("CROSS-TENANT LEAK: tenant B's episode list names tenant A's device:\n%s", bAfter.raw)
	}
	// It can still triage its own.
	if st := f.ack(f.b.token, f.bEpID, ""); st != http.StatusOK {
		t.Errorf("the restriction took tenant B's own triage away from it: ack = %d, want 200", st)
	}
	// And tenant A is unmoved on the write path too.
	if st := f.ack(f.admin, f.aEpID, ""); st != http.StatusOK {
		t.Errorf("restricting tenant B broke the owner's triage of tenant A's episode: %d", st)
	}
}
