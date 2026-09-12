// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alert_surfaces_restriction_test.go — the CLAUDE.md §3a rule-5 isolation tests
// for the operator-visibility restriction (Tenant.OperatorRestricted) on the
// alert readers that are NOT GET /api/alerts: the GraphQL `alerts` field
// (/api/graphql), the topology canvas overlay (/api/topology/view), the omnibox
// (/api/search/global) and the per-device grouping the persisted graph enriches
// through (activeAlertsByDevice).
//
// Correlix has two rules on an alert and they are not the same thing:
//
//	alertVisibleTenantOnly — tenancy only. Is this alert owned by a tenant the
//	                         caller may see? Answers TRUE FOR EVERYTHING on the
//	                         cross-tenant path, because the platform owner may
//	                         see every tenant.
//	alertVisibility.visible — that rule PLUS the operator-visibility restriction,
//	                         which says platform staff may ADMINISTER a restricted
//	                         tenant but must not READ its data.
//
// The alert lane (REST + WebSocket) and the dashboard tile ask the second. The
// surfaces here asked the first, so a tenant that the operator's own alert feed
// hides came back — with the rule that fired and a summary naming the device —
// the moment the operator asked for the same alerts through a different door.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/topology"
)

// The identifiers that must never cross, named so every assertion below says
// WHICH value leaked rather than "the test failed".
const (
	surfAcmeAlertID   = "alert-acme-core-ospf"
	surfAcmeSummary   = "OSPF adjacency to 198.51.100.9 is down on acme-core"
	surfAcmeExpID     = "alert-acme-experience"
	surfAcmeExpTarget = "checkout.acme.example"
	surfGlobexAlertID = "alert-globex-core-ospf"
	surfStackAlertID  = "alert-stack-kafka-lag"
)

// restrictedSurfaceFixture is a real server over real stores (tenant store, role
// store, device registry, alert engine), so the switch under test is the
// production one and the devices are keyed on the OPAQUE tenant ids the store
// mints.
type restrictedSurfaceFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

func (f *restrictedSurfaceFixture) owner() jwtClaims {
	return jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
}

func (f *restrictedSurfaceFixture) acmeUser() jwtClaims {
	return jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
}

func (f *restrictedSurfaceFixture) restrictAcme() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		f.t.Fatalf("restrict acme: %v", err)
	}
}

// newRestrictedSurfaceFixture seeds two tenants plus the platform:
//
//	acme     — acme-core        ← the tenant that gets restricted
//	globex   — globex-core      ← must be unmoved throughout
//	platform — stack-jump       ← must survive every filter
//
// and four active alerts: acme's device alert, acme's DEVICE-LESS experience
// alert (owner carried in a label, not a device), globex's device alert and a
// genuinely platform-owned stack alert that nothing owns. A "fix" that passed by
// serving nothing would fail on the last two.
func newRestrictedSurfaceFixture(t *testing.T) *restrictedSurfaceFixture {
	t.Helper()
	dir := t.TempDir()
	// No VictoriaMetrics in a unit test: point the metric reads at a closed port
	// so they fail fast and honestly rather than spending the handler's budget on
	// a DNS timeout.
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")

	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID},
		{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID},
		{ID: "stack-jump", Name: "stack-jump", Address: "10.9.0.1"},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}

	sv, err := newSavedStore(filepath.Join(dir, "saved.json"))
	if err != nil {
		t.Fatalf("newSavedStore: %v", err)
	}

	now := time.Now().UTC()
	s := &server{discovery: d, tenants: ts, roles: roles, saved: sv}
	s.alerts = alerts.NewEngine("", nil)
	s.alerts.SeedActiveForTest(
		models.Alert{ID: surfAcmeAlertID, Rule: "OSPFAdjacencyDown", Severity: "critical",
			DeviceID: "acme-core", Summary: surfAcmeSummary, FiredAt: now},
		models.Alert{ID: surfGlobexAlertID, Rule: "OSPFAdjacencyDown", Severity: "critical",
			DeviceID: "globex-core", Summary: "OSPF adjacency is down on globex-core", FiredAt: now},
		// Device-LESS but OWNED: the experience rules aggregate by target and
		// carry the tenant in a label.
		models.Alert{ID: surfAcmeExpID, Rule: "ExperienceLatencyOverBudget", Severity: "critical",
			Summary: "Experience target " + surfAcmeExpTarget + " p95 is 812 ms",
			Labels:  map[string]string{"tenant": acme.ID, "target": surfAcmeExpTarget},
			FiredAt: now},
		// Device-less AND unowned: genuinely platform-owned, visible throughout.
		models.Alert{ID: surfStackAlertID, Rule: "KafkaLagHigh", Severity: "warning",
			Summary: "engine consumer lag is climbing", FiredAt: now},
	)
	return &restrictedSurfaceFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

// ── /api/graphql — the `alerts` root field ───────────────────────────────────

// gqlAlerts drives the REAL POST /api/graphql handler and returns the alert ids
// it answered with plus the raw body, so a leak test can grep bytes rather than
// only typed ids.
func (f *restrictedSurfaceFixture) gqlAlerts(claims jwtClaims) (map[string]bool, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	body := `{"query":"{ alerts { id rule severity summary } }"}`
	f.s.handleGraphQL(w, req(http.MethodPost, "/api/graphql", body, claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("POST /api/graphql = %d (%s)", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			Alerts []struct {
				ID string `json:"id"`
			} `json:"alerts"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode graphql: %v (%s)", err, w.Body.String())
	}
	if len(out.Errors) > 0 {
		f.t.Fatalf("graphql errors: %v (%s)", out.Errors, w.Body.String())
	}
	ids := map[string]bool{}
	for _, a := range out.Data.Alerts {
		ids[a.ID] = true
	}
	return ids, w.Body.String()
}

// TestGraphQLAlertsHonourTheOperatorVisibilityRestriction — the GraphQL `alerts`
// field is GET /api/alerts through a second door. It filtered ONLY when the
// caller was tenant-scoped, and with the tenancy-only rule even then, so the
// platform owner's Global query returned every restricted tenant's incidents
// unfiltered and an ?as_tenant into one returned that tenant's outright.
func TestGraphQLAlertsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSurfaceFixture(t)

	// Baseline: before anything is restricted the owner reads all four, so this
	// test cannot pass on a field that answers with nothing.
	ids, _ := f.gqlAlerts(f.owner())
	for _, want := range []string{surfAcmeAlertID, surfAcmeExpID, surfGlobexAlertID, surfStackAlertID} {
		if !ids[want] {
			t.Fatalf("baseline: owner's GraphQL alerts do not contain %q (got %v) — the fixture does not reach the resolver", want, ids)
		}
	}
	// acme's OWN view, captured BEFORE the switch so the guard at the end
	// compares against a set this test measured rather than one it assumed.
	acmeBefore, _ := f.gqlAlerts(f.acmeUser())
	if !acmeBefore[surfAcmeAlertID] || !acmeBefore[surfAcmeExpID] {
		t.Fatalf("baseline: acme's own GraphQL alerts = %v, want its device alert and its experience alert", acmeBefore)
	}

	f.restrictAcme()

	// ── half 1: the Global/cross view drops the restricted tenant. ──
	ids, raw := f.gqlAlerts(f.owner())
	for _, hidden := range []string{surfAcmeAlertID, surfAcmeExpID} {
		if ids[hidden] {
			t.Errorf("RESTRICTION LEAK: the platform owner's GraphQL Global alerts returned acme's %q: %s", hidden, raw)
		}
	}
	for _, leak := range []string{surfAcmeSummary, "acme-core", surfAcmeExpTarget, "198.51.100.9"} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: acme's %q appears in the owner's GraphQL response body: %s", leak, raw)
		}
	}
	// ── an unrestricted tenant is unmoved, and a platform-owned object survives
	//    every filter. ──
	if !ids[surfGlobexAlertID] {
		t.Errorf("restricting acme also hid globex's %q from the owner (got %v)", surfGlobexAlertID, ids)
	}
	if !ids[surfStackAlertID] {
		t.Errorf("restricting acme also hid the platform's own %q (got %v)", surfStackAlertID, ids)
	}

	// ── half 2: ?as_tenant into the restricted tenant is denied — no alert of
	//    that tenant, and not the platform's own either. ──
	ids, raw = f.gqlAlerts(ownerActing(f.owner(), f.acme))
	if len(ids) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme GraphQL alerts returned %d alerts: %s", len(ids), raw)
	}
	for _, leak := range []string{surfAcmeAlertID, surfAcmeSummary, surfAcmeExpTarget} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→acme GraphQL body contains acme's %q: %s", leak, raw)
		}
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads it. ──
	if ids, _ = f.gqlAlerts(ownerActing(f.owner(), f.globex)); !ids[surfGlobexAlertID] {
		t.Errorf("owner→globex GraphQL alerts = %v, want globex's own alert — restricting acme must not move globex", ids)
	}

	// ── the restricted tenant's OWN view is unchanged. The switch hides a tenant
	//    from the PLATFORM, never from itself. ──
	acmeAfter, rawAcme := f.gqlAlerts(f.acmeUser())
	if !sameSet(acmeBefore, acmeAfter) {
		t.Errorf("the restriction damaged acme's OWN GraphQL view: %v before, %v after (%s)",
			sortedKeys(acmeBefore), sortedKeys(acmeAfter), rawAcme)
	}
	if acmeAfter[surfGlobexAlertID] {
		t.Errorf("acme's own GraphQL view saw globex's %q: %v", surfGlobexAlertID, acmeAfter)
	}
}

// ── /api/topology/view — the alert overlay on the canvas ─────────────────────

// topoViewBody drives the REAL GET /api/topology/view and returns the raw
// response. The alert overlay is projected ONTO nodes (node.issues / metrics
// .alert_count), so the assertion is on the bytes the operator's browser
// receives, not on an internal filter call.
func (f *restrictedSurfaceFixture) topoViewBody(claims jwtClaims) (topology.View, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.handleTopologyView(w, req(http.MethodGet, "/api/topology/view?mode=explore", "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET /api/topology/view = %d (%s)", w.Code, w.Body.String())
	}
	var v topology.View
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		f.t.Fatalf("decode topology view: %v (%s)", err, w.Body.String())
	}
	return v, w.Body.String()
}

func nodeIDSet(v topology.View) map[string]bool {
	out := map[string]bool{}
	for _, n := range v.Nodes {
		out[n.ID] = true
	}
	return out
}

// TestTopologyViewAlertOverlayHonoursTheOperatorVisibilityRestriction covers the
// canvas overlay. The NODE half is already closed (visibleDevicesFor), so what
// this pins is that the alert overlay cannot reintroduce what the node filter
// removed — and that the restricted tenant's own canvas keeps its own alerts.
func TestTopologyViewAlertOverlayHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSurfaceFixture(t)

	// Baseline: the owner's canvas draws all three devices and the acme alert
	// summary is on it, so the assertions below cannot pass on an empty canvas.
	base, baseRaw := f.topoViewBody(f.owner())
	if got := nodeIDSet(base); !got["acme-core"] || !got["globex-core"] || !got["stack-jump"] {
		t.Fatalf("baseline: owner canvas nodes = %v, want all three — the fixture does not reach the handler", sortedKeys(got))
	}
	if !strings.Contains(baseRaw, surfAcmeSummary) {
		t.Fatalf("baseline: the owner's canvas does not carry acme's alert summary %q — the overlay does not reach the response: %s",
			surfAcmeSummary, baseRaw)
	}
	// acme's OWN canvas, captured BEFORE the switch.
	acmeBefore, acmeBeforeRaw := f.topoViewBody(f.acmeUser())
	acmeBeforeNodes := nodeIDSet(acmeBefore)
	if !acmeBeforeNodes["acme-core"] || !strings.Contains(acmeBeforeRaw, surfAcmeSummary) {
		t.Fatalf("baseline: acme's own canvas = %v, want acme-core carrying its own alert", sortedKeys(acmeBeforeNodes))
	}

	f.restrictAcme()

	// ── half 1: the Global view. ──
	global, globalRaw := f.topoViewBody(f.owner())
	gnodes := nodeIDSet(global)
	if gnodes["acme-core"] {
		t.Errorf("RESTRICTION LEAK: the owner's Global canvas still draws acme-core: %v", sortedKeys(gnodes))
	}
	for _, leak := range []string{surfAcmeSummary, surfAcmeExpTarget, "198.51.100.9"} {
		if strings.Contains(globalRaw, leak) {
			t.Errorf("RESTRICTION LEAK: acme's %q appears in the owner's Global topology view: %s", leak, globalRaw)
		}
	}
	if !gnodes["globex-core"] || !gnodes["stack-jump"] {
		t.Errorf("restricting acme also removed globex-core/stack-jump from the owner's canvas: %v", sortedKeys(gnodes))
	}

	// ── half 2: ?as_tenant into the restricted tenant draws nothing. ──
	scoped, scopedRaw := f.topoViewBody(ownerActing(f.owner(), f.acme))
	if n := len(scoped.Nodes); n != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme canvas drew %d node(s): %s", n, scopedRaw)
	}
	for _, leak := range []string{surfAcmeSummary, surfAcmeExpTarget} {
		if strings.Contains(scopedRaw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→acme canvas body contains acme's %q: %s", leak, scopedRaw)
		}
	}

	// ── the owner scoped into the UNRESTRICTED tenant is unmoved. ──
	gscoped, _ := f.topoViewBody(ownerActing(f.owner(), f.globex))
	if got := nodeIDSet(gscoped); !got["globex-core"] {
		t.Errorf("owner→globex canvas = %v, want globex-core", sortedKeys(got))
	}

	// ── the restricted tenant's OWN canvas is unchanged. ──
	acmeAfter, acmeAfterRaw := f.topoViewBody(f.acmeUser())
	if !sameSet(acmeBeforeNodes, nodeIDSet(acmeAfter)) {
		t.Errorf("the restriction damaged acme's OWN canvas: %v before, %v after",
			sortedKeys(acmeBeforeNodes), sortedKeys(nodeIDSet(acmeAfter)))
	}
	if !strings.Contains(acmeAfterRaw, surfAcmeSummary) {
		t.Errorf("acme's own canvas lost its own alert %q after the restriction: %s", surfAcmeSummary, acmeAfterRaw)
	}
}

// ── /api/search/global — the omnibox ─────────────────────────────────────────

func (f *restrictedSurfaceFixture) omnibox(q string, claims jwtClaims) (map[string]bool, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.handleGlobalSearch(w, req(http.MethodGet, "/api/search/global?q="+q, "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET /api/search/global = %d (%s)", w.Code, w.Body.String())
	}
	var out struct {
		Results []globalResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode omnibox: %v (%s)", err, w.Body.String())
	}
	ids := map[string]bool{}
	for _, g := range out.Results {
		if g.Kind == "alert" {
			ids[g.ID] = true
		}
	}
	return ids, w.Body.String()
}

// TestGlobalSearchAlertsHonourTheOperatorVisibilityRestriction pins the omnibox.
// It answers on a SUMMARY, which is the disclosure itself: typing a rule name
// into the top bar returned a restricted tenant's incident and the device in it.
func TestGlobalSearchAlertsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSurfaceFixture(t)

	// Baseline: "ospf" matches both device alerts for the owner.
	ids, _ := f.omnibox("ospf", f.owner())
	if !ids[surfAcmeAlertID] || !ids[surfGlobexAlertID] {
		t.Fatalf("baseline: owner omnibox %q = %v, want both OSPF alerts — the fixture does not reach the handler", "ospf", ids)
	}
	acmeBefore, _ := f.omnibox("ospf", f.acmeUser())
	if !acmeBefore[surfAcmeAlertID] {
		t.Fatalf("baseline: acme's own omnibox = %v, want its own alert", acmeBefore)
	}

	f.restrictAcme()

	// ── half 1: the Global view. ──
	ids, raw := f.omnibox("ospf", f.owner())
	if ids[surfAcmeAlertID] {
		t.Errorf("RESTRICTION LEAK: the owner's omnibox returned acme's %q: %s", surfAcmeAlertID, raw)
	}
	for _, leak := range []string{surfAcmeSummary, "acme-core", "198.51.100.9"} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: acme's %q appears in the owner's omnibox body: %s", leak, raw)
		}
	}
	if !ids[surfGlobexAlertID] {
		t.Errorf("restricting acme also hid globex's %q from the omnibox: %v", surfGlobexAlertID, ids)
	}
	// The platform's own alert is still findable.
	if stack, _ := f.omnibox("kafka", f.owner()); !stack[surfStackAlertID] {
		t.Errorf("restricting acme also hid the platform's own %q from the omnibox: %v", surfStackAlertID, stack)
	}
	// The device-less OWNED experience alert too.
	if exp, expRaw := f.omnibox("experience", f.owner()); exp[surfAcmeExpID] {
		t.Errorf("RESTRICTION LEAK: the owner's omnibox returned acme's device-less %q (target %s): %s",
			surfAcmeExpID, surfAcmeExpTarget, expRaw)
	}

	// ── half 2: ?as_tenant into the restricted tenant. ──
	ids, raw = f.omnibox("ospf", ownerActing(f.owner(), f.acme))
	if len(ids) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme omnibox returned %d alert hit(s): %s", len(ids), raw)
	}
	if strings.Contains(raw, surfAcmeSummary) {
		t.Errorf("RESTRICTION LEAK: owner→acme omnibox body contains acme's %q: %s", surfAcmeSummary, raw)
	}

	// ── the unrestricted tenant is unmoved. ──
	if g, _ := f.omnibox("ospf", ownerActing(f.owner(), f.globex)); !g[surfGlobexAlertID] {
		t.Errorf("owner→globex omnibox = %v, want globex's own alert", g)
	}

	// ── the restricted tenant's OWN omnibox is unchanged. ──
	acmeAfter, _ := f.omnibox("ospf", f.acmeUser())
	if !sameSet(acmeBefore, acmeAfter) {
		t.Errorf("the restriction damaged acme's OWN omnibox: %v before, %v after",
			sortedKeys(acmeBefore), sortedKeys(acmeAfter))
	}
}

// ── activeAlertsByDevice — the persisted graph's live enrichment ─────────────

// TestActiveAlertsByDeviceHonoursTheOperatorVisibilityRestriction pins the alert
// grouping /api/topology/graph enriches through. Its OUTPUT reaches the response
// only through nodes the persisted-graph filter (visibleGraphRecords) has already
// removed, so this is defence in depth rather than a live leak — but the function
// is a named seam any future caller can reach, and it was resolving tenancy alone.
func TestActiveAlertsByDeviceHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedSurfaceFixture(t)

	base := f.s.activeAlertsByDevice(f.owner())
	if len(base["acme-core"]) != 1 || len(base["globex-core"]) != 1 {
		t.Fatalf("baseline: activeAlertsByDevice(owner) = %v, want one alert on each device", base)
	}
	acmeBefore := f.s.activeAlertsByDevice(f.acmeUser())
	if len(acmeBefore["acme-core"]) != 1 {
		t.Fatalf("baseline: acme's own grouping = %v, want its own alert", acmeBefore)
	}

	f.restrictAcme()

	if got := f.s.activeAlertsByDevice(f.owner()); len(got["acme-core"]) != 0 {
		t.Errorf("RESTRICTION LEAK: the owner's Global grouping still carries acme-core's %q: %v",
			surfAcmeSummary, got["acme-core"])
	} else if len(got["globex-core"]) != 1 {
		t.Errorf("restricting acme also dropped globex-core's alert: %v", got)
	}
	if got := f.s.activeAlertsByDevice(ownerActing(f.owner(), f.acme)); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: the owner→acme grouping returned %d device(s): %v", len(got), got)
	}
	if got := f.s.activeAlertsByDevice(f.acmeUser()); len(got["acme-core"]) != 1 {
		t.Errorf("the restriction damaged acme's OWN grouping: %v", got)
	}
}
