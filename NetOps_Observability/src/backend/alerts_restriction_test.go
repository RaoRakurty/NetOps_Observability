// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alerts_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// operator-visibility restriction (Tenant.OperatorRestricted) on the LIVE ALERT
// lane: GET /api/alerts, the WebSocket feed that fans the same alerts out, and
// the broadcast cache key both share.
//
// An alert is the customer's live incident: the rule that fired, the device it
// fired on, and a summary that names that device and what is wrong with it. A
// tenant that has switched the restriction on is invisible to the platform owner
// in flows, findings, logs, metrics, tunnels and the BMP feed, and must be
// invisible here too.
//
// The third test is the one that is easy to miss. The WebSocket hub builds each
// payload ONCE PER SCOPE and reuses it, and the scope key used to be the literal
// "cross:*" for every platform owner — while the restriction is resolved per
// SUBJECT, because break-glass is a per-operator session. Two owners with
// different break-glass state therefore shared one cache entry, which would have
// silently defeated the filter above it.

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
)

// restrictedAlertFixture is a server with a REAL tenant store and a REAL binding
// store, so the switch under test is the production one (Tenant.OperatorRestricted
// → effectiveRestrictedIDs → restrictedTelemetry) and break-glass is the real
// binding, not a stub.
type restrictedAlertFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

// The identifiers that must never cross. Named here so every assertion below
// says WHICH field leaked.
const (
	acmeAlertID      = "alert-acme-core-bgp"
	acmeAlertSummary = "BGP session to 203.0.113.7 is down on acme-core"
	acmeExpAlertID   = "alert-acme-experience"
	acmeExpTarget    = "pay.acme.example"
)

func newRestrictedAlertFixture(t *testing.T) *restrictedAlertFixture {
	t.Helper()
	dir := t.TempDir()
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
	bs, err := newBindingStore(filepath.Join(dir, "role_bindings.json"))
	if err != nil {
		t.Fatalf("newBindingStore: %v", err)
	}

	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})

	s := &server{discovery: d, tenants: ts, bindings: bs, hub: newHubWithLimit(0)}
	s.hub.SetScopeSalt(s.broadcastRestrictionSalt)
	s.alerts = alerts.NewEngine("", nil)
	s.alerts.SeedActiveForTest(
		models.Alert{ID: acmeAlertID, Rule: "BGPSessionDown", Severity: "critical",
			DeviceID: "acme-core", Summary: acmeAlertSummary, FiredAt: time.Now().UTC()},
		models.Alert{ID: "alert-globex-core-bgp", Rule: "BGPSessionDown", Severity: "critical",
			DeviceID: "globex-core", Summary: "BGP session is down on globex-core", FiredAt: time.Now().UTC()},
		// A device-LESS alert that still has an owner: the experience rules
		// aggregate by target and carry the tenant in a label.
		models.Alert{ID: acmeExpAlertID, Rule: "ExperienceLatencyOverBudget", Severity: "critical",
			Summary: "Experience target " + acmeExpTarget + " p95 is 812 ms",
			Labels:  map[string]string{"tenant": acme.ID, "target": acmeExpTarget},
			FiredAt: time.Now().UTC()},
		// A genuinely platform-owned alert: no device AND no owner. It must stay
		// visible throughout, so the fix cannot pass by hiding everything.
		models.Alert{ID: "alert-stack-kafka", Rule: "KafkaLagHigh", Severity: "warning",
			Summary: "engine consumer lag is climbing", FiredAt: time.Now().UTC()},
	)
	return &restrictedAlertFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

// rest runs one GET /api/alerts and returns the ids plus the raw body — a leak
// test must be able to grep bytes, not only typed ids.
func (f *restrictedAlertFixture) rest(claims jwtClaims) (map[string]bool, string) {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.handleAlerts(w, req(http.MethodGet, "/api/alerts", "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET /api/alerts = %d (%s)", w.Code, w.Body.String())
	}
	var out []models.Alert
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode: %v", err)
	}
	ids := map[string]bool{}
	for _, a := range out {
		ids[a.ID] = true
	}
	return ids, w.Body.String()
}

// openBreakGlass gives the operator a live, time-boxed session into one tenant —
// the real binding the restriction consults, not a stub.
func (f *restrictedAlertFixture) openBreakGlass(principal, tenantID string) {
	f.t.Helper()
	exp := time.Now().UTC().Add(30 * time.Minute)
	if _, err := f.s.bindings.Add(RoleBinding{
		PrincipalID: principal, RoleID: RoleSuperAdmin, ScopeID: scopeTenant(tenantID),
		Effect: EffectAllow, Condition: map[string]any{conditionBreakGlass: true}, ExpiresAt: &exp,
	}); err != nil {
		f.t.Fatalf("open break-glass: %v", err)
	}
}

// ── half 1 + half 2: the REST surface ────────────────────────────────────────

// TestAlertsRESTHonoursTheOperatorVisibilityRestriction covers both halves of GET
// /api/alerts: the platform owner's Global view, and the owner scoped into the
// restricted tenant with ?as_tenant.
func TestAlertsRESTHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedAlertFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// Baseline: before anything is restricted the owner reads every alert, so
	// this test cannot pass by serving nothing.
	ids, _ := f.rest(owner)
	for _, want := range []string{acmeAlertID, acmeExpAlertID, "alert-globex-core-bgp", "alert-stack-kafka"} {
		if !ids[want] {
			t.Fatalf("baseline: owner Global alerts do not contain %q (got %v)", want, ids)
		}
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the Global view. Acme's alerts are gone; everyone else's stay.
	ids, raw := f.rest(owner)
	for _, hidden := range []string{acmeAlertID, acmeExpAlertID} {
		if ids[hidden] {
			t.Errorf("RESTRICTION LEAK: the platform owner's Global alert list returned acme's %q: %s", hidden, raw)
		}
	}
	for _, leak := range []string{acmeAlertID, acmeAlertSummary, "acme-core", acmeExpTarget, "203.0.113.7"} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: acme's %q appears in the owner's Global alert body: %s", leak, raw)
		}
	}
	if !ids["alert-globex-core-bgp"] {
		t.Errorf("restricting acme also hid globex's alert (got %v)", ids)
	}
	if !ids["alert-stack-kafka"] {
		t.Errorf("restricting acme also hid the platform's own stack alert (got %v)", ids)
	}

	// ── half 2: ?as_tenant into the restricted tenant. No alert of that tenant,
	// and not the platform's own either — the operator is denied this scope.
	ids, raw = f.rest(ownerActing(owner, f.acme))
	if len(ids) != 0 {
		t.Errorf("RESTRICTION LEAK: owner→acme alert list returned %d alerts: %s", len(ids), raw)
	}
	for _, leak := range []string{acmeAlertID, acmeAlertSummary, acmeExpTarget} {
		if strings.Contains(raw, leak) {
			t.Errorf("RESTRICTION LEAK: owner→acme alert body contains acme's %q: %s", leak, raw)
		}
	}

	// The owner scoped into the UNRESTRICTED tenant still reads it.
	if ids, _ = f.rest(ownerActing(owner, f.globex)); !ids["alert-globex-core-bgp"] {
		t.Errorf("owner→globex = %v, want globex's own alert", ids)
	}

	// And acme's OWN user is never restricted from acme's own alerts — the
	// switch hides a tenant from the PLATFORM, never from itself.
	acmeUser := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	ids, raw = f.rest(acmeUser)
	if !ids[acmeAlertID] || !ids[acmeExpAlertID] {
		t.Fatalf("acme's own user lost its own alerts: %v (%s)", ids, raw)
	}
	if ids["alert-globex-core-bgp"] {
		t.Fatalf("acme's own user saw globex's alert: %v", ids)
	}

	// Break-glass un-hides acme for the operator that opened it, and only then.
	f.openBreakGlass("root", f.acme)
	if ids, _ = f.rest(owner); !ids[acmeAlertID] {
		t.Errorf("with a live break-glass session the owner should read acme again, got %v", ids)
	}
}

// ── the WebSocket half ───────────────────────────────────────────────────────

// broadcastAlert is the builder watchAlertsForBroadcast uses, verbatim: the same
// per-claims filter, so this test exercises the production rule.
func (f *restrictedAlertFixture) broadcastAlert(a models.Alert) func(jwtClaims) []map[string]any {
	return func(claims jwtClaims) []map[string]any {
		if !f.s.alertVisibleTo(a, claims) {
			return nil
		}
		return []map[string]any{{"type": "alert", "data": a}}
	}
}

// frames drains one client's queued frames.
func frames(c *wsClient) []string {
	var out []string
	for {
		select {
		case b := <-c.send:
			out = append(out, string(b))
		default:
			return out
		}
	}
}

// TestAlertWebSocketHonoursTheOperatorVisibilityRestriction is the same rule over
// the live feed: the frame is built per scope and fanned out, so a restricted
// tenant's alert must never be marshalled into a frame the operator receives.
func TestAlertWebSocketHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedAlertFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	acmeAlert := models.Alert{ID: acmeAlertID, Rule: "BGPSessionDown", Severity: "critical",
		DeviceID: "acme-core", Summary: acmeAlertSummary, FiredAt: time.Now().UTC()}

	ownerSock, p1 := newTestClient(t, f.s.hub, owner, 8)
	defer p1.Close()
	scopedSock, p2 := newTestClient(t, f.s.hub, ownerActing(owner, f.acme), 8)
	defer p2.Close()
	acmeSock, p3 := newTestClient(t, f.s.hub, jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}, 8)
	defer p3.Close()

	// Baseline: unrestricted, every one of them receives the alert.
	f.s.hub.BroadcastFiltered(f.broadcastAlert(acmeAlert))
	for name, c := range map[string]*wsClient{"owner": ownerSock, "owner→acme": scopedSock, "acme": acmeSock} {
		if len(frames(c)) == 0 {
			t.Fatalf("baseline: %s socket received no alert frame", name)
		}
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	f.s.hub.BroadcastFiltered(f.broadcastAlert(acmeAlert))
	if got := frames(ownerSock); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: the platform owner's socket received acme's %q: %v", acmeAlertID, got)
	}
	if got := frames(scopedSock); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: the owner→acme socket received acme's %q: %v", acmeAlertID, got)
	}
	// Acme's own socket keeps its own alert.
	got := frames(acmeSock)
	if len(got) != 1 || !strings.Contains(got[0], acmeAlertID) || !strings.Contains(got[0], acmeAlertSummary) {
		t.Errorf("acme's own socket lost its own alert frame: %v", got)
	}
}

// ── the cache key both halves share ──────────────────────────────────────────

// TestBroadcastScopeKeySeparatesOperatorsByRestrictionState is the trap. The hub
// builds a payload once per scope key and reuses it. If the key is the same for
// two platform owners whose RESTRICTION state differs, one operator's allowed
// view is served to the other out of the cache and every filter above it is
// silently defeated.
func TestBroadcastScopeKeySeparatesOperatorsByRestrictionState(t *testing.T) {
	f := newRestrictedAlertFixture(t)
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	// One operator holds a live break-glass session into acme; the other does not.
	f.openBreakGlass("root-with", f.acme)

	with := jwtClaims{Sub: "root-with", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	without := jwtClaims{Sub: "root-without", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// The key itself must differ. Both collapse to "cross:*" on tenancy alone.
	if broadcastScopeKey(with) != broadcastScopeKey(without) {
		t.Fatalf("premise broken: the two owners already differ on the tenant key (%q vs %q)",
			broadcastScopeKey(with), broadcastScopeKey(without))
	}
	if f.s.hub.scopeKey(with) == f.s.hub.scopeKey(without) {
		t.Fatalf("CACHE COLLISION: two operators with different break-glass state share the broadcast key %q",
			f.s.hub.scopeKey(with))
	}

	withSock, p1 := newTestClient(t, f.s.hub, with, 8)
	defer p1.Close()
	withoutSock, p2 := newTestClient(t, f.s.hub, without, 8)
	defer p2.Close()

	acmeAlert := models.Alert{ID: acmeAlertID, Rule: "BGPSessionDown", Severity: "critical",
		DeviceID: "acme-core", Summary: acmeAlertSummary, FiredAt: time.Now().UTC()}
	builds := 0
	f.s.hub.BroadcastFiltered(func(c jwtClaims) []map[string]any {
		builds++
		return f.broadcastAlert(acmeAlert)(c)
	})
	if builds != 2 {
		t.Errorf("build ran %d times, want 2 — one per restriction state", builds)
	}
	if got := frames(withSock); len(got) != 1 || !strings.Contains(got[0], acmeAlertID) {
		t.Errorf("the operator holding break-glass should receive acme's alert, got %v", got)
	}
	if got := frames(withoutSock); len(got) != 0 {
		t.Errorf("RESTRICTION LEAK: the operator with NO break-glass received acme's %q from the shared cache entry: %v",
			acmeAlertID, got)
	}

	// A tenant principal is never restricted, so ordinary tenant scopes must keep
	// sharing ONE cache entry — the key fix must not cost the build-once property.
	if salt := f.s.broadcastRestrictionSalt(jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}); salt != "" {
		t.Errorf("tenant principal salt = %q, want empty", salt)
	}
}
