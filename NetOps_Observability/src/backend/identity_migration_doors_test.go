// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// identity_migration_doors_test.go — the INTEGRATOR half of the owner's Decision 2
// (2026-09-13): the boot backfill takes its issuer namespaces from the very
// configuration the doors sign people in with, the three numbers reach /metrics,
// and the admin surface can be filtered by the explicit state.
//
// RED BEFORE this change, on the code at HEAD 065f62d2:
//
//	/metrics is missing "netops_identity_migration_accounts{state=\"bound-deterministic\"}"
//	/metrics is missing "netops_identity_migration_accounts{state=\"unresolved\"}"
//	/metrics is missing "netops_identity_migration_accounts{state=\"ambiguous\"}"
//	/metrics is missing "netops_identity_legacy_bind_total{result=\"bound\"}"
//	identity_status = "pending", want unresolved (an explicit stored state)

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/users"
)

// migrationDoorLDAP / migrationDoorTACACS are the two doors as an operator would
// have them configured. The SAME values feed the backfill plan and the sign-in
// assertions, which is the property that matters: a namespace the migration wrote
// and a namespace the door resolves against must be one string.
var (
	migrationDoorLDAP   = ldapConfig{Host: "dir.example.com", DefaultTenant: TenantGlobal}
	migrationDoorTACACS = tacacsConfig{Enabled: true, Host: "tac1.example.com", DefaultTenant: TenantGlobal, DefaultRole: RoleReadOnly}
)

func seedLegacyAccount(t *testing.T, s *server, name, source, tenant string) {
	t.Helper()
	seeder, ok := s.users.(users.LegacySeeder)
	if !ok {
		t.Fatalf("%T cannot seed a legacy row", s.users)
	}
	if err := seeder.SeedLegacyForTest(User{
		Username: name, Role: RoleReadOnly, Status: "active", TenantID: tenant,
		AuthSource: source, CreatedAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// The plan is built from the doors' own configuration, so the issuer the migration
// writes is byte-identical to the issuer the next sign-in looks up. A door with no
// host contributes nothing — and its rows wait rather than being given a guessed
// namespace no login would ever resolve.
func TestIdentityBackfillPlanTracksTheDoorConfiguration(t *testing.T) {
	ldapStore := &ldapConfigStore{cfg: &migrationDoorLDAP}
	tacacsStore := &tacacsConfigStore{cfg: &migrationDoorTACACS}
	plan := identityBackfillPlan(ldapStore, tacacsStore)

	wantLDAP := ldapAssertion(migrationDoorLDAP, &ldapIdentity{DN: "cn=x"}, "x", RoleReadOnly).Issuer
	if plan.LDAPIssuer != wantLDAP || plan.LDAPIssuer == "" {
		t.Errorf("plan LDAP issuer = %q, want the door's own %q", plan.LDAPIssuer, wantLDAP)
	}
	wantTAC := tacacsAssertion(migrationDoorTACACS.client(), "x").Issuer
	if plan.TACACSIssuer != wantTAC || plan.TACACSIssuer == "" {
		t.Errorf("plan TACACS issuer = %q, want the door's own %q", plan.TACACSIssuer, wantTAC)
	}

	// Neither door configured: no issuers, so those rows stay `unresolved` with
	// reason issuer-unavailable and are migrated by a later boot.
	empty := identityBackfillPlan(&ldapConfigStore{cfg: &ldapConfig{}}, &tacacsConfigStore{cfg: &tacacsConfig{}})
	if empty.LDAPIssuer != "" || empty.TACACSIssuer != "" {
		t.Errorf("an unconfigured pair of doors produced issuers %+v — a guessed namespace is worse than waiting", empty)
	}
}

// The whole owner-facing contract in one test: a mixed legacy estate, one boot
// pass, and the three numbers on /metrics.
func TestMigrationCensusReachesMetrics(t *testing.T) {
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil)

	// 2 ldap + 1 tacacs rows (deterministically migratable), 2 oidc rows (not),
	// and one ldap row whose derivation collides with an account that already
	// holds the tuple. Plus the bootstrap admin, which is already bound.
	for _, n := range []string{"dir-1", "dir-2"} {
		seedLegacyAccount(t, s, n, users.ProtocolLDAP, TenantGlobal)
	}
	seedLegacyAccount(t, s, "tac-1", users.ProtocolTACACS, TenantGlobal)
	for _, n := range []string{"oidc-1", "oidc-2"} {
		seedLegacyAccount(t, s, n, users.ProtocolOIDC, TenantGlobal)
	}
	// The holder: someone who signed in through the LDAP door after the upgrade and
	// was provisioned fresh, taking (global, ldap:dir.example.com:389, clash).
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/ldap/login", nil)
	s.completeFederatedLogin(rec, r, ldapAssertion(migrationDoorLDAP,
		&ldapIdentity{DN: "cn=clash,ou=people,dc=example,dc=com"}, "clash", RoleReadOnly))
	if rec.Code != http.StatusOK {
		t.Fatalf("provision the holder: %d (%s)", rec.Code, rec.Body.String())
	}
	seedLegacyAccount(t, s, "clash", users.ProtocolLDAP, TenantGlobal)

	// One boot pass, with the doors configured.
	plan := identityBackfillPlan(&ldapConfigStore{cfg: &migrationDoorLDAP}, &tacacsConfigStore{cfg: &migrationDoorTACACS})
	rep, err := runIdentityBackfillAtBoot(s.users, plan)
	if err != nil {
		t.Fatalf("boot backfill: %v", err)
	}
	s.setIdentityCensus(rep.Census)

	if rep.Migrated != 3 || rep.Unresolved != 2 || rep.Ambiguous != 1 {
		t.Fatalf("run report = %+v, want 3 migrated / 2 unresolved / 1 ambiguous", rep)
	}
	want := users.MigrationCensus{BoundDeterministic: 5, BoundLegacyLazy: 0, Unresolved: 2, Ambiguous: 1}
	if rep.Census != want {
		t.Fatalf("census = %+v, want %+v (admin + 3 migrated + the asserted holder)", rep.Census, want)
	}
	if rep.Census.Total() != s.users.Count() {
		t.Fatalf("the census totals %d but the store holds %d accounts", rep.Census.Total(), s.users.Count())
	}

	scrape := func(t *testing.T) string {
		t.Helper()
		w := httptest.NewRecorder()
		s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return w.Body.String()
	}
	out := scrape(t)
	for _, line := range []string{
		"# TYPE netops_identity_migration_accounts gauge",
		`netops_identity_migration_accounts{state="bound-deterministic"} 5`,
		`netops_identity_migration_accounts{state="bound-legacy-lazy"} 0`,
		`netops_identity_migration_accounts{state="unresolved"} 2`,
		`netops_identity_migration_accounts{state="ambiguous"} 1`,
		"# TYPE netops_identity_legacy_bind_total counter",
		`netops_identity_legacy_bind_total{result="bound"} 0`,
		`netops_identity_legacy_bind_total{result="ambiguous"} 0`,
		`netops_identity_legacy_bind_total{result="refused"} 0`,
	} {
		if !strings.Contains(out, line) {
			t.Errorf("/metrics is missing %q — owner Decision 2 asks for these numbers", line)
		}
	}

	// A CONSTRAINED lazy bind of one oidc row moves exactly one account from
	// `unresolved` to `bound-legacy-lazy`, and the gauges are re-measured without
	// anyone asking.
	rec = httptest.NewRecorder()
	s.completeFederatedLogin(rec, httptest.NewRequest(http.MethodPost, "/api/auth/sso/callback", nil),
		oidcLegacyAssertion("kc-sub-oidc-1", "oidc-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the legacy oidc sign-in: %d (%s)", rec.Code, rec.Body.String())
	}
	out = scrape(t)
	for _, line := range []string{
		`netops_identity_migration_accounts{state="bound-legacy-lazy"} 1`,
		`netops_identity_migration_accounts{state="unresolved"} 1`,
		`netops_identity_legacy_bind_total{result="bound"} 1`,
	} {
		if !strings.Contains(out, line) {
			t.Errorf("/metrics is missing %q after a lazy bind — the gauges are not refreshed", line)
		}
	}
	// The deterministic count did NOT move: a lazy repair must never be counted as
	// a deterministic migration.
	if !strings.Contains(out, `netops_identity_migration_accounts{state="bound-deterministic"} 5`) {
		t.Error("a lazy bind was counted as a deterministic migration")
	}
}

// The AMBIGUOUS outcome's audit trail and counter. The lazy path can only reach
// this state through a write race (the deterministic backfill is where a collision
// is normally found — see the design's §10.5 deviation 2), so the WIRING is tested
// directly: an ambiguous outcome must be audited as `identity.ambiguous`, counted,
// and must never be counted as a bind.
func TestAmbiguousLegacyBindIsAuditedAndCounted(t *testing.T) {
	_, s := newTestServerState(t)
	seedLegacyAccount(t, s, "amb-audit", users.ProtocolOIDC, TenantGlobal)
	u, ok := s.users.Get("amb-audit")
	if !ok {
		t.Fatal("the seeded row is missing")
	}
	boundBefore, ambBefore := s.identityLegacyBinds.Load(), s.identityLegacyBindAmbiguous.Load()

	s.onIdentityLegacyBind(users.LegacyBindEvent{
		Result:    users.LegacyBindAmbiguous,
		Reason:    users.ReasonTupleClaimed,
		User:      u,
		Assertion: oidcLegacyAssertion("kc-sub-amb", "amb-audit"),
	})

	if got := s.identityLegacyBindAmbiguous.Load(); got != ambBefore+1 {
		t.Fatalf(`netops_identity_legacy_bind_total{result="ambiguous"} went %d → %d, want +1`, ambBefore, got)
	}
	if got := s.identityLegacyBinds.Load(); got != boundBefore {
		t.Fatalf("an ambiguous outcome was counted as a BIND: %d → %d", boundBefore, got)
	}
	events, err := s.audit.List("", true, auditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	seen := 0
	for _, e := range events {
		if action, _ := e.Detail["action"].(string); action != "identity.ambiguous" {
			continue
		}
		seen++
		if e.Actor != u.ID {
			t.Errorf("audit actor = %q, want the flagged account %q", e.Actor, u.ID)
		}
		if r, _ := e.Detail["reason"].(string); r != users.ReasonTupleClaimed {
			t.Errorf("audited reason = %q, want %q", r, users.ReasonTupleClaimed)
		}
	}
	if seen != 1 {
		t.Fatalf("identity.ambiguous audited %d times, want exactly 1", seen)
	}
}

// The admin work queue: the three states are filterable, `pending` still works for
// the shipped SPA, and an unrecognised value narrows nothing.
func TestIdentityStateFilters(t *testing.T) {
	srv, s := newTestServerState(t)
	seedLegacyAccount(t, s, "oidc-f", users.ProtocolOIDC, TenantGlobal)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/ldap/login", nil)
	s.completeFederatedLogin(rec, r, ldapAssertion(migrationDoorLDAP,
		&ldapIdentity{DN: "cn=taken"}, "taken", RoleReadOnly))
	if rec.Code != http.StatusOK {
		t.Fatalf("holder: %d", rec.Code)
	}
	seedLegacyAccount(t, s, "taken", users.ProtocolLDAP, TenantGlobal)
	if _, err := runIdentityBackfillAtBoot(s.users, identityBackfillPlan(
		&ldapConfigStore{cfg: &migrationDoorLDAP}, &tacacsConfigStore{cfg: &migrationDoorTACACS})); err != nil {
		t.Fatalf("boot backfill: %v", err)
	}
	tok := adminToken(t, srv)

	list := func(t *testing.T, q string) []publicUser {
		t.Helper()
		st, b := do(t, srv, "GET", "/api/users"+q, tok, nil)
		if st != http.StatusOK {
			t.Fatalf("GET %s: %d %s", q, st, b)
		}
		var out []publicUser
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ids := func(us []publicUser) string {
		var b strings.Builder
		for _, u := range us {
			fmt.Fprintf(&b, "%s(%s/%s) ", u.ID, u.IdentityStatus, u.IdentityReason)
		}
		return b.String()
	}

	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"?identity=unresolved", []string{"oidc-f"}},
		{"?identity=pending", []string{"oidc-f"}}, // the retained alias
		{"?identity=ambiguous", []string{"taken"}},
	} {
		got := list(t, tc.query)
		if len(got) != len(tc.want) || got[0].ID != tc.want[0] {
			t.Fatalf("%s returned %s, want %v", tc.query, ids(got), tc.want)
		}
	}
	if u := list(t, "?identity=ambiguous")[0]; u.IdentityReason != users.ReasonTupleClaimed {
		t.Errorf("the ambiguous account's reason = %q, want %q", u.IdentityReason, users.ReasonTupleClaimed)
	}
	bound := list(t, "?identity=bound")
	if len(bound) == 0 {
		t.Fatal("?identity=bound returned nothing — the bootstrap admin and the holder are bound")
	}
	for _, u := range bound {
		if u.IdentityStatus != users.IdentityStateBound {
			t.Errorf("?identity=bound returned %s", ids([]publicUser{u}))
		}
	}
	if all, filtered := list(t, ""), list(t, "?identity=bogus"); len(all) != len(filtered) {
		t.Errorf("an unrecognised filter changed the list: %d → %d", len(all), len(filtered))
	}
}
