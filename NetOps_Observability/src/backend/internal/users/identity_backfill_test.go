// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// identity_backfill_test.go — the DETERMINISTIC migration contract (owner
// Decision 2, 2026-09-13), run against BOTH backends through the Repo seam.
//
// WHAT THE OWNER VETOED, and therefore what these tests exist to prove: the first
// cut namespaced only LOCAL accounts and left every federated one waiting for a
// future login to repair it one at a time. RED BEFORE this change, on the code at
// HEAD 065f62d2:
//
//	a legacy `auth_source: ldap` row, two boots in a row → Identity == nil both
//	times ("STILL has no canonical identity"), and no explicit state anywhere.
//
// So each test below is one clause of the decision:
//
//	deterministic where provenance can be established  → TestBackfill…Deterministically
//	explicit unresolved state for what cannot be       → the oidc rows
//	idempotent                                         → run twice, nothing moves
//	reject ambiguous instead of guessing               → the collision case
//	never silently merge two identities                → the collision case
//	metrics: migrated / unresolved / ambiguous          → the census case

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/platformdb"

	"github.com/jackc/pgx/v5"
)

// ldapPlan is a fully configured pair of doors: both issuer namespaces known, so
// every legacy ldap/tacacs row is deterministically migratable.
func ldapPlan(now time.Time) BackfillPlan {
	return BackfillPlan{LDAPIssuer: dirIssuer, TACACSIssuer: tacIssuer, Now: now}
}

// seedRow plants a PRE-TRACKER-300 account through the store's own legacy seeder:
// id == lower(username), an auth_source, and NO identity row.
func seedRow(t *testing.T, s Repo, name, source, tenant string) User {
	t.Helper()
	sd, ok := s.(LegacySeeder)
	if !ok {
		t.Fatalf("%T cannot seed a legacy row — the contract cannot run", s)
	}
	u := User{Username: name, Role: "read-only", TenantID: tenant, Status: "active",
		AuthSource: source, Email: name + "@old.example",
		CreatedAt: identityEpoch.Add(-24 * time.Hour)}
	if err := sd.SeedLegacyForTest(u); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	got, ok := s.Get(name)
	if !ok {
		t.Fatalf("seeded %s is not readable by its legacy id", name)
	}
	if got.IdentityBound() {
		t.Fatalf("seeded %s already has an identity — the fixture is wrong", name)
	}
	return got
}

func runBackfillContract(t *testing.T, newStore func(t *testing.T, d Deps) Repo) {
	t.Helper()
	now := identityEpoch

	// ---- the core clause: ldap and tacacs are migrated OFFLINE --------------
	t.Run("ldap and tacacs legacy rows are migrated deterministically", func(t *testing.T) {
		d, _ := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		seedRow(t, s, "dir-sam", ProtocolLDAP, tenantA)
		seedRow(t, s, "tac-sam", ProtocolTACACS, tenantA)
		seedRow(t, s, "loc-sam", ProtocolLocal, tenantA)

		rep, err := s.BackfillIdentities(ldapPlan(now))
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if rep.Migrated != 3 {
			t.Fatalf("migrated %d accounts, want 3 (ldap + tacacs + local are ALL derivable offline): %+v", rep.Migrated, rep)
		}
		for _, tc := range []struct{ id, issuer, prov string }{
			{"dir-sam", dirIssuer, ProvenanceBackfilledLDAP},
			{"tac-sam", tacIssuer, ProvenanceBackfilledTACACS},
			{"loc-sam", LocalIssuer, ProvenanceBackfilledLocal},
		} {
			u, ok := s.Get(tc.id)
			if !ok {
				t.Fatalf("%s vanished", tc.id)
			}
			id := identityOf(t, u)
			// THE SUBJECT IS THE LOGIN NAME the directory authenticated — not a DN,
			// which is what makes the row backfillable offline at all.
			if id.Issuer != tc.issuer || id.Subject != tc.id {
				t.Errorf("%s: identity = %+v, want (%s, %s, %s)", tc.id, id.key(), tenantA, tc.issuer, tc.id)
			}
			if id.TenantID != tenantA {
				t.Errorf("%s: identity tenant = %q, want the account's own %q", tc.id, id.TenantID, tenantA)
			}
			if id.Provenance != tc.prov {
				t.Errorf("%s: provenance = %q, want %q — an operator must be able to tell a deterministic migration from a lazy repair", tc.id, id.Provenance, tc.prov)
			}
			if u.IdentityState() != IdentityStateBound || u.IdentityStateReason() != "" {
				t.Errorf("%s: state = %q/%q, want bound with no reason", tc.id, u.IdentityState(), u.IdentityStateReason())
			}
			if tc.issuer != LocalIssuer && id.SubjectKind != SubjectKindLogin {
				t.Errorf("%s: subject_kind = %q, want %q", tc.id, id.SubjectKind, SubjectKindLogin)
			}
		}

		// THE ROUND TRIP, which is the whole point: the tuple the backfill DERIVED
		// is the tuple the door LOOKS UP, so the migrated account signs in — no new
		// account, no lazy bind, nothing pending.
		before := s.Count()
		got, err := s.ResolveFederatedUnbound(Assertion{
			Identity: Identity{TenantID: tenantA, Issuer: dirIssuer, Subject: "dir-sam",
				Protocol: ProtocolLDAP, SubjectKind: SubjectKindLogin, DirectoryDN: "cn=dir-sam,ou=people,dc=example,dc=com"},
			Role: "read-only",
		})
		if err != nil {
			t.Fatalf("the migrated account could not sign in: %v", err)
		}
		if got.ID != "dir-sam" {
			t.Fatalf("the LDAP door resolved %q, want the migrated account %q — the derivation and the door disagree", got.ID, "dir-sam")
		}
		if s.Count() != before {
			t.Fatalf("the sign-in created an account: count %d → %d", before, s.Count())
		}
		// And the DN arrived as a PROFILE attribute, refreshed on login, never keyed.
		if dn := identityOf(t, got).DirectoryDN; dn != "cn=dir-sam,ou=people,dc=example,dc=com" {
			t.Errorf("directory_dn = %q, want the DN the directory returned", dn)
		}
	})

	// ---- what genuinely cannot be reconstructed offline ---------------------
	t.Run("an oidc row gets an explicit unresolved state with a reason", func(t *testing.T) {
		d, _ := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		seedRow(t, s, "oidc-sam", ProtocolOIDC, tenantA)
		rep, err := s.BackfillIdentities(ldapPlan(now))
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if rep.Migrated != 0 || rep.Unresolved != 1 {
			t.Fatalf("report = %+v, want 0 migrated / 1 unresolved — a broker `sub` is not derivable from a username or an email", rep)
		}
		u, _ := s.Get("oidc-sam")
		if u.IdentityState() != IdentityStateUnresolved {
			t.Fatalf("state = %q, want %q", u.IdentityState(), IdentityStateUnresolved)
		}
		if u.IdentityStateReason() != ReasonUnreconstructable {
			t.Errorf("reason = %q, want %q", u.IdentityStateReason(), ReasonUnreconstructable)
		}
		if u.Identity != nil {
			t.Fatalf("an identity was GUESSED for an oidc row: %+v", *u.Identity)
		}
	})

	// ---- a door that is not configured yet ---------------------------------
	t.Run("issuer-unavailable is recorded and resolved by a later boot", func(t *testing.T) {
		d, _ := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		seedRow(t, s, "dir-later", ProtocolLDAP, tenantA)

		// Boot 1: LDAP is not configured, so the namespace is unknown. Guessing a
		// host would mint a namespace no login ever resolves.
		if _, err := s.BackfillIdentities(BackfillPlan{Now: now}); err != nil {
			t.Fatalf("boot 1: %v", err)
		}
		u, _ := s.Get("dir-later")
		if u.IdentityState() != IdentityStateUnresolved || u.IdentityStateReason() != ReasonIssuerUnavailable {
			t.Fatalf("state = %q/%q, want unresolved/%s", u.IdentityState(), u.IdentityStateReason(), ReasonIssuerUnavailable)
		}

		// Boot 2: the operator configured the directory. The SAME pass now migrates
		// it — which is why the backfill must re-examine unresolved rows every boot.
		rep, err := s.BackfillIdentities(ldapPlan(now))
		if err != nil {
			t.Fatalf("boot 2: %v", err)
		}
		if rep.Migrated != 1 {
			t.Fatalf("boot 2 migrated %d, want 1", rep.Migrated)
		}
		u, _ = s.Get("dir-later")
		id := identityOf(t, u)
		if id.Issuer != dirIssuer || id.Provenance != ProvenanceBackfilledLDAP || !u.IdentityBound() {
			t.Fatalf("after boot 2: identity %+v, state %q", id, u.IdentityState())
		}
	})

	// ---- never merge, never guess -----------------------------------------
	t.Run("a colliding derivation is ambiguous and never merged", func(t *testing.T) {
		d, ev := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		// An account that ALREADY holds (global, ldap:dir, clash) — e.g. someone who
		// signed in after the upgrade and was provisioned fresh.
		holder, err := s.ResolveFederatedUnbound(Assertion{
			Identity: Identity{TenantID: globalTenant, Issuer: dirIssuer, Subject: "clash",
				Protocol: ProtocolLDAP, SubjectKind: SubjectKindLogin},
			Role: "read-only",
		})
		if err != nil {
			t.Fatalf("provision the holder: %v", err)
		}
		// …and a legacy row whose deterministic derivation is that very tuple.
		legacy := seedRow(t, s, "clash", ProtocolLDAP, globalTenant)
		before := s.Count()

		rep, err := s.BackfillIdentities(ldapPlan(now))
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if rep.Ambiguous != 1 || rep.Migrated != 0 {
			t.Fatalf("report = %+v, want 0 migrated / 1 ambiguous", rep)
		}
		u, ok := s.Get(legacy.ID)
		if !ok {
			t.Fatal("the legacy row vanished")
		}
		if u.IdentityState() != IdentityStateAmbiguous || u.IdentityStateReason() != ReasonTupleClaimed {
			t.Fatalf("state = %q/%q, want ambiguous/%s", u.IdentityState(), u.IdentityStateReason(), ReasonTupleClaimed)
		}
		if u.Identity != nil {
			t.Fatalf("the colliding row was given an identity anyway: %+v", *u.Identity)
		}
		// NOT MERGED: two rows, two principals, the holder untouched.
		if s.Count() != before {
			t.Fatalf("the backfill changed the account count %d → %d — it must never merge two identities", before, s.Count())
		}
		if h, _ := s.Get(holder.ID); identityOf(t, h).Provenance != ProvenanceAsserted {
			t.Errorf("the holder's identity was rewritten: %+v", h.Identity)
		}
		if len(ev.bound) != 0 {
			t.Fatalf("the lazy-bind sink fired during a deterministic backfill: %v", ev.bound)
		}
	})

	// ---- idempotency + the census the owner reads --------------------------
	t.Run("a mixed estate: idempotent, and the census is the three numbers", func(t *testing.T) {
		d, ev := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		// 3 local, 2 ldap, 1 tacacs, 2 oidc (unresolvable), 1 colliding ldap row.
		for _, n := range []string{"loc-a", "loc-b", "loc-c"} {
			seedRow(t, s, n, ProtocolLocal, tenantA)
		}
		for _, n := range []string{"dir-a", "dir-b"} {
			seedRow(t, s, n, ProtocolLDAP, tenantA)
		}
		seedRow(t, s, "tac-a", ProtocolTACACS, tenantA)
		for _, n := range []string{"oidc-a", "oidc-b"} {
			seedRow(t, s, n, ProtocolOIDC, tenantA)
		}
		holder, err := s.ResolveFederatedUnbound(Assertion{
			Identity: Identity{TenantID: tenantA, Issuer: dirIssuer, Subject: "amb-a",
				Protocol: ProtocolLDAP, SubjectKind: SubjectKindLogin},
			Role: "read-only",
		})
		if err != nil {
			t.Fatalf("holder: %v", err)
		}
		seedRow(t, s, "amb-a", ProtocolLDAP, tenantA)

		rep, err := s.BackfillIdentities(ldapPlan(now))
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		// THE NUMBERS (the owner's validation section): 6 deterministically
		// migrated, 2 unresolved, 1 ambiguous.
		if rep.Migrated != 6 || rep.Unresolved != 2 || rep.Ambiguous != 1 {
			t.Fatalf("run report = %+v, want 6 migrated / 2 unresolved / 1 ambiguous", rep)
		}
		want := MigrationCensus{BoundDeterministic: 7, BoundLegacyLazy: 0, Unresolved: 2, Ambiguous: 1}
		if rep.Census != want {
			t.Fatalf("census = %+v, want %+v (the 7th deterministic account is the asserted holder)", rep.Census, want)
		}
		if rep.Census.Total() != s.Count() {
			t.Fatalf("the census totals %d but the store holds %d accounts — the four states must partition the estate",
				rep.Census.Total(), s.Count())
		}

		// IDEMPOTENT: a second boot decides the same things and writes nothing.
		again, err := s.BackfillIdentities(ldapPlan(now.Add(time.Hour)))
		if err != nil {
			t.Fatalf("second backfill: %v", err)
		}
		if again.Migrated != 0 {
			t.Fatalf("a second boot migrated %d accounts — the backfill is not idempotent", again.Migrated)
		}
		if again.Census != want {
			t.Fatalf("a second boot changed the census: %+v → %+v", want, again.Census)
		}
		// …and it did not move `since` on a row whose state did not change, or
		// "unresolved for how long" would have no answer.
		u, _ := s.Get("oidc-a")
		if !u.IdentityStateSince().Equal(now) {
			t.Errorf("a re-run moved `since` to %v, want the original %v", u.IdentityStateSince(), now)
		}

		// A LAZY BIND of one oidc account moves exactly one account from
		// `unresolved` to `bound-legacy-lazy` — the fourth number, kept separate so a
		// repair is never counted as a deterministic migration.
		bound, err := s.ResolveFederated(Assertion{
			Identity:       Identity{TenantID: tenantA, Issuer: kcIssuer, Subject: "kc-oidc-a", Protocol: ProtocolOIDC},
			Role:           "read-only",
			LegacyUsername: "oidc-a",
		}, realmOf(tenantA), true)
		if err != nil {
			t.Fatalf("lazy bind: %v", err)
		}
		if bound.ID != "oidc-a" || len(ev.bound) != 1 {
			t.Fatalf("the constrained lazy bind did not adopt the oidc row: %q, %v", bound.ID, ev.bound)
		}
		census, err := s.IdentityCensus()
		if err != nil {
			t.Fatalf("census: %v", err)
		}
		wantAfter := MigrationCensus{BoundDeterministic: 7, BoundLegacyLazy: 1, Unresolved: 1, Ambiguous: 1}
		if census != wantAfter {
			t.Fatalf("census after the lazy bind = %+v, want %+v", census, wantAfter)
		}
		_ = holder
	})
	// ---- the enforce gate's reading of the states ---------------------------
	t.Run("the enforce gate tolerates an ambiguous row but not an unmigrated one", func(t *testing.T) {
		d, _ := identityTestDeps(identityEpoch)
		s := newStore(t, d)
		// A LOCAL row nothing has migrated yet fails the gate: after the backfill a
		// local account can only be bound or ambiguous, so this means the backfill
		// did not run.
		seedRow(t, s, "loc-unmigrated", ProtocolLocal, tenantA)
		if err := s.VerifyIdentityInvariants(); !errors.Is(err, ErrIdentityBackfillIncomplete) {
			t.Fatalf("err = %v, want ErrIdentityBackfillIncomplete", err)
		}
		// Once the backfill has had its say the gate passes…
		if _, err := s.BackfillIdentities(ldapPlan(now)); err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if err := s.VerifyIdentityInvariants(); err != nil {
			t.Fatalf("the gate refused a converged estate: %v", err)
		}
		// …and an AMBIGUOUS local row does not fail it: that is a recorded state
		// waiting for a human, and refusing to boot over one flagged account would
		// be a self-inflicted platform outage (owner Decision 2).
		sd := s.(LegacySeeder)
		if err := sd.SeedLegacyForTest(User{
			Username: "loc-ambiguous", Role: "read-only", TenantID: tenantA, Status: "active",
			AuthSource: ProtocolLocal, CreatedAt: identityEpoch.Add(-time.Hour),
			IdentityMigration: &MigrationState{State: IdentityStateAmbiguous, Reason: ReasonTupleClaimed, Since: now},
		}); err != nil {
			t.Fatalf("seed ambiguous local row: %v", err)
		}
		if err := s.VerifyIdentityInvariants(); err != nil {
			t.Fatalf("the gate refused to start over ONE flagged account: %v", err)
		}
	})
}

// planBackfill as a PURE table: what is derivable, what is not, and the two
// defensive readings a hand-written or older-release row can need.
func TestPlanBackfillDecisions(t *testing.T) {
	now := identityEpoch
	plan := ldapPlan(now)
	for name, tc := range map[string]struct {
		user       User
		plan       BackfillPlan
		wantIssuer string // "" = no identity written
		wantProv   string
		wantState  string
		wantReason string
	}{
		"local": {
			user: User{ID: "a", Username: "A", AuthSource: ProtocolLocal, TenantID: tenantA}, plan: plan,
			wantIssuer: LocalIssuer, wantProv: ProvenanceBackfilledLocal, wantState: IdentityStateBound,
		},
		"legacy blank auth source reads as local": {
			user: User{ID: "a", Username: "a", AuthSource: "", TenantID: tenantA}, plan: plan,
			wantIssuer: LocalIssuer, wantProv: ProvenanceBackfilledLocal, wantState: IdentityStateBound,
		},
		"ldap": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolLDAP, TenantID: tenantA}, plan: plan,
			wantIssuer: dirIssuer, wantProv: ProvenanceBackfilledLDAP, wantState: IdentityStateBound,
		},
		// A blob written by hand, or by a release that did not fold the source.
		"LDAP in mixed case is still migratable": {
			user: User{ID: "a", Username: "a", AuthSource: "LDAP", TenantID: tenantA}, plan: plan,
			wantIssuer: dirIssuer, wantProv: ProvenanceBackfilledLDAP, wantState: IdentityStateBound,
		},
		"tacacs": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolTACACS, TenantID: tenantA}, plan: plan,
			wantIssuer: tacIssuer, wantProv: ProvenanceBackfilledTACACS, wantState: IdentityStateBound,
		},
		"ldap with no configured door": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolLDAP, TenantID: tenantA}, plan: BackfillPlan{Now: now},
			wantState: IdentityStateUnresolved, wantReason: ReasonIssuerUnavailable,
		},
		"oidc": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolOIDC, TenantID: tenantA}, plan: plan,
			wantState: IdentityStateUnresolved, wantReason: ReasonUnreconstructable,
		},
		"saml": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolSAML, TenantID: tenantA}, plan: plan,
			wantState: IdentityStateUnresolved, wantReason: ReasonUnreconstructable,
		},
		"an unknown source is listed, never guessed at": {
			user: User{ID: "a", Username: "a", AuthSource: "kerberos", TenantID: tenantA}, plan: plan,
			wantState: IdentityStateUnresolved, wantReason: ReasonUnknownAuthSource,
		},
		// No login name = nothing derivable, whatever the source says. The opaque id
		// is deliberately NOT used as a fallback subject: no directory asserts it.
		"no login name": {
			user: User{ID: "fed_x", AuthSource: ProtocolLDAP, TenantID: tenantA}, plan: plan,
			wantState: IdentityStateUnresolved, wantReason: ReasonUnknownAuthSource,
		},
		"an account that already holds a tuple is only stamped": {
			user: User{ID: "a", Username: "a", AuthSource: ProtocolOIDC, TenantID: tenantA,
				Identity: &Identity{TenantID: tenantA, Issuer: kcIssuer, Subject: "s", Protocol: ProtocolOIDC}},
			plan: plan, wantState: IdentityStateBound,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := planBackfill(tc.user, tc.plan.normalized(), now)
			if tc.wantIssuer == "" {
				if got.identity != nil {
					t.Fatalf("derived %+v, want NO identity — nothing may be guessed", *got.identity)
				}
			} else {
				if got.identity == nil {
					t.Fatalf("derived nothing, want (%s, %s, a)", tenantA, tc.wantIssuer)
				}
				if got.identity.Issuer != tc.wantIssuer || got.identity.Subject != "a" || got.identity.TenantID != tenantA {
					t.Errorf("derived %+v, want (%s, %s, a)", got.identity.key(), tenantA, tc.wantIssuer)
				}
				if got.identity.Provenance != tc.wantProv {
					t.Errorf("provenance = %q, want %q", got.identity.Provenance, tc.wantProv)
				}
			}
			if got.state.State != tc.wantState || got.state.Reason != tc.wantReason {
				t.Errorf("state = %q/%q, want %q/%q", got.state.State, got.state.Reason, tc.wantState, tc.wantReason)
			}
		})
	}
}

func TestFileStoreBackfillContract(t *testing.T) {
	runBackfillContract(t, newFileStoreForContract)
}

// A converged FILE estate persists its states, so a restart reads them back
// rather than re-deriving them (the states are stored, not inferred).
func TestFileStoreBackfillStatesArePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	d, _ := identityTestDeps(identityEpoch)
	s, err := NewFileStore(path, d)
	if err != nil {
		t.Fatal(err)
	}
	seedRow(t, s, "dir-p", ProtocolLDAP, tenantA)
	seedRow(t, s, "oidc-p", ProtocolOIDC, tenantA)
	if _, err := s.BackfillIdentities(ldapPlan(identityEpoch)); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	blob, err := os.ReadFile(path) // #nosec G304 -- the path is this test's TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(blob), `"identity_state"`, `"unresolved"`, ReasonUnreconstructable, ProvenanceBackfilledLDAP) {
		t.Fatalf("the persisted blob does not carry the explicit states:\n%s", blob)
	}
	reopened, err := NewFileStore(path, d)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	u, ok := reopened.Get("oidc-p")
	if !ok || u.IdentityState() != IdentityStateUnresolved || u.IdentityStateReason() != ReasonUnreconstructable {
		t.Fatalf("after a restart: %+v", u.IdentityMigration)
	}
	if v, _ := reopened.Get("dir-p"); !v.IdentityBound() {
		t.Fatalf("the deterministically migrated account came back as %q", v.IdentityState())
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func TestPGStoreBackfillContract(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres deterministic-backfill contract")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	runBackfillContract(t, func(t *testing.T, d Deps) Repo {
		// Every case asserts ABSOLUTE census numbers, so each one starts from an
		// empty estate. The DELETE cascades: `user_identities` and
		// `user_identity_state` both hang off users(id) ON DELETE CASCADE, which is
		// itself worth knowing works.
		if err := ps.DB().WithTenant(ctx, "", true, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM users`)
			return err
		}); err != nil {
			t.Fatalf("reset the estate: %v", err)
		}
		s, err := NewPGStore(ps.DB(), d)
		if err != nil {
			t.Fatalf("NewPGStore: %v", err)
		}
		return s
	})
}
