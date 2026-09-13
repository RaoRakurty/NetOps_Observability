// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// users_wiring.go — composition root + source-compat shims for internal/users.
//
// The identity store owns account records and the invariants that must hold
// across both backends; what it must NOT own are its cross-domain inputs —
// persistence, structured logging, the SR-025 federated-role guard, the role
// predicate behind the last-super-admin floor, account_policy's password-change
// stamping, and the env-derived limits — so those are supplied here.

import (
	"errors"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/users"
)

// Type shims (the jwtClaims-alias technique): User fans into ~59 files.
type (
	User      = users.User
	usersRepo = users.Repo
)

// guardFederatedRole prevents a federated identity from SILENTLY becoming the
// platform owner (global tenant + super-admin) via an IdP role/tenant mapping
// (SR-025). A mis-mapped IdP group must not seize cross-tenant control; require
// an explicit FEDERATION_ALLOW_PLATFORM_OWNER=true opt-in, otherwise downgrade.
//
// H1c: the predicate must match isPlatformOwner's exactly, or the guard has
// holes the owner check does not — tenant is normalized (lowercase/trim) and ""
// counts as the global/platform realm, and the role goes through
// isSuperAdminRole so the legacy "admin" alias (which grants full super-admin
// everywhere else) cannot slip past a literal RoleSuperAdmin comparison.
func guardFederatedRole(role, tenant, username, source string) string {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if (t == "" || t == TenantGlobal) && isSuperAdminRole(role) && os.Getenv("FEDERATION_ALLOW_PLATFORM_OWNER") != "true" {
		logWarn("auth", "refused federated platform-owner mapping — downgrading role; set FEDERATION_ALLOW_PLATFORM_OWNER=true to allow",
			map[string]any{"user": username, "source": source})
		return RoleReadOnly
	}
	return role
}

// maxUsersLimit reads the configurable account cap from MAX_USERS (0/unset =
// unlimited). Negative/garbage → 0 (unlimited), preserving existing behavior.
func maxUsersLimit() int {
	if v := os.Getenv("MAX_USERS"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// userDeps supplies the store's injected cross-domain dependencies.
func userDeps() users.Deps { return userDepsWith(nil) }

// userDepsWith is userDeps plus the §2.6 legacy-bind sink. Separated because the
// store is constructed BEFORE the server (the server is built from it), so the
// audit reporter can only be bound afterwards — see identityAuditSink.
func userDepsWith(sink *identityAuditSink) users.Deps {
	d := users.Deps{
		KV:                  platformKV{},
		Errorf:              logError,
		GuardRole:           guardFederatedRole,
		IsSuperAdmin:        isSuperAdminRole,
		ApplyPasswordChange: applyPasswordChange,
		DefaultTenant:       TenantGlobal,
		MaxUsers:            maxUsersLimit(),

		// Tracker 300 §2.1: a NEW local account gets an OPAQUE principal id, so
		// the login name stops being a key. Accounts that already exist keep
		// `id == lower(username)` — nothing that references a user today changes
		// value. Wired in the SAME change that teaches handleLogin to resolve a
		// typed name through LookupLocal, because an opaque id with a
		// username-keyed login door would be a store nobody can sign in to
		// (store deviation 2).
		MintID: mintUserID,

		// MigrationMarker stays ZERO on purpose: that is the store's instruction
		// to READ the epoch from the backend it is opening (the one-row
		// `identity_migration` table on Postgres, a KV key beside users.json on
		// the file backend) and to write it ONCE if absent. Pinning it here would
		// move the epoch on every boot and widen the §2.6 lazy-bind window to
		// every account created since — the one thing that must never happen.
		// A non-zero value is a test-only override.
	}
	if sink != nil {
		d.OnLegacyBind = sink.report
	}
	return d
}

// newUsersStore selects the user-store backend: under STORE_BACKEND=postgres
// the per-row RLS-backed PGStore; otherwise the file-backed store. `sink` is the
// §2.6 legacy-bind reporter and may be nil (nothing to report to).
func newUsersStore(path string, sink *identityAuditSink) (usersRepo, error) {
	if ps, ok := platformdb.ActivePG(); ok {
		return users.NewPGStore(ps.DB(), userDepsWith(sink))
	}
	return users.NewFileStore(path, userDepsWith(sink))
}

// ---- the §2.6 legacy-bind report ------------------------------------------

// identityAuditSink is the one-way seam between the user store — constructed
// before the server exists, because the server is built FROM it — and the audit
// trail, which lives on the server. The store reports a §2.6 adoption through
// this value; newServer binds the real reporter once `srv` exists.
//
// Injected, not global: newServer creates one, hands it to the store's Deps, and
// binds it. Until it is bound, report() is a no-op — which can only happen
// during boot, before any door can be reached.
type identityAuditSink struct {
	mu sync.RWMutex
	fn func(users.LegacyBindEvent)
}

func (k *identityAuditSink) bind(fn func(users.LegacyBindEvent)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fn = fn
}

func (k *identityAuditSink) report(ev users.LegacyBindEvent) {
	k.mu.RLock()
	fn := k.fn
	k.mu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// onIdentityLegacyBind records what the CONSTRAINED lazy path did (owner Decision
// 2, 2026-09-13). The lazy bind is no longer the migration — the deterministic
// boot backfill is — so this path now runs only for an `unresolved` oidc/saml
// account, and every one of its three outcomes is evidence:
//
//   - bound     — a pre-migration federated account, created by this very door
//     from this very username before any tuple existed, adopting the tuple it can
//     finally be given. Audited `identity.legacy_bound`, counted.
//   - ambiguous — the tuple the adoption would write is already another account's.
//     NEVER MERGED (the owner's rule 6): the account is flagged for manual
//     remediation, audited `identity.ambiguous`, and the sign-in provisions a
//     fresh account instead.
//   - refused   — a condition said no (the reason names WHICH). Counted, logged,
//     and deliberately NOT audited per event: a refusal is the steady state for
//     every legacy row an unrelated IdP asserts a matching name for, and one audit
//     entry per sign-in attempt would be a log-flooding surface.
//
// The gauges are refreshed from the store afterwards, so the census the owner
// reads is measured rather than incremented hopefully.
func (s *server) onIdentityLegacyBind(ev users.LegacyBindEvent) {
	switch ev.Result {
	case users.LegacyBindBound:
		s.identityLegacyBinds.Add(1)
		s.auditIdentityLegacyBind(ev, "identity.legacy_bound",
			"legacy federated account bound to its canonical identity (design §2.6, constrained by owner Decision 2)")
	case users.LegacyBindAmbiguous:
		s.identityLegacyBindAmbiguous.Add(1)
		s.auditIdentityLegacyBind(ev, "identity.ambiguous",
			"legacy identity is AMBIGUOUS — the derived tuple is already another account's; flagged for manual remediation, never merged")
	case users.LegacyBindRefused:
		s.identityLegacyBindRefused.Add(1)
		logInfo("auth", "legacy identity bind refused — the account keeps its recorded state",
			map[string]any{"user": ev.User.ID, "reason": ev.Reason, "protocol": ev.Assertion.Protocol})
		return
	default:
		return
	}
	// Both write paths changed the census, so re-measure it (rare: once per legacy
	// account, ever).
	s.refreshIdentityCensus()
}

// auditIdentityLegacyBind is the shared audit + log shape for the two outcomes
// that WROTE something. The ACTOR is the account — the opaque principal id, never
// the IdP-derived handle (§4.9: no PII in the trail).
func (s *server) auditIdentityLegacyBind(ev users.LegacyBindEvent, action, msg string) {
	u, a := ev.User, ev.Assertion
	detail := map[string]any{
		"action":   action,
		"issuer":   a.Issuer,
		"protocol": a.Protocol,
	}
	if ev.Reason != "" {
		detail["reason"] = ev.Reason
	}
	if a.ConnectionID != "" {
		detail["connection_id"] = a.ConnectionID
	}
	if u.Identity != nil {
		detail["provenance"] = u.Identity.Provenance
		detail["subject_kind"] = u.Identity.SubjectKind
	}
	detail["identity_state"] = u.IdentityState()
	logWarn("auth", msg, map[string]any{"user": u.ID, "issuer": a.Issuer, "protocol": a.Protocol, "reason": ev.Reason})
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Actor:    u.ID,
		Tenant:   u.TenantID,
		Method:   "IDENTITY",
		Path:     "/identity/" + strings.TrimPrefix(action, "identity."),
		Decision: "allow",
		Detail:   detail,
	})
}

// ---- the deterministic migration (owner Decision 2) ------------------------

// identityBackfillPlan takes the issuer namespaces from the SAME configuration the
// doors sign people in with, so the namespace the backfill writes and the
// namespace the next LDAP/TACACS+ login looks up cannot disagree. A door with no
// host configured contributes NO issuer, and its legacy rows stay `unresolved`
// with reason `issuer-unavailable` until a boot that has one — which is why the
// backfill must be, and is, idempotent and re-run every boot.
//
// Note it does NOT require the door to be ENABLED: the issuer is a pure function
// of host:port, so an operator who has configured the directory but temporarily
// disabled sign-in still gets a deterministic migration, and re-enabling does not
// re-namespace anything.
func identityBackfillPlan(ldapCfg *ldapConfigStore, tacacsCfg *tacacsConfigStore) users.BackfillPlan {
	var plan users.BackfillPlan
	if ldapCfg != nil {
		plan.LDAPIssuer = ldapDirectoryIssuer(ldapCfg.effective())
	}
	if tacacsCfg != nil {
		// The client's Addr() is host:port with a defaulted port, so an unconfigured
		// door would otherwise hand over ":49" — a port with no host. Gate on the
		// host, which is the half the namespace is made of.
		if cfg := tacacsCfg.effective(); strings.TrimSpace(cfg.Host) != "" {
			plan.TACACSIssuer = users.TACACSIssuer(cfg.client().Addr())
		}
	}
	return plan
}

// runIdentityBackfillAtBoot is the owner's Decision 2 in one call: expand (0049) →
// BACKFILL EVERY IDENTITY WHOSE PROVENANCE CAN BE ESTABLISHED (here) → validate
// (verifyIdentityInvariantsAtBoot, next) → the resolver already switched → the
// uniqueness is already enforced at the DB.
//
// It runs BEFORE the enforce gate and before the listener, it is idempotent, and
// it emits ONE structured summary line — the three numbers the owner asked for —
// so a boot log is a migration report.
func runIdentityBackfillAtBoot(repo usersRepo, plan users.BackfillPlan) (users.BackfillReport, error) {
	if repo == nil {
		return users.BackfillReport{}, errors.New("identity: user store is nil")
	}
	rep, err := repo.BackfillIdentities(plan)
	if err != nil {
		return users.BackfillReport{}, errors.New("identity backfill (tracker 300, owner Decision 2) failed — " +
			"the estate is left exactly as found, nothing was repaired or deleted: " + err.Error())
	}
	if rep.Census.Ambiguous > 0 {
		// Not buried in the summary line: these are the accounts a HUMAN has to
		// decide about, and nothing else will remind the operator.
		logWarn("identity", "identity migration left account(s) AMBIGUOUS — their identity is already another account's, nothing was merged; list them with GET /api/users?identity=ambiguous",
			map[string]any{"accounts": rep.Census.Ambiguous})
	}
	logInfo("identity", "deterministic identity migration complete", map[string]any{
		"examined":                 rep.Examined,
		"migrated_this_boot":       rep.Migrated,
		"unresolved_this_boot":     rep.Unresolved,
		"ambiguous_this_boot":      rep.Ambiguous,
		"accounts_deterministic":   rep.Census.BoundDeterministic,
		"accounts_legacy_lazy":     rep.Census.BoundLegacyLazy,
		"accounts_unresolved":      rep.Census.Unresolved,
		"accounts_ambiguous":       rep.Census.Ambiguous,
		"ldap_issuer_configured":   plan.LDAPIssuer != "",
		"tacacs_issuer_configured": plan.TACACSIssuer != "",
	})
	return rep, nil
}

// setIdentityCensus publishes a census onto the gauges.
func (s *server) setIdentityCensus(c users.MigrationCensus) {
	s.identityBoundDeterministic.Store(int64(c.BoundDeterministic))
	s.identityBoundLegacyLazy.Store(int64(c.BoundLegacyLazy))
	s.identityUnresolved.Store(int64(c.Unresolved))
	s.identityAmbiguous.Store(int64(c.Ambiguous))
}

// refreshIdentityCensus re-measures the estate and republishes the gauges. Never
// silent: a census that cannot be read is a metric that would otherwise freeze at
// a stale value and be read as "nothing changed" (§10).
func (s *server) refreshIdentityCensus() {
	if s.users == nil {
		return
	}
	c, err := s.users.IdentityCensus()
	if err != nil {
		logError("identity", "identity migration census unreadable — the netops_identity_migration_accounts gauges are stale", errf(err))
		return
	}
	s.setIdentityCensus(c)
}

// ---- §3 Enforce: the boot gate --------------------------------------------

// verifyIdentityInvariantsAtBoot is design §3's "Enforce" step: after the
// expand + backfill have run inside the store's constructor, every LOCAL account
// must hold an identity and no account may hold two.
//
// It REFUSES; it never repairs. A converge step must not destroy the estate it
// is converging (the F-58 lesson), and an account whose namespace entry is
// missing is exactly the state in which a federated assertion could otherwise be
// resolved into the wrong record. A PENDING FEDERATED account is not a failure —
// that is the documented waiting state of §2.6, not a broken one.
//
// Separated from its log.Fatalf caller so the invariant is testable without a
// process exit.
func verifyIdentityInvariantsAtBoot(repo usersRepo) error {
	if repo == nil {
		return errors.New("identity: user store is nil")
	}
	if err := repo.VerifyIdentityInvariants(); err != nil {
		return errors.New("identity invariants (tracker 300 §3 Enforce) are not satisfied — " +
			"the estate is left exactly as found, nothing was repaired or deleted: " + err.Error())
	}
	return nil
}
