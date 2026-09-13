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
		d.OnLegacyBound = sink.report
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
	fn func(users.User, users.Assertion)
}

func (k *identityAuditSink) bind(fn func(users.User, users.Assertion)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fn = fn
}

func (k *identityAuditSink) report(u users.User, a users.Assertion) {
	k.mu.RLock()
	fn := k.fn
	k.mu.RUnlock()
	if fn != nil {
		fn(u, a)
	}
}

// onIdentityLegacyBound records the ONE bounded exception design §2.6 allows: a
// pre-migration federated account, created by this very door from this very
// username before any tuple existed, adopting the tuple it can finally be given.
//
// Every adoption is evidence. It is counted (netops_identity_legacy_bound_total)
// and audited as `identity.legacy_bound` with the account as the ACTOR and the
// issuer, protocol, connection and provenance as detail, so an operator can list
// every account whose identity was claimed this way rather than asserted — and
// the owner can judge the exception against real numbers (§2.6 is flagged for
// veto; switching it off leaves these accounts `identity_status: pending`).
func (s *server) onIdentityLegacyBound(u User, a users.Assertion) {
	s.identityLegacyBinds.Add(1)
	detail := map[string]any{
		"action":   "identity.legacy_bound",
		"issuer":   a.Issuer,
		"protocol": a.Protocol,
	}
	if a.ConnectionID != "" {
		detail["connection_id"] = a.ConnectionID
	}
	if u.Identity != nil {
		detail["provenance"] = u.Identity.Provenance
		detail["subject_kind"] = u.Identity.SubjectKind
	}
	logWarn("auth", "legacy federated account bound to its canonical identity (design §2.6)",
		map[string]any{"user": u.ID, "issuer": a.Issuer, "protocol": a.Protocol})
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		// The ACTOR is the account that was adopted — the opaque principal id,
		// never the IdP-derived handle (§4.9: no PII in the trail).
		Actor:    u.ID,
		Tenant:   u.TenantID,
		Method:   "IDENTITY",
		Path:     "/identity/legacy_bound",
		Decision: "allow",
		Detail:   detail,
	})
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
