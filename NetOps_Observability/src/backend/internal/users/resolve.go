// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// resolve.go — how a VERIFIED assertion becomes an account (design §2.5/§2.6),
// plus the FileStore half of it. The Postgres half is pg.go; the pure decision
// helpers here are shared by both so the two backends cannot drift.
//
// THE WHOLE POINT: the ONLY thing consulted is the canonical tuple
// (tenant_id, issuer, subject). Email, preferred_username and login name are
// PROFILE attributes refreshed on the way past. Two issuers asserting the same
// email, the same preferred_username or even the same `sub` therefore produce
// TWO accounts, and no code path can link them.
//
// The single, bounded exception is the legacy lazy bind (§2.6), and owner
// Decision 2 (2026-09-13) narrowed it to what it was always claimed to be. It is
// NO LONGER the migration — migrate.go's deterministic backfill is — so it may
// now run ONLY for the class whose provenance genuinely cannot be reconstructed
// offline: an `unresolved` oidc/saml account. It can no longer touch a bound, an
// ambiguous, a local, an ldap or a tacacs account, because every one of those
// either already has its identity or can be given one deterministically.
//
// It keeps every original condition: adopted exactly once, by the same door that
// created it, before the migration epoch, inside the flow's realm, into the
// account's own tenant, and never for a disabled account. Everything about it is
// written down in legacyBindRefusal below, one named condition per rule, and the
// name of the condition that refused is what the audit trail and the
// netops_identity_legacy_bind_total{result="refused"} counter carry.

import (
	"fmt"
	"strings"
	"time"
)

// ---- pure decision helpers (shared by both backends) ----------------------

// validateAssertion is the store's zero-trust gate on a door's claim (§3: every
// input is malicious until validated). It refuses:
//   - an incomplete tuple (the same shape migration 0049's CHECKs refuse);
//   - an assertion claiming the LOCAL issuer namespace or the local protocol —
//     the key-level form of H1. A federated door can never reach a local
//     account, however its subject is spelled, because it cannot even name the
//     namespace local accounts live in.
func validateAssertion(a Assertion) error {
	if err := a.validate(); err != nil {
		return err
	}
	if a.Issuer == LocalIssuer || a.Protocol == ProtocolLocal {
		return ErrLocalAccount
	}
	return nil
}

// realmScopedOwner is the §2.5 Amendment (architect ruling, 2026-09-13): a person
// is not duplicated per tenant inside one org. After the EXACT
// (tenant, issuer, subject) miss, a BOUND connection looks the same canonical
// (issuer, subject) up across the tenants its sign-in REALM reaches, and signs
// into the single account it finds.
//
// THE BOUND IS THE REALM, NEVER WIDER. An UNCONSTRAINED realm (Realm.Reaches ==
// nil — the shared platform front door) therefore gets NO cross-tenant reach
// here at all: "everything" is wider than any realm, and widening a lookup to
// the whole estate is precisely the cross-tenant takeover C3 closed. Those flows
// keep exact-tuple semantics, which is also what keeps the tenant part of the
// key meaningful (the same subject asserted for another tenant is another
// principal). The deliberately unbound door — one platform LDAP/TACACS+/bearer
// config that legitimately signs in every tenant — is a different method,
// ResolveFederatedUnbound, and says so in its name.
//
// candidates is every (tenant, owner) pair matching (issuer, subject), the exact
// tuple included; the exact hit is handled by the caller before this runs.
// Exactly one reachable account → that account. More than one → the refusal, so
// nothing is ever guessed. None → "" and the caller provisions.
func realmScopedOwner(realm Realm, candidates map[string]string) (string, error) {
	if realm.Reaches == nil {
		return "", nil
	}
	var found string
	for tenant, owner := range candidates {
		if !realm.Permits(tenant) {
			continue
		}
		if found != "" && found != owner {
			return "", ErrAmbiguousIdentity
		}
		found = owner
	}
	return found, nil
}

// lazyBindableProtocol reports whether the constrained lazy path may run for this
// protocol at all (owner Decision 2). Only oidc and saml: their subject is a
// broker-minted `sub` that no offline derivation can produce. LDAP and TACACS+
// are DETERMINISTICALLY migrated (migrate.go), and local accounts were never
// eligible (H1) — for all three, reaching this path would mean guessing where a
// certainty exists.
func lazyBindableProtocol(protocol string) bool {
	switch protocol {
	case ProtocolOIDC, ProtocolSAML:
		return true
	}
	return false
}

// The named conditions. Each string is the value an operator sees in the audit
// detail and in the refusal log, so they say WHICH rule refused rather than "no".
const (
	refusalAlreadyBound          = "already-bound"
	refusalNotUnresolved         = "state-not-unresolved"
	refusalProtocolDeterministic = "protocol-deterministically-migrated"
	refusalLocalAccount          = "local-account"
	refusalAuthSourceMismatch    = "auth-source-mismatch"
	refusalPostEpoch             = "post-epoch"
	refusalUnknownEpoch          = "unknown-epoch"
	refusalLegacyUsername        = "legacy-username-mismatch"
	refusalOutsideRealm          = "outside-realm"
	refusalForeignIdentityTenant = "foreign-identity-tenant"
	refusalDisabled              = "disabled"
)

// legacyBindRefusal is design §2.6 as narrowed by owner Decision 2: one named
// condition per rule, returning "" when the adoption is permitted and the NAME of
// the condition that refused otherwise. identityTenant is the tenant the identity
// row WOULD be written with — see condition 5b.
func legacyBindRefusal(account User, a Assertion, realm Realm, markerAt time.Time, hasIdentity bool, identityTenant string) string {
	// 1. the account has NO identity row (UNIQUE(user_id) would refuse anyway).
	if hasIdentity {
		return refusalAlreadyBound
	}
	// 1b. owner Decision 2: the account's STORED state must be `unresolved`. An
	//     `ambiguous` account is waiting for a human precisely because its identity
	//     cannot be settled without guessing, and a login must not settle it.
	if account.IdentityState() != IdentityStateUnresolved {
		return refusalNotUnresolved
	}
	// 1c. owner Decision 2: only the class that cannot be reconstructed offline.
	//     An ldap/tacacs assertion has a deterministic backfill and must use it.
	if !lazyBindableProtocol(a.Protocol) {
		return refusalProtocolDeterministic
	}
	// 2. the account's auth_source equals the assertion's protocol. An OIDC
	//    assertion can never adopt an LDAP account — and never a LOCAL one (H1),
	//    which IsLocalSource excludes explicitly because "" reads as local.
	if IsLocalSource(account.AuthSource) {
		return refusalLocalAccount
	}
	if !strings.EqualFold(strings.TrimSpace(account.AuthSource), a.Protocol) {
		return refusalAuthSourceMismatch
	}
	// 3. the account was created BEFORE the migration epoch. A zero epoch means
	//    the epoch is unknown, which fails closed: nothing is ever adopted.
	if markerAt.IsZero() {
		return refusalUnknownEpoch
	}
	if !account.CreatedAt.Before(markerAt) {
		return refusalPostEpoch
	}
	// 4. the legacy derivation of THIS door equals the account's own id — the one
	//    place username equality is ever consulted, and only for a row the legacy
	//    code created from that very string.
	legacy := legacyUserID(a.LegacyUsername)
	if legacy == "" || legacy != normID(account.ID) {
		return refusalLegacyUsername
	}
	// 5a. the realm permits the account's tenant (a bound flow never reaches out
	//     of its realm), and
	// 5b. the identity row would land in the account's OWN tenant.
	//
	//     5b is a TIGHTENING of the design's condition 5, and it is required for
	//     coherence: an identity row whose tenant differed from the account's
	//     would be invisible to the tenant-scoped RLS join, and the next sign-in
	//     would miss the tuple and provision a duplicate. When the flow's
	//     provisioning tenant is not the legacy account's tenant the provenance
	//     IS ambiguous, so rule 6 applies: it is left pending for an operator,
	//     never guessed.
	if !realm.Permits(account.TenantID) {
		return refusalOutsideRealm
	}
	if identityTenant != normTenant(account.TenantID) {
		return refusalForeignIdentityTenant
	}
	// 6. the account is not disabled. JIT never resurrects a disabled account
	//    (design §4.2.5), and adoption is a stronger write than a refresh.
	if strings.EqualFold(strings.TrimSpace(account.Status), "disabled") {
		return refusalDisabled
	}
	return ""
}

// assertedIdentity is the identity row a fresh (or newly-bound) assertion writes.
// provenance distinguishes a normal provision from a §2.6 adoption so an operator
// can always tell the two apart.
func assertedIdentity(a Assertion, tenant, provenance string, now time.Time) Identity {
	return Identity{
		TenantID:     tenant,
		Issuer:       a.Issuer,
		Subject:      a.Subject,
		Protocol:     a.Protocol,
		ConnectionID: a.ConnectionID,
		SubjectKind:  a.SubjectKind,
		DirectoryDN:  a.DirectoryDN,
		Provenance:   provenance,
		FirstSeenAt:  now,
		LastLoginAt:  now,
	}
}

// newFederatedUser is the account a first-sight assertion provisions. Its
// USERNAME IS THE OPAQUE ID (§2.1): a federated account has no login handle, is
// never accepted at a login form, and is never displayed — the UI shows the
// display name or email instead.
func newFederatedUser(a Assertion, id, tenant, role string, now time.Time) User {
	ident := assertedIdentity(a, tenant, ProvenanceAsserted, now)
	// The state is STAMPED at birth (owner Decision 2): every account carries an
	// explicit migration state, so "what is waiting for me?" never depends on which
	// code path last looked at the row.
	state := boundState(now)
	return User{
		ID:          id,
		Username:    id,
		Role:        role,
		Email:       a.Email,
		DisplayName: a.DisplayName,
		TenantID:    tenant,
		Status:      "active",
		AuthSource:  a.Protocol,
		CreatedAt:   now,
		Identity:    &ident,

		IdentityMigration: &state,
	}
}

// refreshIdentityMeta updates the NON-KEY columns of an existing identity on a
// successful sign-in: the last-login stamp, and the connection/subject-kind the
// assertion came through. The tuple itself is immutable — re-keying an identity
// is not a refresh, it is a new identity.
func refreshIdentityMeta(cur Identity, a Assertion, now time.Time) Identity {
	cur.LastLoginAt = now
	if a.ConnectionID != "" {
		cur.ConnectionID = a.ConnectionID
	}
	if a.SubjectKind != "" {
		cur.SubjectKind = a.SubjectKind
	}
	// The DN is a PROFILE attribute (owner Decision 2): refreshed on every login,
	// so an OU move updates it instead of re-namespacing the account.
	if a.DirectoryDN != "" {
		cur.DirectoryDN = a.DirectoryDN
	}
	return cur
}

// provisioningTenant is the tenant a NEW federated account is created in: the
// one the flow asserted, falling back to the platform default.
func (d Deps) provisioningTenant(a Assertion) string {
	if t := normTenant(a.TenantID); t != "" {
		return t
	}
	return normTenant(d.DefaultTenant)
}

// ---- FileStore ------------------------------------------------------------

// ResolveFederated — see Repo. The whole decision runs inside s.mu, because the
// merge write is itself the damage: refusing the session but rewriting the
// account's role on the way out would still be a breach (the C3 lesson).
func (s *FileStore) ResolveFederated(a Assertion, realm Realm, provision bool) (User, error) {
	return s.resolve(a, realm, provision, false)
}

// ResolveFederatedUnbound — see Repo. The platform-default-connection form.
func (s *FileStore) ResolveFederatedUnbound(a Assertion) (User, error) {
	return s.resolve(a, Realm{}, true, true)
}

func (s *FileStore) resolve(a Assertion, realm Realm, provision, unbound bool) (User, error) {
	a.Identity = a.normalized()
	if err := validateAssertion(a); err != nil {
		return User{}, err
	}
	var (
		out   User
		event *LegacyBindEvent
		err   error
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		out, event, err = s.resolveLocked(a, realm, provision, unbound)
	}()
	// Reported OUTSIDE the lock — including on the error paths, because a refusal
	// is exactly what the owner asked to be able to count: the integrator's audit
	// sink writes to its own store, and holding the user-store lock across a
	// foreign write is how a deadlock gets built.
	reportLegacyBind(s.deps, event)
	if err != nil {
		return User{}, err
	}
	return out, nil
}

// reportLegacyBind hands one lazy-path outcome to the integrator. Shared by both
// backends so neither can forget half of the vocabulary.
func reportLegacyBind(d Deps, event *LegacyBindEvent) {
	if event == nil || d.OnLegacyBind == nil {
		return
	}
	d.OnLegacyBind(*event)
}

// resolveLocked returns (user, lazy-path outcome or nil, error). Caller holds s.mu.
func (s *FileStore) resolveLocked(a Assertion, realm Realm, provision, unbound bool) (User, *LegacyBindEvent, error) {
	owner, err := s.lookupTupleLocked(a, unbound)
	if err != nil {
		return User{}, nil, err
	}
	if owner == "" && !unbound {
		// §2.5 Amendment: the same canonical (issuer, subject) inside the realm's
		// OWN tenants is the same person, not a second one. Runs before the §2.6
		// legacy check and before provisioning — and before the read-only door's
		// refusal, because finding the person's existing account is exactly what
		// an org-realm elevation sign-in needs and it provisions nothing.
		owner, err = realmScopedOwner(realm, s.tupleCandidatesLocked(a))
		if err != nil {
			return User{}, nil, err
		}
	}
	if owner != "" {
		u, ok := s.users[owner]
		if !ok {
			// The index and the collection disagree — refuse rather than provision
			// a second account over the top of a row we cannot see.
			return User{}, nil, fmt.Errorf("%w: identity index points at missing account %q", ErrIdentityConflict, owner)
		}
		refreshed, rerr := s.refreshLocked(u, a, realm)
		return refreshed, nil, rerr
	}
	if !provision {
		// The read-only door (elevation): a tuple miss is a refusal. It never
		// binds by username again, and it writes nothing.
		return User{}, nil, ErrNoSuchUser
	}
	u, event, err := s.bindLegacyLocked(a, realm, unbound)
	if err != nil {
		return User{}, event, err
	}
	if event != nil && event.Result == LegacyBindBound {
		return u, event, nil
	}
	// Refused or ambiguous: the assertion provisions a FRESH account and the legacy
	// row is left for the operator — design §2.6's "flagged, never guessed".
	fresh, err := s.provisionLocked(a, realm)
	return fresh, event, err
}

// lookupTupleLocked finds the account holding this identity. The bound form is an
// EXACT tuple match; the unbound form matches (issuer, subject) across tenants
// and refuses an ambiguous result rather than picking one.
func (s *FileStore) lookupTupleLocked(a Assertion, unbound bool) (string, error) {
	if !unbound {
		return s.byTuple[a.key()], nil
	}
	var found string
	for tk, owner := range s.byTuple {
		if tk.issuer != a.Issuer || tk.subject != a.Subject {
			continue
		}
		if found != "" && found != owner {
			return "", ErrAmbiguousIdentity
		}
		found = owner
	}
	return found, nil
}

// tupleCandidatesLocked maps tenant → owning account id for every identity that
// matches this assertion's (issuer, subject), whatever tenant it sits in. The
// REALM, not this function, decides which of them may be reached.
func (s *FileStore) tupleCandidatesLocked(a Assertion) map[string]string {
	var out map[string]string
	for tk, owner := range s.byTuple {
		if tk.issuer != a.Issuer || tk.subject != a.Subject {
			continue
		}
		if out == nil {
			out = make(map[string]string, 2)
		}
		out[tk.tenant] = owner
	}
	return out
}

// refreshLocked is the tuple-hit path: realm check, then the profile refresh.
func (s *FileStore) refreshLocked(u User, a Assertion, realm Realm) (User, error) {
	// H1, defence in depth: a local account cannot hold a federated tuple, so
	// this can only fire if something upstream corrupted the index. Refuse.
	if IsLocalSource(u.AuthSource) {
		return User{}, ErrLocalAccount
	}
	// The account must live in the realm this flow came in on. Refused BEFORE
	// MergeFederated, inside the lock, so a sign-in from another tenant's IdP
	// rewrites nothing on its way to being refused.
	if !realm.Permits(u.TenantID) {
		return User{}, ErrForeignTenant
	}
	before := u
	now := time.Now().UTC()
	// SR-025: the guard judges the IdP-mapped role against the account's EXISTING
	// tenant, and its verdict — never the raw asserted role — is what persists.
	// The principal passed to the guard is the opaque id, not a username: an
	// audit line must not carry an IdP-derived handle (§4.9).
	u = MergeFederated(u, a.Email, a.DisplayName, s.deps.GuardRole(a.Role, u.TenantID, u.ID, a.Protocol), a.Protocol)
	if u.Identity != nil {
		next := refreshIdentityMeta(*u.Identity, a, now)
		u.Identity = &next
		applyState(&u, boundState(now))
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.putLocked(before)
		return User{}, err
	}
	return u, nil
}

// bindLegacyLocked is design §2.6 as narrowed by owner Decision 2. It returns the
// OUTCOME (bound / ambiguous / refused, or nil when there was no candidate at
// all) rather than a bare bool, because the owner asked for the numbers: a
// refusal nobody counts is a migration nobody can judge.
//
// It NEVER merges. When the tuple the adoption would write is already another
// account's, the legacy row is marked `ambiguous` — durably, so it appears in
// ?identity=ambiguous — and the assertion provisions a fresh account instead.
func (s *FileStore) bindLegacyLocked(a Assertion, realm Realm, unbound bool) (User, *LegacyBindEvent, error) {
	cand := legacyUserID(a.LegacyUsername)
	if cand == "" {
		return User{}, nil, nil
	}
	u, ok := s.users[cand]
	if !ok {
		return User{}, nil, nil
	}
	identityTenant := normTenant(a.TenantID)
	if unbound {
		// No realm and no per-connection tenant: the identity belongs where the
		// account already lives.
		identityTenant = normTenant(u.TenantID)
	}
	if reason := legacyBindRefusal(u, a, realm, s.markerAt, u.Identity != nil, identityTenant); reason != "" {
		return User{}, &LegacyBindEvent{Result: LegacyBindRefused, Reason: reason, User: u, Assertion: a}, nil
	}
	before := u
	now := time.Now().UTC()
	ident := assertedIdentity(a, identityTenant, ProvenanceLegacyLazyBound, now)
	// NEVER SILENTLY MERGE TWO IDENTITIES (owner Decision 2). Checked BEFORE any
	// write, so the refusal needs no rollback.
	if other, dup := s.byTuple[ident.key()]; dup && other != cand {
		u = s.markAmbiguousLocked(u, ReasonTupleClaimed, now)
		return User{}, &LegacyBindEvent{Result: LegacyBindAmbiguous, Reason: ReasonTupleClaimed, User: u, Assertion: a}, nil
	}
	u.Identity = &ident
	applyState(&u, boundState(now))
	u = MergeFederated(u, a.Email, a.DisplayName, s.deps.GuardRole(a.Role, u.TenantID, u.ID, a.Protocol), a.Protocol)
	if err := s.indexLocked(u); err != nil {
		// The index refused what the tuple check allowed (a torn index): do NOT
		// adopt, and record the ambiguity rather than proceeding. unindexLocked
		// drops anything the failed index write left behind for THIS account.
		s.unindexLocked(u)
		s.putLocked(before)
		marked := s.markAmbiguousLocked(before, ReasonTupleClaimed, now)
		return User{}, &LegacyBindEvent{Result: LegacyBindAmbiguous, Reason: ReasonTupleClaimed, User: marked, Assertion: a},
			fmt.Errorf("%w: %w", ErrIdentityConflict, err)
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.unindexLocked(u)
		s.putLocked(before)
		return User{}, nil, err
	}
	return u, &LegacyBindEvent{Result: LegacyBindBound, Reason: "", User: u, Assertion: a}, nil
}

// markAmbiguousLocked stamps the ambiguous state on a legacy row and persists it.
// Best-effort on the flush: the refusal has already been decided, and a failed
// write must not turn "we refused to guess" into an error the caller reads as
// "try again". It is never silent — the error sink gets it (§10).
func (s *FileStore) markAmbiguousLocked(u User, reason string, now time.Time) User {
	if !applyState(&u, ambiguousState(reason, now)) {
		return u
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.deps.Errorf("users", "identity ambiguity could not be persisted — the account will be re-examined at the next boot",
			map[string]any{"user": u.ID, "reason": reason, "err": err.Error()})
	}
	return u
}

// provisionLocked mints a brand-new federated account. It is CAP-EXEMPT on
// purpose: MAX_USERS must never lock an organisation out of SSO.
func (s *FileStore) provisionLocked(a Assertion, realm Realm) (User, error) {
	tenant := s.deps.provisioningTenant(a)
	// Defence in depth: the caller derives the provisioning tenant from the
	// connection it already checked, so the two must never disagree.
	if !realm.Permits(tenant) {
		return User{}, ErrForeignTenant
	}
	id, err := s.mintFederatedIDLocked(a, tenant)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	role := s.deps.GuardRole(a.Role, tenant, id, a.Protocol)
	u := newFederatedUser(a, id, tenant, role, now)
	if err := s.indexLocked(u); err != nil {
		return User{}, fmt.Errorf("%w: %w", ErrIdentityConflict, err)
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.unindexLocked(u)
		delete(s.users, normID(u.ID))
		return User{}, err
	}
	return u, nil
}

// mintFederatedIDLocked derives the deterministic id of §2.4 and applies §4.3's
// collision rule: an id already held by a DIFFERENT tuple extends the hash to the
// full digest; still taken → refuse. It never resolves a collision by email or
// username, and it never reuses another tuple's account.
func (s *FileStore) mintFederatedIDLocked(a Assertion, tenant string) (string, error) {
	id := FederatedID(tenant, a.Issuer, a.Subject)
	if _, taken := s.users[normID(id)]; !taken {
		return id, nil
	}
	id = FederatedIDExtended(tenant, a.Issuer, a.Subject)
	if _, taken := s.users[normID(id)]; taken {
		return "", fmt.Errorf("%w: federated id %q already held by a different identity", ErrIdentityConflict, id)
	}
	return id, nil
}
