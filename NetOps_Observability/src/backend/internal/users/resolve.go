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
// The single, bounded exception is the legacy lazy bind (§2.6): a pre-migration
// FEDERATED account carries no issuer/subject, cannot have one derived offline,
// and is adopted exactly once — by the same door that created it, before the
// migration epoch, for an account that is not local, not disabled, not already
// bound, and inside the flow's realm. Everything about it is written down in
// legacyBindPermitted below, with a named condition per rule.

import (
	"errors"
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
	if err := a.Identity.validate(); err != nil {
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

// legacyBindPermitted is design §2.6, one boolean per written-down condition.
// Every one must hold. identityTenant is the tenant the identity row WOULD be
// written with — see condition 5b.
func legacyBindPermitted(account User, a Assertion, realm Realm, markerAt time.Time, hasIdentity bool, identityTenant string) bool {
	// 1. the account has NO identity row (UNIQUE(user_id) would refuse anyway).
	if hasIdentity {
		return false
	}
	// 2. the account's auth_source equals the assertion's protocol. An OIDC
	//    assertion can never adopt an LDAP account — and never a LOCAL one (H1),
	//    which IsLocalSource excludes explicitly because "" reads as local.
	if IsLocalSource(account.AuthSource) || !strings.EqualFold(strings.TrimSpace(account.AuthSource), a.Protocol) {
		return false
	}
	// 3. the account was created BEFORE the migration epoch. A zero epoch means
	//    the epoch is unknown, which fails closed: nothing is ever adopted.
	if markerAt.IsZero() || !account.CreatedAt.Before(markerAt) {
		return false
	}
	// 4. the legacy derivation of THIS door equals the account's own id — the one
	//    place username equality is ever consulted, and only for a row the legacy
	//    code created from that very string.
	legacy := legacyUserID(a.LegacyUsername)
	if legacy == "" || legacy != normID(account.ID) {
		return false
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
	if !realm.Permits(account.TenantID) || identityTenant != normTenant(account.TenantID) {
		return false
	}
	// 6. the account is not disabled. JIT never resurrects a disabled account
	//    (design §4.2.5), and adoption is a stronger write than a refresh.
	return !strings.EqualFold(strings.TrimSpace(account.Status), "disabled")
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
	a.Identity = a.Identity.normalized()
	if err := validateAssertion(a); err != nil {
		return User{}, err
	}
	var (
		out   User
		bound bool
		err   error
	)
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		out, bound, err = s.resolveLocked(a, realm, provision, unbound)
	}()
	if err != nil {
		return User{}, err
	}
	// Reported OUTSIDE the lock: the integrator's audit sink writes to its own
	// store, and holding the user-store lock across a foreign write is how a
	// deadlock gets built.
	if bound && s.deps.OnLegacyBound != nil {
		s.deps.OnLegacyBound(out, a)
	}
	return out, nil
}

// resolveLocked returns (user, boundLegacy, error). Caller holds s.mu.
func (s *FileStore) resolveLocked(a Assertion, realm Realm, provision, unbound bool) (User, bool, error) {
	owner, err := s.lookupTupleLocked(a, unbound)
	if err != nil {
		return User{}, false, err
	}
	if owner == "" && !unbound {
		// §2.5 Amendment: the same canonical (issuer, subject) inside the realm's
		// OWN tenants is the same person, not a second one. Runs before the §2.6
		// legacy check and before provisioning — and before the read-only door's
		// refusal, because finding the person's existing account is exactly what
		// an org-realm elevation sign-in needs and it provisions nothing.
		owner, err = realmScopedOwner(realm, s.tupleCandidatesLocked(a))
		if err != nil {
			return User{}, false, err
		}
	}
	if owner != "" {
		u, ok := s.users[owner]
		if !ok {
			// The index and the collection disagree — refuse rather than provision
			// a second account over the top of a row we cannot see.
			return User{}, false, fmt.Errorf("%w: identity index points at missing account %q", ErrIdentityConflict, owner)
		}
		refreshed, rerr := s.refreshLocked(u, a, realm)
		return refreshed, false, rerr
	}
	if !provision {
		// The read-only door (elevation): a tuple miss is a refusal. It never
		// binds by username again, and it writes nothing.
		return User{}, false, ErrNoSuchUser
	}
	if u, ok, err := s.bindLegacyLocked(a, realm, unbound); err != nil {
		return User{}, false, err
	} else if ok {
		return u, true, nil
	}
	u, err := s.provisionLocked(a, realm)
	return u, false, err
}

// lookupTupleLocked finds the account holding this identity. The bound form is an
// EXACT tuple match; the unbound form matches (issuer, subject) across tenants
// and refuses an ambiguous result rather than picking one.
func (s *FileStore) lookupTupleLocked(a Assertion, unbound bool) (string, error) {
	if !unbound {
		return s.byTuple[a.Identity.key()], nil
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
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.putLocked(before)
		return User{}, err
	}
	return u, nil
}

// bindLegacyLocked is design §2.6. It returns ok=false (not an error) when the
// conditions do not hold, so the caller provisions a fresh account instead —
// which is exactly the "flagged, never guessed" outcome for ambiguous provenance.
func (s *FileStore) bindLegacyLocked(a Assertion, realm Realm, unbound bool) (User, bool, error) {
	cand := legacyUserID(a.LegacyUsername)
	if cand == "" {
		return User{}, false, nil
	}
	u, ok := s.users[cand]
	if !ok {
		return User{}, false, nil
	}
	identityTenant := normTenant(a.TenantID)
	if unbound {
		// No realm and no per-connection tenant: the identity belongs where the
		// account already lives.
		identityTenant = normTenant(u.TenantID)
	}
	if !legacyBindPermitted(u, a, realm, s.markerAt, u.Identity != nil, identityTenant) {
		return User{}, false, nil
	}
	before := u
	now := time.Now().UTC()
	ident := assertedIdentity(a, identityTenant, ProvenanceLegacyLazyBound, now)
	u.Identity = &ident
	u = MergeFederated(u, a.Email, a.DisplayName, s.deps.GuardRole(a.Role, u.TenantID, u.ID, a.Protocol), a.Protocol)
	if err := s.indexLocked(u); err != nil {
		// The tuple is already claimed by someone else: do NOT adopt, and do NOT
		// fall through to provisioning a duplicate of a claimed identity.
		s.putLocked(before)
		return User{}, false, fmt.Errorf("%w: %v", ErrIdentityConflict, err)
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.unindexLocked(u)
		s.putLocked(before)
		return User{}, false, err
	}
	return u, true, nil
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
		return User{}, fmt.Errorf("%w: %v", ErrIdentityConflict, err)
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

// ---- deprecated username-keyed federated upsert ---------------------------

// UpsertFederated provisions or refreshes a user authenticated by an external
// IdP, keyed by USERNAME.
//
// Deprecated: tracker 300 — username is not an identity. Superseded by
// ResolveFederated / ResolveFederatedUnbound, which key on
// (tenant_id, issuer, subject). Kept UNCHANGED in behaviour only so the doors
// keep compiling until the 300-doors change rewrites them, and deleted by that
// change. Nothing new may call it.
func (s *FileStore) UpsertFederated(username, email, displayName, role, source, tenant string) (User, error) {
	return s.UpsertFederatedInRealm(username, email, displayName, role, source, tenant, Realm{})
}

// UpsertFederatedInRealm is UpsertFederated with the flow's login realm applied.
// An EXISTING federated account whose tenant the realm does not reach is refused
// with ErrForeignTenant BEFORE the merge, inside the same lock, so a sign-in
// from another tenant's IdP cannot rewrite the account's role or auth source on
// its way to being refused.
//
// Deprecated: tracker 300 — see UpsertFederated.
func (s *FileStore) UpsertFederatedInRealm(username, email, displayName, role, source, tenant string, realm Realm) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if source == "" {
		source = ProtocolOIDC
	}
	key := legacyUserID(username)
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[key]; ok {
		if IsLocalSource(u.AuthSource) {
			return User{}, ErrLocalAccount
		}
		// The account must live in the realm this flow came in on. Refused here,
		// before MergeFederated, so the record is left exactly as it was.
		if !realm.Permits(u.TenantID) {
			return User{}, ErrForeignTenant
		}
		// Federated account — keep it in sync with the IdP (SR-025: guard the
		// IdP-mapped role against silent platform-owner escalation, using the
		// account's existing tenant).
		u = MergeFederated(u, email, displayName, s.deps.GuardRole(role, u.TenantID, username, source), source)
		s.putLocked(u)
		if err := s.flushLocked(); err != nil {
			return User{}, err
		}
		return u, nil
	}
	if tenant == "" {
		tenant = s.deps.DefaultTenant
	}
	// A new account is provisioned into the realm the flow is bound to. The
	// caller already proved the connection belongs to that realm; this is the
	// same rule applied one layer down, so the two can never disagree.
	if !realm.Permits(tenant) {
		return User{}, ErrForeignTenant
	}
	role = s.deps.GuardRole(role, tenant, username, source)
	u := User{
		ID: key, Username: username, Role: role, Email: email, DisplayName: displayName,
		TenantID: tenant, Status: "active", AuthSource: source, CreatedAt: time.Now().UTC(),
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		delete(s.users, key)
		return User{}, err
	}
	return u, nil
}
