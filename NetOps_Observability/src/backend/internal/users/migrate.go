// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// migrate.go — the DETERMINISTIC identity migration (owner Decision 2,
// 2026-09-13), plus the FileStore half of it. The Postgres half is pg_migrate.go;
// every decision is made by the pure helpers here so the two backends cannot
// drift.
//
// THE DECISION THIS FILE IMPLEMENTS (owner, binding):
//
//	"Use deterministic migration/backfill for identities whose current provenance
//	 can be established. Preferred process: expand schema -> backfill known
//	 identity mappings -> validate -> switch resolver -> enforce uniqueness ->
//	 retire global-username assumptions. Do not leave all existing identities
//	 un-namespaced and rely on future logins to repair them one at a time."
//
// So the lazy bind (§2.6) is NO LONGER the migration; it is the narrow repair
// path for the ONE class whose provenance genuinely cannot be reconstructed
// offline. What can be reconstructed, and why:
//
//	local          issuer 'local', subject lower(username)      — certain: we own it
//	ldap           issuer ldap:host:port, subject lower(login)   — certain once the
//	               door's host:port is known: the login name is what the directory
//	               authenticated and it is what the legacy row was keyed by
//	tacacs         issuer tacacs:host:port, subject lower(login) — same
//	oidc / saml    NOTHING. The broker `sub` is not a function of the username or
//	               the email, and deriving it from either IS the auto-linking the
//	               owner's rule 4 forbids. → unresolved, with a reason.
//
// THREE THINGS THIS FILE MUST NEVER DO, each of them a line in the decision:
// never auto-link by email; never auto-link by username (the subject it derives
// is the login name the DIRECTORY authenticated for that very account, which is
// not a cross-issuer link); and never silently merge two identities — a
// derivation that collides with another account's tuple becomes `ambiguous` and
// waits for a human.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// BackfillPlan is the door configuration the deterministic backfill needs, taken
// from the SAME config the doors sign people in with (the integrator passes
// s.ldap.effective() / the TACACS+ client), so the namespace the backfill writes
// and the namespace the next login looks up cannot disagree.
//
// An EMPTY issuer means "that door is not configured on this boot": its legacy
// rows are left `unresolved` with reason `issuer-unavailable` and picked up by a
// later boot once it is configured. Guessing a host would mint a namespace no
// login ever resolves, which is worse than waiting.
type BackfillPlan struct {
	LDAPIssuer   string
	TACACSIssuer string

	// Now pins the state timestamps (tests); zero = time.Now().UTC().
	Now time.Time
}

func (p BackfillPlan) now() time.Time {
	if p.Now.IsZero() {
		return time.Now().UTC()
	}
	return p.Now.UTC()
}

// normalized canonicalises the two issuer strings exactly as an asserted identity
// is canonicalised, so a config spelt differently from the door's own
// normalisation cannot produce a second namespace.
func (p BackfillPlan) normalized() BackfillPlan {
	p.LDAPIssuer = NormalizeIssuer(p.LDAPIssuer)
	p.TACACSIssuer = NormalizeIssuer(p.TACACSIssuer)
	return p
}

// MigrationCensus is the estate counted by migration state — the four gauge
// values the owner asked for. The sum is the account count, which is what makes
// the gauges checkable at a glance.
type MigrationCensus struct {
	// BoundDeterministic: the account holds a tuple that was established WITHOUT
	// the lazy path — asserted at first sight by a door, or derived offline by this
	// backfill. These are the "deterministically migrated" accounts.
	BoundDeterministic int
	// BoundLegacyLazy: bound by the constrained §2.6 lazy path. On a converged
	// estate this stops growing; a number that keeps climbing means legacy oidc
	// accounts are still arriving.
	BoundLegacyLazy int
	// Unresolved: no tuple, and none could be established offline.
	Unresolved int
	// Ambiguous: the derivation collided. Manual remediation.
	Ambiguous int
}

// Total is the account count the four buckets partition.
func (c MigrationCensus) Total() int {
	return c.BoundDeterministic + c.BoundLegacyLazy + c.Unresolved + c.Ambiguous
}

// add classifies ONE account into the census from its stored state and the
// provenance of its identity (empty = no identity row).
//
// The two inputs disagree only when a write path forgot to stamp, and the rule is
// written down here rather than in two backends: `ambiguous` is authoritative
// (nothing else can produce it), an account with NO provenance cannot be bound
// whatever its stamp says, and provenance is what splits the bound population.
func (c *MigrationCensus) add(state, provenance string) { c.addN(state, provenance, 1) }

// addN is add for a GROUP BY row that already counted n accounts.
func (c *MigrationCensus) addN(state, provenance string, n int) {
	switch {
	case state == IdentityStateAmbiguous:
		c.Ambiguous += n
	case provenance == "":
		c.Unresolved += n
	case provenance == ProvenanceLegacyLazyBound:
		c.BoundLegacyLazy += n
	default:
		c.BoundDeterministic += n
	}
}

// BackfillReport is what one run of the backfill did, plus the estate it left
// behind. Migrated/Unresolved/Ambiguous count THIS RUN's decisions; Census counts
// the whole estate, and on a converged deployment the first three are 0 while the
// census is unchanged — which is what "idempotent" looks like in the boot log.
type BackfillReport struct {
	Examined   int
	Migrated   int
	Unresolved int
	Ambiguous  int
	Census     MigrationCensus
}

// backfillDecision is what the pure planner decided for one account: the identity
// to write (nil = none) and the state to stamp.
type backfillDecision struct {
	identity *Identity
	state    MigrationState
}

func boundState(now time.Time) MigrationState {
	return MigrationState{State: IdentityStateBound, Since: now}
}

func unresolvedState(reason string, now time.Time) MigrationState {
	return MigrationState{State: IdentityStateUnresolved, Reason: reason, Since: now}
}

func ambiguousState(reason string, now time.Time) MigrationState {
	return MigrationState{State: IdentityStateAmbiguous, Reason: reason, Since: now}
}

// planBackfill is THE decision, pure and shared by both backends. It never looks
// at an email, and the only username it reads is the account's OWN login name —
// the string the directory that created the row authenticated it by.
//
// It is called for every account, bound or not: a bound account's state is
// stamped too, because the states are stored rather than inferred.
func planBackfill(u User, plan BackfillPlan, now time.Time) backfillDecision {
	if u.Identity != nil {
		// Already namespaced. Nothing to derive; record the state explicitly.
		return backfillDecision{state: boundState(now)}
	}
	login := strings.ToLower(strings.TrimSpace(u.Username))
	if login == "" {
		// A row with no login name has nothing derivable at all, whatever its
		// source. (normID(u.ID) is NOT used as a fallback: for a federated row the
		// id is opaque and would mint a subject no directory ever asserts.)
		return backfillDecision{state: unresolvedState(ReasonUnknownAuthSource, now)}
	}
	// The source is folded: a legacy blob written by hand (or by a release that did
	// not normalise) can carry "LDAP", and reading that as an unknown source would
	// strand a migratable account in `unresolved`.
	source := strings.ToLower(strings.TrimSpace(u.AuthSource))
	switch {
	case IsLocalSource(source):
		// Certain: we are the issuer. Same row migration 0050 and the file-store
		// load already write — repeated here so a row that escaped either (an
		// account created by an older release, a restored blob) still converges.
		id := localIdentity(u.TenantID, u.Username, ProvenanceBackfilledLocal, now)
		return backfillDecision{identity: &id, state: boundState(now)}
	case source == ProtocolLDAP:
		if plan.LDAPIssuer == "" {
			return backfillDecision{state: unresolvedState(ReasonIssuerUnavailable, now)}
		}
		id := directoryIdentity(u.TenantID, plan.LDAPIssuer, login, ProtocolLDAP, ProvenanceBackfilledLDAP, now)
		return backfillDecision{identity: &id, state: boundState(now)}
	case source == ProtocolTACACS:
		if plan.TACACSIssuer == "" {
			return backfillDecision{state: unresolvedState(ReasonIssuerUnavailable, now)}
		}
		id := directoryIdentity(u.TenantID, plan.TACACSIssuer, login, ProtocolTACACS, ProvenanceBackfilledTACACS, now)
		return backfillDecision{identity: &id, state: boundState(now)}
	case source == ProtocolOIDC, source == ProtocolSAML:
		// The one class that genuinely cannot be reconstructed offline: the
		// broker's `sub` is not a function of anything on this row. It waits for
		// the constrained lazy bind (resolve.go) or for an operator.
		return backfillDecision{state: unresolvedState(ReasonUnreconstructable, now)}
	default:
		return backfillDecision{state: unresolvedState(ReasonUnknownAuthSource, now)}
	}
}

// directoryIdentity is the deterministically derived identity of a legacy
// LDAP/TACACS+ account: the configured server's namespace, and the LOGIN NAME the
// directory authenticated as the subject (`subject_kind = login`).
//
// The login name — not the DN — is the subject for BOTH doors (design §2.3 as
// amended by owner Decision 2). It is what the directory authenticated, it is
// stable across an OU move, and it is the one thing about a legacy row that can
// be established offline with certainty.
func directoryIdentity(tenant, issuer, login, protocol, provenance string, now time.Time) Identity {
	return Identity{
		TenantID:    normTenant(tenant),
		Issuer:      issuer,
		Subject:     login,
		Protocol:    protocol,
		SubjectKind: SubjectKindLogin,
		Provenance:  provenance,
		FirstSeenAt: now,
	}
}

// applyState is the compare-then-write stamp. It returns false when the state and
// reason are unchanged, which is what keeps a re-run from rewriting the estate
// (and from moving `since`, which would make "unresolved for three weeks"
// unanswerable).
func applyState(u *User, next MigrationState) bool {
	if cur := u.IdentityMigration; cur != nil && cur.State == next.State && cur.Reason == next.Reason {
		return false
	}
	stamped := next
	u.IdentityMigration = &stamped
	return true
}

// countDecision folds one decision into the run report.
func (r *BackfillReport) countDecision(d backfillDecision, wrote bool) {
	switch {
	case wrote:
		r.Migrated++
	case d.state.State == IdentityStateAmbiguous:
		r.Ambiguous++
	case d.state.State == IdentityStateUnresolved:
		r.Unresolved++
	}
}

// ---- FileStore ------------------------------------------------------------

// BackfillIdentities — see Repo. One pass under the store lock, ordered by id so
// two runs make the same decisions in the same order, and ONE flush at the end
// (a partial flush per account would leave the blob half-migrated if the disk
// filled).
func (s *FileStore) BackfillIdentities(plan BackfillPlan) (BackfillReport, error) {
	plan = plan.normalized()
	now := plan.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.users))
	for id := range s.users {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var rep BackfillReport
	changed := false
	for _, id := range ids {
		u := s.users[id]
		rep.Examined++
		dec := planBackfill(u, plan, now)
		wrote := false
		if dec.identity != nil {
			// NEVER MERGE. If the derived tuple is already another account's, the
			// two rows cannot both be that principal and which of them is, is not
			// ours to guess: the row becomes `ambiguous` and waits for a human.
			if other, dup := s.byTuple[dec.identity.key()]; dup && other != id {
				dec = backfillDecision{state: ambiguousState(ReasonTupleClaimed, now)}
			} else {
				u.Identity = dec.identity
				if err := s.indexLocked(u); err != nil {
					// The index refused what the tuple check allowed: treat it as the
					// collision it is rather than proceeding on a half-indexed row, and
					// drop anything the failed write left behind for THIS account.
					s.unindexLocked(u)
					u.Identity = nil
					dec = backfillDecision{state: ambiguousState(ReasonTupleClaimed, now)}
				} else {
					wrote = true
				}
			}
		}
		if applyState(&u, dec.state) || wrote {
			changed = true
		}
		s.putLocked(u)
		rep.countDecision(dec, wrote)
	}
	if changed {
		if err := s.flushLocked(); err != nil {
			return BackfillReport{}, fmt.Errorf("users: identity backfill could not persist: %w", err)
		}
	}
	rep.Census = s.censusLocked()
	return rep, nil
}

// IdentityCensus — see Repo.
func (s *FileStore) IdentityCensus() (MigrationCensus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.censusLocked(), nil
}

func (s *FileStore) censusLocked() MigrationCensus {
	var c MigrationCensus
	for _, u := range s.users {
		prov := ""
		if u.Identity != nil {
			prov = u.Identity.Provenance
		}
		c.add(u.IdentityState(), prov)
	}
	return c
}
