// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

// pg_migrate.go — the Postgres half of the deterministic identity migration
// (owner Decision 2, 2026-09-13). Every DECISION is made by the pure planner in
// migrate.go; this file is only the SQL that carries it out, so the two backends
// cannot drift.
//
// TRANSACTION SHAPE, and why it is per-account rather than one big one: a
// collision on one row must not abort the migration of the rest. Each account is
// planned, locked and written in its own transaction, and the candidate set is
// read first — so a row that turns out to be ambiguous is recorded as ambiguous
// and the pass continues, which is exactly the "flag it, never guess, keep going"
// behaviour the decision asks for.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BackfillIdentities — see Repo. Idempotent: a second run re-examines the same
// rows, plans the same decisions, and writes nothing because every write is
// ON CONFLICT DO NOTHING / compare-then-write.
func (s *PGStore) BackfillIdentities(plan BackfillPlan) (BackfillReport, error) {
	plan = plan.normalized()
	now := plan.now()
	ctx, cancel := usersCtx()
	defer cancel()

	ids, err := s.backfillCandidates(ctx)
	if err != nil {
		return BackfillReport{}, err
	}
	var rep BackfillReport
	for _, id := range ids {
		dec, wrote, err := s.backfillOne(ctx, id, plan, now)
		if err != nil {
			return BackfillReport{}, fmt.Errorf("users: identity backfill of %q: %w", id, err)
		}
		rep.Examined++
		rep.countDecision(dec, wrote)
	}
	// Every BOUND account also owes an explicit state. Migration 0051 stamps the
	// estate it finds; this catches anything written between then and now by a
	// path that predates the stamp (and is a no-op on the second run).
	if err := s.stampBoundStates(ctx, now); err != nil {
		return BackfillReport{}, err
	}
	census, err := s.IdentityCensus()
	if err != nil {
		return BackfillReport{}, err
	}
	rep.Census = census
	return rep, nil
}

// backfillCandidates lists the accounts with NO identity row, plus any account
// whose state is `ambiguous` — the latter are re-examined on every boot because
// the collision that made them ambiguous may have been remediated since, and an
// `issuer-unavailable` row must resolve itself once its door is configured.
//
// Ordered by id so two runs make the same decisions in the same order.
func (s *PGStore) backfillCandidates(ctx context.Context) ([]string, error) {
	var out []string
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.id FROM users u
			LEFT JOIN user_identities i ON i.user_id = u.id
			LEFT JOIN user_identity_state st ON st.user_id = u.id
			WHERE i.user_id IS NULL OR st.state = 'ambiguous'
			ORDER BY u.id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// backfillOne plans and applies ONE account inside its own transaction, with the
// row held FOR UPDATE so a concurrent sign-in cannot bind the same account behind
// the pass.
func (s *PGStore) backfillOne(ctx context.Context, id string, plan BackfillPlan, now time.Time) (backfillDecision, bool, error) {
	var (
		dec   backfillDecision
		wrote bool
	)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
		if errors.Is(err, ErrNoSuchUser) {
			// Deleted between the candidate read and now: nothing to migrate.
			dec, wrote = backfillDecision{}, false
			return nil
		}
		if err != nil {
			return err
		}
		dec = planBackfill(u, plan, now)
		wrote = false
		if dec.identity != nil {
			// NEVER MERGE. ON CONFLICT DO NOTHING makes the collision a
			// zero-row-affected insert instead of an aborted transaction, so the row
			// can be recorded as `ambiguous` in the very same transaction.
			landed, err := insertIdentityIfFreeTx(ctx, tx, normID(u.ID), *dec.identity)
			if err != nil {
				return err
			}
			if landed {
				u.Identity = dec.identity
				wrote = true
			} else {
				dec = backfillDecision{state: ambiguousState(ReasonTupleClaimed, now)}
			}
		}
		applyState(&u, dec.state)
		return writeUserTx(ctx, tx, u)
	})
	if err != nil {
		return backfillDecision{}, false, err
	}
	return dec, wrote, nil
}

// insertIdentityIfFreeTx inserts the derived identity unless the tuple (or the
// account) is already claimed. It reports whether the row landed; false is the
// collision, never an error, because "two accounts want one identity" is a fact
// for an operator rather than a failure of the migration.
func insertIdentityIfFreeTx(ctx context.Context, tx pgx.Tx, userID string, i Identity) (bool, error) {
	if err := i.validate(); err != nil {
		return false, err
	}
	if i.FirstSeenAt.IsZero() {
		return false, errors.New("users: derived identity has no first_seen_at")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO user_identities
		(tenant_id, issuer, subject, user_id, protocol, connection_id, subject_kind, provenance,
		 directory_dn, first_seen_at, last_login_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`,
		i.TenantID, i.Issuer, i.Subject, userID, i.Protocol, i.ConnectionID, i.SubjectKind, i.Provenance,
		i.DirectoryDN, i.FirstSeenAt, nullableTime(i.LastLoginAt))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// stampBoundStates gives every account that HOLDS a tuple an explicit `bound`
// state. Insert-only (ON CONFLICT DO NOTHING): it never overwrites a state some
// other path decided, so it cannot erase an `ambiguous` flag.
func (s *PGStore) stampBoundStates(ctx context.Context, now time.Time) error {
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO user_identity_state (user_id, tenant_id, state, reason, since)
			SELECT u.id, u.tenant_id, $1, '', $2
			  FROM users u JOIN user_identities i ON i.user_id = u.id
			ON CONFLICT (user_id) DO NOTHING`, IdentityStateBound, now)
		return err
	})
}

// IdentityCensus — see Repo. One grouped query: the gauges are read on a metrics
// scrape and after every legacy bind, so this must not walk the estate row by row.
func (s *PGStore) IdentityCensus() (MigrationCensus, error) {
	ctx, cancel := usersCtx()
	defer cancel()
	var c MigrationCensus
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT COALESCE(st.state,''), COALESCE(i.provenance,''), count(*)
			  FROM users u
			  LEFT JOIN user_identities i ON i.user_id = u.id
			  LEFT JOIN user_identity_state st ON st.user_id = u.id
			 GROUP BY 1, 2`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var fresh MigrationCensus
		for rows.Next() {
			var state, provenance string
			var n int
			if err := rows.Scan(&state, &provenance, &n); err != nil {
				return err
			}
			// The unstamped case ('' state) falls through to the same classification
			// the file backend uses, because the census reads provenance when the
			// state says nothing.
			fresh.addN(state, provenance, n)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		c = fresh
		return nil
	})
	return c, err
}
