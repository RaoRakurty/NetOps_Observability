// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// pg.go — the Postgres backend (migration 0046, `metering_daily` with the
// tenant_iso FORCE-RLS policy).
//
// Every statement runs inside WithTenant, so the row policy always has its
// `app.tenant_id` GUC and the database enforces isolation even if a query here
// ever forgot its predicate (§3a rule 4 — the app layer is the first line, RLS
// is the backstop, and a backstop only works if it is always armed).
//
// The scoped read deliberately carries no `WHERE tenant_id = …`: that is RLS's
// job, and duplicating it would let a future edit remove the real enforcement
// while the redundant predicate kept the tests green.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (the dem/maintenance idiom): run fn inside
// a transaction whose row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres-backed metering store.
type PGStore struct{ db DB }

var _ Store = (*PGStore)(nil)

// NewPGStore wraps the relational seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

// pgTimeout bounds every statement (§9: all IO has a timeout).
const pgTimeout = 15 * time.Second

// Record folds one snapshot into the day's rows.
//
// Each tenant's row is read, folded and written inside ONE transaction scoped
// to that tenant, so a concurrent snapshot cannot interleave a read and a write
// of the same row — `FOR UPDATE` on the read is what serialises them.
//
// The write runs under the tenant's own RLS scope, EXCEPT for the installation
// row, whose tenant key is the empty string and which therefore needs the
// platform scope. The two are separated explicitly rather than by running everything cross-scoped:
// a write path that is always '*' is a write path that cannot demonstrate it
// respects the policy.
func (s *PGStore) Record(ctx context.Context, at time.Time, byTenant map[string][]Reading) error {
	at = at.UTC()
	day := at.Format(DayFormat)
	for tenant, readings := range byTenant {
		t := NormaliseTenant(tenant)
		cross := t == ScopeInstallation
		if err := s.recordOne(ctx, t, cross, day, at, readings); err != nil {
			return err
		}
	}
	return nil
}

func (s *PGStore) recordOne(ctx context.Context, tenant string, cross bool, day string, at time.Time, readings []Reading) error {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := DailyRecord{Day: day, TenantID: tenant}
		var raw []byte
		err := tx.QueryRow(ctx,
			`SELECT data FROM metering_daily WHERE tenant_id=$1 AND day=$2 FOR UPDATE`,
			tenant, day).Scan(&raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// First sample of the day. Nothing to merge.
		case err != nil:
			return err
		default:
			if uerr := json.Unmarshal(raw, &row); uerr != nil {
				return uerr
			}
			row.Day, row.TenantID = day, tenant
		}
		next, ferr := Fold(row, readings, at)
		if ferr != nil {
			return ferr
		}
		body, merr := json.Marshal(next)
		if merr != nil {
			return merr
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO metering_daily (tenant_id, day, samples, updated_at, data)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, day) DO UPDATE
			  SET samples = EXCLUDED.samples, updated_at = EXCLUDED.updated_at, data = EXCLUDED.data`,
			tenant, day, next.Samples, next.UpdatedAt, body); err != nil {
			return err
		}
		// Seal the tenant's older open days in the same transaction, so the
		// identity sets a closed day no longer needs do not outlive it.
		_, err = tx.Exec(ctx, `
			UPDATE metering_daily SET data = data - 'open'
			WHERE tenant_id = $1 AND day < $2 AND data ? 'open'`, tenant, day)
		return err
	})
}

// List returns the rows the caller may see.
func (s *PGStore) List(ctx context.Context, tenant string, cross bool, from, to string) ([]DailyRecord, error) {
	if err := checkRange(from, to); err != nil {
		return nil, err
	}
	out := []DailyRecord{}
	if !cross && NormaliseTenant(tenant) == ScopeInstallation {
		// Default-closed: no scope, no rows — and never the installation row,
		// whose key is also "".
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err := s.db.WithTenant(ctx, NormaliseTenant(tenant), cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT data FROM metering_daily WHERE day >= $1 AND day <= $2 ORDER BY day, tenant_id`, from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var rec DailyRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			out = append(out, rec.Seal())
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sortRecords(out)
	return out, nil
}

// Rows counts every persisted row. Platform scope: it is a metric about the
// installation, never shown to a tenant.
func (s *PGStore) Rows(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	n := 0
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM metering_daily`).Scan(&n)
	})
	return n, err
}

// Prune drops rows older than `before`.
func (s *PGStore) Prune(ctx context.Context, before string) (int, error) {
	if !ValidDay(before) {
		return 0, fmt.Errorf("metering: %q is not a UTC day", before)
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	n := 0
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM metering_daily WHERE day < $1`, before)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}
