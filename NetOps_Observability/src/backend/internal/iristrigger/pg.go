// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iristrigger

// pg.go — the Postgres store over migration 0075. Every tenant statement runs
// inside WithTenant(tenant, cross=false) under the FORCE-RLS tenant_iso policy
// and also filters tenant_id explicitly. Admit counts the day's admitted runs
// under a transaction-scoped advisory lock on the tenant, so two concurrent
// admissions cannot both pass the cap; the UNIQUE (tenant, trigger, dedupe key)
// makes a second run for the same incident or slot impossible even across
// replicas. DueSchedules is the only cross-tenant read (platform scope '*').

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct{ db DB }

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

const pgTimeout = 10 * time.Second

const trigCols = `id, tenant_id, name, kind, enabled, min_severity, signature, site, device_role, every_minutes,
    question, created_by, created_at, updated_at, last_run_at`

const runCols = `id, trigger_id, trigger_name, incident_id, dedupe_key, status, reason, investigation_id, tokens,
    summary, started_at, finished_at`

func scanTrigger(row pgx.Row) (Trigger, error) {
	var (
		t       Trigger
		kind    string
		lastRun *time.Time
	)
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &kind, &t.Enabled, &t.Filter.MinSeverity, &t.Filter.Signature,
		&t.Filter.Site, &t.Filter.Role, &t.Schedule.EveryMinutes, &t.Question, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt, &lastRun); err != nil {
		return Trigger{}, err
	}
	t.Kind = Kind(kind)
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	if lastRun != nil {
		at := lastRun.UTC()
		t.LastRunAt = &at
	}
	return t, nil
}

func scanRun(row pgx.Row, tenant string) (Run, error) {
	var (
		r        Run
		finished *time.Time
	)
	if err := row.Scan(&r.ID, &r.TriggerID, &r.TriggerName, &r.IncidentID, &r.DedupeKey, &r.Status, &r.Reason,
		&r.InvestigationID, &r.Tokens, &r.Summary, &r.StartedAt, &finished); err != nil {
		return Run{}, err
	}
	r.TenantID, r.StartedAt = tenant, r.StartedAt.UTC()
	if finished != nil {
		f := finished.UTC()
		r.FinishedAt = &f
	}
	return r, nil
}

func (s *PGStore) tx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, false, fn)
}

func (s *PGStore) Settings(ctx context.Context, tenant string) (Settings, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Settings{}, err
	}
	out := DefaultSettings()
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT enabled, max_runs_per_day, max_tokens_per_day
            FROM iris_investigation_trigger_settings WHERE tenant_id = $1`, t).
			Scan(&out.Enabled, &out.MaxRunsPerDay, &out.MaxTokensPerDay)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // no row: the defaults (switch off)
		}
		return err
	})
	return out, err
}

func (s *PGStore) PutSettings(ctx context.Context, tenant string, set Settings) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	if err := ValidateSettings(&set); err != nil {
		return err
	}
	return s.tx(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iris_investigation_trigger_settings
            (tenant_id, enabled, max_runs_per_day, max_tokens_per_day, updated_at) VALUES ($1,$2,$3,$4,now())
            ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled,
                max_runs_per_day = EXCLUDED.max_runs_per_day, max_tokens_per_day = EXCLUDED.max_tokens_per_day,
                updated_at = now()`, t, set.Enabled, set.MaxRunsPerDay, set.MaxTokensPerDay)
		return err
	})
}

func (s *PGStore) List(ctx context.Context, tenant string) ([]Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return nil, err
	}
	var out []Trigger
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+trigCols+` FROM iris_investigation_triggers
            WHERE tenant_id = $1 ORDER BY created_at, id`, t)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			tr, err := scanTrigger(rows)
			if err != nil {
				return err
			}
			out = append(out, tr)
		}
		return rows.Err()
	})
	if out == nil {
		out = []Trigger{}
	}
	return out, err
}

func (s *PGStore) Get(ctx context.Context, tenant, id string) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	if !ValidID(id) {
		return Trigger{}, ErrNotFound
	}
	var out Trigger
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		tr, err := scanTrigger(tx.QueryRow(ctx, `SELECT `+trigCols+` FROM iris_investigation_triggers
            WHERE tenant_id = $1 AND id = $2`, t, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		out = tr
		return err
	})
	return out, err
}

func (s *PGStore) Create(ctx context.Context, tenant, author string, tr Trigger, now time.Time) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	if err := Validate(&tr); err != nil {
		return Trigger{}, err
	}
	id, err := NewID()
	if err != nil {
		return Trigger{}, err
	}
	var out Trigger
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('iristrigger:' || $1))`, t); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigation_triggers WHERE tenant_id = $1`, t).Scan(&n); err != nil {
			return err
		}
		if n >= MaxTriggersPerTenant {
			return ErrTooMany
		}
		row := tx.QueryRow(ctx, `INSERT INTO iris_investigation_triggers
            (tenant_id, id, name, kind, enabled, min_severity, signature, site, device_role, every_minutes,
             question, created_by, created_at, updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
            RETURNING `+trigCols, t, id, tr.Name, string(tr.Kind), tr.Enabled, tr.Filter.MinSeverity, tr.Filter.Signature,
			tr.Filter.Site, tr.Filter.Role, tr.Schedule.EveryMinutes, tr.Question, author, now.UTC())
		created, err := scanTrigger(row)
		out = created
		return err
	})
	return out, err
}

func (s *PGStore) SetEnabled(ctx context.Context, tenant, id string, on bool, now time.Time) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	if !ValidID(id) {
		return Trigger{}, ErrNotFound
	}
	var out Trigger
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		tr, err := scanTrigger(tx.QueryRow(ctx, `UPDATE iris_investigation_triggers SET enabled = $3, updated_at = $4
            WHERE tenant_id = $1 AND id = $2 RETURNING `+trigCols, t, id, on, now.UTC()))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		out = tr
		return err
	})
	return out, err
}

func (s *PGStore) Delete(ctx context.Context, tenant, id string) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	if !ValidID(id) {
		return ErrNotFound
	}
	return s.tx(ctx, t, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM iris_investigation_triggers WHERE tenant_id = $1 AND id = $2`, t, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// insertRun writes one run row inside tx. A dedupe collision is ErrDuplicate.
func insertRun(ctx context.Context, tx pgx.Tx, t string, run Run, now time.Time) (Run, error) {
	id, err := NewID()
	if err != nil {
		return Run{}, err
	}
	var finished *time.Time
	if run.Status == RunSkipped {
		f := now.UTC()
		finished = &f
	}
	// A savepoint, so a dedupe collision leaves the surrounding transaction
	// usable (the caller decides what to do with ErrDuplicate).
	if _, err := tx.Exec(ctx, `SAVEPOINT iris_trigger_run`); err != nil {
		return Run{}, err
	}
	out, err := scanRun(tx.QueryRow(ctx, `INSERT INTO iris_investigation_trigger_runs
        (tenant_id, id, trigger_id, trigger_name, incident_id, dedupe_key, status, reason, summary, started_at, finished_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+runCols,
		t, id, run.TriggerID, run.TriggerName, run.IncidentID, run.DedupeKey, run.Status, run.Reason,
		clampSummary(run.Summary), now.UTC(), finished), t)
	if err != nil {
		if _, rerr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT iris_trigger_run`); rerr != nil {
			return Run{}, fmt.Errorf("%w (rollback: %w)", err, rerr)
		}
		if isUniqueViolation(err) {
			return Run{}, ErrDuplicate
		}
		return Run{}, err
	}
	return out, nil
}

func (s *PGStore) Admit(ctx context.Context, tenant string, run Run, maxRunsPerDay int, now time.Time) (Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Run{}, err
	}
	if !ValidID(run.TriggerID) {
		return Run{}, fmt.Errorf("%w: trigger id", ErrInvalid)
	}
	var out Run
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('iristrigger-run:' || $1))`, t); err != nil {
			return err
		}
		var admitted int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_investigation_trigger_runs
            WHERE tenant_id = $1 AND status IN ('running','done','failed') AND started_at >= $2`,
			t, Day(now)).Scan(&admitted); err != nil {
			return err
		}
		if admitted >= maxRunsPerDay {
			run.Status, run.Reason = RunSkipped, SkipRunCap
		} else {
			run.Status, run.Reason = RunRunning, ""
		}
		r, err := insertRun(ctx, tx, t, run, now)
		if err != nil {
			return err
		}
		if r.Status == RunRunning {
			if _, err := tx.Exec(ctx, `UPDATE iris_investigation_triggers SET last_run_at = $3
                WHERE tenant_id = $1 AND id = $2`, t, run.TriggerID, now.UTC()); err != nil {
				return err
			}
		}
		out = r
		return nil
	})
	return out, err
}

func (s *PGStore) Skip(ctx context.Context, tenant string, run Run, now time.Time) (Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Run{}, err
	}
	if !ValidID(run.TriggerID) {
		return Run{}, fmt.Errorf("%w: trigger id", ErrInvalid)
	}
	run.Status = RunSkipped
	var out Run
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		r, err := insertRun(ctx, tx, t, run, now)
		out = r
		return err
	})
	return out, err
}

func (s *PGStore) Finish(ctx context.Context, tenant, id, status, reason, invID string, tokens int, summary string, now time.Time) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	if !ValidID(id) {
		return ErrNotFound
	}
	return s.tx(ctx, t, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE iris_investigation_trigger_runs
            SET status = $3, reason = $4, investigation_id = $5, tokens = $6, summary = $7, finished_at = $8
            WHERE tenant_id = $1 AND id = $2`, t, id, status, reason, invID, max(tokens, 0), clampSummary(summary), now.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *PGStore) TokensToday(ctx context.Context, tenant string, day time.Time) (int, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return 0, err
	}
	var n int
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(sum(tokens), 0) FROM iris_investigation_trigger_runs
            WHERE tenant_id = $1 AND started_at >= $2 AND started_at < $3`,
			t, Day(day), Day(day).Add(24*time.Hour)).Scan(&n)
	})
	return n, err
}

func (s *PGStore) Runs(ctx context.Context, tenant string, limit int) ([]Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return nil, err
	}
	out := []Run{}
	err = s.tx(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+runCols+` FROM iris_investigation_trigger_runs
            WHERE tenant_id = $1 ORDER BY started_at DESC, id LIMIT $2`, t, clampLimit(limit))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRun(rows, t)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PGStore) DueSchedules(ctx context.Context, now time.Time) ([]Trigger, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Trigger
	// The scheduler's one cross-tenant read: which schedule triggers exist in
	// workspaces whose switch is on. Every run it starts is written under the
	// trigger's own tenant.
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+prefixed("t", trigCols)+`
            FROM iris_investigation_triggers t
            JOIN iris_investigation_trigger_settings st ON st.tenant_id = t.tenant_id AND st.enabled
            WHERE t.kind = 'schedule' AND t.enabled
            ORDER BY t.id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			tr, err := scanTrigger(rows)
			if err != nil {
				return err
			}
			if tr.Due(now) {
				out = append(out, tr)
			}
		}
		return rows.Err()
	})
	return out, err
}

// prefixed qualifies a comma-separated column list with a table alias.
func prefixed(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = alias + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}
