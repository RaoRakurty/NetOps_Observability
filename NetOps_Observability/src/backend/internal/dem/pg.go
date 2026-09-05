package dem

// pg.go — the Postgres catalogue (migration 0043, `dem_targets` with the
// tenant_iso FORCE-RLS policy).
//
// Every statement runs inside WithTenant, so the RLS policy always has its
// `app.tenant_id` GUC and the database enforces isolation even if a query here
// ever forgot its predicate (§3a rule 4 — the app layer is the first line, RLS
// is the backstop, and a backstop only works if it is always armed).
//
// The SQL deliberately carries no `WHERE tenant_id = …` on the scoped reads:
// that is RLS's job, and duplicating it would let a future edit remove the real
// enforcement while the redundant predicate kept the tests green.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (the maintenance/portintel idiom): run fn
// inside a transaction whose row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres-backed catalogue.
type PGStore struct{ db DB }

var _ Catalogue = (*PGStore)(nil)

// NewPGStore wraps the relational seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

// pgTimeout bounds every statement (§9: all IO has a timeout).
const pgTimeout = 10 * time.Second

func (s *PGStore) List(ctx context.Context, tenant string) ([]Target, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []Target{}, nil // default-closed: no scope, no rows
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Target{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM dem_targets ORDER BY site, name, target_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var tgt Target
			if err := json.Unmarshal(raw, &tgt); err != nil {
				return err
			}
			out = append(out, tgt)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sortTargets(out)
	return out, nil
}

// ListAll is the projector's platform read (RLS scope '*'). It is the exact
// mirror of the file store's ListAll and, like it, no HTTP handler may call it.
func (s *PGStore) ListAll(ctx context.Context) ([]Target, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Target{}
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM dem_targets ORDER BY tenant_id, target_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var tgt Target
			if err := json.Unmarshal(raw, &tgt); err != nil {
				return err
			}
			out = append(out, tgt)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sortTargets(out)
	return out, nil
}

func (s *PGStore) Get(ctx context.Context, tenant, id string) (Target, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Target{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Target
	found := false
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM dem_targets WHERE target_id=$1`, id).Scan(&raw)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return nil // RLS already hid another tenant's row: absent == foreign
		}
		if qerr != nil {
			return qerr
		}
		if jerr := json.Unmarshal(raw, &out); jerr != nil {
			return jerr
		}
		found = true
		return nil
	})
	if err != nil {
		return Target{}, err
	}
	if !found {
		return Target{}, ErrNotFound
	}
	return out, nil
}

func (s *PGStore) Create(ctx context.Context, in Target) (Target, error) {
	if err := in.Validate(); err != nil {
		return Target{}, err
	}
	now := time.Now().UTC()
	in.ID = newTargetID()
	in.CreatedAt, in.UpdatedAt = now, now
	in.CreatedBy = clip(in.CreatedBy, 128)
	data, err := json.Marshal(in)
	if err != nil {
		return Target{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = s.db.WithTenant(ctx, in.TenantID, false, func(tx pgx.Tx) error {
		// The per-tenant cap is enforced INSIDE the transaction, so two
		// concurrent creates cannot both see room for the last slot.
		var n int
		if cerr := tx.QueryRow(ctx, `SELECT count(*) FROM dem_targets`).Scan(&n); cerr != nil {
			return cerr
		}
		if n >= MaxTargetsPerTenant {
			return ErrCatalogueFull
		}
		_, ierr := tx.Exec(ctx,
			`INSERT INTO dem_targets (tenant_id, target_id, name, kind, site, app, paused, data, created_by, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			in.TenantID, in.ID, in.Name, in.Kind, in.Site, in.App, in.Paused, data, in.CreatedBy, in.CreatedAt, in.UpdatedAt)
		return ierr
	})
	if err != nil {
		return Target{}, err
	}
	return in, nil
}

func (s *PGStore) Update(ctx context.Context, tenant, id string, patch Patch) (Target, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Target{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Target
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM dem_targets WHERE target_id=$1 FOR UPDATE`, id).Scan(&raw)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if qerr != nil {
			return qerr
		}
		var prev Target
		if jerr := json.Unmarshal(raw, &prev); jerr != nil {
			return jerr
		}
		next := patch.apply(prev)
		next.TenantID, next.ID, next.Kind = prev.TenantID, prev.ID, prev.Kind
		next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
		if verr := next.Validate(); verr != nil {
			return verr
		}
		next.UpdatedAt = time.Now().UTC()
		data, merr := json.Marshal(next)
		if merr != nil {
			return merr
		}
		_, uerr := tx.Exec(ctx,
			`UPDATE dem_targets SET name=$2, site=$3, app=$4, paused=$5, data=$6, updated_at=$7 WHERE target_id=$1`,
			id, next.Name, next.Site, next.App, next.Paused, data, next.UpdatedAt)
		out = next
		return uerr
	})
	if err != nil {
		return Target{}, err
	}
	return out, nil
}

func (s *PGStore) Delete(ctx context.Context, tenant, id string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, derr := tx.Exec(ctx, `DELETE FROM dem_targets WHERE target_id=$1`, id)
		if derr != nil {
			return derr
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}
