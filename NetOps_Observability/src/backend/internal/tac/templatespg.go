// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// templatespg.go — the Postgres template store (migration 0044, `tac_templates`
// with the tenant_iso FORCE-RLS policy).
//
// Every statement runs inside WithTenant, so the RLS policy always has its
// `app.tenant_id` GUC and the database enforces isolation even if a query here
// ever forgot its predicate (§3a rule 4 — the app layer is the first line, RLS
// is the backstop, and a backstop only works if it is always armed).
//
// The SQL deliberately carries no `WHERE tenant_id = …` on the scoped reads:
// that is RLS's job, and duplicating it would let a future edit remove the real
// enforcement while the redundant predicate kept the tests green.
//
// There is NO platform-scoped read here at all. dem has one for its projector;
// this store has no fleet-wide consumer, so it ships no method that could
// enumerate every tenant's templates — the narrowest surface that serves the
// feature (§3a rule 4's "no unscoped list all").

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// TemplateDB is the injected relational seam (the dem/maintenance idiom): run fn
// inside a transaction whose row-level security is scoped to tenant.
type TemplateDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGTemplateStore is the Postgres-backed template store.
type PGTemplateStore struct{ db TemplateDB }

var _ TemplateStore = (*PGTemplateStore)(nil)

// NewPGTemplateStore wraps the relational seam.
func NewPGTemplateStore(db TemplateDB) *PGTemplateStore { return &PGTemplateStore{db: db} }

// templatePGTimeout bounds every statement (§9: all IO has a timeout).
const templatePGTimeout = 10 * time.Second

func (s *PGTemplateStore) List(ctx context.Context, tenant string) ([]Template, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return []Template{}, nil // default-closed: no scope, no rows
	}
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	out := []Template{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `SELECT data FROM tac_templates ORDER BY dialect, name, template_id`)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if serr := rows.Scan(&raw); serr != nil {
				return serr
			}
			var tpl Template
			if jerr := json.Unmarshal(raw, &tpl); jerr != nil {
				return jerr
			}
			tpl.TenantID = t
			tpl.Source = SourceTenant
			out = append(out, tpl)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	SortTemplates(out)
	return out, nil
}

func (s *PGTemplateStore) Get(ctx context.Context, tenant, id string) (Template, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Template{}, ErrTemplateNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	var out Template
	found := false
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM tac_templates WHERE template_id=$1`, id).Scan(&raw)
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
		return Template{}, err
	}
	if !found {
		return Template{}, ErrTemplateNotFound
	}
	out.TenantID = t
	out.Source = SourceTenant
	return out, nil
}

func (s *PGTemplateStore) Create(ctx context.Context, in Template) (Template, error) {
	t, err := concreteTenantID(in.TenantID)
	if err != nil {
		return Template{}, err
	}
	in.TenantID = t
	in.Source = SourceTenant // stamped, never accepted
	in.ID = newTemplateID()
	if in.ID == "" {
		return Template{}, errors.New("tac: could not mint a template id")
	}
	now := time.Now().UTC()
	in.CreatedAt, in.UpdatedAt, in.Version = now, now, 1
	in.CreatedBy = clip(in.CreatedBy, 128)
	data, merr := json.Marshal(in)
	if merr != nil {
		return Template{}, merr
	}
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		// The per-tenant cap is enforced INSIDE the transaction, so two
		// concurrent creates cannot both see room for the last slot.
		var n int
		if cerr := tx.QueryRow(ctx, `SELECT count(*) FROM tac_templates`).Scan(&n); cerr != nil {
			return cerr
		}
		if n >= MaxTemplatesPerTenant {
			return ErrTemplatesFull
		}
		_, ierr := tx.Exec(ctx,
			`INSERT INTO tac_templates (tenant_id, template_id, dialect, name, based_on, version, data, created_by, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			in.TenantID, in.ID, in.Dialect, in.Name, in.BasedOn, in.Version, data, in.CreatedBy, in.CreatedAt, in.UpdatedAt)
		return ierr
	})
	if err != nil {
		return Template{}, err
	}
	return in, nil
}

func (s *PGTemplateStore) Update(ctx context.Context, tenant, id string, next Template) (Template, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Template{}, ErrTemplateNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	var out Template
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM tac_templates WHERE template_id=$1 FOR UPDATE`, id).Scan(&raw)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return ErrTemplateNotFound
		}
		if qerr != nil {
			return qerr
		}
		var prev Template
		if jerr := json.Unmarshal(raw, &prev); jerr != nil {
			return jerr
		}
		prev.TenantID, prev.ID, prev.Source = t, id, SourceTenant
		merged := mergeTemplate(prev, next, time.Now().UTC())
		data, merr := json.Marshal(merged)
		if merr != nil {
			return merr
		}
		_, uerr := tx.Exec(ctx,
			`UPDATE tac_templates SET dialect=$2, name=$3, based_on=$4, version=$5, data=$6, updated_at=$7 WHERE template_id=$1`,
			id, merged.Dialect, merged.Name, merged.BasedOn, merged.Version, data, merged.UpdatedAt)
		out = merged
		return uerr
	})
	if err != nil {
		return Template{}, err
	}
	return out, nil
}

func (s *PGTemplateStore) Delete(ctx context.Context, tenant, id string) error {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return ErrTemplateNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, templatePGTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, derr := tx.Exec(ctx, `DELETE FROM tac_templates WHERE template_id=$1`, id)
		if derr != nil {
			return derr
		}
		if tag.RowsAffected() == 0 {
			return ErrTemplateNotFound
		}
		return nil
	})
}
