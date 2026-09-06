// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// pg.go — the Postgres backend for the two persisted objects (journeys and
// change events), against the `dem_journeys` / `dem_change_events` tables with
// their tenant_iso FORCE-RLS policies.
//
// Every statement runs inside WithTenant, so the policy always has its
// `app.tenant_id` GUC and the database enforces isolation even if a query here
// ever forgot its predicate. The scoped reads deliberately carry NO
// `WHERE tenant_id = …`: that is RLS's job, and duplicating it would let a
// future edit remove the real enforcement while a redundant predicate kept the
// tests green (internal/dem/pg.go's reasoning, applied unchanged).

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres-backed store.
type PGStore struct{ db DB }

var _ Store = (*PGStore)(nil)

// NewPGStore wraps the relational seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

// pgTimeout bounds every statement (§9: all IO has a timeout).
const pgTimeout = 10 * time.Second

func (s *PGStore) ListJourneys(ctx context.Context, tenant string) ([]JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []JourneyDefinition{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []JourneyDefinition{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `SELECT data FROM dem_journeys ORDER BY name, journey_id`)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if serr := rows.Scan(&raw); serr != nil {
				return serr
			}
			var j JourneyDefinition
			if jerr := json.Unmarshal(raw, &j); jerr != nil {
				return jerr
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sortJourneys(out)
	return out, nil
}

func (s *PGStore) GetJourney(ctx context.Context, tenant, id string) (JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return JourneyDefinition{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out JourneyDefinition
	found := false
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM dem_journeys WHERE journey_id=$1`, id).Scan(&raw)
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
		return JourneyDefinition{}, err
	}
	if !found {
		return JourneyDefinition{}, ErrNotFound
	}
	return out, nil
}

func (s *PGStore) CreateJourney(ctx context.Context, in JourneyDefinition) (JourneyDefinition, error) {
	if err := in.Validate(); err != nil {
		return JourneyDefinition{}, err
	}
	now := time.Now().UTC()
	in.ID, in.Version = newJourneyID(), 1
	in.CreatedAt, in.UpdatedAt = now, now
	data, err := json.Marshal(in)
	if err != nil {
		return JourneyDefinition{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = s.db.WithTenant(ctx, in.TenantID, false, func(tx pgx.Tx) error {
		// The per-tenant cap is enforced INSIDE the transaction, so two
		// concurrent creates cannot both see room for the last slot.
		var n int
		if cerr := tx.QueryRow(ctx, `SELECT count(*) FROM dem_journeys`).Scan(&n); cerr != nil {
			return cerr
		}
		if n >= MaxJourneysPerTenant {
			return ErrFull
		}
		_, ierr := tx.Exec(ctx,
			`INSERT INTO dem_journeys (tenant_id, journey_id, name, app, importance, version, data, created_by, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			in.TenantID, in.ID, in.Name, in.App, in.BusinessImportance, in.Version, data,
			in.CreatedBy, in.CreatedAt, in.UpdatedAt)
		return ierr
	})
	if err != nil {
		return JourneyDefinition{}, err
	}
	return in, nil
}

func (s *PGStore) UpdateJourney(ctx context.Context, tenant, id string, in JourneyDefinition) (JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return JourneyDefinition{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out JourneyDefinition
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM dem_journeys WHERE journey_id=$1 FOR UPDATE`, id).Scan(&raw)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if qerr != nil {
			return qerr
		}
		var prev JourneyDefinition
		if jerr := json.Unmarshal(raw, &prev); jerr != nil {
			return jerr
		}
		next := in
		next.TenantID, next.ID = prev.TenantID, prev.ID
		next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
		next.Version = prev.Version + 1
		if verr := next.Validate(); verr != nil {
			return verr
		}
		next.UpdatedAt = time.Now().UTC()
		data, merr := json.Marshal(next)
		if merr != nil {
			return merr
		}
		_, uerr := tx.Exec(ctx,
			`UPDATE dem_journeys SET name=$2, app=$3, importance=$4, version=$5, data=$6, updated_at=$7 WHERE journey_id=$1`,
			id, next.Name, next.App, next.BusinessImportance, next.Version, data, next.UpdatedAt)
		out = next
		return uerr
	})
	if err != nil {
		return JourneyDefinition{}, err
	}
	return out, nil
}

func (s *PGStore) DeleteJourney(ctx context.Context, tenant, id string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, derr := tx.Exec(ctx, `DELETE FROM dem_journeys WHERE journey_id=$1`, id)
		if derr != nil {
			return derr
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *PGStore) ListChanges(ctx context.Context, tenant string, q ChangeQuery) ([]ChangeEvent, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []ChangeEvent{}, nil
	}
	limit := q.Limit
	if limit <= 0 || limit > changeRetention {
		limit = changeRetention
	}
	since := q.Since
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []ChangeEvent{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		// The predicate is pushed into SQL rather than applied in Go: the whole
		// point of a bounded query is that the rows never leave the database.
		rows, qerr := tx.Query(ctx,
			`SELECT data FROM dem_change_events WHERE event_at >= $1 ORDER BY event_at DESC LIMIT $2`,
			since, limit)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if serr := rows.Scan(&raw); serr != nil {
				return serr
			}
			var c ChangeEvent
			if jerr := json.Unmarshal(raw, &c); jerr != nil {
				return jerr
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	// The remaining filters (type/app/site) are applied in Go so both backends
	// answer identically from ONE implementation of the predicate.
	return filterChanges(out, q), nil
}

func (s *PGStore) RecordChange(ctx context.Context, in ChangeEvent) (ChangeEvent, error) {
	if in.ID == "" {
		in.ID = newChangeID()
	}
	if err := in.Validate(); err != nil {
		return ChangeEvent{}, err
	}
	data, err := json.Marshal(in)
	if err != nil {
		return ChangeEvent{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = s.db.WithTenant(ctx, in.TenantID, false, func(tx pgx.Tx) error {
		// ON CONFLICT DO NOTHING: a change is an IMMUTABLE fact, so a repeated
		// id is idempotent and never rewrites what was recorded.
		_, ierr := tx.Exec(ctx,
			`INSERT INTO dem_change_events (tenant_id, change_id, change_type, app, site, event_at, data)
			 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id, change_id) DO NOTHING`,
			in.TenantID, in.ID, in.Type, in.App, in.Site, in.EventAt, data)
		return ierr
	})
	if err != nil {
		return ChangeEvent{}, err
	}
	return in, nil
}

// ── promotions (tracker 255) ────────────────────────────────────────────────
//
// Against `dem_incident_promotions` (migration 0047, tenant_iso FORCE RLS).
// Same discipline as the two tables above: every statement runs inside
// WithTenant so the policy always has its GUC, and the scoped reads carry no
// redundant `WHERE tenant_id = …` — that is RLS's job, and duplicating it would
// let a future edit remove the real enforcement while the tests stayed green.

func (s *PGStore) ListPromotions(ctx context.Context, tenant string) ([]Promotion, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []Promotion{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Promotion{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx,
			`SELECT data FROM dem_incident_promotions ORDER BY promoted_at DESC, experience_id
			 LIMIT $1`, MaxPromotionsPerTenant)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if serr := rows.Scan(&raw); serr != nil {
				return serr
			}
			var p Promotion
			if jerr := json.Unmarshal(raw, &p); jerr != nil {
				return jerr
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sortPromotions(out)
	return out, nil
}

func (s *PGStore) GetPromotion(ctx context.Context, tenant, experienceID string) (Promotion, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Promotion{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Promotion
	found := false
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		qerr := tx.QueryRow(ctx, `SELECT data FROM dem_incident_promotions WHERE experience_id=$1`, experienceID).Scan(&raw)
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
		return Promotion{}, err
	}
	if !found {
		return Promotion{}, ErrNotFound
	}
	return out, nil
}

func (s *PGStore) SavePromotion(ctx context.Context, in Promotion) (Promotion, error) {
	if err := in.Validate(); err != nil {
		return Promotion{}, err
	}
	data, err := json.Marshal(in)
	if err != nil {
		return Promotion{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Promotion
	err = s.db.WithTenant(ctx, in.TenantID, false, func(tx pgx.Tx) error {
		// ON CONFLICT DO NOTHING, then read back: the FIRST promotion is the one
		// that happened, and the frozen packet must never be rewritten by a
		// later derivation — that packet is the record of what the operator
		// actually acted on.
		if _, ierr := tx.Exec(ctx,
			`INSERT INTO dem_incident_promotions
			   (tenant_id, experience_id, incident_id, severity, promoted_at, promoted_by, data)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (tenant_id, experience_id) DO NOTHING`,
			in.TenantID, in.ExperienceID, in.IncidentID, in.Packet.Severity,
			in.PromotedAt, in.PromotedBy, data); ierr != nil {
			return ierr
		}
		var raw []byte
		if qerr := tx.QueryRow(ctx,
			`SELECT data FROM dem_incident_promotions WHERE experience_id=$1`, in.ExperienceID).Scan(&raw); qerr != nil {
			return qerr
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return Promotion{}, err
	}
	return out, nil
}
