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
type PGStore struct {
	db DB
	// now is the clock retention is measured against (tests pin it).
	now func() time.Time
}

var _ Store = (*PGStore)(nil)

// NewPGStore wraps the relational seam.
func NewPGStore(db DB) *PGStore {
	return &PGStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

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

// pgChangeWhere is the ONE predicate ListChanges and CountChanges run — the
// same string, so a count can never answer a different question from the list
// it accompanies. Every filter of a ChangeQuery is here, beside the time bound:
// applying any of them in Go AFTER the row limit bounds a DIFFERENT set from the
// one the caller asked for (on a busy tenant the limit is spent on rows that do
// not match, and the answer comes back "nothing changed" while the deploy sits
// one page down), and it made the two backends disagree about one question.
//
// An empty list is "no such filter", expressed in the statement so one
// prepared shape serves every combination. COALESCE guards cardinality() against
// a NULL array: without it `NULL = 0` is NULL and the row would be dropped by a
// filter nobody asked for. There is deliberately no `tenant_id = …`: that is
// RLS's job (see the file header).
//
// Positional arguments, in order (pgChangeArgs builds them):
//
//	$1 since  $2 until (NULL = open)  $3 types  $4 apps  $5 sites  $6 seams
//	$7 actors (lower-cased)  $8 objects  $9 object kinds  $10 sources
//	$11 excluded ids
const pgChangeWhere = `WHERE event_at >= $1
	    AND ($2::timestamptz IS NULL OR event_at <= $2::timestamptz)
	    AND (COALESCE(cardinality($3::text[]), 0) = 0 OR change_type = ANY($3::text[]))
	    AND (COALESCE(cardinality($4::text[]), 0) = 0 OR app = ANY($4::text[]))
	    AND (COALESCE(cardinality($5::text[]), 0) = 0 OR site = ANY($5::text[]))
	    AND (COALESCE(cardinality($6::text[]), 0) = 0 OR COALESCE(data->>'seam', '') = ANY($6::text[]))
	    AND (COALESCE(cardinality($7::text[]), 0) = 0 OR lower(actor) = ANY($7::text[])
	         OR lower(actor_id) = ANY($7::text[]) OR lower(actor_display) = ANY($7::text[]))
	    AND (COALESCE(cardinality($8::text[]), 0) = 0 OR object = ANY($8::text[]))
	    AND (COALESCE(cardinality($9::text[]), 0) = 0 OR object_kind = ANY($9::text[]))
	    AND (COALESCE(cardinality($10::text[]), 0) = 0 OR source_system = ANY($10::text[]))
	    AND (COALESCE(cardinality($11::text[]), 0) = 0 OR NOT (change_id = ANY($11::text[])))`

// pgChangeArgs binds a normalized filter to pgChangeWhere's positions.
func pgChangeArgs(f changeFilter) []any {
	since := f.since
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	var until any // an untyped nil binds SQL NULL: "no upper bound"
	if !f.until.IsZero() {
		until = f.until
	}
	return []any{since, until, f.types, f.apps, f.sites, f.seams, f.actors,
		f.objects, f.objectKinds, f.sources, f.excludeIDs}
}

func (s *PGStore) ListChanges(ctx context.Context, tenant string, q ChangeQuery) ([]ChangeEvent, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []ChangeEvent{}, nil
	}
	f, err := normalizeChangeQuery(q)
	if err != nil {
		return nil, err
	}
	limit := f.limit
	if limit <= 0 || limit > maxChangeRead {
		limit = maxChangeRead
	}
	args := append(pgChangeArgs(f), limit)
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []ChangeEvent{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		// The predicate is pushed into SQL rather than applied in Go: the whole
		// point of a bounded query is that the rows never leave the database.
		rows, qerr := tx.Query(ctx,
			`SELECT data FROM dem_change_events `+pgChangeWhere+`
			  ORDER BY event_at DESC, change_id ASC LIMIT $12`, args...)
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
			// A row written before N-D1 carries none of the new fields in its
			// JSON; the SAME defaults the migration backfilled into the typed
			// columns are applied, so what the caller is shown matches what the
			// filters matched on.
			c.applyDefaults()
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	// The rows arrive filtered, ordered and limited by the database. They are
	// deliberately NOT re-filtered here: a Go post-check that "must be a no-op"
	// is a second predicate that can drift from the SQL one unnoticed; the
	// backend-parity tests hold the two definitions together instead.
	return out, nil
}

// CountChanges runs the SAME predicate as ListChanges (pgChangeWhere) with no
// LIMIT and no row transfer — `SELECT count(*)`, which is what a database is
// for. The bounded read above cannot answer "how many exist"; asking it to
// would mean shipping every matching row across the wire to length one slice,
// which is the thing the bound exists to prevent.
func (s *PGStore) CountChanges(ctx context.Context, tenant string, q ChangeQuery) (int, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return 0, nil
	}
	f, err := normalizeChangeQuery(q)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	n := 0
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM dem_change_events `+pgChangeWhere, pgChangeArgs(f)...).Scan(&n)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// pgInsertChange is the ONE insert both RecordChange and ImportFile issue, so
// the typed columns can never be filled differently by the two paths.
const pgInsertChange = `INSERT INTO dem_change_events
	  (tenant_id, change_id, change_type, app, site, event_at, data,
	   source_system, actor, actor_type, actor_id, actor_display,
	   object, object_kind, ticket_ref, automation, detected_at)
	 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`

// pgInsertChangeArgs binds a VALIDATED change to pgInsertChange.
func pgInsertChangeArgs(c ChangeEvent, data []byte) []any {
	return []any{c.TenantID, c.ID, c.Type, c.App, c.Site, c.EventAt, data,
		c.SourceSystem, c.Actor, c.ActorType, c.ActorID, c.ActorDisplay,
		c.Object, c.ObjectKind, c.TicketRef, c.Automation, c.ObservedAt}
}

// pgPruneChanges deletes at most $2 of the scoped tenant's rows older than $1,
// oldest first. ctid-limited because DELETE has no LIMIT; RLS scopes both the
// inner SELECT and the DELETE to the transaction's tenant, so this statement can
// only ever reach the writing tenant's rows.
const pgPruneChanges = `DELETE FROM dem_change_events WHERE ctid = ANY(ARRAY(
	    SELECT ctid FROM dem_change_events WHERE event_at < $1
	     ORDER BY event_at ASC LIMIT $2))`

func (s *PGStore) RecordChange(ctx context.Context, in ChangeEvent) (ChangeEvent, error) {
	if in.ID == "" {
		in.ID = newChangeID()
	}
	if err := in.Validate(); err != nil {
		return ChangeEvent{}, err
	}
	cutoff := s.now().Add(-ChangeRetention)
	if in.EventAt.Before(cutoff) {
		return ChangeEvent{}, ErrChangeTooOld
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
		if _, ierr := tx.Exec(ctx, pgInsertChange+` ON CONFLICT (tenant_id, change_id) DO NOTHING`,
			pgInsertChangeArgs(in, data)...); ierr != nil {
			return ierr
		}
		// Age-based retention, in the SAME tenant-scoped transaction: bounded to
		// one batch per write, and unable to reach another tenant's rows.
		_, perr := tx.Exec(ctx, pgPruneChanges, cutoff, changePruneBatch)
		return perr
	})
	if err != nil {
		return ChangeEvent{}, err
	}
	return in, nil
}

// PruneChanges ages out at most max of ONE tenant's changes older than before.
func (s *PGStore) PruneChanges(ctx context.Context, tenant string, before time.Time, max int) (int, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return 0, err
	}
	if max <= 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	n := 0
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, derr := tx.Exec(ctx, pgPruneChanges, before, max)
		if derr != nil {
			return derr
		}
		n = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
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
