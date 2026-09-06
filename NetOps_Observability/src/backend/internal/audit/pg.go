// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// audit_pg.go — the Postgres-backed audit repository (#32).
//
// Unlike the file backend's bounded in-memory ring (load-all + rewrite the whole
// blob on every event), this appends ONE row per event and serves queries
// straight from SQL: newest-first, time-windowed, paginated. It is the first
// store to use PER-REQUEST tenant-scoped reads (the #33 pattern): a scoped
// admin's List runs inside withTenant(tenant) so Row-Level Security filters at
// the database — the platform owner runs '*' and sees all. No app-side tenant
// filtering, no full-table scan into memory.
// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewPGStore builds the per-row RLS-backed trail over the injected seam.
func NewPGStore(db DB, errf func(component, msg string, fields map[string]any)) *PGStore {
	if errf == nil {
		errf = func(string, string, map[string]any) {}
	}
	return &PGStore{db: db, errf: errf}
}

type PGStore struct {
	errf func(component, msg string, fields map[string]any)
	db   DB
}

// normTenant matches withTenant's GUC normalization (lower+trim) so the stored
// tenant_id column compares equal to the RLS session tenant regardless of the
// casing the caller's claim happened to carry. The verbatim event (original
// casing) is preserved in the JSONB data column.
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func (s *PGStore) Record(e Event) {
	if err := s.record(e); err != nil {
		// Best-effort: an audit write must never break the request, but the
		// failure must be observable (no silent drop).
		s.errf("audit", "persist event", map[string]any{"error": err.Error()})
	}
}

// RecordStrict propagates the persistence error (see Repo): a failed INSERT is
// returned to the caller so a high-value action can refuse to complete rather
// than complete unwitnessed (M19).
func (s *PGStore) RecordStrict(e Event) error { return s.record(e) }

func (s *PGStore) record(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = randHex8()
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Record as platform owner ('*'): the middleware logs events across many
	// tenants and the RLS WITH CHECK would reject any tenant_id != the scoped GUC.
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, tenant_id, ts, data) VALUES ($1, $2, $3, $4)`,
			e.ID, normTenant(e.Tenant), e.Time, data)
		return err
	})
}

// pgWhere builds the shared time-window fragment for List and Count so a
// page and its reported total are always computed under identical filters.
// Fragments are constant (no user input) — only the parameterized values vary.
func pgWhere(q Query) (string, []any) {
	args := []any{}
	var conds []string
	if !q.Before.IsZero() {
		args = append(args, q.Before)
		conds = append(conds, fmt.Sprintf("ts < $%d", len(args)))
	}
	if !q.Since.IsZero() {
		args = append(args, q.Since)
		conds = append(conds, fmt.Sprintf("ts >= $%d", len(args)))
	}
	if q.Path != "" {
		// data->>'path' rather than a LIKE: an exact match on the JSON field,
		// so a caller cannot turn this into a scan or a prefix probe.
		args = append(args, q.Path)
		conds = append(conds, fmt.Sprintf("data->>'path' = $%d", len(args)))
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Count is the TRUE number of audit rows visible to this principal in the
// window — the number that makes unbounded growth of an unbounded table
// observable at all (F-57). RLS scopes it exactly like List.
func (s *PGStore) Count(tenant string, cross bool, q Query) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	where, args := pgWhere(q)
	var n int
	if err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events"+where, args...).Scan(&n)
	}); err != nil {
		// -1 is "unknown", never 0: on the audit surface, a failed count must
		// not be able to render as "no privileged actions occurred" (F-73's
		// lesson applied to the total).
		s.errf("audit", "count trail", map[string]any{"error": err.Error()})
		return -1
	}
	return n
}

func (s *PGStore) List(tenant string, cross bool, q Query) ([]Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	where, args := pgWhere(q)
	sql := "SELECT data FROM audit_events" + where
	args = append(args, ClampLimit(q.Limit))
	sql += fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT $%d", len(args))
	if q.Offset > 0 {
		args = append(args, q.Offset)
		sql += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	var out []Event
	// RLS scopes the read: a scoped tenant sees only its own rows; '*' sees all.
	if err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return err
			}
			var e Event
			if err := json.Unmarshal(data, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	}); err != nil {
		// F-73: `return nil` here rendered as `{"events":[],"count":0}` with a
		// 200 — a SIEM polling through a PG blip or an RLS regression recorded
		// "no privileged actions occurred". The error must reach the caller.
		s.errf("audit", "query trail", map[string]any{"error": err.Error()})
		return nil, err
	}
	return out, nil
}
