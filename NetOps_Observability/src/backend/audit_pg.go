package main

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
type pgAuditStore struct {
	db *pgDB
}

// normTenant matches withTenant's GUC normalization (lower+trim) so the stored
// tenant_id column compares equal to the RLS session tenant regardless of the
// casing the caller's claim happened to carry. The verbatim event (original
// casing) is preserved in the JSONB data column.
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func (s *pgAuditStore) Record(e AuditEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = randHex(8)
	}
	data, err := json.Marshal(e)
	if err != nil {
		logError("audit", "marshal event", map[string]any{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Record as platform owner ('*'): the middleware logs events across many
	// tenants and the RLS WITH CHECK would reject any tenant_id != the scoped GUC.
	if err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, tenant_id, ts, data) VALUES ($1, $2, $3, $4)`,
			e.ID, normTenant(e.Tenant), e.Time, data)
		return err
	}); err != nil {
		// Best-effort: an audit write must never break the request, but the
		// failure must be observable (no silent drop).
		logError("audit", "persist event", map[string]any{"error": err.Error()})
	}
}

// auditWhere builds the shared time-window fragment for List and Count so a
// page and its reported total are always computed under identical filters.
// Fragments are constant (no user input) — only the parameterized values vary.
func auditWhere(q auditQuery) (string, []any) {
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
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Count is the TRUE number of audit rows visible to this principal in the
// window — the number that makes unbounded growth of an unbounded table
// observable at all (F-57). RLS scopes it exactly like List.
func (s *pgAuditStore) Count(tenant string, cross bool, q auditQuery) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	where, args := auditWhere(q)
	var n int
	if err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events"+where, args...).Scan(&n)
	}); err != nil {
		// -1 is "unknown", never 0: on the audit surface, a failed count must
		// not be able to render as "no privileged actions occurred" (F-73's
		// lesson applied to the total).
		logError("audit", "count trail", map[string]any{"error": err.Error()})
		return -1
	}
	return n
}

func (s *pgAuditStore) List(tenant string, cross bool, q auditQuery) []AuditEvent {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	where, args := auditWhere(q)
	sql := "SELECT data FROM audit_events" + where
	args = append(args, clampAuditLimit(q.Limit))
	sql += fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT $%d", len(args))
	if q.Offset > 0 {
		args = append(args, q.Offset)
		sql += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	var out []AuditEvent
	// RLS scopes the read: a scoped tenant sees only its own rows; '*' sees all.
	if err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
			var e AuditEvent
			if err := json.Unmarshal(data, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	}); err != nil {
		logError("audit", "query trail", map[string]any{"error": err.Error()})
		return nil
	}
	return out
}
