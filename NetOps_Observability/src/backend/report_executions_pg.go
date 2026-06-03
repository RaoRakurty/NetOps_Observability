package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/reports"
)

// report_executions_pg.go — the immutable report execution history + per-phase
// event timeline (reports.ExecutionStore). Modeled on audit_pg.go: per-row writes
// run as platform owner (infrastructure), reads run RLS tenant-scoped so a scoped
// tenant sees only its own executions. The executions row is the denormalized
// summary; report_execution_events carries the phase timestamps that answer
// "where did the time go".
type pgExecStore struct {
	db *pgDB
}

func newPgExecStore(db *pgDB) *pgExecStore { return &pgExecStore{db: db} }

func (s *pgExecStore) Append(ctx context.Context, e reports.ExecutionRecord) error {
	if e.ID == "" {
		e.ID = randHex(8)
	}
	if e.Status == "" {
		e.Status = reports.StatusQueued
	}
	kind := e.Kind
	if kind == "" {
		kind = "report"
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO report_executions (id, kind, tenant_id, schedule_id, job_id, fire_time, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			e.ID, kind, normTenant(e.TenantID), e.ScheduleID, nullText(e.JobID), e.FireTime, string(e.Status))
		return err
	})
}

func (s *pgExecStore) MarkRunning(ctx context.Context, id string, at time.Time) error {
	return s.exec(ctx, `
		UPDATE report_executions SET status='running', started_at=$2, updated_at=now()
		 WHERE id=$1`, id, at)
}

func (s *pgExecStore) Complete(ctx context.Context, id string, at time.Time, refs []reports.ArtifactRef, deliveries []reports.DeliveryStatus) error {
	var refJSON []byte
	if len(refs) > 0 {
		var err error
		if refJSON, err = json.Marshal(refs); err != nil {
			return err
		}
	}
	delJSON, err := marshalDeliveries(deliveries)
	if err != nil {
		return err
	}
	return s.exec(ctx, `
		UPDATE report_executions
		   SET status='completed', completed_at=$2, artifact_ref=$3, delivery_status=$4, updated_at=now()
		 WHERE id=$1`, id, at, refJSON, delJSON)
}

func (s *pgExecStore) FailExec(ctx context.Context, id string, at time.Time, cause string, deliveries []reports.DeliveryStatus) error {
	delJSON, err := marshalDeliveries(deliveries)
	if err != nil {
		return err
	}
	return s.exec(ctx, `
		UPDATE report_executions
		   SET status='failed', completed_at=$2, error=$3, delivery_status=$4, updated_at=now()
		 WHERE id=$1`, id, at, cause, delJSON)
}

func (s *pgExecStore) Cancel(ctx context.Context, id string, at time.Time, reason string) error {
	return s.exec(ctx, `
		UPDATE report_executions
		   SET status='cancelled', completed_at=$2, error=$3, updated_at=now()
		 WHERE id=$1`, id, at, reason)
}

func (s *pgExecStore) RecordEvent(ctx context.Context, tenant, execID string, phase reports.Phase, at time.Time, note string) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO report_execution_events (id, tenant_id, execution_id, phase, at, note)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			randHex(8), normTenant(tenant), execID, string(phase), at, nullText(note))
		return err
	})
}

func (s *pgExecStore) Get(ctx context.Context, tenant string, cross bool, id string) (reports.ExecutionRecord, []reports.ExecEvent, bool, error) {
	var rec reports.ExecutionRecord
	var events []reports.ExecEvent
	found := false
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectExecCols+` FROM report_executions WHERE id=$1`, id)
		r, ok, err := scanExec(row)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		found = true
		rec = r
		// Phase timeline (same RLS scope).
		rows, err := tx.Query(ctx, `
			SELECT phase, at, COALESCE(note,'') FROM report_execution_events
			 WHERE execution_id=$1 ORDER BY at ASC`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev reports.ExecEvent
			var phase string
			if err := rows.Scan(&phase, &ev.At, &ev.Note); err != nil {
				return err
			}
			ev.Phase = reports.Phase(phase)
			events = append(events, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return reports.ExecutionRecord{}, nil, false, err
	}
	return rec, events, found, nil
}

func (s *pgExecStore) List(ctx context.Context, tenant string, cross bool, q reports.ExecQuery) ([]reports.ExecutionRecord, error) {
	sql := selectExecCols + ` FROM report_executions`
	var args []any
	var conds []string
	if q.Kind != "" {
		args = append(args, q.Kind)
		conds = append(conds, fmt.Sprintf("kind = $%d", len(args)))
	}
	if q.ScheduleID != "" {
		args = append(args, q.ScheduleID)
		conds = append(conds, fmt.Sprintf("schedule_id = $%d", len(args)))
	}
	if !q.Before.IsZero() {
		args = append(args, q.Before)
		conds = append(conds, fmt.Sprintf("fire_time < $%d", len(args)))
	}
	if len(conds) > 0 {
		sql += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, clampExecLimit(q.Limit))
	sql += fmt.Sprintf(" ORDER BY fire_time DESC, id DESC LIMIT $%d", len(args))

	var out []reports.ExecutionRecord
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, _, err := scanExec(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- helpers ----

const selectExecCols = `SELECT id, COALESCE(kind,'report'), tenant_id, schedule_id, COALESCE(job_id,''), fire_time,
	started_at, completed_at, status, artifact_ref, delivery_status, COALESCE(error,'')`

// scanExec reads one report_executions row. The bool is false only when a
// QueryRow finds no row (pgx.ErrNoRows); for Query/rows.Next it is always true.
func scanExec(row pgx.Row) (reports.ExecutionRecord, bool, error) {
	var r reports.ExecutionRecord
	var status string
	var started, completed *time.Time
	var refJSON, delJSON []byte
	if err := row.Scan(&r.ID, &r.Kind, &r.TenantID, &r.ScheduleID, &r.JobID, &r.FireTime,
		&started, &completed, &status, &refJSON, &delJSON, &r.Error); err != nil {
		if err == pgx.ErrNoRows {
			return reports.ExecutionRecord{}, false, nil
		}
		return reports.ExecutionRecord{}, false, err
	}
	r.Status = reports.ExecStatus(status)
	if started != nil {
		r.StartedAt = *started
	}
	if completed != nil {
		r.CompletedAt = *completed
	}
	if len(refJSON) > 0 {
		_ = json.Unmarshal(refJSON, &r.Artifacts)
	}
	if len(delJSON) > 0 {
		_ = json.Unmarshal(delJSON, &r.Deliveries)
	}
	return r, true, nil
}

// exec runs a by-id status transition as platform owner (worker is infrastructure).
func (s *pgExecStore) exec(ctx context.Context, sql string, args ...any) error {
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func marshalDeliveries(d []reports.DeliveryStatus) ([]byte, error) {
	if len(d) == 0 {
		return nil, nil // store SQL NULL
	}
	return json.Marshal(d)
}

func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func clampExecLimit(n int) int {
	if n <= 0 || n > 500 {
		return 100
	}
	return n
}

var _ reports.ExecutionStore = (*pgExecStore)(nil)
