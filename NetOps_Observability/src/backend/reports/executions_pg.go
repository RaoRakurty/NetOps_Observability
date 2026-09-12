// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"crypto/rand"
	"encoding/hex"
)

// report_executions_pg.go — the immutable report execution history + per-phase
// event timeline (ExecutionStore). Modeled on audit_pg.go: per-row writes
// run as platform owner (infrastructure), reads run RLS tenant-scoped so a scoped
// tenant sees only its own executions. The executions row is the denormalized
// summary; report_execution_events carries the phase timestamps that answer
// "where did the time go".
type PGExecStore struct {
	db DB
}

// NewPGExecStore builds the execution store over the injected seam.
func NewPGExecStore(db DB) *PGExecStore { return &PGExecStore{db: db} }

// normTenant / randHex mirror the integrator's helpers (duplicated per the
// no-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return hex.EncodeToString(b)
}

func (s *PGExecStore) Append(ctx context.Context, e ExecutionRecord) error {
	if e.ID == "" {
		e.ID = randHex(8)
	}
	if e.Status == "" {
		e.Status = StatusQueued
	}
	kind := e.Kind
	if kind == "" {
		kind = "report"
	}
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO report_executions (id, kind, tenant_id, schedule_id, job_id, fire_time, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			e.ID, kind, normTenant(e.TenantID), e.ScheduleID, nullText(e.JobID), e.FireTime, string(e.Status))
		return err
	})
}

// The worker-owned status transitions below carry a lease guard (NV-B): the
// UPDATE applies only while the presented worker still holds the report_jobs
// lease for this execution — report_jobs is the single source of lease truth,
// mirroring the queue's own Complete/Fail guards. A zombie worker (lease
// re-claimed elsewhere) matches zero rows and gets ErrLeaseLost instead of
// overwriting the new owner's ledger state. The worker's exec write always
// precedes its queue.Complete/Fail (which flips the job out of 'running'), so
// the rightful lease holder always passes.

func (s *PGExecStore) MarkRunning(ctx context.Context, id string, at time.Time, lockedBy string) error {
	return s.execOwned(ctx, `
		UPDATE report_executions SET status='running', started_at=$2, updated_at=now()
		 WHERE id=$1 AND EXISTS (
			SELECT 1 FROM report_jobs j
			 WHERE j.execution_id = report_executions.id
			   AND j.locked_by = $3 AND j.status = 'running')`, id, at, lockedBy)
}

func (s *PGExecStore) Complete(ctx context.Context, id string, at time.Time, refs []ArtifactRef, deliveries []DeliveryStatus, lockedBy string) error {
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
	return s.execOwned(ctx, `
		UPDATE report_executions
		   SET status='completed', completed_at=$2, artifact_ref=$3, delivery_status=$4, updated_at=now()
		 WHERE id=$1 AND EXISTS (
			SELECT 1 FROM report_jobs j
			 WHERE j.execution_id = report_executions.id
			   AND j.locked_by = $5 AND j.status = 'running')`, id, at, refJSON, delJSON, lockedBy)
}

func (s *PGExecStore) FailExec(ctx context.Context, id string, at time.Time, cause string, deliveries []DeliveryStatus, lockedBy string) error {
	delJSON, err := marshalDeliveries(deliveries)
	if err != nil {
		return err
	}
	return s.execOwned(ctx, `
		UPDATE report_executions
		   SET status='failed', completed_at=$2, error=$3, delivery_status=$4, updated_at=now()
		 WHERE id=$1 AND EXISTS (
			SELECT 1 FROM report_jobs j
			 WHERE j.execution_id = report_executions.id
			   AND j.locked_by = $5 AND j.status = 'running')`, id, at, cause, delJSON, lockedBy)
}

func (s *PGExecStore) Cancel(ctx context.Context, id string, at time.Time, reason string) error {
	return s.exec(ctx, `
		UPDATE report_executions
		   SET status='cancelled', completed_at=$2, error=$3, updated_at=now()
		 WHERE id=$1`, id, at, reason)
}

func (s *PGExecStore) RecordEvent(ctx context.Context, tenant, execID string, phase Phase, at time.Time, note string) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO report_execution_events (id, tenant_id, execution_id, phase, at, note)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			randHex(8), normTenant(tenant), execID, string(phase), at, nullText(note))
		return err
	})
}

func (s *PGExecStore) Get(ctx context.Context, tenant string, cross bool, id string) (ExecutionRecord, []ExecEvent, bool, error) {
	var rec ExecutionRecord
	var events []ExecEvent
	found := false
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
			var ev ExecEvent
			var phase string
			if err := rows.Scan(&phase, &ev.At, &ev.Note); err != nil {
				return err
			}
			ev.Phase = Phase(phase)
			events = append(events, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return ExecutionRecord{}, nil, false, err
	}
	return rec, events, found, nil
}

func (s *PGExecStore) List(ctx context.Context, tenant string, cross bool, q ExecQuery) ([]ExecutionRecord, error) {
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

	var out []ExecutionRecord
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
func scanExec(row pgx.Row) (ExecutionRecord, bool, error) {
	var r ExecutionRecord
	var status string
	var started, completed *time.Time
	var refJSON, delJSON []byte
	if err := row.Scan(&r.ID, &r.Kind, &r.TenantID, &r.ScheduleID, &r.JobID, &r.FireTime,
		&started, &completed, &status, &refJSON, &delJSON, &r.Error); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ExecutionRecord{}, false, nil
		}
		return ExecutionRecord{}, false, err
	}
	r.Status = ExecStatus(status)
	if started != nil {
		r.StartedAt = *started
	}
	if completed != nil {
		r.CompletedAt = *completed
	}
	if len(refJSON) > 0 {
		_ = json.Unmarshal(refJSON, &r.Artifacts) // best-effort: engine-authored JSON; malformed decodes to zero value
	}
	if len(delJSON) > 0 {
		_ = json.Unmarshal(delJSON, &r.Deliveries) // best-effort: engine-authored JSON; malformed decodes to zero value
	}
	return r, true, nil
}

// exec runs a by-id status transition as platform owner (worker is infrastructure).
func (s *PGExecStore) exec(ctx context.Context, sql string, args ...any) error {
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

// execOwned is exec for lease-guarded transitions: zero rows means the caller
// no longer holds the job lease for this execution (or the row is gone) —
// surfaced as ErrLeaseLost so the zombie's refusal is observable, never silent.
func (s *PGExecStore) execOwned(ctx context.Context, sql string, args ...any) error {
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrLeaseLost
		}
		return nil
	})
}

func marshalDeliveries(d []DeliveryStatus) ([]byte, error) {
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

var _ ExecutionStore = (*PGExecStore)(nil)
