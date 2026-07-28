package reports

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// report_jobs_pg.go — the Postgres-backed report job queue (JobQueue).
//
// This is queue *mechanics*: infrastructure, not tenant data. Every method runs
// under the platform scope (withTenant(ctx,"",true,..)) so a worker can claim and
// finalize jobs across all tenants; the worker re-enters tenant scope only when it
// later reads tenant data to render/deliver. Jobs are leased with a visibility
// timeout (lease_until) and consumed with FOR UPDATE SKIP LOCKED, so concurrent
// workers never double-claim and a crashed worker's job is automatically re-leased.
// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type PGJobQueue struct {
	db          DB
	maxAttempts int
}

func NewPGJobQueue(db DB, maxAttempts int) *PGJobQueue {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	return &PGJobQueue{db: db, maxAttempts: maxAttempts}
}

// ErrLeaseLost signals that a RenewLease found the job no longer leased by this
// worker (it expired and was re-claimed elsewhere) — the worker must abort.
var ErrLeaseLost = errors.New("report job lease lost")

func payloadOrEmpty(p json.RawMessage) []byte {
	if len(p) == 0 {
		return []byte("{}")
	}
	return p
}

func (q *PGJobQueue) Enqueue(ctx context.Context, j Job, runAfter time.Time) (Job, bool, error) {
	if j.ID == "" {
		j.ID = randHex(8)
	}
	if runAfter.IsZero() {
		runAfter = time.Now().UTC()
	}
	jobType := j.JobType
	if jobType == "" {
		jobType = "report"
	}
	created := false
	err := q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO report_jobs
				(id, job_type, tenant_id, schedule_id, execution_id, fire_time, status, attempts, max_attempts, run_after, payload)
			VALUES ($1,$2,$3,$4,$5,$6,'queued',0,$7,$8,$9)
			ON CONFLICT (schedule_id, fire_time) DO NOTHING`,
			j.ID, jobType, normTenant(j.TenantID), j.ScheduleID, j.ExecutionID, j.FireTime,
			q.maxAttempts, runAfter, payloadOrEmpty(j.Payload))
		if err != nil {
			return err
		}
		created = tag.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return Job{}, false, err
	}
	return j, created, nil
}

// claimSQL atomically leases runnable jobs. The CTE selects+locks candidate rows
// (skipping those another worker holds) and the UPDATE flips them to running with
// a fresh lease; RETURNING hands back exactly the rows this worker won. The
// predicate `lease_until < now()` re-claims jobs abandoned by a crashed worker.
const claimSQL = `
WITH claimable AS (
    SELECT id FROM report_jobs
     WHERE status IN ('queued','running')
       AND run_after <= now()
       AND (lease_until IS NULL OR lease_until < now())
     ORDER BY run_after
     FOR UPDATE SKIP LOCKED
     LIMIT $2)
UPDATE report_jobs j
   SET status='running', locked_by=$1, locked_at=now(),
       lease_until = now() + make_interval(secs => $3),
       attempts = j.attempts + 1, updated_at = now()
  FROM claimable c
 WHERE j.id = c.id
RETURNING j.id, j.job_type, j.tenant_id, j.schedule_id, j.execution_id, j.fire_time, j.attempts, j.payload`

func (q *PGJobQueue) Claim(ctx context.Context, workerID string, n int, lease time.Duration) ([]Job, error) {
	if n <= 0 {
		return nil, nil
	}
	var out []Job
	err := q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, claimSQL, workerID, n, lease.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var j Job
			var payload []byte
			if err := rows.Scan(&j.ID, &j.JobType, &j.TenantID, &j.ScheduleID, &j.ExecutionID, &j.FireTime, &j.Attempts, &payload); err != nil {
				return err
			}
			j.Payload = json.RawMessage(payload)
			out = append(out, j)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (q *PGJobQueue) RenewLease(ctx context.Context, jobID, workerID string, lease time.Duration) error {
	return q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report_jobs
			   SET lease_until = now() + make_interval(secs => $3), updated_at = now()
			 WHERE id = $1 AND locked_by = $2 AND status = 'running'`,
			jobID, workerID, lease.Seconds())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrLeaseLost
		}
		return nil
	})
}

func (q *PGJobQueue) Complete(ctx context.Context, jobID string) error {
	return q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE report_jobs
			   SET status='done', lease_until=NULL, updated_at=now()
			 WHERE id=$1`, jobID)
		return err
	})
}

func (q *PGJobQueue) Fail(ctx context.Context, jobID string, attempt int, cause string, retryAfter time.Time, dead bool) error {
	status := "queued"
	if dead {
		status = "failed"
	}
	if retryAfter.IsZero() {
		retryAfter = time.Now().UTC()
	}
	return q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE report_jobs
			   SET status=$2, last_error=$3, run_after=$4,
			       locked_by=NULL, locked_at=NULL, lease_until=NULL, updated_at=now()
			 WHERE id=$1`,
			jobID, status, cause, retryAfter)
		return err
	})
}

func (q *PGJobQueue) Release(ctx context.Context, jobID string) error {
	return q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE report_jobs
			   SET status='queued', locked_by=NULL, locked_at=NULL, lease_until=NULL, updated_at=now()
			 WHERE id=$1 AND status='running'`, jobID)
		return err
	})
}

func (q *PGJobQueue) RecoverExpiredLeases(ctx context.Context, now time.Time) (int, error) {
	var n int64
	err := q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report_jobs
			   SET status='queued', locked_by=NULL, locked_at=NULL, lease_until=NULL, updated_at=now()
			 WHERE status='running' AND lease_until IS NOT NULL AND lease_until < $1`, now)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return int(n), err
}

func (q *PGJobQueue) Pending(ctx context.Context) (int, error) {
	var n int
	err := q.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM report_jobs
			 WHERE status IN ('queued','running') AND run_after <= now()`).Scan(&n)
	})
	return n, err
}

// Compile-time assurance the repository satisfies the interface.
var _ JobQueue = (*PGJobQueue)(nil)
