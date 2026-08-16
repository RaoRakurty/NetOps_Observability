package backend

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/integration"
	"netops/backend/reports"
)

// integration_inbound_recovery_test.go — M14 (2026-08-15 review).
//
// Two defects: (1) an inbound event RECORDED in the ledger whose apply-job
// enqueue failed was unrecoverable — the sender's redelivery hit the level-1
// dedup and the enqueue was never retried (fixed by the event-keyed idempotent
// job + the redelivery-recovery branch); (2) transient STORE errors in the
// apply worker (GetConfig et al) were recorded as terminal "dropped" verdicts
// instead of retried.

// dedupJobQueue simulates the PG queue's UNIQUE(schedule_id, fire_time)
// idempotency plus an injectable transient Enqueue failure.
type dedupJobQueue struct {
	fakeJobQueue
	failFirst bool
	enqueues  int
	jobs      map[string]reports.Job // scheduleID|fireTime -> job
}

func (q *dedupJobQueue) Enqueue(_ context.Context, j reports.Job, _ time.Time) (reports.Job, bool, error) {
	q.enqueues++
	if q.failFirst {
		q.failFirst = false
		return reports.Job{}, false, errors.New("pg down")
	}
	if q.jobs == nil {
		q.jobs = map[string]reports.Job{}
	}
	key := j.ScheduleID + "|" + j.FireTime.UTC().Format(time.RFC3339Nano)
	if _, ok := q.jobs[key]; ok {
		return j, false, nil // the UNIQUE(schedule_id, fire_time) dedup
	}
	q.jobs[key] = j
	return j, true, nil
}

// countingExecStore counts execution-record appends.
type countingExecStore struct {
	leaseFakeExecStore
	appends int
}

func (s *countingExecStore) Append(context.Context, reports.ExecutionRecord) error {
	s.appends++
	return nil
}

// FAILING-FIRST (M14): the apply job's FireTime used to be time.Now(), so a
// re-enqueue after a lost first attempt minted a SECOND job — and because of
// that the recovery path could never exist. With the ledger row's RecordedAt
// as the FireTime, a failed enqueue is recovered by the redelivery and a
// duplicate enqueue collapses without appending a phantom execution record.
func TestM14InboundEnqueueRedeliveryIdempotent(t *testing.T) {
	ctx := context.Background()
	fq := &dedupJobQueue{failFirst: true}
	execs := &countingExecStore{}
	p := &reportPipeline{queue: fq, execs: execs}
	recordedAt := time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC)

	// First delivery: the ledger write succeeded, the enqueue did not.
	if _, _, err := p.EnqueueIntegrationInbound(ctx, "acme", "ev-1", "ic-1", recordedAt); err == nil {
		t.Fatal("expected the injected enqueue failure")
	}
	// The redelivery recovers: same event id + RecordedAt → the job lands.
	execID, created, err := p.EnqueueIntegrationInbound(ctx, "acme", "ev-1", "ic-1", recordedAt)
	if err != nil || !created || execID == "" {
		t.Fatalf("redelivery enqueue: created=%v exec=%q err=%v, want a fresh job", created, execID, err)
	}
	// A THIRD delivery dedupes: no second job, no phantom execution record.
	if _, created, err := p.EnqueueIntegrationInbound(ctx, "acme", "ev-1", "ic-1", recordedAt); err != nil || created {
		t.Fatalf("triple delivery: created=%v err=%v, want deduped no-op", created, err)
	}
	if len(fq.jobs) != 1 {
		t.Fatalf("job rows = %d, want exactly 1 for one event", len(fq.jobs))
	}
	if execs.appends != 1 {
		t.Fatalf("execution records appended = %d, want 1", execs.appends)
	}
}

// ── fake relational seam for the apply worker's store-error path ─────────────

// seamRow satisfies pgx.Row with an injected scan.
type seamRow struct{ scan func(dest ...any) error }

func (r seamRow) Scan(dest ...any) error { return r.scan(dest...) }

// seamTx fakes the two tx calls the apply path makes: the ledger payload read
// (integration_events SELECT) succeeds; the config read errors; verdict writes
// (integration_events UPDATE) are counted. Everything else panics loudly via
// the embedded nil pgx.Tx — this test must not silently exercise more surface.
type seamTx struct {
	pgx.Tx
	payload       []byte
	verdictWrites *int
}

func (tx seamTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "FROM integration_events"):
		return seamRow{scan: func(dest ...any) error {
			*(dest[0].(*[]byte)) = tx.payload
			return nil
		}}
	case strings.Contains(sql, "FROM integration_configs"):
		return seamRow{scan: func(...any) error { return errors.New("config store down") }}
	default:
		return seamRow{scan: func(...any) error { return errors.New("unexpected query: " + sql) }}
	}
}

func (tx seamTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "UPDATE integration_events") {
		*tx.verdictWrites++
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	return pgconn.CommandTag{}, errors.New("unexpected exec: " + sql)
}

type seamDB struct{ tx seamTx }

func (d seamDB) WithTenant(_ context.Context, _ string, _ bool, fn func(pgx.Tx) error) error {
	return fn(d.tx)
}

// FAILING-FIRST (M14): a GetConfig STORE ERROR used to be indistinguishable
// from "config removed" (`cfg, ok, _ :=`) — the worker recorded a terminal
// "dropped" verdict and completed the job, silently losing the transition to a
// database blip. It must instead retry: queue.Fail, no Complete, no verdict.
func TestM14GetConfigErrorRetriesNotDropped(t *testing.T) {
	ctx := context.Background()
	ev := integration.IntegrationEvent{Tenant: "acme", Provider: "servicenow", ExternalID: "INC1", Type: integration.EventResolved}
	payload, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	verdicts := 0
	db := seamDB{tx: seamTx{payload: payload, verdictWrites: &verdicts}}
	fq := &fakeJobQueue{}
	p := &reportPipeline{
		srv:         &server{integrations: integration.NewStore(db, nil)},
		queue:       fq,
		execs:       leaseFakeExecStore{},
		maxAttempts: 5,
	}
	jobPayload, _ := json.Marshal(integrationInboundPayload{EventID: "ev-1", CorrelationID: "ic-1"})
	job := reports.Job{ID: "j1", JobType: jobTypeIntegrationInbound, TenantID: "acme",
		ExecutionID: "x1", Attempts: 1, Payload: jobPayload, LockedBy: "w1"}

	p.processIntegrationInbound(ctx, ctx, "w1", job, "acme", map[string]any{})

	if fq.failCalls != 1 {
		t.Fatalf("queue.Fail calls = %d, want 1 (retry) — the store error must not be swallowed", fq.failCalls)
	}
	if fq.completes != 0 {
		t.Fatalf("queue.Complete calls = %d, want 0 — a failed config read is not a finished job", fq.completes)
	}
	if verdicts != 0 {
		t.Fatalf("ledger verdict writes = %d, want 0 — 'dropped: config-removed' over a db blip is the M14 bug", verdicts)
	}
}
