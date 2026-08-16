package backend

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
)

// report_pipeline_lease_test.go — M11/M12 (2026-08-15 review): the worker must
// STOP DELIVERING the moment its lease is lost (another worker owns the job —
// every further send is a duplicate), retry transient renew errors instead of
// silently letting the lease lapse, and run its terminal ledger/queue writes on
// a context detached from worker shutdown so a delivered report can always
// record that it was delivered.

// fakeJobQueue is an in-memory reports.JobQueue for hermetic pipeline tests.
// Behavior knobs are injected per-test; unused methods are inert.
type fakeJobQueue struct {
	mu           sync.Mutex
	renewErr     func(call int) error // per-call renew outcome
	renewCalls   int
	failCalls    int
	failCtxAlive bool // was the ctx handed to Fail still alive?
	completes    int
}

func (q *fakeJobQueue) Enqueue(_ context.Context, j reports.Job, _ time.Time) (reports.Job, bool, error) {
	return j, true, nil
}
func (q *fakeJobQueue) Claim(context.Context, string, int, time.Duration) ([]reports.Job, error) {
	return nil, nil
}
func (q *fakeJobQueue) RenewLease(context.Context, string, string, time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.renewCalls++
	if q.renewErr != nil {
		return q.renewErr(q.renewCalls)
	}
	return nil
}
func (q *fakeJobQueue) Complete(context.Context, string, string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.completes++
	return nil
}
func (q *fakeJobQueue) Fail(ctx context.Context, _, _ string, _ int, _ string, _ time.Time, _ bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failCalls++
	q.failCtxAlive = ctx.Err() == nil
	return nil
}
func (q *fakeJobQueue) Release(context.Context, string) error                        { return nil }
func (q *fakeJobQueue) RecoverExpiredLeases(context.Context, time.Time) (int, error) { return 0, nil }
func (q *fakeJobQueue) Pending(context.Context) (int, error)                         { return 0, nil }

// leaseFakeExecStore is an inert reports.ExecutionStore.
type leaseFakeExecStore struct{}

func (leaseFakeExecStore) Append(context.Context, reports.ExecutionRecord) error { return nil }
func (leaseFakeExecStore) MarkRunning(context.Context, string, time.Time) error  { return nil }
func (leaseFakeExecStore) Complete(context.Context, string, time.Time, []reports.ArtifactRef, []reports.DeliveryStatus) error {
	return nil
}
func (leaseFakeExecStore) FailExec(context.Context, string, time.Time, string, []reports.DeliveryStatus) error {
	return nil
}
func (leaseFakeExecStore) Cancel(context.Context, string, time.Time, string) error { return nil }
func (leaseFakeExecStore) RecordEvent(context.Context, string, string, reports.Phase, time.Time, string) error {
	return nil
}
func (leaseFakeExecStore) Get(context.Context, string, bool, string) (reports.ExecutionRecord, []reports.ExecEvent, bool, error) {
	return reports.ExecutionRecord{}, nil, false, nil
}
func (leaseFakeExecStore) List(context.Context, string, bool, reports.ExecQuery) ([]reports.ExecutionRecord, error) {
	return nil, nil
}

// FAILING-FIRST (M11): RenewLease answering ErrLeaseLost used to just end the
// heartbeat goroutine — nothing aborted the job, and the worker kept rendering
// and DELIVERING a job another worker had re-claimed and was delivering too.
// The heartbeat must cancel the job-scoped context.
func TestHeartbeatM11LeaseLostCancelsJob(t *testing.T) {
	fq := &fakeJobQueue{renewErr: func(int) error { return reports.ErrLeaseLost }}
	p := &reportPipeline{queue: fq, lease: 30 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go p.heartbeat(ctx, cancel, "w1", "j1", stop)
	select {
	case <-ctx.Done():
		// the lost lease aborted the job — no further Deliver can run (Deliver
		// checks ctx between sends, see TestDeliverM11CancelledCtxSendsNothing).
	case <-time.After(2 * time.Second):
		t.Fatal("lease lost but the job context was never cancelled — the worker would keep delivering a job another worker owns")
	}
}

// M11: a TRANSIENT renew error (db blip) must not kill the heartbeat — before
// the fix any error ended it, guaranteeing the lease would lapse mid-job.
func TestHeartbeatM11TransientRenewErrorRetries(t *testing.T) {
	fq := &fakeJobQueue{renewErr: func(call int) error {
		if call <= 2 {
			return errors.New("db blip")
		}
		return nil
	}}
	p := &reportPipeline{queue: fq, lease: 30 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	go p.heartbeat(ctx, cancel, "w1", "j1", stop)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fq.mu.Lock()
		calls := fq.renewCalls
		fq.mu.Unlock()
		if calls >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	fq.mu.Lock()
	calls := fq.renewCalls
	fq.mu.Unlock()
	if calls < 3 {
		t.Fatalf("heartbeat stopped after a transient renew error (calls=%d, want >=3)", calls)
	}
	if ctx.Err() != nil {
		t.Fatal("transient renew error cancelled the job — only a LOST lease may abort it")
	}
}

// M11: Deliver must honour ctx between sends — with a cancelled job context
// (lease lost) no recipient may be contacted, and the un-attempted recipients
// get NO status rows so the lease's new owner sends to them exactly once.
func TestDeliverM11CancelledCtxSendsNothing(t *testing.T) {
	sends := 0
	dispatched := 0
	d := &reportDelivery{
		resolveEmail: func([]string, string, bool) []string { return []string{"a@x.com", "b@x.com"} },
		resolveWebhooks: func([]string, string, bool) []ContactPoint {
			return []ContactPoint{{Name: "hook", Type: "slack", Target: "https://x"}}
		},
		emailSender: func([]string) (docSender, bool) { sends++; return &fakeDoc{}, true },
		postWebhook: func(string, string) error { sends++; return nil },
		dispatch: func(models.Alert, []string) []notify.SendResult {
			dispatched++
			return []notify.SendResult{{Channel: "slack-ops"}}
		},
		now: fixedNow,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := d.Deliver(ctx, deliverReq{
		ContactPoints: []string{"cp"}, Channels: []string{"slack-ops"},
	})
	if sends != 0 || dispatched != 0 {
		t.Fatalf("cancelled ctx still sent: emails/webhooks=%d dispatches=%d — double delivery after a lost lease", sends, dispatched)
	}
	if len(got) != 0 {
		t.Fatalf("un-attempted recipients got status rows: %+v (a retry would wrongly skip them)", got)
	}
}

// M11: named notify channels consult SkipRecipients like every other recipient
// — a second worker retrying after an expired lease must produce a single
// page per channel, not one per attempt.
func TestDeliverM11NamedChannelSkipRecipients(t *testing.T) {
	var dispatchedWith []string
	d := &reportDelivery{
		resolveEmail: func([]string, string, bool) []string { return nil },
		emailSender:  func([]string) (docSender, bool) { return nil, false },
		dispatch: func(_ models.Alert, names []string) []notify.SendResult {
			dispatchedWith = append(dispatchedWith, names...)
			out := make([]notify.SendResult, 0, len(names))
			for _, n := range names {
				out = append(out, notify.SendResult{Channel: n})
			}
			return out
		},
		now: fixedNow,
	}
	got := d.Deliver(context.Background(), deliverReq{
		Cross:          true, // named-channel dispatch is platform-owned (M15)
		Channels:       []string{"slack-ops", "pd-oncall"},
		Attempt:        2,
		SkipRecipients: map[string]bool{"slack-ops": true}, // delivered on attempt 1
	})
	if len(dispatchedWith) != 1 || dispatchedWith[0] != "pd-oncall" {
		t.Fatalf("dispatch called with %v, want only the undelivered channel [pd-oncall]", dispatchedWith)
	}
	if len(got) != 2 {
		t.Fatalf("statuses = %d, want 2 (skipped channel recorded ok without re-sending)", len(got))
	}
	for _, ds := range got {
		if !ds.OK {
			t.Errorf("status not ok: %+v", ds)
		}
	}
}

// M12: terminal writes (queue.Fail here) must survive worker-pool shutdown —
// they ride a ctx detached from the cancelled parent. Before the fix the
// whole terminal sequence ran on the pool ctx, so a job finishing right at
// SIGTERM could deliver and then fail to record it, re-delivering on restart.
func TestProcessM12TerminalWritesSurviveShutdownCancel(t *testing.T) {
	fq := &fakeJobQueue{}
	p := &reportPipeline{
		srv:         &server{},
		queue:       fq,
		execs:       leaseFakeExecStore{},
		lease:       time.Minute,
		jobTimeout:  time.Minute,
		maxAttempts: 3,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the pool is shutting down
	// An integration-inbound job with an invalid payload finalizes immediately
	// (dead-letter) — the terminal queue.Fail must still be issued on a LIVE ctx.
	job := reports.Job{ID: "j1", JobType: jobTypeIntegrationInbound, TenantID: "acme",
		ExecutionID: "x1", Attempts: 3, Payload: []byte("{not json"), LockedBy: "w1"}
	p.process(ctx, "w1", job)
	if fq.failCalls != 1 {
		t.Fatalf("queue.Fail calls = %d, want 1", fq.failCalls)
	}
	if !fq.failCtxAlive {
		t.Fatal("terminal Fail ran on the cancelled shutdown ctx — the write would be refused and the job replayed after restart")
	}
}

var _ reports.JobQueue = (*fakeJobQueue)(nil)
