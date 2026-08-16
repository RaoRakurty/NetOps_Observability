package backend

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
)

// report_pipeline_nv_test.go — NV-A/NV-B (2026-08-16, third-pass deferred
// items): the double-send window between "recipient physically sent" and the
// batch deliveries.Record must be narrowed by ledgering each send the moment it
// returns, and the execution ledger's status transitions must carry the worker
// identity so a zombie worker (lease re-claimed elsewhere) cannot overwrite the
// rightful owner's terminal state.

// nvDoc is a docSender that invokes a hook on every physical send.
type nvDoc struct{ onSend func() }

func (d *nvDoc) SendDocument(string, string, string) error { d.onSend(); return nil }
func (d *nvDoc) SendReport(string, string, []notify.Attachment) error {
	d.onSend()
	return nil
}

// nvLedger is an in-memory reports.DeliveryRecorder. down simulates the DB
// becoming unreachable (the same partition that lapses the lease): while set,
// Record fails, exactly like the real ledger would mid-outage.
type nvLedger struct {
	mu   sync.Mutex
	ok   map[string]bool
	down atomic.Bool
}

func newNVLedger() *nvLedger { return &nvLedger{ok: map[string]bool{}} }

func (l *nvLedger) Record(_ context.Context, _, _ string, ds []reports.DeliveryStatus) error {
	if l.down.Load() {
		return errors.New("db unreachable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range ds {
		if d.OK {
			l.ok[d.Recipient] = true
		}
	}
	return nil
}

func (l *nvLedger) Delivered(context.Context, string) (map[string]bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]bool, len(l.ok))
	for k := range l.ok {
		out[k] = true
	}
	return out, nil
}

// NV-A (delivery seam): a Deliver that sends r1 and then loses the lease must
// have ALREADY ledgered r1 — without any batch Record — so a second Deliver
// whose skip set comes from the ledger does not re-send r1. Pre-fix the ledger
// was only written in one batch after Deliver fully returned, so the re-claimer
// read an empty delivered set and re-sent every already-sent recipient.
func TestDeliverNVAIncrementalLedgerSkipsAlreadySentRecipient(t *testing.T) {
	ledger := newNVLedger()
	sends := map[string]int{}

	mkDelivery := func(onR1 func()) *reportDelivery {
		return &reportDelivery{
			resolveEmail: func([]string, string, bool) []string { return []string{"r1@x.com", "r2@x.com"} },
			emailSender: func(rcpts []string) (docSender, bool) {
				r := rcpts[0]
				return &nvDoc{onSend: func() {
					sends[r]++
					if r == "r1@x.com" && onR1 != nil {
						onR1()
					}
				}}, true
			},
			dispatch: func(models.Alert, []string) []notify.SendResult { return nil },
			now:      fixedNow,
		}
	}

	// Worker A: r1's send returns, then the heartbeat cancels the job ctx
	// (lease lost). A never gets to a batch Record (DB unreachable).
	ctxA, cancelA := context.WithCancel(context.Background())
	record := func(ds reports.DeliveryStatus) {
		if err := ledger.Record(context.Background(), "acme", "x1", []reports.DeliveryStatus{ds}); err != nil {
			t.Fatalf("incremental record: %v", err)
		}
	}
	mkDelivery(cancelA).Deliver(ctxA, deliverReq{ContactPoints: []string{"cp"}, Record: record})

	delivered, err := ledger.Delivered(context.Background(), "x1")
	if err != nil {
		t.Fatalf("delivered: %v", err)
	}
	if !delivered["r1@x.com"] {
		t.Fatal("r1 was physically sent but not ledgered before the batch Record — a concurrent lease owner would re-send it")
	}

	// Worker B re-claims and delivers with the ledger's skip set.
	got := mkDelivery(nil).Deliver(context.Background(), deliverReq{
		ContactPoints: []string{"cp"}, SkipRecipients: delivered, Record: record,
	})
	if sends["r1@x.com"] != 1 {
		t.Fatalf("r1 physically sent %d times, want exactly 1 (double-send window)", sends["r1@x.com"])
	}
	if sends["r2@x.com"] != 1 {
		t.Fatalf("r2 physically sent %d times, want 1", sends["r2@x.com"])
	}
	// The skipped recipient is still reported ok so the execution record stays
	// complete.
	var r1OK bool
	for _, ds := range got {
		if ds.Recipient == "r1@x.com" && ds.OK {
			r1OK = true
		}
	}
	if !r1OK {
		t.Fatalf("skipped r1 missing an ok status row: %+v", got)
	}
}

// captureExecStore records the worker identity presented on each guarded
// transition (NV-B wiring).
type captureExecStore struct {
	leaseFakeExecStore
	mu          sync.Mutex
	runningBy   []string
	completedBy []string
	failedBy    []string
}

func (c *captureExecStore) MarkRunning(_ context.Context, _ string, _ time.Time, lockedBy string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runningBy = append(c.runningBy, lockedBy)
	return nil
}
func (c *captureExecStore) Complete(_ context.Context, _ string, _ time.Time, _ []reports.ArtifactRef, _ []reports.DeliveryStatus, lockedBy string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.completedBy = append(c.completedBy, lockedBy)
	return nil
}
func (c *captureExecStore) FailExec(_ context.Context, _ string, _ time.Time, _ string, _ []reports.DeliveryStatus, lockedBy string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failedBy = append(c.failedBy, lockedBy)
	return nil
}

// nvArtifacts is an inert reports.ArtifactStore.
type nvArtifacts struct{}

func (nvArtifacts) Save(_ context.Context, key string, a reports.Artifact) (reports.ArtifactRef, error) {
	return reports.ArtifactRef{Format: a.Format, ContentType: a.ContentType, Key: key}, nil
}
func (nvArtifacts) Load(context.Context, reports.ArtifactRef) (reports.Artifact, error) {
	return reports.Artifact{}, nil
}
func (nvArtifacts) Delete(context.Context, reports.ArtifactRef) error { return nil }

// NV-A end-to-end + NV-B wiring: worker A's processReport sends r1, then the DB
// partitions and its lease is lost mid-fanout (r2's send returns right at the
// loss; r3 is never attempted; every later ledger write fails, batch Record
// included). Worker B re-claims the SAME execution id and re-runs. r1 must be
// sent exactly once across both workers — B observes A's incremental record —
// and every execution-ledger transition must carry its caller's worker id.
func TestProcessReportNVAIncrementalRecordSurvivesLostLease(t *testing.T) {
	dir := t.TempDir()
	sv, err := newSavedStore(dir + "/saved.json")
	if err != nil {
		t.Fatalf("saved store: %v", err)
	}
	o, err := sv.Create("report", "Weekly", "admin", "acme",
		json.RawMessage(`{"kind":"alerts_summary","enabled":true,"contact_points":["cp1"]}`))
	if err != nil {
		t.Fatalf("create report: %v", err)
	}
	srv := &server{saved: sv}
	srv.reports = &reportScheduler{
		srv: srv, saved: sv, runs: map[string]reportRun{},
		ds: reports.DataSource{Alerts: func(string) []models.Alert { return nil }},
	}

	ledger := newNVLedger()
	execs := &captureExecStore{}
	fq := &fakeJobQueue{}
	html, err := reports.NewHTMLRenderer()
	if err != nil {
		t.Fatalf("html renderer: %v", err)
	}

	sends := map[string]int{}
	jctxA, cancelA := context.WithCancel(context.Background())
	mkDelivery := func(loseLeaseOnR2 bool) *reportDelivery {
		return &reportDelivery{
			resolveEmail: func([]string, string, bool) []string {
				return []string{"r1@x.com", "r2@x.com", "r3@x.com"}
			},
			emailSender: func(rcpts []string) (docSender, bool) {
				r := rcpts[0]
				return &nvDoc{onSend: func() {
					sends[r]++
					if r == "r2@x.com" && loseLeaseOnR2 {
						cancelA()               // heartbeat: lease lost → job ctx cancelled
						ledger.down.Store(true) // the DB partition behind the lapse
					}
				}}, true
			},
			dispatch: func(models.Alert, []string) []notify.SendResult { return nil },
			now:      fixedNow,
		}
	}

	p := &reportPipeline{
		srv:        srv,
		queue:      fq,
		execs:      execs,
		artifacts:  nvArtifacts{},
		renderers:  map[string]reports.Renderer{"html": html},
		deliveries: ledger,
	}

	// Worker A: loses its lease right after r2's send returns.
	p.delivery = mkDelivery(true)
	jobA := reports.Job{ID: "j1", TenantID: "acme", ScheduleID: o.ID, ExecutionID: "x1",
		FireTime: fixedNow(), Attempts: 1, LockedBy: "wA"}
	p.processReport(context.Background(), jctxA, "wA", jobA, "acme", map[string]any{})

	if sends["r3@x.com"] != 0 {
		t.Fatalf("r3 was contacted after the lease was lost (sends=%d)", sends["r3@x.com"])
	}
	delivered, _ := ledger.Delivered(context.Background(), "x1")
	if !delivered["r1@x.com"] {
		t.Fatal("r1's send was not ledgered incrementally — with the batch Record unreachable, the re-claimer would re-send r1")
	}

	// Worker B re-claims the same execution after the DB heals.
	ledger.down.Store(false)
	p.delivery = mkDelivery(false)
	jobB := jobA
	jobB.Attempts, jobB.LockedBy = 2, "wB"
	p.processReport(context.Background(), context.Background(), "wB", jobB, "acme", map[string]any{})

	if sends["r1@x.com"] != 1 {
		t.Fatalf("r1 physically sent %d times, want exactly 1", sends["r1@x.com"])
	}
	if sends["r3@x.com"] != 1 {
		t.Fatalf("r3 physically sent %d times, want 1", sends["r3@x.com"])
	}

	// NV-B wiring: every execution-ledger write presented its worker identity.
	execs.mu.Lock()
	defer execs.mu.Unlock()
	if len(execs.completedBy) != 2 || execs.completedBy[0] != "wA" || execs.completedBy[1] != "wB" {
		t.Fatalf("Complete lockedBy = %v, want [wA wB]", execs.completedBy)
	}
}

// NV-B wiring (fail path): the terminal FailExec must present the worker id so
// the PG store's lease guard can 0-row a zombie's write.
func TestProcessNVBFailExecCarriesWorkerIdentity(t *testing.T) {
	fq := &fakeJobQueue{}
	execs := &captureExecStore{}
	p := &reportPipeline{
		srv:         &server{},
		queue:       fq,
		execs:       execs,
		lease:       time.Minute,
		jobTimeout:  time.Minute,
		maxAttempts: 3,
	}
	// Invalid integration-inbound payload dead-letters immediately (same shape
	// as the M12 test) — the terminal FailExec must carry the lease holder.
	job := reports.Job{ID: "j1", JobType: jobTypeIntegrationInbound, TenantID: "acme",
		ExecutionID: "x1", Attempts: 3, Payload: []byte("{not json"), LockedBy: "w1"}
	p.process(context.Background(), "w1", job)
	execs.mu.Lock()
	defer execs.mu.Unlock()
	if len(execs.runningBy) != 1 || execs.runningBy[0] != "w1" {
		t.Fatalf("MarkRunning lockedBy = %v, want [w1]", execs.runningBy)
	}
	if len(execs.failedBy) != 1 || execs.failedBy[0] != "w1" {
		t.Fatalf("FailExec lockedBy = %v, want [w1]", execs.failedBy)
	}
}

var _ reports.DeliveryRecorder = (*nvLedger)(nil)
var _ reports.ExecutionStore = (*captureExecStore)(nil)
var _ reports.ArtifactStore = (nvArtifacts{})
