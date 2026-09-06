package collectors

// dem_runs_test.go — tracker 253, the PROBER half: one immutable run record per
// check, published on the same key-value channel the work queue arrives on.
//
// The record is what makes a flaky check distinguishable from a broken service.
// Two properties are load-bearing and are what these tests hold:
//   * a RUNNER fault is recorded as `error`, never as the target failing;
//   * the buffer is a rolling window that is republished WHOLE, because the
//     channel is a TTL'd key rather than a queue — a delta publication would
//     make a record visible for less than one api drain and lose it.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/internal/dem"
)

// captureRuns swaps the runner's publish seam for an in-memory capture.
func captureRuns(r *demRunner) *[][]dem.WireRun {
	var seen [][]dem.WireRun
	r.publishRuns = func(_ context.Context, runs []dem.WireRun) error {
		seen = append(seen, append([]dem.WireRun(nil), runs...))
		return nil
	}
	return &seen
}

func TestProberPublishesOneRunRecordPerCheck(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	h := newDEMHarness(t, []dem.WireTarget{
		{ID: "dem-up", Tenant: "acme", Kind: dem.KindHTTP, Host: up.URL, IntervalSec: 60},
		{ID: "dem-down", Tenant: "acme", Kind: dem.KindHTTP, Host: down.URL, IntervalSec: 60},
	})
	seen := captureRuns(h.runner)
	h.tick(t)

	if len(*seen) != 1 {
		t.Fatalf("publications = %d, want 1", len(*seen))
	}
	byTarget := map[string]dem.WireRun{}
	for _, r := range (*seen)[0] {
		byTarget[r.TargetID] = r
	}
	if len(byTarget) != 2 {
		t.Fatalf("run records = %d, want one per check: %+v", len(byTarget), (*seen)[0])
	}
	if got := byTarget["dem-up"]; got.Outcome != dem.RunSuccess || got.FailReason != "" {
		t.Fatalf("a healthy check recorded %+v", got)
	}
	if got := byTarget["dem-down"]; got.Outcome != dem.RunFailure || got.FailReason == "" {
		t.Fatalf("a failing check recorded %+v", got)
	}
	for id, r := range byTarget {
		if err := r.Validate(); err != nil {
			t.Fatalf("%s produced a record the api will refuse: %v (%+v)", id, err, r)
		}
		if r.Vantage != "test-prober" {
			t.Fatalf("%s recorded vantage %q — a run with the wrong vantage is not an independent observation", id, r.Vantage)
		}
		if r.Tenant != "acme" {
			t.Fatalf("%s recorded tenant %q", id, r.Tenant)
		}
	}
	if byTarget["dem-up"].ID == byTarget["dem-down"].ID {
		t.Fatal("two executions share one id — the api dedupes by id and would file only one of them")
	}
}

func TestRunnerFaultIsRecordedAsAnErrorNotATargetFailure(t *testing.T) {
	h := newDEMHarness(t, nil)
	// failClass "unknown" is what tick() records when the check function itself
	// could not produce a verdict (a panic caught by safego, an unreachable
	// kind). Grading that as a target failure is the confusion the reliability
	// model exists to prevent.
	got := demRun(
		dem.WireTarget{ID: "dem-1", Tenant: "acme", Kind: dem.KindHTTP, Host: "x"},
		demOutcome{ran: true, res: synResult{failClass: "unknown"}},
		"test-prober", time.Now().UTC())
	if got.Outcome != dem.RunError {
		t.Fatalf("outcome = %q, want %q", got.Outcome, dem.RunError)
	}
	_ = h
}

func TestRunBufferIsBoundedAndRepublishedWhole(t *testing.T) {
	h := newDEMHarness(t, nil)
	seen := captureRuns(h.runner)
	// Two cycles with no work still republish whatever the buffer holds, which
	// is how a record survives long enough for the api's next drain.
	h.runner.publishRunRecords(context.Background(),
		[]dem.WireRun{{ID: "a", Tenant: "acme", TargetID: "dem-1", Kind: dem.KindHTTP,
			Vantage: "p", StartedAt: time.Now().UTC(), Outcome: dem.RunSuccess}})
	h.runner.publishRunRecords(context.Background(), nil)
	if len(*seen) != 2 {
		t.Fatalf("publications = %d, want 2", len(*seen))
	}
	if len((*seen)[1]) != 1 || (*seen)[1][0].ID != "a" {
		t.Fatalf("the buffer was not republished whole: %+v", (*seen)[1])
	}

	over := make([]dem.WireRun, demRunBuffer+50)
	for i := range over {
		over[i] = dem.WireRun{ID: "r", Tenant: "acme", TargetID: "dem-1", Kind: dem.KindHTTP,
			Vantage: "p", StartedAt: time.Now().UTC(), Outcome: dem.RunSuccess}
	}
	h.runner.publishRunRecords(context.Background(), over)
	last := (*seen)[len(*seen)-1]
	if len(last) != demRunBuffer {
		t.Fatalf("buffer holds %d records, want the bound %d — an unbounded buffer on a 128 MiB container",
			len(last), demRunBuffer)
	}
}

func TestAFailedRunPublicationNeverCostsTheMeasurementCycle(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()
	h := newDEMHarness(t, []dem.WireTarget{
		{ID: "dem-1", Tenant: "acme", Kind: dem.KindHTTP, Host: up.URL, IntervalSec: 60},
	})
	h.runner.publishRuns = func(context.Context, []dem.WireRun) error {
		return errors.New("the key-value channel is down")
	}
	h.tick(t)
	if _, ok := h.lineFor(dem.MetricSuccess, "dem-1"); !ok {
		t.Fatal("a failed run publication suppressed the measurement series — the cycle must survive it")
	}
	if !h.runner.Status().Healthy {
		t.Fatal("a failed run publication marked the collector unhealthy; the measurement succeeded")
	}
}
