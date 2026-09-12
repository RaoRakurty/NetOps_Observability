// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

// probe_retry_test.go — the three defects the restorability probe carried into
// the 2026-09-12 review, each of which made the backup surface say something
// that was not true:
//
//	3.8-01  a probe that COULD NOT RUN was written down as a failed verify, and
//	        ProbeTick then skipped that snapshot forever.
//	3.8-04  the cleanup DELETE's 404 — the answer the cluster gives when the
//	        restore never created the temp index — was reported as a leak.
//	3.8-05  the scheduled probe bypassed the single operation slot every
//	        operator action takes, so it could collide with one and was invisible
//	        in GET /operations.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── 3.8-01 ──────────────────────────────────────────────────────────────────

// TestProbeTickRetriesAProbeThatCouldNotRun is the whole finding in one test: a
// transport failure must NOT become a permanent "verify failed" verdict, the
// tick must try again, and the recovered transport must produce a real verdict.
func TestProbeTickRetriesAProbeThatCouldNotRun(t *testing.T) {
	stub := newOSStub()
	stub.failRestore = true // the restore call itself fails: the probe cannot run
	log := &recordingLog{}
	h := newHarness(t, stub, func(d *Deps) { d.Log = log })

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)

	// 1. The failed attempt is recorded as an ATTEMPT, not as a verdict.
	rec, seen := h.svc.verdicts.all()["netops-daily-2026-09-02"]
	if !seen {
		t.Fatal("the attempt must be recorded so the retry can be bounded")
	}
	if !rec.Inconclusive || rec.Attempts != 1 {
		t.Fatalf("a probe that could not run must be inconclusive, attempt 1: %+v", rec)
	}
	if rec.Verified {
		t.Fatal("a probe that never compared anything must never read as verified")
	}

	// 2. The metric must NOT stamp a verdict timestamp. The vmalert rule reads a
	//    non-zero timestamp as "the probe RAN and the restore FAILED".
	restorable, verifiedAt, _ := h.svc.Metrics().Snapshot()
	if restorable {
		t.Error("an unrun probe must never report restorable=1")
	}
	if !verifiedAt.IsZero() {
		t.Errorf("a probe that never ran must leave the verdict timestamp at zero, got %v", verifiedAt)
	}

	// 3. The list view must NOT report a failed verification that never happened.
	st, b := h.do(t, "GET", "/api/system/backup/snapshots/list", nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var list SnapshotListView
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	var row *SnapshotView
	for i := range list.Snapshots {
		if list.Snapshots[i].Name == "netops-daily-2026-09-02" {
			row = &list.Snapshots[i]
		}
	}
	if row == nil {
		t.Fatal("the newest snapshot is missing from the list")
	}
	if row.RestorableVerified != nil {
		t.Fatalf("a probe that could not run must render as UNPROVEN (null), not as a failed verify: %v", *row.RestorableVerified)
	}
	if !strings.Contains(row.RestorableDetail, "could NOT be run") {
		t.Errorf("the detail must say the probe could not be run: %q", row.RestorableDetail)
	}

	// 4. The next tick RE-PROBES it — the defect was that it never did.
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if rec = h.svc.verdicts.all()["netops-daily-2026-09-02"]; rec.Attempts != 2 {
		t.Fatalf("the next tick must retry a probe that could not run, attempts=%d", rec.Attempts)
	}

	// 5. Once the transport recovers, a REAL verdict is recorded.
	stub.setFailRestore(false)
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	rec = h.svc.verdicts.all()["netops-daily-2026-09-02"]
	if rec.Inconclusive || !rec.Verified {
		t.Fatalf("a recovered transport must produce a real verdict: %+v", rec)
	}
	if restorable, verifiedAt, _ = h.svc.Metrics().Snapshot(); !restorable || verifiedAt.IsZero() {
		t.Errorf("the metric must carry the real verdict: restorable=%v at=%v", restorable, verifiedAt)
	}
}

// TestProbeTickStopsRetryingAfterTheAttemptBudget — a repository that refuses
// every restore must not be probed forever (§9 bounded everything).
func TestProbeTickStopsRetryingAfterTheAttemptBudget(t *testing.T) {
	stub := newOSStub()
	stub.failRestore = true
	h := newHarness(t, stub)

	var last time.Time
	for i := 0; i < maxProbeAttempts+3; i++ {
		h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	}
	rec := h.svc.verdicts.all()["netops-daily-2026-09-02"]
	if rec.Attempts != maxProbeAttempts {
		t.Fatalf("attempts must stop at the budget of %d, got %d", maxProbeAttempts, rec.Attempts)
	}
}

// TestProbeTickDoesNotRetryAGenuineVerificationFailure — a probe that RAN and
// disproved the snapshot is evidence. Re-running it nightly buys nothing, and
// the record must stay a real (negative) verdict.
func TestProbeTickDoesNotRetryAGenuineVerificationFailure(t *testing.T) {
	stub := newOSStub()
	stub.probeCount = 41 // one doc short of the live source: a real mismatch
	h := newHarness(t, stub)

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	rec := h.svc.verdicts.all()["netops-daily-2026-09-02"]
	if rec.Inconclusive || rec.Verified {
		t.Fatalf("a mismatch is a durable NEGATIVE verdict: %+v", rec)
	}
	if rec.At.IsZero() {
		t.Fatal("a real verdict must carry the time it was reached")
	}

	restores := 0
	for _, req := range h.stub.allRequests() {
		if strings.Contains(req, "/_restore") {
			restores++
		}
	}
	for i := 0; i < 5; i++ {
		h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	}
	after := 0
	for _, req := range h.stub.allRequests() {
		if strings.Contains(req, "/_restore") {
			after++
		}
	}
	if after != restores {
		t.Fatalf("a disproved snapshot must not be re-probed: %d restores became %d", restores, after)
	}
	// And the coverage row must call it what it is: a fail, with a verdict.
	row := h.svc.coverageRowForTest(t)
	if row.LastVerified == nil || row.LastVerified.Result != "fail" {
		t.Fatalf("a real mismatch must render as a failed verification: %+v", row.LastVerified)
	}
}

// TestCoverageDoesNotReportAnUnrunProbeAsAFailedVerify — the coverage table is
// read as evidence, and "the verify failed" and "the verify could not be run"
// send an operator down two different roads.
func TestCoverageDoesNotReportAnUnrunProbeAsAFailedVerify(t *testing.T) {
	stub := newOSStub()
	stub.failRestore = true
	h := newHarness(t, stub)

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)

	row := h.svc.coverageRowForTest(t)
	if row.LastVerified != nil {
		t.Fatalf("a probe that never ran is not a verification result: %+v", row.LastVerified)
	}
	if !strings.Contains(row.Detail, "could NOT be run") {
		t.Errorf("the row must say the probe could not be run: %q", row.Detail)
	}
}

// coverageRowForTest returns the OpenSearch coverage row.
func (s *Service) coverageRowForTest(t *testing.T) EngineCoverage {
	t.Helper()
	view := s.BuildCoverage(t.Context())
	for _, row := range view.Engines {
		if row.ID == "opensearch" {
			return row
		}
	}
	t.Fatalf("no opensearch coverage row in %+v", view.Engines)
	return EngineCoverage{}
}

// ── 3.8-04 ──────────────────────────────────────────────────────────────────

// TestProbeCleanup404IsNotALeak — OpenSearch answers 404 when the restore never
// created the temp index, which is the commonest way out of a failed probe.
// Reporting that as a leaked index tainted the verdict and logged an ERROR
// about something that had not happened.
func TestProbeCleanup404IsNotALeak(t *testing.T) {
	stub := newOSStub()
	stub.deleteTempStatus = 404
	log := &recordingLog{}
	h := newHarness(t, stub, func(d *Deps) { d.Log = log })

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !res.TempDeleted {
		t.Error("nothing was left behind, so the cleanup must not report a leak")
	}
	if strings.Contains(res.Detail, "could NOT be deleted") {
		t.Errorf("a 404 must not taint the verdict detail: %q", res.Detail)
	}
	for _, ln := range log.at("error") {
		t.Errorf("a 404 on the cleanup delete must not be logged as an error: %+v", ln)
	}
	if !h.stub.sent("DELETE /probe-netops-syslog-2026.09.02") {
		t.Error("the DELETE must still be attempted")
	}
}

// TestProbeCleanup500IsStillALeak — the other half: a real cleanup failure stays
// loud. (Guards against "fixing" the 404 by swallowing every cleanup error.)
func TestProbeCleanup500IsStillALeak(t *testing.T) {
	stub := newOSStub()
	stub.deleteTempStatus = 500
	log := &recordingLog{}
	h := newHarness(t, stub, func(d *Deps) { d.Log = log })

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.TempDeleted {
		t.Error("a 500 on the cleanup delete is a real leak")
	}
	if !strings.Contains(res.Detail, "could NOT be deleted") {
		t.Errorf("a real cleanup failure must surface in Detail: %q", res.Detail)
	}
	if !log.says("error", "could not delete its temporary index") {
		t.Error("a real cleanup failure must be logged as an error")
	}
}

// ── 3.8-05 ──────────────────────────────────────────────────────────────────

// TestProbeTickSkipsWhenTheOperationSlotIsHeld — the scheduled probe takes the
// same single slot every operator action takes, and when an operator holds it
// the probe SKIPS the tick (never queues behind, never races) and says so.
func TestProbeTickSkipsWhenTheOperationSlotIsHeld(t *testing.T) {
	stub := newOSStub()
	log := &recordingLog{}
	h := newHarness(t, stub, func(d *Deps) { d.Log = log })

	// An operator action holds the slot.
	held, conflict, ok := h.svc.ops.begin(OpKindSnapshotDelete, "alice", OperationTarget{Snapshot: "netops-daily-2026-09-02"})
	if !ok {
		t.Fatalf("could not claim the slot for the test: %q", conflict)
	}

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if h.stub.sent("/_restore") {
		t.Fatal("the scheduled probe must NOT restore while an operator operation holds the slot")
	}
	if !log.says("info", "SKIPPED") {
		t.Errorf("a skipped tick must say so: %+v", log.at("info"))
	}
	if _, seen := h.svc.verdicts.all()["netops-daily-2026-09-02"]; seen {
		t.Error("a skipped tick must not record anything about the snapshot")
	}
	if !last.IsZero() {
		t.Error("a skipped tick must not consume the probe interval")
	}

	// The operator's action ends; the next tick runs, and the probe is VISIBLE
	// in the operations register.
	h.svc.ops.finish(held.ID, func(o *Operation) { o.State = OpStateSucceeded })
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if !h.stub.sent("/_restore") {
		t.Fatal("with the slot free the scheduled probe must run")
	}
	if last.IsZero() {
		t.Error("a probe that ran must consume the probe interval")
	}

	var probeOp *Operation
	ops := h.svc.Operations()
	for i := range ops {
		if ops[i].Actor == probeActor {
			probeOp = &ops[i]
		}
	}
	if probeOp == nil {
		t.Fatalf("the scheduled probe must appear in the operations listing: %+v", ops)
	}
	if probeOp.Kind != OpKindSnapshotVerify || probeOp.State != OpStateSucceeded {
		t.Errorf("scheduled probe operation: kind=%s state=%s err=%s", probeOp.Kind, probeOp.State, probeOp.Error)
	}
	if probeOp.Verify == nil || !probeOp.Verify.Match {
		t.Errorf("the scheduled probe's operation must carry its evidence: %+v", probeOp.Verify)
	}
	if probeOp.EndedAt == nil {
		t.Error("a finished operation must carry an end time — and the slot must be released")
	}
	// The slot is free again: an operator action is accepted straight after.
	if _, conflict, ok := h.svc.ops.begin(OpKindSnapshotCreate, "alice", OperationTarget{}); !ok {
		t.Fatalf("the scheduled probe wedged the slot (held by %q)", conflict)
	}
}

// TestScheduledProbeFailureStillReleasesTheSlot — a probe that cannot run must
// end its operation `failed` and free the slot, never leave it held.
func TestScheduledProbeFailureStillReleasesTheSlot(t *testing.T) {
	stub := newOSStub()
	stub.failRestore = true
	h := newHarness(t, stub)

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)

	ops := h.svc.Operations()
	if len(ops) == 0 || ops[0].Actor != probeActor {
		t.Fatalf("the failed scheduled probe must be recorded: %+v", ops)
	}
	if ops[0].State != OpStateFailed || ops[0].Error == "" {
		t.Errorf("a probe that could not run must end failed, with the reason: %+v", ops[0])
	}
	if _, conflict, ok := h.svc.ops.begin(OpKindSnapshotCreate, "alice", OperationTarget{}); !ok {
		t.Fatalf("a failed scheduled probe wedged the slot (held by %q)", conflict)
	}
}
