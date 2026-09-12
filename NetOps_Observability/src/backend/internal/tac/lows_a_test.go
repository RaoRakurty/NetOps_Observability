// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// lows_a_test.go — the review findings 3.1-03 · 3.1-04 · 3.1-13 · 3.1-14 ·
// 3.1-15 · 3.1-16, each proved by the behaviour it broke rather than by the shape of the
// code that fixed it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 3.1-03 — AN OUT-OF-BOUNDS PROBE IS FILED, NOT ERASED.
//
// `addBound` claims seen[intent] at the top of the closure, so the guard that
// filed an unrenderable probe as Unbound (`if !seen[intent]`) could never be
// true. The intent left BOTH lists and the plan then read as if every command
// it owned had been authored.
//
// ospf-adjacency binds reachability.unicast to `ping {peer}` on cisco-iosxe; a
// plan built with no Target has nothing to put in {peer}.
func TestUnrenderableProbeIsReportedUnbound(t *testing.T) {
	c := mustCatalog(t)
	p, err := c.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	const intent = "reachability.unicast"
	for _, st := range p.Steps {
		if st.Intent == intent {
			t.Fatalf("an unbounded probe was authored as a runnable step: %q", st.Command)
		}
	}
	var found *Step
	for i := range p.Unbound {
		if p.Unbound[i].Intent == intent {
			found = &p.Unbound[i]
			break
		}
	}
	if found == nil {
		t.Fatal("the probe intent is in neither Steps nor Unbound — it vanished, and the plan's coverage reads as complete")
	}
	if !strings.Contains(found.Note, "no address to probe") {
		t.Fatalf("the unbound step does not say why: %q", found.Note)
	}
}

// 3.1-04 — A DEDENTED BLOCK-SCALAR LINE IS PARSED, NOT A PANIC.
//
// parseBlockScalar fixed its indent base on the first body line and never
// re-floored it, so a later, less-indented line asked strings.Repeat for a
// negative count and panicked. The document below is reachable from the
// capture-upload route, where every other malformed upload gets a refusal.
func TestBlockScalarSurvivesADedentedBodyLine(t *testing.T) {
	doc := "" +
		"name: dedent\n" +
		"note: |\n" +
		"      first line is deeply indented\n" +
		"  second line is not\n" +
		"steps:\n" +
		"  - command: show version\n"
	n, err := parseYAML(doc)
	if err != nil {
		t.Fatalf("a dedented block scalar was refused instead of read: %v", err)
	}
	if n == nil {
		t.Fatal("no document")
	}
}

// 3.1-13 — THE REVIEWED ALLOW SET BELONGS TO ONE COLLECTION.
//
// Register was keyed on the bare device with no ownership, so a second
// escalation on the same device replaced the running collection's allow set and
// then deleted it on its own busy exit — the running collection's approved
// commands started being refused mid-flight.
func TestReviewRegistryIsOwnedByTheCollectionThatOpenedIt(t *testing.T) {
	reg := NewReviewRegistry()
	const dev = "dev-1"
	first := reg.Register(dev, []string{"show ip nhrp brief"})
	if first == 0 {
		t.Fatal("an idle device refused to open an allow set")
	}
	second := reg.Register(dev, []string{"show something else"})
	if second != 0 {
		t.Fatal("a second collection took over a live device's allow set")
	}
	if !reg.allows(dev, "show ip nhrp brief") {
		t.Fatal("the running collection's reviewed command was overwritten by the one that will be refused as busy")
	}
	// The refused collection's deferred Release must not take the running
	// collection's set with it.
	reg.Release(dev, second)
	if !reg.allows(dev, "show ip nhrp brief") {
		t.Fatal("a collection that never ran released the allow set of the one that did")
	}
	reg.Release(dev, first)
	if reg.Size() != 0 {
		t.Fatal("the owning collection's Release did not release")
	}
}

// 3.1-14 — A NEW COLLECTION INVALIDATES THE PREPARED CASE.
//
// StartCollect nils the capture the proposal was built from but left the
// proposal standing, so Confirm — which checks only that a proposal exists —
// could open a vendor case naming no device at all.
func TestStartingACollectionDropsThePreparedCase(t *testing.T) {
	f := newFake()
	cat := mustCatalog(t)
	plan, _ := cat.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	for _, st := range plan.Steps {
		f.out[st.Command] = "ok"
	}
	s := testService(t, WithCollector(testCollector(t, f)))
	if _, err := s.Plan("t1", "inc-1", "ospf-adjacency", iosxeDevice(), PlanOptions{}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	// The confirmation screen has been prepared from an EARLIER capture.
	s.mu.Lock()
	s.states["t1"]["inc-1"].Proposal = &Proposal{IncidentID: "inc-1", Ready: true}
	s.mu.Unlock()

	if _, err := s.StartCollect("t1", "inc-1", nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	if st := s.Get("t1", "inc-1"); st.Proposal != nil {
		t.Fatal("the prepared case outlived the capture it described — Confirm would open a case naming no device")
	}
	waitJob(t, s, "t1", "inc-1")

	_, cerr := s.Confirm(context.Background(), "t1", "inc-1", "someone", CaseForm{}, CaseSecrets{})
	if cerr == nil || !strings.Contains(cerr.Error(), "nothing has been prepared") {
		t.Fatalf("Confirm accepted a stale proposal: %v", cerr)
	}
}

// 3.1-16 — A FAILED FLUSH KEEPS THE LOG THE FILE HOLDS.
//
// PutRecord saved the live slice HEADER and put it back on a failed flush. The
// in-place sort had already permuted the array underneath it, so the rollback
// KEPT the record it had just reported as failed and DROPPED the oldest one —
// and the next successful write made both durable.
func TestPutRecordRollbackKeepsTheRecordsTheFileHolds(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "tac_learning.json")
	s := NewFileLearningStore(path)

	base := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	kept := map[string]bool{}
	for i := 0; i < 3; i++ {
		rec := LearningRecord{
			ID: NewRecordID(), TenantID: "tenant-a", IncidentID: "corr-1",
			DeviceID: "dev-1", Dialect: "cisco-iosxe",
			CollectedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := s.PutRecord(ctx, rec); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		kept[rec.ID] = true
	}

	// Make the next flush fail: the path becomes a directory, so the save
	// cannot write it. Nothing about the in-memory log has changed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}

	doomed := LearningRecord{
		ID: NewRecordID(), TenantID: "tenant-a", IncidentID: "corr-2",
		DeviceID: "dev-1", Dialect: "cisco-iosxe",
		CollectedAt: base.Add(time.Hour), // the NEWEST, so the sort moves it to the head
	}
	if err := s.PutRecord(ctx, doomed); err == nil {
		t.Fatal("a write onto an unwritable path reported success")
	}

	rows, err := s.Records(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	if len(rows) != len(kept) {
		t.Fatalf("the log changed size on a failed write: %d rows, wanted %d", len(rows), len(kept))
	}
	for _, r := range rows {
		if !kept[r.ID] {
			t.Fatalf("the REFUSED record %q is in the log", r.ID)
		}
		delete(kept, r.ID)
	}
	if len(kept) != 0 {
		t.Fatalf("a record the store had already made durable was dropped by the rollback: %v", kept)
	}
}

// 3.1-15 — THE DURABLE LINK OUTLIVES THE BROWSER.
//
// Both PersistCase calls ran on the CLIENT's request context, after the vendor
// case already existed. An operator closing the tab between the vendor's answer
// and the write lost the only durable link to a real, open case. fileLearning in
// this package already detaches for exactly this hazard.
func TestPersistCaseSurvivesAClientDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, p *gateProbe, r *http.Request)
	}{
		{"record", func(t *testing.T, p *gateProbe, r *http.Request) {
			t.Helper()
			p.api.recordCase(r, Subject{Tenant: "t1", IncidentID: "inc-1"},
				CaseResult{ConnectorID: "juniper", CaseID: "2026-1234", Status: "open"}, "S3")
		}},
		{"refresh", func(t *testing.T, p *gateProbe, r *http.Request) {
			t.Helper()
			p.api.deps.Tracker.Record("t1", "inc-1", CaseLink{
				Connector: "juniper", CaseID: "2026-1234", Status: "open", Pollable: true,
			})
			w := httptest.NewRecorder()
			p.api.HandleRefresh(w, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newGateProbe(t, testService(t), roleOperator)
			var got context.Context
			p.api.deps.PersistCase = func(ctx context.Context, _, _ string, _ CaseLink) { got = ctx }

			ctx, cancel := context.WithCancel(context.Background())
			cancel() // the operator's browser is gone
			r := httptest.NewRequest(http.MethodPost, "/api/incidents/inc-1/tac/case", nil).WithContext(ctx)
			r.SetPathValue("id", "inc-1")
			tc.run(t, p, r)

			if got == nil {
				t.Fatal("the case link was never persisted at all")
			}
			if err := got.Err(); err != nil {
				t.Fatalf("the case link was written on the CLIENT's dead context (%v) — a disconnect loses the link to a case that exists at the vendor", err)
			}
		})
	}
}
