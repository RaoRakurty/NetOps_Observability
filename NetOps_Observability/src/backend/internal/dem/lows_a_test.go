// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// lows_a_test.go — review findings 3.2-08, 3.2-13 and 3.2-14.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// brokenCatalogue answers every read with a store failure, which is what a
// database outage looks like from the API's side.
type brokenCatalogue struct{ Catalogue }

func (brokenCatalogue) Get(context.Context, string, string) (Target, error) {
	return Target{}, errStoreDown
}

var errStoreDown = &storeDownError{}

type storeDownError struct{}

func (*storeDownError) Error() string { return "dem: the catalogue is unreachable" }

// 3.2-08 — A CATALOGUE OUTAGE IS NOT A DELETED TARGET.
//
// The GET arm mapped EVERY store error to 404, with no log and no counter, so
// an operator watching a target disappear had no way to tell a deletion from a
// database that was simply down. The PUT and DELETE arms beside it have always
// split the two.
func TestTargetGetSeparatesAStoreFailureFromAnAbsentTarget(t *testing.T) {
	h := newAPIHarness(t, true, true)
	h.api.deps.Targets = brokenCatalogue{h.cat}

	code, body := h.call(t, http.MethodGet, TargetItemPath+"dem-0123456789abcdef0123456789abcdef", "")
	if code == http.StatusNotFound {
		t.Fatal("a catalogue outage answered 404 — the operator reads it as 'somebody deleted this target'")
	}
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d (%s), want 502", code, strings.TrimSpace(body))
	}
	if h.api.deps.Counters.QueryErrors.Load() == 0 {
		t.Fatal("the failure is invisible: no counter moved")
	}
}

// 3.2-13 — A RUN CANNOT CLAIM TO HAVE STARTED IN THE FUTURE.
//
// Validate bounds the record's shape but places no upper bound on StartedAt,
// and pruneLocked decides retention from the NEWEST run in a ring. A single
// far-future record therefore pinned its ring forever and permanently consumed
// one of the MaxTrackedDefinitions slots — a slot no operator could ever get
// back, from an untrusted field.
func TestRunStoreRefusesAFarFutureStart(t *testing.T) {
	now := time.Unix(1_757_000_000, 0).UTC()
	s := NewRunStore()
	s.now = func() time.Time { return now }

	future := WireRun{
		ID: "run-future", Tenant: "acme", TargetID: "tgt-1", Kind: KindICMP,
		Vantage: "probe-1", Outcome: RunSuccess, StartedAt: now.Add(48 * time.Hour),
	}
	res := s.Record([]WireRun{future})
	if res.Accepted != 0 {
		t.Fatal("a run dated 48 hours in the future was accepted — its ring can never be pruned and its definition slot is gone for good")
	}
	if res.Rejected != 1 {
		t.Fatalf("intake result = %+v, want one rejection", res)
	}

	// The bound is a SKEW bound, not a ban on clocks that run slightly fast.
	ok := future
	ok.ID = "run-ok"
	ok.StartedAt = now.Add(MaxClockSkew / 2)
	if res := s.Record([]WireRun{ok}); res.Accepted != 1 {
		t.Fatalf("a run inside the skew allowance was refused: %+v", res)
	}
}

// 3.2-14 — AN ENTIRELY PAUSED CATALOGUE SAYS SO.
//
// When every target is paused nothing scores, and the response-level reason was
// overwritten with no_prober: the operator was sent to debug a prober that was
// doing exactly what it had been told. Every ROW already said paused.
func TestExperienceSaysPausedNotNoProberWhenEveryTargetIsPaused(t *testing.T) {
	h := newAPIHarness(t, true, true)
	ctx := context.Background()
	for _, name := range []string{"checkout", "search"} {
		tgt, err := h.cat.Create(ctx, Target{
			TenantID: "acme", Name: name, Kind: KindICMP, Host: "10.0.0.1",
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		paused := true
		if _, err := h.cat.Update(ctx, "acme", tgt.ID, Patch{Paused: &paused}); err != nil {
			t.Fatalf("pause: %v", err)
		}
	}

	code, body := h.call(t, http.MethodGet, ExperiencePath, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, body)
	}
	var resp ExperienceResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Reason == ReasonNoProber {
		t.Fatal("an entirely paused catalogue reported no_prober — it sends the operator to debug a prober that is working")
	}
	if resp.Reason != ReasonPaused {
		t.Fatalf("reason = %q, want %q", resp.Reason, ReasonPaused)
	}
	if !strings.Contains(resp.Note, "paused") {
		t.Fatalf("the note does not say why: %q", resp.Note)
	}
}
