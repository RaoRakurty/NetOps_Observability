// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// trace_transient_test.go — a stage that FAILED ITS QUERY must be asked again.
//
// follow() settles a stage the moment its verdict is not `not_seen`, and the
// stages answer `not_observable` for a failed query as well as for a structural
// fact. One blip on the first poll therefore used to fix that stage's answer for
// the entire trace: an OpenSearch that was restarting for two seconds made the
// debugger report "OpenSearch query failed" for the next fifteen minutes and
// never looked again. The reason string named the failure, so it was not silent
// — it was simply wrong, and wrong in the direction ("we could not look") that
// sends an operator hunting the wrong hop.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// entryFor pulls one stage out of a follow's result.
func entryFor(t *testing.T, entries []Entry, st Stage) Entry {
	t.Helper()
	for _, e := range entries {
		if e.Stage == st {
			return e
		}
	}
	t.Fatalf("stage %s is absent from the follow's result (%d entries)", st, len(entries))
	return Entry{}
}

// osHit is a minimal OpenSearch answer carrying one document.
const osHit = `{"hits":{"total":{"value":1},"hits":[{"_index":"logs-acme","_id":"doc1","_source":{"timestamp":"2026-01-01T00:00:00Z","message":"hello"}}]}}`

// flakySearch fails the first n calls and then answers with a hit.
type flakySearch struct {
	mu    sync.Mutex
	calls int
	fail  int
}

func (f *flakySearch) do(_ string, _ string, _ any) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.fail {
		return nil, errors.New("dial tcp 10.0.0.5:9200: connect: connection refused")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(osHit)),
	}, nil
}

func (f *flakySearch) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// transientFollowDeps wires ONLY the OpenSearch stage. Every other server stage
// is structurally not-observable in this build (no Kafka peek, no ClickHouse
// client, no metric series for a syslog marker, no debug ring), so the follow
// finishes as soon as the OpenSearch stage settles — which is exactly the
// behaviour under test.
func transientFollowDeps(search func(string, string, any) (*http.Response, error)) Deps {
	return Deps{
		Search:         search,
		OSIndexPattern: func(signal, tenant string, cross bool) string { return "logs-" + signal },
	}
}

func TestATransientStageFailureIsRetriedOnTheNextPoll(t *testing.T) {
	f := &flakySearch{fail: 1}
	api := New(transientFollowDeps(f.do))

	// The TTL must outlast one poll interval: the point is that poll 2 happens.
	ctx, cancel := context.WithTimeout(context.Background(), 3*pollInterval)
	defer cancel()

	entries := api.follow(ctx, Principal{Subject: "owner", Cross: true}, "dbg-transient-1", KindSyslog, "acme")

	os := entryFor(t, entries, StageOpenSearch)
	if os.Verdict != VerdictSeen {
		t.Fatalf("opensearch verdict = %q (%s) after %d query attempts; want %q — the poll-1 query failure settled the stage and it was never asked again",
			os.Verdict, os.Reason, f.count(), VerdictSeen)
	}
	if f.count() < 2 {
		t.Fatalf("the opensearch stage was queried %d time(s); a transient failure must be retried", f.count())
	}
}

// TestAStructuralNotObservableIsNotRetried is the other half of the rule: a
// stage that cannot be observed here AT ALL must settle on the first poll, or
// the follow would burn its whole TTL re-asking a question whose answer cannot
// change.
func TestAStructuralNotObservableIsNotRetried(t *testing.T) {
	f := &flakySearch{fail: 0}
	deps := transientFollowDeps(f.do)
	deps.Search = nil // no OpenSearch client is wired into this build
	deps.OSIndexPattern = nil
	api := New(deps)

	ctx, cancel := context.WithTimeout(context.Background(), 3*pollInterval)
	defer cancel()

	start := time.Now()
	entries := api.follow(ctx, Principal{Subject: "owner", Cross: true}, "dbg-transient-2", KindSyslog, "acme")
	elapsed := time.Since(start)

	os := entryFor(t, entries, StageOpenSearch)
	if os.Verdict != VerdictNotObservable {
		t.Fatalf("opensearch verdict = %q, want %q", os.Verdict, VerdictNotObservable)
	}
	if os.Transient {
		t.Errorf("a missing client is a STRUCTURAL not-observable; it must not be marked transient (reason: %s)", os.Reason)
	}
	if elapsed >= pollInterval {
		t.Fatalf("the follow took %s — a structurally unobservable stage must settle on the first poll, not be re-polled", elapsed)
	}
}

// TestATransientFailureIsMarkedTransient pins the flag the retry rule reads, so
// a future stage that starts answering not-observable for a failed query is not
// silently added to the settle-on-first-blip set.
func TestATransientFailureIsMarkedTransient(t *testing.T) {
	f := &flakySearch{fail: 1}
	api := New(transientFollowDeps(f.do))
	e := api.OpenSearchStage(context.Background(), Principal{Subject: "owner", Cross: true}, KindSyslog, "dbg-transient-3", "acme")
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("verdict = %q, want %q", e.Verdict, VerdictNotObservable)
	}
	if !e.Transient {
		t.Fatalf("a failed OpenSearch query is TRANSIENT; entry was not marked so (reason: %s)", e.Reason)
	}
	if !strings.Contains(e.Reason, "OpenSearch query failed") {
		t.Errorf("reason %q does not name the query failure", e.Reason)
	}
}
