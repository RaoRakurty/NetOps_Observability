// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// lows_a_test.go — review findings 3.2-07 and 3.2-12.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// brokenJourneyStore answers the journey read with a store failure — what a
// database outage looks like from the handler's side. Everything else is the
// real file store, so only the one path under test changes.
type brokenJourneyStore struct {
	Store
	err error
}

func (b brokenJourneyStore) GetJourney(context.Context, string, string) (JourneyDefinition, error) {
	return JourneyDefinition{}, b.err
}

// 3.2-07 — A STORE OUTAGE IS NOT A DELETED JOURNEY.
//
// The GET arm mapped EVERY store error to 404, so a database outage read as
// "somebody deleted this journey". The PUT and DELETE arms beside it split
// ErrNotFound from a failure correctly. Both backends return ErrNotFound for a
// cross-tenant id, so the §3a answer is unchanged by the split.
func TestJourneyGetSeparatesAStoreFailureFromAnAbsentJourney(t *testing.T) {
	api, counters := newTestAPI(t, nil)
	api.deps.Store = brokenJourneyStore{Store: api.deps.Store, err: errors.New("dial tcp: connection refused")}

	code, body := call(t, api.HandleJourneyItem, http.MethodGet,
		JourneyItemPath+"jny-0123456789abcdef0123456789abcdef", "", nil)
	if code == http.StatusNotFound {
		t.Fatal("a store outage answered 404 — an operator reads that as a journey somebody deleted")
	}
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d: %s", code, body)
	}
	if counters.QueryErrors.Load() == 0 {
		t.Fatal("the failure moved no counter: it is invisible on /metrics")
	}
	if strings.Contains(string(body), "connection refused") {
		t.Fatalf("the store's own error text was handed to the caller: %s", body)
	}
}

// 3.2-12 — EVERY COUNTER THIS MODULE KEEPS CAN BE RENDERED.
//
// metricHelp named 9 of the 15 counters and Write iterates metricHelp, so the
// ingest refusals, the ingest rejections and the promotion errors could never
// reach /metrics however high they climbed. This is the ratchet: a counter
// added to Snapshot with no HELP line fails here rather than shipping blind.
func TestEveryCounterHasAHelpLineAndIsRendered(t *testing.T) {
	c := NewCounters()
	snap := c.Snapshot()

	helped := map[string]bool{}
	for _, name := range helpedMetrics() {
		if _, ok := snap[name]; !ok {
			t.Errorf("metricHelp documents %q, which no counter reports", name)
		}
		helped[name] = true
	}
	missing := []string{}
	for name := range snap {
		if !helped[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d counter(s) can never be rendered — they have no HELP line, so Write skips them: %v",
			len(missing), missing)
	}

	// And the render actually carries them.
	c.IngestRefused.Add(7)
	c.PromotionErrors.Add(3)
	var sb strings.Builder
	c.Write(&sb)
	out := sb.String()
	for _, want := range []string{
		"dem_experience_ingest_refused_total 7",
		"dem_experience_promotion_errors_total 3",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the exposition does not carry %q:\n%s", want, out)
		}
	}
}
