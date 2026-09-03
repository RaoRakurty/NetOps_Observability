package pipedebug

// trace.go — the async follow behind POST /api/debug/trace.
//
// WHY ASYNC. A record takes seconds to cross the pipeline, and the stores are
// polled: doing that inside the request would hold an HTTP handler open for the
// TTL and turn a debug call into a slow-loris on the API's own worker pool. The
// POST therefore returns a receipt immediately and one bounded goroutine polls
// the server-side stages until every stage has settled or the TTL expires; the
// CLI polls GET /api/debug/trace/{marker}.
//
// EVERY DIMENSION IS BOUNDED (§9). At most maxLiveTraces run at once, each for
// at most its clamped TTL, each polling on a fixed interval; finished traces are
// retained for retention and then dropped. A debug facility must not be able to
// grow the API's memory or goroutine count without limit.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"netops/backend/safego"
)

const (
	// maxLiveTraces bounds concurrent follows AND retained results.
	maxLiveTraces = 16
	// pollInterval is how often an unsettled stage is re-queried.
	pollInterval = 3 * time.Second
	// retention is how long a finished trace stays pollable.
	retention = 15 * time.Minute
)

// TraceStatus is what GET /api/debug/trace/{marker} returns.
type TraceStatus struct {
	Marker   string    `json:"marker"`
	Kind     Kind      `json:"kind"`
	Device   string    `json:"device"`
	Tenant   string    `json:"tenant"`
	Started  time.Time `json:"started"`
	Deadline time.Time `json:"deadline"`
	Done     bool      `json:"done"`
	// Stages carries every server-side stage's current entry, in pipeline order.
	Stages []Entry `json:"stages"`
}

type traceStore struct {
	mu   sync.Mutex
	byID map[string]*TraceStatus
	// cancel lets Stop tear a follow down (process shutdown, tests).
	cancel map[string]context.CancelFunc
	seen   []string // insertion order for the bound
}

func newTraceStore() *traceStore {
	return &traceStore{byID: map[string]*TraceStatus{}, cancel: map[string]context.CancelFunc{}}
}

func (s *traceStore) get(marker string) (TraceStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byID[marker]
	if !ok {
		return TraceStatus{}, false
	}
	out := *st
	out.Stages = append([]Entry(nil), st.Stages...)
	return out, true
}

func (s *traceStore) put(st *TraceStatus, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[st.Marker] = st
	s.cancel[st.Marker] = cancel
	s.seen = append(s.seen, st.Marker)
	for len(s.seen) > maxLiveTraces {
		victim := s.seen[0]
		s.seen = s.seen[1:]
		if c, ok := s.cancel[victim]; ok {
			c()
			delete(s.cancel, victim)
		}
		delete(s.byID, victim)
	}
}

func (s *traceStore) update(marker string, entries []Entry, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byID[marker]
	if !ok {
		return
	}
	st.Stages = entries
	st.Done = done
}

func (s *traceStore) forget(marker string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cancel[marker]; ok {
		c()
		delete(s.cancel, marker)
	}
	delete(s.byID, marker)
	kept := s.seen[:0]
	for _, m := range s.seen {
		if m != marker {
			kept = append(kept, m)
		}
	}
	s.seen = kept
}

// start registers a trace and launches its bounded follow goroutine.
func (s *traceStore) start(a *API, marker string, kind Kind, device, tenant string, p Principal, ttl time.Duration) {
	now := a.deps.now()
	st := &TraceStatus{
		Marker: marker, Kind: kind, Device: device, Tenant: tenant,
		Started: now, Deadline: now.Add(ttl),
	}
	// The follow outlives the HTTP request that started it, so it gets its own
	// context bounded by the TTL — never the request's, which is cancelled the
	// moment the receipt is written.
	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	s.put(st, cancel)

	safego.Go("pipedebug-trace", func() {
		defer cancel()
		entries := a.follow(ctx, p, marker, kind, tenant)
		s.update(marker, entries, true)
		// Retain the finished result for a bounded window so the CLI can poll
		// it, then drop it: a debug result is evidence, not state.
		t := time.NewTimer(retention)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		s.forget(marker)
	})
}

// follow polls every server-side stage until each has a settled verdict or the
// context expires, updating the status as it goes so a poller sees progress.
//
// A stage SETTLES on `seen` or `not_observable`. `not_seen` is retried, because
// early in a trace it only means "not yet" — reporting the first miss as the
// answer is how a debugger tells you the pipeline is broken when it is merely
// fast. On timeout the last `not_seen` stands, with the wait recorded.
func (a *API) follow(ctx context.Context, p Principal, marker string, kind Kind, tenant string) []Entry {
	settled := map[Stage]Entry{}
	started := a.deps.now()

	poll := func() bool {
		allSettled := true
		for _, st := range ServerStages {
			if e, ok := settled[st]; ok && e.Verdict != VerdictNotSeen {
				continue
			}
			e := a.stageCtx(ctx, p, st, kind, marker, tenant)
			settled[st] = e
			if e.Verdict == VerdictNotSeen {
				allSettled = false
			}
		}
		return allSettled
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for !poll() {
		a.traces.update(marker, orderedEntries(settled, started, a.deps.now()), false)
		select {
		case <-ctx.Done():
			return orderedEntries(settled, started, a.deps.now())
		case <-ticker.C:
		}
	}
	return orderedEntries(settled, started, a.deps.now())
}

// stageCtx is stage() without an *http.Request — the follow has no request.
func (a *API) stageCtx(ctx context.Context, p Principal, stage Stage, kind Kind, marker, tenant string) Entry {
	switch stage {
	case StageKafka:
		return a.KafkaStage(ctx, kind, marker)
	case StageOpenSearch:
		return a.OpenSearchStage(ctx, p, kind, marker, tenant)
	case StageVictoria:
		return a.VictoriaStage(ctx, kind, marker)
	case StageClickHouse:
		return a.ClickHouseStage(ctx, p, kind, marker)
	case StageCorrelation:
		return a.CorrelationStage(ctx, p, marker)
	case StageAPI:
		return a.APIStage(marker)
	default:
		return notObservable(Entry{Stage: stage, Module: string(stage)},
			"this stage has no server-side evidence source")
	}
}

// orderedEntries renders the settled map in pipeline order, stamping how long a
// still-unseen stage has been waited on so a reader can tell "not there" from
// "we only looked once".
func orderedEntries(settled map[Stage]Entry, started, now time.Time) []Entry {
	out := make([]Entry, 0, len(settled))
	for _, st := range Stages {
		e, ok := settled[st]
		if !ok {
			continue
		}
		if e.Verdict == VerdictNotSeen {
			e.Reason = e.Reason + fmt.Sprintf(" (waited %s)", now.Sub(started).Round(time.Second))
		}
		out = append(out, e)
	}
	return out
}
