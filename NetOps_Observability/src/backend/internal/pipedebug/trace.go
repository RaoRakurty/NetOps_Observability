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
	// defaultRetention is how long a FINISHED trace stays pollable.
	//
	// It is a property of the STORE, not of the run: the run is bounded by its
	// TTL and the result outlives it. Carrying it as a field (rather than
	// reading this constant at the wait) is what lets the test prove both
	// halves of that sentence in milliseconds instead of half an hour.
	defaultRetention = 15 * time.Minute
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
	// Passive marks a follow that injected nothing. It is on the status, not
	// only on the receipt, so a reader who polls a status they did not start
	// still knows whether a synthetic record exists for this marker.
	Passive bool `json:"passive,omitempty"`
	// Stages carries every server-side stage's current entry, in pipeline order.
	Stages []Entry `json:"stages"`
}

// traceEntry is one live-or-retained trace.
//
// THE TWO LIFETIMES ARE SEPARATE, and keeping them separate is the whole point
// of this type:
//
//   - `cancel` bounds the RUN. It belongs to the follow's context.WithTimeout
//     (the TTL) and is released the moment the follow finishes.
//   - `gone` bounds the RESULT. It is closed only when the entry is actually
//     dropped — evicted by the maxLiveTraces bound, or torn down at shutdown —
//     and it is what the retention wait listens on.
//
// They used to be the same channel (the retention wait selected on the run's
// own ctx.Done()), which meant a finished trace was forgotten the instant its
// TTL expired: the stated 15-minute retention never once elapsed, and a caller
// who polled a settled trace a minute later got "no such trace".
type traceEntry struct {
	status *TraceStatus
	cancel context.CancelFunc
	gone   chan struct{}
}

type traceStore struct {
	mu   sync.Mutex
	byID map[string]*traceEntry
	seen []string // insertion order for the bound
	// retention is how long a finished result stays readable (seam for tests).
	retention time.Duration
	// stopped refuses new traces after a shutdown, so a late request cannot
	// resurrect a store that was just torn down.
	stopped bool
}

func newTraceStore() *traceStore {
	return &traceStore{byID: map[string]*traceEntry{}, retention: defaultRetention}
}

func (s *traceStore) get(marker string) (TraceStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[marker]
	if !ok {
		return TraceStatus{}, false
	}
	out := *e.status
	out.Stages = append([]Entry(nil), e.status.Stages...)
	return out, true
}

// put registers a trace and returns its DROP signal — the channel the retention
// wait uses to notice an eviction or a shutdown. It is deliberately not the run
// context: that one expires on schedule, and expiry is not a reason to discard
// the evidence the run produced.
func (s *traceStore) put(st *TraceStatus, cancel context.CancelFunc) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		cancel()
		dead := make(chan struct{})
		close(dead)
		return dead
	}
	e := &traceEntry{status: st, cancel: cancel, gone: make(chan struct{})}
	s.byID[st.Marker] = e
	s.seen = append(s.seen, st.Marker)
	for len(s.seen) > maxLiveTraces {
		victim := s.seen[0]
		s.seen = s.seen[1:]
		s.dropLocked(victim)
	}
	return e.gone
}

// dropLocked removes one entry, cancels its run and signals its waiter. It is
// the ONLY place `gone` is closed, and it deletes before closing, so the close
// can never happen twice.
func (s *traceStore) dropLocked(marker string) {
	e, ok := s.byID[marker]
	if !ok {
		return
	}
	delete(s.byID, marker)
	e.cancel()
	close(e.gone)
}

func (s *traceStore) update(marker string, entries []Entry, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[marker]
	if !ok {
		return
	}
	e.status.Stages = entries
	e.status.Done = done
}

func (s *traceStore) forget(marker string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(marker)
	kept := s.seen[:0]
	for _, m := range s.seen {
		if m != marker {
			kept = append(kept, m)
		}
	}
	s.seen = kept
}

// stop tears every trace down at once: no follow keeps running and no retention
// timer keeps a goroutine alive past the process's own life.
func (s *traceStore) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	for _, m := range s.seen {
		s.dropLocked(m)
	}
	s.seen = nil
}

// retain is the tail every follow ends in: release the RUN's context, then keep
// the finished result readable for the retention window — or until the entry is
// evicted or the store is stopped, which is the only thing that may cut it
// short.
func (s *traceStore) retain(marker string, cancel context.CancelFunc, gone <-chan struct{}) {
	cancel() // the follow is finished; its context has no further work to bound
	t := time.NewTimer(s.retention)
	defer t.Stop()
	select {
	case <-t.C:
		s.forget(marker)
	case <-gone:
		// Already dropped by the bound or by stop(); nothing left to forget.
	}
}

// Stop releases every live follow and retained result. It exists so a process
// (or a test) can tear the debugger down deterministically instead of leaving
// retention timers running behind it.
func (a *API) Stop() { a.traces.stop() }

// startPassive registers a PASSIVE follow. It shares the store, the bound and
// the retention of an active trace — a debug facility must not grow a second,
// differently-bounded lifecycle — and differs only in what it runs: no
// injection happened, so there is nothing to wait for and passiveFollow queries
// each stage once.
func (s *traceStore) startPassive(a *API, marker string, spec PassiveSpec, tenant string, p Principal, ttl time.Duration, persist *persistSpec) {
	now := a.deps.now()
	st := &TraceStatus{
		Marker: marker, Kind: spec.Kind, Device: spec.Device, Tenant: tenant,
		Started: now, Deadline: now.Add(ttl), Passive: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	gone := s.put(st, cancel)

	safego.Go("pipedebug-passive", func() {
		defer cancel() // belt and braces: retain() cancels on every normal path
		entries := a.passiveFollow(ctx, p, spec, marker)
		s.update(marker, entries, true)
		// The session is written from the FINISHED entries, once, before the
		// retention timer starts: a caller that comes back for the directory
		// must not race the in-memory result being dropped. The status is taken
		// through the store's own accessor — `st` is shared with update() and
		// reading it here directly would be a data race.
		if snap, ok := s.get(marker); ok {
			a.persistFinished(persist, snap, entries)
		}
		s.retain(marker, cancel, gone)
	})
}

// start registers a trace and launches its bounded follow goroutine.
func (s *traceStore) start(a *API, marker string, kind Kind, device, tenant string, p Principal, ttl time.Duration, persist *persistSpec) {
	now := a.deps.now()
	st := &TraceStatus{
		Marker: marker, Kind: kind, Device: device, Tenant: tenant,
		Started: now, Deadline: now.Add(ttl),
	}
	// The follow outlives the HTTP request that started it, so it gets its own
	// context bounded by the TTL — never the request's, which is cancelled the
	// moment the receipt is written.
	ctx, cancel := context.WithTimeout(context.Background(), ttl)
	gone := s.put(st, cancel)

	safego.Go("pipedebug-trace", func() {
		defer cancel() // belt and braces: retain() cancels on every normal path
		entries := a.follow(ctx, p, marker, kind, tenant)
		s.update(marker, entries, true)
		if snap, ok := s.get(marker); ok {
			a.persistFinished(persist, snap, entries)
		}
		// Retain the finished result for a bounded window so a poller — the CLI,
		// or the screen — can still read it AFTER the run's own TTL has passed,
		// then drop it: a debug result is evidence, not state.
		s.retain(marker, cancel, gone)
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
		return a.CorrelationStage(ctx, p, kind, marker)
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
