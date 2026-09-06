package dem

// runs.go — the PER-RUN record: the prober's immutable "this check executed and
// this is what happened", and the bounded store the api keeps them in.
//
// WHY THIS EXISTS (tracker 253). The prober publishes AGGREGATE series
// (dem_check_success, dem_check_latency_ms, …). A series can say "this check is
// failing"; it cannot say "this check changed its mind eleven times in the last
// hour", which is the only question that separates a real outage from a flaky
// test. experience.GradeReliability answers that question and the incident
// detector consults the answer before it raises a high-severity incident — but
// with no per-run records to grade, every check read `unknown` and the rule
// never bit.
//
// TRANSPORT: the SAME key-value channel that carries the work queue, in the
// opposite direction, with the same failure semantics — per-vantage key, short
// TTL, and a prober that loses the api simply stops contributing runs rather
// than accumulating them forever. The prober still holds no credential, still
// cannot call the api, and the record carries nothing a tenant would mind
// seeing in an unprivileged container: an id, its own catalogue id, an outcome
// and three timings.
//
// ISOLATION (§3a rule 4): the store is tenant-keyed, so a read for tenant A can
// only ever walk A's bucket, and a record whose tenant is not concrete is
// dropped rather than filed under a shared key.
//
// BOUNDS (§9): a fixed ring per definition and a fixed number of tracked
// definitions. A prober that publishes a million runs costs a fixed amount of
// memory; the OLDEST runs are the ones lost, which is the right end — grading
// reliability is a question about the recent past.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Run outcomes. Byte-identical to experience's RunSuccess/… on purpose: this is
// the wire half of that vocabulary, and the two are pinned together by
// TestWireRunOutcomesMatchTheExperienceVocabulary.
const (
	RunSuccess = "success"
	RunFailure = "failure"
	// RunError means the RUNNER broke, which is not the same as the target
	// failing and must never be graded as if it were.
	RunError   = "error"
	RunSkipped = "skipped"
)

var knownRunOutcomes = map[string]bool{
	RunSuccess: true, RunFailure: true, RunError: true, RunSkipped: true,
}

// ValidRunOutcome reports whether o is a declared outcome.
func ValidRunOutcome(o string) bool { return knownRunOutcomes[o] }

// WireRun is ONE execution of one catalogue target, as the prober publishes it.
//
// It is deliberately smaller than experience.SyntheticRun: the prober knows
// nothing about journeys, steps, definitions-as-documents or artifacts, and a
// field it cannot fill honestly is a field it must not carry.
type WireRun struct {
	// ID is unique per execution. It is what makes the channel idempotent: the
	// api re-reads the same TTL'd key many times before it expires, and a run
	// already in the ring is a duplicate, not a second execution.
	ID string `json:"id"`
	// Tenant owns the target and therefore the run. A run with no concrete
	// tenant is dropped: it could not be scoped to anyone.
	Tenant   string `json:"tenant"`
	TargetID string `json:"target_id"`
	Kind     string `json:"kind"`
	// Vantage is the observing prober. One vantage can never be its own second
	// opinion, so it is recorded rather than assumed.
	Vantage string `json:"vantage"`

	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Outcome    string `json:"outcome"`
	FailReason string `json:"fail_reason,omitempty"`

	DurationMs float64 `json:"duration_ms,omitempty"`
	TTFBMs     float64 `json:"ttfb_ms,omitempty"`
	StatusCode int     `json:"status_code,omitempty"`

	// Retries is how many attempts the runner made before recording this
	// outcome. The DEM runner makes none today (the next tick is the retry), so
	// it is 0 — declared now so a runner that does retry cannot land without
	// the reliability model seeing it.
	Retries int `json:"retries,omitempty"`
	// RunnerVersion lets selector/runner churn be attributed the day a browser
	// runner exists. Empty from today's prober.
	RunnerVersion string `json:"runner_version,omitempty"`
}

// MaxFailReasonBytes bounds the one free-form field on the record.
const MaxFailReasonBytes = 64

// Validate normalizes an UNTRUSTED record. Every field round-tripped through a
// shared datastore, so this is a boundary in the §3 sense even though we
// published it ourselves.
func (r *WireRun) Validate() error {
	r.ID = clip(strings.TrimSpace(r.ID), 128)
	if r.ID == "" {
		return errors.New("dem run: id is required")
	}
	t, err := concreteTenant(r.Tenant)
	if err != nil {
		return err
	}
	r.Tenant = t
	r.TargetID = clip(strings.TrimSpace(r.TargetID), 128)
	if r.TargetID == "" {
		return errors.New("dem run: target_id is required")
	}
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	if !ValidKind(r.Kind) {
		return errors.New("dem run: unknown check kind")
	}
	r.Vantage = clip(strings.TrimSpace(r.Vantage), 128)
	if r.Vantage == "" {
		return errors.New("dem run: vantage is required (a measurement with no vantage is not an independent observation)")
	}
	if !ValidRunOutcome(r.Outcome) {
		return errors.New("dem run: outcome must be success|failure|error|skipped")
	}
	if r.Outcome == RunSuccess && r.FailReason != "" {
		return errors.New("dem run: a successful run cannot carry a fail reason")
	}
	if r.StartedAt.IsZero() {
		return errors.New("dem run: started_at is required")
	}
	if !r.EndedAt.IsZero() && r.EndedAt.Before(r.StartedAt) {
		return errors.New("dem run: ended_at precedes started_at")
	}
	if r.Retries < 0 {
		return errors.New("dem run: retries must not be negative")
	}
	r.StartedAt, r.EndedAt = r.StartedAt.UTC(), r.EndedAt.UTC()
	r.FailReason = clip(strings.TrimSpace(r.FailReason), MaxFailReasonBytes)
	r.RunnerVersion = clip(strings.TrimSpace(r.RunnerVersion), 64)
	if r.DurationMs < 0 {
		r.DurationMs = 0
	}
	if r.TTFBMs < 0 {
		r.TTFBMs = 0
	}
	return nil
}

// Bounds on the store (§9). MaxRunsPerDefinition sits comfortably above
// experience.MinRunsForReliability (10) so a grade is computed from a real
// sample, and comfortably below anything that could grow into a memory problem:
// the worst case is MaxTrackedDefinitions × MaxRunsPerDefinition records.
const (
	MaxRunsPerDefinition  = 60
	MaxTrackedDefinitions = 5000
	// RunRetention is how long a definition's ring is kept after its newest
	// run. A target that stopped being measured stops being graded — its
	// coverage entry then reads "no check has succeeded recently", which is the
	// honest answer, not a stale `solid` from last week.
	RunRetention = 6 * time.Hour
	// MaxRunsPerIntake bounds one drain. A malformed or hostile payload cannot
	// make the api walk an unbounded list.
	MaxRunsPerIntake = 20000
)

// RunStore holds the recent runs per (tenant, target). In-memory ONLY and
// deliberately so: runs are graded over a short recent window, they are
// reconstructible from the prober within one retention period, and persisting
// them would add a write path whose failure mode is worse than the loss it
// prevents. A restarted api grades `unknown` until the rings refill, which is
// the honest state and is what the coverage surface renders.
type RunStore struct {
	mu sync.RWMutex
	// rows is tenant → target id → ring, oldest FIRST. The tenant key IS the
	// isolation boundary.
	rows map[string]map[string][]WireRun
	// seen is tenant → target id → the ids already in the ring, so a re-read of
	// the same published batch is a no-op. It is derived from rows and trimmed
	// with it, so it cannot outgrow the rings.
	tracked int
	now     func() time.Time
}

// NewRunStore builds an empty store.
func NewRunStore() *RunStore {
	return &RunStore{
		rows: map[string]map[string][]WireRun{},
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// RunIntakeResult reports what one drain did. Returned rather than logged
// inside so the caller owns the observability decision (§10).
type RunIntakeResult struct {
	Accepted  int
	Duplicate int
	Rejected  int // failed validation
	Dropped   int // refused because the store is at its definition bound
}

// Record folds a published batch into the store. Idempotent by run id.
func (s *RunStore) Record(runs []WireRun) RunIntakeResult {
	var res RunIntakeResult
	if s == nil {
		return res
	}
	if len(runs) > MaxRunsPerIntake {
		res.Dropped += len(runs) - MaxRunsPerIntake
		runs = runs[:MaxRunsPerIntake]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	for _, r := range runs {
		if err := r.Validate(); err != nil {
			res.Rejected++
			continue
		}
		bucket := s.rows[r.Tenant]
		if bucket == nil {
			bucket = map[string][]WireRun{}
			s.rows[r.Tenant] = bucket
		}
		ring, known := bucket[r.TargetID]
		if !known {
			if s.tracked >= MaxTrackedDefinitions {
				// Refuse the NEW definition rather than evicting a tracked
				// one at random: a store that silently sheds whichever ring
				// it happened to hit would make one tenant's grades depend on
				// another tenant's target count.
				res.Dropped++
				continue
			}
			s.tracked++
		}
		if runIDPresent(ring, r.ID) {
			res.Duplicate++
			continue
		}
		ring = append(ring, r)
		sort.SliceStable(ring, func(i, j int) bool { return ring[i].StartedAt.Before(ring[j].StartedAt) })
		if len(ring) > MaxRunsPerDefinition {
			ring = append([]WireRun(nil), ring[len(ring)-MaxRunsPerDefinition:]...)
		}
		bucket[r.TargetID] = ring
		res.Accepted++
	}
	return res
}

func runIDPresent(ring []WireRun, id string) bool {
	for _, r := range ring {
		if r.ID == id {
			return true
		}
	}
	return false
}

// pruneLocked drops rings whose newest run is older than RunRetention.
func (s *RunStore) pruneLocked() {
	cutoff := s.now().Add(-RunRetention)
	for tenant, bucket := range s.rows {
		for id, ring := range bucket {
			if len(ring) == 0 || ring[len(ring)-1].StartedAt.Before(cutoff) {
				delete(bucket, id)
				s.tracked--
			}
		}
		if len(bucket) == 0 {
			delete(s.rows, tenant)
		}
	}
	if s.tracked < 0 {
		s.tracked = 0
	}
}

// Runs returns one definition's ring, oldest first. A copy: the caller must not
// be able to mutate the store's history.
func (s *RunStore) Runs(tenant, targetID string) []WireRun {
	if s == nil {
		return nil
	}
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil // default-closed: no scope, no runs
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ring := s.rows[t][targetID]
	if len(ring) == 0 {
		return nil
	}
	return append([]WireRun(nil), ring...)
}

// RunsForTenant returns every tracked definition's ring for ONE tenant. There
// is no cross-tenant read on this store at all.
func (s *RunStore) RunsForTenant(tenant string) map[string][]WireRun {
	out := map[string][]WireRun{}
	if s == nil {
		return out
	}
	t, err := concreteTenant(tenant)
	if err != nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, ring := range s.rows[t] {
		if len(ring) == 0 {
			continue
		}
		out[id] = append([]WireRun(nil), ring...)
	}
	return out
}

// Tracked reports how many definitions currently hold a ring (the bound's
// observable side, for the status surface).
func (s *RunStore) Tracked() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tracked
}

// ── intake worker ───────────────────────────────────────────────────────────

// RunFetcher is the injected transport from the prober's channel.
type RunFetcher interface {
	FetchRuns(ctx context.Context) ([]WireRun, error)
}

// RunIntake drains the published run records on a timer.
type RunIntake struct {
	fetch    RunFetcher
	store    *RunStore
	interval time.Duration
	counters *Metrics
	logWarn  func(msg string, fields map[string]any)
}

// DefaultRunIntakeInterval is the drain cadence. Half the projector's, because
// the prober's key TTL is short and a missed drain loses runs outright — and
// runs are the evidence that a check is flaky, which is exactly the evidence a
// gap in sampling would hide.
const DefaultRunIntakeInterval = 30 * time.Second

// NewRunIntake fails CLOSED on missing collaborators rather than silently never
// draining (the failure mode where every check reads `unknown` forever and
// nobody can tell that from "no runs happened").
func NewRunIntake(f RunFetcher, store *RunStore, interval time.Duration, counters *Metrics,
	logWarn func(string, map[string]any)) (*RunIntake, error) {
	if f == nil || store == nil {
		return nil, errors.New("dem: the run intake needs both a fetcher and a store")
	}
	if logWarn == nil {
		return nil, errors.New("dem: the run intake needs a logger")
	}
	if interval < 5*time.Second || interval > 5*time.Minute {
		interval = DefaultRunIntakeInterval
	}
	if counters == nil {
		counters = NewMetrics()
	}
	return &RunIntake{fetch: f, store: store, interval: interval, counters: counters, logWarn: logWarn}, nil
}

// Interval exposes the resolved cadence.
func (i *RunIntake) Interval() time.Duration { return i.interval }

// RunOnce drains exactly once. Exported so the integrator can drain at boot and
// so tests need no clock.
func (i *RunIntake) RunOnce(ctx context.Context) error {
	// A fetcher may return BOTH a partial batch and an error (one vantage's
	// payload unreadable while the rest are fine). File what arrived and then
	// report the failure: discarding good evidence because a neighbour's was
	// corrupt is how one broken prober blinds the whole grade.
	runs, err := i.fetch.FetchRuns(ctx)
	if err != nil {
		i.counters.RunIntakeErrors.Add(1)
	}
	res := i.store.Record(runs)
	i.counters.RunsRecorded.Add(int64(res.Accepted))
	i.counters.RunsDuplicate.Add(int64(res.Duplicate))
	i.counters.RunsRejected.Add(int64(res.Rejected))
	i.counters.RunsDropped.Add(int64(res.Dropped))
	i.counters.RunsTracked.Store(int64(i.store.Tracked()))
	if res.Rejected > 0 || res.Dropped > 0 {
		// §10: never silent. A rejected run is a record we could not attribute;
		// a dropped one is the store's bound biting. Both change what the
		// coverage surface can say, so both are said out loud.
		i.logWarn("some experience run records could not be filed — the checks they belong to stay ungraded",
			map[string]any{"rejected": res.Rejected, "dropped": res.Dropped, "accepted": res.Accepted})
	}
	return err
}

// Run drains on a ticker until ctx is done. A failed drain is LOUD (counted +
// logged) and the loop continues: the store keeps its previous rings, which age
// out of RunRetention on their own if the prober never comes back.
func (i *RunIntake) Run(ctx context.Context) {
	if err := i.RunOnce(ctx); err != nil && ctx.Err() == nil {
		i.logWarn("the experience run records could not be read — check reliability stays ungraded until they can be",
			map[string]any{"err": err.Error()})
	}
	t := time.NewTicker(i.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := i.RunOnce(ctx); err != nil && ctx.Err() == nil {
				i.logWarn("the experience run records could not be read — check reliability stays ungraded until they can be",
					map[string]any{"err": err.Error()})
			}
		}
	}
}
