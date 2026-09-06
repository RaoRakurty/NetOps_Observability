package dem

// runs_test.go — tracker 253: the per-run record channel's api half.
//
// What is proven here is what the reliability grade depends on being true:
// the store is tenant-keyed and has NO cross-tenant read, it is bounded in both
// dimensions, and a re-read of the same still-published batch is a no-op rather
// than a fabricated second execution — which would turn one run into ten and
// make an ungraded check look graded.

import (
	"context"
	"errors"
	"testing"
	"time"
)

var runNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func wireRun(id, tenant, target string, at time.Time, outcome string) WireRun {
	return WireRun{
		ID: id, Tenant: tenant, TargetID: target, Kind: KindHTTP, Vantage: "prober",
		StartedAt: at, EndedAt: at.Add(150 * time.Millisecond), Outcome: outcome,
	}
}

func newTestRunStore() *RunStore {
	s := NewRunStore()
	s.now = func() time.Time { return runNow }
	return s
}

func TestRunStoreIsTenantKeyedAndHasNoCrossTenantRead(t *testing.T) {
	s := newTestRunStore()
	s.Record([]WireRun{
		wireRun("a1", "acme", "dem-1", runNow, RunSuccess),
		wireRun("b1", "globex", "dem-9", runNow, RunFailure),
	})
	if got := s.Runs("acme", "dem-9"); len(got) != 0 {
		t.Fatalf("acme read globex's target: %+v", got)
	}
	if got := s.RunsForTenant("acme"); len(got) != 1 || len(got["dem-1"]) != 1 {
		t.Fatalf("acme's own runs are wrong: %+v", got)
	}
	for _, scope := range []string{"", "*", "  ", "ACME "} {
		got := s.RunsForTenant(scope)
		if scope == "ACME " {
			// normalization, not a wildcard: the trimmed/lowered tenant IS acme
			if len(got) != 1 {
				t.Fatalf("a normalizable tenant lost its own rows: %+v", got)
			}
			continue
		}
		if len(got) != 0 {
			t.Fatalf("scope %q read %d definitions — a scopeless read must return nothing, never everything", scope, len(got))
		}
	}
}

func TestRunStoreIsIdempotentByRunID(t *testing.T) {
	s := newTestRunStore()
	batch := []WireRun{
		wireRun("a1", "acme", "dem-1", runNow.Add(-2*time.Minute), RunSuccess),
		wireRun("a2", "acme", "dem-1", runNow.Add(-time.Minute), RunFailure),
	}
	first := s.Record(batch)
	second := s.Record(batch) // the channel is a TTL'd key; the api re-reads it
	if first.Accepted != 2 || first.Duplicate != 0 {
		t.Fatalf("first drain: %+v", first)
	}
	if second.Accepted != 0 || second.Duplicate != 2 {
		t.Fatalf("a re-read of the same batch was filed as new runs: %+v", second)
	}
	if got := s.Runs("acme", "dem-1"); len(got) != 2 {
		t.Fatalf("ring holds %d runs, want 2", len(got))
	}
}

func TestRunStoreRingIsBoundedAndKeepsTheNewest(t *testing.T) {
	s := newTestRunStore()
	batch := make([]WireRun, 0, MaxRunsPerDefinition+20)
	for i := 0; i < MaxRunsPerDefinition+20; i++ {
		batch = append(batch, wireRun(
			"r"+itoa(i), "acme", "dem-1",
			runNow.Add(time.Duration(i-(MaxRunsPerDefinition+20))*time.Minute), RunSuccess))
	}
	s.Record(batch)
	got := s.Runs("acme", "dem-1")
	if len(got) != MaxRunsPerDefinition {
		t.Fatalf("ring holds %d, want the bound %d", len(got), MaxRunsPerDefinition)
	}
	if got[0].StartedAt.After(got[len(got)-1].StartedAt) {
		t.Fatal("the ring is not oldest-first")
	}
	if got[len(got)-1].ID != "r"+itoa(MaxRunsPerDefinition+19) {
		t.Fatalf("the newest run was evicted: last id %q", got[len(got)-1].ID)
	}
}

func TestRunStoreRefusesRecordsItCannotAttribute(t *testing.T) {
	s := newTestRunStore()
	res := s.Record([]WireRun{
		{ID: "", Tenant: "acme", TargetID: "dem-1", Kind: KindHTTP, Vantage: "p", StartedAt: runNow, Outcome: RunSuccess},
		{ID: "x", Tenant: "*", TargetID: "dem-1", Kind: KindHTTP, Vantage: "p", StartedAt: runNow, Outcome: RunSuccess},
		{ID: "x", Tenant: "acme", TargetID: "", Kind: KindHTTP, Vantage: "p", StartedAt: runNow, Outcome: RunSuccess},
		{ID: "x", Tenant: "acme", TargetID: "dem-1", Kind: "quantum", Vantage: "p", StartedAt: runNow, Outcome: RunSuccess},
		{ID: "x", Tenant: "acme", TargetID: "dem-1", Kind: KindHTTP, Vantage: "", StartedAt: runNow, Outcome: RunSuccess},
		{ID: "x", Tenant: "acme", TargetID: "dem-1", Kind: KindHTTP, Vantage: "p", StartedAt: runNow, Outcome: "great"},
		{ID: "x", Tenant: "acme", TargetID: "dem-1", Kind: KindHTTP, Vantage: "p", Outcome: RunSuccess},
		{ID: "x", Tenant: "acme", TargetID: "dem-1", Kind: KindHTTP, Vantage: "p", StartedAt: runNow, Outcome: RunSuccess, FailReason: "timeout"},
	})
	if res.Accepted != 0 {
		t.Fatalf("an unattributable record was filed: %+v", res)
	}
	if res.Rejected != 8 {
		t.Fatalf("rejected %d of 8 invalid records — a record that slips through is graded as if it were real", res.Rejected)
	}
}

func TestRunStorePrunesRingsPastRetention(t *testing.T) {
	s := newTestRunStore()
	s.Record([]WireRun{wireRun("old", "acme", "dem-1", runNow.Add(-RunRetention-time.Hour), RunSuccess)})
	if s.Tracked() != 1 {
		t.Fatalf("tracked = %d, want 1", s.Tracked())
	}
	// The next drain prunes: a target that stopped being measured stops being
	// graded rather than carrying last week's verdict forever.
	s.Record([]WireRun{wireRun("new", "acme", "dem-2", runNow, RunSuccess)})
	if got := s.Runs("acme", "dem-1"); len(got) != 0 {
		t.Fatalf("a ring past retention survived: %+v", got)
	}
	if s.Tracked() != 1 {
		t.Fatalf("tracked = %d after prune, want 1", s.Tracked())
	}
}

func TestRunStoreBoundsTheNumberOfTrackedDefinitions(t *testing.T) {
	s := newTestRunStore()
	batch := make([]WireRun, 0, MaxTrackedDefinitions+5)
	for i := 0; i < MaxTrackedDefinitions+5; i++ {
		batch = append(batch, wireRun("r"+itoa(i), "acme", "dem-"+itoa(i), runNow, RunSuccess))
	}
	res := s.Record(batch)
	if s.Tracked() != MaxTrackedDefinitions {
		t.Fatalf("tracked = %d, want the bound %d", s.Tracked(), MaxTrackedDefinitions)
	}
	if res.Dropped != 5 {
		t.Fatalf("dropped = %d, want 5 — the bound must be VISIBLE, not silent", res.Dropped)
	}
}

func TestRunStoreCapsOneDrain(t *testing.T) {
	s := newTestRunStore()
	batch := make([]WireRun, MaxRunsPerIntake+10)
	for i := range batch {
		batch[i] = wireRun("r"+itoa(i), "acme", "dem-1", runNow, RunSuccess)
	}
	res := s.Record(batch)
	if res.Dropped < 10 {
		t.Fatalf("an oversized drain was walked in full: %+v", res)
	}
}

// ── the intake worker ───────────────────────────────────────────────────────

type stubRunFetcher struct {
	runs []WireRun
	err  error
	hits int
}

func (f *stubRunFetcher) FetchRuns(context.Context) ([]WireRun, error) {
	f.hits++
	return f.runs, f.err
}

func TestRunIntakeFailsClosedOnMissingCollaborators(t *testing.T) {
	if _, err := NewRunIntake(nil, NewRunStore(), 0, nil, func(string, map[string]any) {}); err == nil {
		t.Fatal("a run intake with no fetcher was built — it would drain nothing and say nothing")
	}
	if _, err := NewRunIntake(&stubRunFetcher{}, nil, 0, nil, func(string, map[string]any) {}); err == nil {
		t.Fatal("a run intake with no store was built")
	}
	if _, err := NewRunIntake(&stubRunFetcher{}, NewRunStore(), 0, nil, nil); err == nil {
		t.Fatal("a run intake with no logger was built — its failures would be invisible")
	}
}

func TestRunIntakeFilesAPartialBatchAndStillReportsTheError(t *testing.T) {
	store := newTestRunStore()
	counters := NewMetrics()
	f := &stubRunFetcher{
		runs: []WireRun{wireRun("a1", "acme", "dem-1", runNow, RunSuccess)},
		err:  errors.New("one vantage batch was unreadable"),
	}
	in, err := NewRunIntake(f, store, DefaultRunIntakeInterval, counters, func(string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if rerr := in.RunOnce(context.Background()); rerr == nil {
		t.Fatal("a partial drain hid its error — one broken prober would silently degrade every grade")
	}
	if got := store.Runs("acme", "dem-1"); len(got) != 1 {
		t.Fatal("the good half of a partial drain was discarded")
	}
	if counters.RunIntakeErrors.Load() != 1 || counters.RunsRecorded.Load() != 1 {
		t.Fatalf("counters: errors=%d recorded=%d", counters.RunIntakeErrors.Load(), counters.RunsRecorded.Load())
	}
	if counters.RunsTracked.Load() != 1 {
		t.Fatalf("runs_tracked = %d, want 1", counters.RunsTracked.Load())
	}
}

func TestRunIntakeClampsAnAbsurdInterval(t *testing.T) {
	in, err := NewRunIntake(&stubRunFetcher{}, NewRunStore(), time.Millisecond, nil, func(string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if in.Interval() != DefaultRunIntakeInterval {
		t.Fatalf("interval = %s, want the default — a millisecond drain is a busy loop", in.Interval())
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
