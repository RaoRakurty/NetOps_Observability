// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// baseline_test.go — tracker 281. The detection the honesty fix (1bf933fa)
// deliberately did not build, and the false positives it must not become.
//
// THE CASE UNDER TEST. A prefix with NO declared expected origin, which is the
// shipped default. An origin change reaches every vantage point. Before the
// persisted baseline, that change BECAME the baseline in the same pass: the
// real origin fell below MinVantages, was filed as a corroboration shortfall,
// and the verdict was ClassNone. The whole point of the store is that the pass
// is now compared against a row written EARLIER, which does not move.
//
// RED-BEFORE. Wire the evaluator with Baselines: nil (the pre-persistence
// behaviour, which is still a supported deployment) and
// TestFullyPropagatedOriginChangeIsUndetectableWithNoBaselineRegister pins that
// the same two passes produce NOTHING. The two tests are the before and after
// of the same input, in the same file, on purpose.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// baselineRig is the offline evaluator rig for this file: one tenant, one
// watched prefix, NO declared expected origin, and a baseline register that can
// be turned off to stage the red case. Every upstream is a scripted fake (§11:
// CI has no network, no bus and no Postgres).
type baselineRig struct {
	mu       sync.Mutex
	now      time.Time
	watch    []string
	obs      map[string]Observation
	fired    []Alert
	resolved []Alert
	warns    []string

	store BaselineStore
	eval  *Evaluator
}

func newBaselineRig(t *testing.T, store BaselineStore) *baselineRig {
	t.Helper()
	r := &baselineRig{
		now:   clsNow,
		watch: []string{"193.0.0.0/21"},
		obs:   map[string]Observation{"193.0.0.0/21": healthy()},
		store: store,
	}
	// NOTHING DECLARED. That is the shipped default and the only configuration
	// in which tracker 281's blind spot exists at all.
	policies := NewFileStore("")
	if err := policies.SetPolicy(context.Background(), "acme", "tester", TenantPolicy{}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	deps := Deps{
		Now:      func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
		Interval: time.Minute,
		Cooldown: 30 * time.Minute,
		Tenants:  func() []string { return []string{"acme"} },
		Watchlist: func(_ context.Context, tn string) ([]string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if tn != "acme" {
				return nil, nil
			}
			return append([]string(nil), r.watch...), nil
		},
		Policies: policies,
		Observe: func(_ context.Context, p string) (Observation, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			o, ok := r.obs[p]
			if !ok {
				return Observation{}, errors.New("no scripted observation for " + p)
			}
			o.Prefix = p
			return o, nil
		},
		Notify:   func(a Alert) { r.mu.Lock(); defer r.mu.Unlock(); r.fired = append(r.fired, a) },
		Resolve:  func(a Alert) { r.mu.Lock(); defer r.mu.Unlock(); r.resolved = append(r.resolved, a) },
		Bogons:   NewBogonSet(),
		LogWarn:  func(m string, _ map[string]any) { r.mu.Lock(); defer r.mu.Unlock(); r.warns = append(r.warns, m) },
		LogError: func(string, map[string]any) {},
		Rand:     fixedJitter,
		Sleep:    noSleep,
	}
	if store != nil {
		deps.Baselines = store
	}
	e, err := New(deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.eval = e
	return r
}

func (r *baselineRig) set(prefix string, o Observation) {
	r.mu.Lock()
	r.obs[prefix] = o
	r.mu.Unlock()
}

func (r *baselineRig) pass(t *testing.T, d time.Duration) {
	t.Helper()
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
	r.eval.RunOnce(context.Background())
}

func (r *baselineRig) incident(t *testing.T, prefix string) Incident {
	t.Helper()
	list, err := r.eval.Incidents("acme")
	if err != nil {
		t.Fatalf("Incidents: %v", err)
	}
	for _, inc := range list {
		if inc.Prefix == prefix {
			return inc
		}
	}
	t.Fatalf("no incident recorded for %s", prefix)
	return Incident{}
}

func (r *baselineRig) alerts() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.fired...)
}

func (r *baselineRig) resolutions() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Alert(nil), r.resolved...)
}

// ── THE RED CASE: no register, nothing is detected ──────────────────────────

// TestFullyPropagatedOriginChangeIsUndetectableWithNoBaselineRegister is the
// before half of the pair, and it is a REGRESSION GUARD in its own right: it
// pins exactly what a deployment with no baseline register can and cannot see,
// so nobody can later claim the pre-persistence path detects this.
func TestFullyPropagatedOriginChangeIsUndetectableWithNoBaselineRegister(t *testing.T) {
	r := newBaselineRig(t, nil) // no register: the pre-persistence world

	r.pass(t, 0) // the prefix is healthy, originated by AS64496
	r.set("193.0.0.0/21", fullyPropagatedHijack())
	r.pass(t, time.Hour) // AS65001 has now won every vantage point but one

	inc := r.incident(t, "193.0.0.0/21")
	if inc.Class == ClassOriginChange {
		t.Fatalf("the pre-persistence path is not supposed to detect this; the red case no longer stages the bug: %+v", inc)
	}
	if inc.Class != ClassNone {
		t.Fatalf("class=%s, want none (the hijacker became the baseline in its own pass)", inc.Class)
	}
	if got := r.alerts(); len(got) != 0 {
		t.Fatalf("no alert can fire without a stored baseline, got %d", len(got))
	}
	// And it must SAY so, which is what 1bf933fa shipped.
	if !strings.Contains(inc.Summary, "NOT checked against a declared baseline") {
		t.Fatalf("the verdict must still admit the origin was not checked: %q", inc.Summary)
	}
	if st := r.eval.Status("acme"); st.OriginBaselines {
		t.Fatal("status must report the baseline register as off when none is wired")
	}
}

// ── THE GREEN CASE: with a register, the same input is detected ─────────────

// TestFullyPropagatedOriginChangeIsDetectedAgainstAStoredBaseline is the fix.
// Same two passes, same observations, one difference: the first pass recorded a
// baseline, so the second pass has something that is not itself to compare
// against.
func TestFullyPropagatedOriginChangeIsDetectedAgainstAStoredBaseline(t *testing.T) {
	store := NewBaselineFileStore("")
	r := newBaselineRig(t, store)

	r.pass(t, 0) // first observation: AS64496 across two vantage points

	first := r.incident(t, "193.0.0.0/21")
	if first.Class != ClassNone {
		t.Fatalf("a first observation is not an incident, got %s (%s)", first.Class, first.Summary)
	}
	rows, err := store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	row, ok := rows["193.0.0.0/21"]
	if !ok {
		t.Fatal("the first corroborated measurement must record a baseline, or nothing is ever detectable")
	}
	if len(row.Origins) != 1 || row.Origins[0] != 64496 {
		t.Fatalf("baseline origins = %v, want [64496]", row.Origins)
	}
	if row.Source != BaselineFirstSeen {
		t.Fatalf("source = %q, want %q", row.Source, BaselineFirstSeen)
	}

	// The origin change now reaches EVERY vantage point but one.
	r.set("193.0.0.0/21", fullyPropagatedHijack())
	r.pass(t, time.Hour)

	inc := r.incident(t, "193.0.0.0/21")
	if inc.Class != ClassOriginChange {
		t.Fatalf("THE BUG IS BACK: a fully propagated origin change classified %s (%s)", inc.Class, inc.Summary)
	}
	if inc.Severity != SevCritical {
		t.Fatalf("severity = %s, want critical", inc.Severity)
	}
	if !strings.Contains(inc.Summary, "AS65001") {
		t.Fatalf("the verdict must name the new origin: %q", inc.Summary)
	}
	if inc.Baseline == nil || !inc.Baseline.Has(64496) {
		t.Fatalf("the verdict must carry the baseline it was judged against: %+v", inc.Baseline)
	}
	if inc.LearnedOrigin {
		t.Fatal("the baseline came from the store, not from this pass, so learned_origin must be false")
	}
	if len(inc.Evidence.Vantages) < 2 {
		t.Fatalf("evidence must name the corroborating vantage points: %+v", inc.Evidence)
	}
	if !strings.Contains(inc.Evidence.Detail, "accept") {
		t.Fatalf("the evidence must tell the operator how to adopt a legitimate change: %q", inc.Evidence.Detail)
	}
	fired := r.alerts()
	if len(fired) != 1 || fired[0].Class != ClassOriginChange {
		t.Fatalf("exactly one origin_change alert must fire, got %+v", fired)
	}
	// The baseline is NOT moved by the detection. Only an operator moves it.
	rows, err = store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if got := rows["193.0.0.0/21"].Origins; len(got) != 1 || got[0] != 64496 {
		t.Fatalf("detecting a change must not adopt it: baseline is now %v", got)
	}
}

// ── THE THREE THINGS THAT ARE NOT HIJACKS ───────────────────────────────────

// A FIRST OBSERVATION cannot be a change. Even when the very first thing we
// ever see is the hijacked state, there is nothing to have changed from, and
// calling it an incident would page someone on every fresh install.
//
// This test also pins the HONEST BOUND of first-seen learning: what gets
// recorded is what was announced, and if that was already wrong, the wrong
// origin is the baseline. The product says that rather than implying the row
// was verified by anyone.
func TestFirstObservationIsNeverAnOriginChange(t *testing.T) {
	store := NewBaselineFileStore("")
	r := newBaselineRig(t, store)
	r.set("193.0.0.0/21", fullyPropagatedHijack()) // the FIRST thing we ever see

	r.pass(t, 0)

	inc := r.incident(t, "193.0.0.0/21")
	if inc.Class == ClassOriginChange {
		t.Fatalf("a first observation has nothing to have changed from and must never be an origin change: %+v", inc)
	}
	if len(r.alerts()) != 0 {
		t.Fatalf("a first observation must not page anyone, got %+v", r.alerts())
	}
	if !strings.Contains(inc.BaselineNote, "FIRST OBSERVATION") {
		t.Fatalf("the note must say this was a first observation: %q", inc.BaselineNote)
	}
	if !strings.Contains(inc.BaselineNote, "remembered observation, not a declared intent") {
		t.Fatalf("the note must not imply anyone verified the recorded origin: %q", inc.BaselineNote)
	}
	rows, err := store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	// The honest bound, stated as an assertion: the corroborated origin of the
	// first pass is what is recorded, whatever it was.
	if got := rows["193.0.0.0/21"].Origins; len(got) != 1 || got[0] != 65001 {
		t.Fatalf("the first corroborated origin is the baseline, got %v", got)
	}
}

// A NEW PREFIX added to the watchlist later takes the same path: it has no row,
// so its first pass is a first observation and not an incident, even while
// another prefix in the same tenant already has a baseline.
func TestANewlyWatchedPrefixIsNotAnOriginChange(t *testing.T) {
	store := NewBaselineFileStore("")
	r := newBaselineRig(t, store)
	r.pass(t, 0) // 193.0.0.0/21 gets its baseline

	other := healthy()
	other.Prefix = "193.0.16.0/24"
	other.Paths = []VantagePath{vp("rrc00-1", 174, 65001), vp("rrc01-2", 174, 65001)}
	r.set("193.0.16.0/24", other)
	r.mu.Lock()
	r.watch = append(r.watch, "193.0.16.0/24")
	r.mu.Unlock()

	r.pass(t, time.Hour)

	inc := r.incident(t, "193.0.16.0/24")
	if inc.Class == ClassOriginChange {
		t.Fatalf("adding a prefix to the watchlist must not raise a hijack: %+v", inc)
	}
	if len(r.alerts()) != 0 {
		t.Fatalf("adding a prefix must not page anyone, got %+v", r.alerts())
	}
	rows, err := store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("both prefixes should now hold a baseline, got %d", len(rows))
	}
}

// A LEGITIMATE RE-HOMING is accepted by an operator, and that is what stops a
// real origin change alerting forever. Accept the new origin, and the next
// MEASURED pass resolves the open incident.
func TestOperatorAcceptedOriginClearsTheIncident(t *testing.T) {
	store := NewBaselineFileStore("")
	r := newBaselineRig(t, store)
	r.pass(t, 0)
	r.set("193.0.0.0/21", fullyPropagatedHijack())
	r.pass(t, time.Hour)
	if inc := r.incident(t, "193.0.0.0/21"); inc.Class != ClassOriginChange {
		t.Fatalf("setup: expected the change to be detected, got %s", inc.Class)
	}

	// The operator looks, decides the re-homing was theirs, and accepts it.
	row, err := store.Accept(context.Background(), "acme", "193.0.0.0/21", "ops@acme", []uint32{65001}, clsNow)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if row.Source != BaselineAccepted || row.UpdatedBy != "ops@acme" {
		t.Fatalf("an accepted baseline must record who accepted it: %+v", row)
	}
	if row.Vantages != 0 {
		t.Fatalf("an operator decision is not a measurement and must not carry a vantage count: %+v", row)
	}
	if !row.FirstSeen.Equal(clsNow) {
		t.Fatalf("first_seen must survive an accept, got %s", row.FirstSeen)
	}

	r.pass(t, time.Hour) // same observation, new baseline

	inc := r.incident(t, "193.0.0.0/21")
	if inc.Class != ClassNone {
		t.Fatalf("after the accept the prefix must classify clean, got %s (%s)", inc.Class, inc.Summary)
	}
	if !strings.Contains(inc.Summary, "Origin matches the baseline recorded for this prefix") {
		t.Fatalf("a clean verdict against a stored baseline must say the origin WAS checked: %q", inc.Summary)
	}
	res := r.resolutions()
	if len(res) != 1 || !res[0].Resolved || res[0].Class != ClassOriginChange {
		t.Fatalf("the open incident must be resolved exactly once, got %+v", res)
	}
	// The old origin is now the minority one and is a shortfall, not an alert.
	if len(r.alerts()) != 1 {
		t.Fatalf("no second alert may fire after the accept, got %+v", r.alerts())
	}
}

// ── what must NEVER become a baseline ───────────────────────────────────────

// A pass that already looks wrong must not establish the baseline, or a hijack
// in progress becomes the permanent truth about the prefix and stops being an
// incident forever. The prefix keeps its honest "no baseline yet" state.
func TestASuspectFirstPassRecordsNoBaseline(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  func() Observation
	}{
		{"rpki invalid", func() Observation {
			o := healthy()
			o.RPKIState, o.RPKIReason = "invalid", "origin_as"
			return o
		}},
		{"bogon prefix", func() Observation {
			o := healthy()
			o.Paths = []VantagePath{vp("rrc00-1", 174, 65001), vp("rrc01-2", 174, 65001)}
			return o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewBaselineFileStore("")
			r := newBaselineRig(t, store)
			prefix := "193.0.0.0/21"
			if tc.name == "bogon prefix" {
				prefix = "10.9.0.0/16" // inside RFC 1918, never in the DFZ
				r.mu.Lock()
				r.watch = []string{prefix}
				r.mu.Unlock()
			}
			o := tc.obs()
			o.Prefix = prefix
			r.set(prefix, o)

			r.pass(t, 0)

			rows, err := store.Baselines(context.Background(), "acme")
			if err != nil {
				t.Fatalf("Baselines: %v", err)
			}
			if len(rows) != 0 {
				t.Fatalf("a pass that already looks wrong must not become the baseline, recorded %+v", rows)
			}
		})
	}
}

// One collector peer holding a stale path must not become the permanent truth
// about a prefix. The same corroboration floor that gates an origin_change
// gates the baseline it is measured against.
func TestAnUncorroboratedOriginIsNotRecorded(t *testing.T) {
	store := NewBaselineFileStore("")
	r := newBaselineRig(t, store)
	lonely := healthy()
	lonely.Paths = []VantagePath{vp("rrc00-1", 3356, 64500, 64496)} // ONE vantage point
	r.set("193.0.0.0/21", lonely)

	r.pass(t, 0)

	rows, err := store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("one vantage point must not set a baseline, recorded %+v", rows)
	}
	// And the verdict must SAY that nothing was recorded, rather than promising
	// a row the evaluator refused to write.
	inc := r.incident(t, "193.0.0.0/21")
	if !strings.Contains(inc.BaselineNote, "NO baseline is recorded from this pass") {
		t.Fatalf("the note must say no baseline was recorded: %q", inc.BaselineNote)
	}

	// Two agreeing vantage points do.
	r.set("193.0.0.0/21", healthy())
	r.pass(t, time.Hour)
	rows, err = store.Baselines(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("a corroborated origin must be recorded on a later pass, got %+v", rows)
	}
	if got := r.incident(t, "193.0.0.0/21").BaselineNote; !strings.Contains(got, "meets the 2 required") {
		t.Fatalf("the note must say the corroboration floor was met: %q", got)
	}
}

// A DECLARED expected origin beats a recorded one. A declaration is the only
// one of the three baselines somebody actually asserted.
func TestADeclaredOriginOverridesTheRecordedBaseline(t *testing.T) {
	obs := healthy()
	row := OriginBaseline{
		Prefix: "193.0.0.0/21", Origins: []uint32{65001}, Source: BaselineFirstSeen,
		Vantages: 2, FirstSeen: clsNow, UpdatedAt: clsNow,
	}
	inc := ClassifyWithBaseline(obs, policy(), Baseline{Persisted: true, Origin: &row}, NewBogonSet(), clsNow)
	if inc.Class != ClassNone {
		t.Fatalf("the DECLARED origin AS64496 is what is announced, so the verdict must be clean, got %s (%s)", inc.Class, inc.Summary)
	}
	if inc.BaselineNote != "" {
		t.Fatalf("a declared baseline carries no blind-spot note: %q", inc.BaselineNote)
	}
}

// ── the store itself ────────────────────────────────────────────────────────

// Record is insert-if-absent. Two passes, or two api replicas, must not be able
// to move a baseline between them: moving one is a decision, and a decision
// goes through Accept.
func TestRecordNeverOverwritesAnExistingBaseline(t *testing.T) {
	ctx := context.Background()
	s := NewBaselineFileStore("")
	first := OriginBaseline{Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: BaselineFirstSeen, Vantages: 2, FirstSeen: clsNow, UpdatedAt: clsNow}
	if _, recorded, err := s.Record(ctx, "acme", first); err != nil || !recorded {
		t.Fatalf("first Record: recorded=%v err=%v", recorded, err)
	}
	second := first
	second.Origins = []uint32{65001}
	got, recorded, err := s.Record(ctx, "acme", second)
	if err != nil {
		t.Fatalf("second Record: %v", err)
	}
	if recorded {
		t.Fatal("a second Record must report that it wrote nothing")
	}
	if len(got.Origins) != 1 || got.Origins[0] != 64496 {
		t.Fatalf("the original row must survive, got %v", got.Origins)
	}
}

// A baseline naming no origin matches nothing and would alert forever.
func TestABaselineMustNameAnOrigin(t *testing.T) {
	ctx := context.Background()
	s := NewBaselineFileStore("")
	if _, err := s.Accept(ctx, "acme", "193.0.0.0/21", "ops", nil, clsNow); err == nil {
		t.Fatal("an empty origin set must be refused, not stored")
	}
	// AS0 is reserved (RFC 7607) and cannot be the only member either.
	if _, err := s.Accept(ctx, "acme", "193.0.0.0/21", "ops", []uint32{0}, clsNow); err == nil {
		t.Fatal("AS0 is reserved and must not become a baseline")
	}
}

// Forget answers the same way for a prefix this tenant does not hold as for one
// that does not exist at all, which is what the HTTP layer turns into a 404.
func TestForgetOnAnAbsentPrefixIsErrNoBaseline(t *testing.T) {
	ctx := context.Background()
	s := NewBaselineFileStore("")
	if err := s.Forget(ctx, "acme", "203.0.113.0/24"); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("err = %v, want ErrNoBaseline", err)
	}
}

// Every method refuses a non-concrete tenant outright, so a mis-scoped caller
// reads and writes NOTHING rather than everything (§3a rule 4).
func TestBaselineStoreRefusesANonConcreteTenant(t *testing.T) {
	ctx := context.Background()
	s := NewBaselineFileStore("")
	for _, tenant := range []string{"", "  ", "*"} {
		if _, err := s.Baselines(ctx, tenant); err == nil {
			t.Fatalf("Baselines(%q) must be refused", tenant)
		}
		if _, _, err := s.Record(ctx, tenant, OriginBaseline{Prefix: "193.0.0.0/21", Origins: []uint32{1}, Source: BaselineFirstSeen}); err == nil {
			t.Fatalf("Record(%q) must be refused", tenant)
		}
		if _, err := s.Accept(ctx, tenant, "193.0.0.0/21", "ops", []uint32{1}, clsNow); err == nil {
			t.Fatalf("Accept(%q) must be refused", tenant)
		}
		if err := s.Forget(ctx, tenant, "193.0.0.0/21"); err == nil {
			t.Fatalf("Forget(%q) must be refused", tenant)
		}
	}
}

// ── §3a rule 5: one tenant's baselines are invisible and untouchable to another
//
// The store-level half. The HTTP half, driven through the production authz
// wiring, is bgp_alerts_isolation_test.go.
func TestBaselineFileStoreIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bgp_origin_baseline.json")
	s := NewBaselineFileStore(path)

	acme := OriginBaseline{Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: BaselineFirstSeen, Vantages: 2, FirstSeen: clsNow, UpdatedAt: clsNow}
	globex := OriginBaseline{Prefix: "198.51.100.0/24", Origins: []uint32{64510}, Source: BaselineFirstSeen, Vantages: 3, FirstSeen: clsNow, UpdatedAt: clsNow}
	if _, _, err := s.Record(ctx, "acme", acme); err != nil {
		t.Fatalf("seed acme: %v", err)
	}
	if _, _, err := s.Record(ctx, "globex", globex); err != nil {
		t.Fatalf("seed globex: %v", err)
	}

	// OWN-ONLY LIST.
	rows, err := s.Baselines(ctx, "acme")
	if err != nil {
		t.Fatalf("Baselines(acme): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("acme must see exactly its own row, got %+v", rows)
	}
	if _, leaked := rows["198.51.100.0/24"]; leaked {
		t.Fatal("CROSS-TENANT LEAK: acme can see globex's baseline")
	}

	// CROSS-TENANT DELETE is refused as absent, never performed.
	if err := s.Forget(ctx, "acme", "198.51.100.0/24"); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("a cross-tenant delete must look absent, got %v", err)
	}
	if rows, err := s.Baselines(ctx, "globex"); err != nil || len(rows) != 1 {
		t.Fatalf("globex's row must survive acme's delete: %+v (%v)", rows, err)
	}

	// A CROSS-TENANT ACCEPT writes into the CALLER'S OWN bucket and cannot
	// reach the other tenant's row, even naming its exact prefix.
	if _, err := s.Accept(ctx, "acme", "198.51.100.0/24", "attacker@acme", []uint32{65001}, clsNow); err != nil {
		t.Fatalf("Accept into acme's own bucket: %v", err)
	}
	gx, err := s.Baselines(ctx, "globex")
	if err != nil {
		t.Fatalf("Baselines(globex): %v", err)
	}
	if got := gx["198.51.100.0/24"].Origins; len(got) != 1 || got[0] != 64510 {
		t.Fatalf("CROSS-TENANT WRITE: globex's baseline is now %v", got)
	}
	if gx["198.51.100.0/24"].UpdatedBy != "" {
		t.Fatalf("globex's row was stamped by another tenant's caller: %+v", gx["198.51.100.0/24"])
	}

	// And the same separation survives a reload from disk.
	reloaded := NewBaselineFileStore(path)
	if err := reloaded.LoadErr(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	back, err := reloaded.Baselines(ctx, "globex")
	if err != nil {
		t.Fatalf("Baselines after reload: %v", err)
	}
	if len(back) != 1 || !back["198.51.100.0/24"].Has(64510) {
		t.Fatalf("globex's row did not survive the reload: %+v", back)
	}
}

// ── the load path (4efbc78d): unreadable is NOT absent ──────────────────────

// An unreadable register must not start empty, and the next write must not
// replace the file it could not read. Here that is worse than losing rows: an
// empty register makes every prefix look like a first observation, so the next
// pass would re-record a baseline from whatever is being announced right now.
func TestBaselineFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bgp_origin_baseline.json")
	seed := NewBaselineFileStore(path)
	if _, _, err := seed.Record(ctx, "acme", OriginBaseline{
		Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: BaselineFirstSeen,
		Vantages: 2, FirstSeen: clsNow, UpdatedAt: clsNow,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewBaselineFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable baseline register loaded silently — every prefix then looks like a first observation and the next pass re-learns from the current table")
	}
	if _, _, err := s.Record(ctx, "acme", OriginBaseline{
		Prefix: "198.51.100.0/24", Origins: []uint32{64510}, Source: BaselineFirstSeen,
		Vantages: 2, FirstSeen: clsNow, UpdatedAt: clsNow,
	}); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Record was accepted over a register whose file could not be read: %v", err)
	}
	if _, err := s.Accept(ctx, "acme", "193.0.0.0/21", "ops", []uint32{65001}, clsNow); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("an Accept was accepted over a register whose file could not be read: %v", err)
	}
	assertUntouched(t, path, before)
}

// A MISSING file is genuinely absent and starts empty with nothing reported.
// That is the normal first-boot state and must stay distinguishable from the
// case above.
func TestBaselineFileMissingIsAbsentNotAnError(t *testing.T) {
	s := NewBaselineFileStore(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a missing file is the normal first-boot state, not an error: %v", err)
	}
	rows, err := s.Baselines(context.Background(), "acme")
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows=%+v err=%v, want empty and nil", rows, err)
	}
}

// A file that exists but holds JSON we cannot parse is the same class as
// unreadable: the contents were never established, so writes are refused.
func TestBaselineFileUnparsableRefusesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bgp_origin_baseline.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := NewBaselineFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unparsable register must be reported, not started empty in silence")
	}
	if _, _, err := s.Record(context.Background(), "acme", OriginBaseline{
		Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: BaselineFirstSeen, UpdatedAt: clsNow,
	}); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("err = %v, want ErrStoreUnreadable", err)
	}
}

// A failed flush must leave memory and disk agreeing (33303ace): nothing is
// mutated and then put back, so the row the caller was refused is not sitting
// in the map pretending to be stored.
func TestAFailedFlushAdoptsNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "bgp_origin_baseline.json")
	s := NewBaselineFileStore(path)
	if _, _, err := s.Record(ctx, "acme", OriginBaseline{
		Prefix: "193.0.0.0/21", Origins: []uint32{64496}, Source: BaselineFirstSeen, UpdatedAt: clsNow,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Make the DIRECTORY unwritable so the atomic rename fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, _, err := s.Record(ctx, "acme", OriginBaseline{
		Prefix: "198.51.100.0/24", Origins: []uint32{64510}, Source: BaselineFirstSeen, UpdatedAt: clsNow,
	}); err == nil {
		t.Skip("this environment can still write into a read-only directory (running as root?), so the case cannot be staged")
	}
	rows, err := s.Baselines(ctx, "acme")
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if _, adopted := rows["198.51.100.0/24"]; adopted {
		t.Fatal("a row whose flush failed was adopted into memory anyway — memory and disk now disagree")
	}
	if len(rows) != 1 {
		t.Fatalf("the surviving row set is wrong: %+v", rows)
	}
}
