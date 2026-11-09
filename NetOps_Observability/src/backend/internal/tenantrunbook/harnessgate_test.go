// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
)

func realGate(t *testing.T) *CaseGate {
	t.Helper()
	g, err := NewCaseGate(func() string { return ai.HarnessFingerprint(ai.TierModels{Default: "test-model"}) }, ai.ToolNames)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func request(in NewRunbook) HarnessRequest {
	return HarnessRequest{Tenant: tA, Name: in.Name, Kind: in.Kind, Source: in.Source}
}

func TestTheRealCasesPassAndAFailingCaseNamesItself(t *testing.T) {
	g := realGate(t)
	res, err := g.Run(context.Background(), request(good()))
	if err != nil || !res.Passed || res.Cases != 2 || res.Fingerprint != g.Fingerprint() || len(res.Fingerprint) != 64 {
		t.Fatalf("the fixture's cases must pass: %+v %v", res, err)
	}
	bad := good()
	bad.Source.CasesYAML = strings.Replace(goodCases, "expect_verdict:\n  - quote the message", "expect_verdict:\n  - words the verdict never states", 1)
	res, err = g.Run(context.Background(), request(bad))
	if err != nil || res.Passed {
		t.Fatalf("a wrong expectation must fail: %+v %v", res, err)
	}
	if len(res.Problems) == 0 || res.Problems[0].Case != "logs naming the carrier hand off to Correlix's own log method" || res.Problems[0].Message == "" {
		t.Fatalf("the failure must name its case: %+v", res.Problems)
	}
}

func TestAMOPStoresNotApplicableWithoutRunningAnything(t *testing.T) {
	g := realGate(t)
	g.run = func(*ai.SkillSet, *ai.Skill) ai.HarnessReport {
		t.Error("a MOP must not be run")
		return ai.HarnessReport{}
	}
	res, err := g.Run(context.Background(), request(mop()))
	if err != nil || !res.Passed || res.Fingerprint != FingerprintNotApplicable {
		t.Fatalf("mop: %+v %v", res, err)
	}
	withCases := mop()
	withCases.Source.CasesYAML = "case: x\nquestion: q\n"
	if res, _ := g.Run(context.Background(), request(withCases)); res.Passed {
		t.Fatal("a MOP with cases is the parser's refusal")
	}
}

// Whole-set checks run: a hand-off to a name that exists nowhere fails at the gate.
func TestAHandOffToNothingFailsAtTheGate(t *testing.T) {
	g := realGate(t)
	bad := good()
	for _, target := range []string{"no-such-method", "interface down", ""} {
		bad.Source.SkillMD = strings.Replace(goodMD, "next=interface-down", "next="+target, 1)
		res, err := g.Run(context.Background(), request(bad))
		if err != nil || res.Passed || !strings.Contains(res.Problems[0].Message, "names a skill that does not exist") {
			t.Fatalf("a dangling next=%s: %+v %v", target, res, err)
		}
	}
}

func TestARunbookReachesItsOwnTenantsActiveSiblings(t *testing.T) {
	g := realGate(t)
	sib := named("acme-sibling")
	sib.Source.CasesYAML = strings.ReplaceAll(sib.Source.CasesYAML, "acme wan brownout", "sibling phrase")
	sib.Source.CasesYAML = strings.ReplaceAll(sib.Source.CasesYAML, "expect_select: acme-sibling\n", "")
	// Its own phrases: with the same ones it would win selection over the runbook.
	sib.Source.SkillMD = strings.Replace(sib.Source.SkillMD, "when_to_use: acme wan brownout, acme carrier fault, acme circuit fault", "when_to_use: sibling phrase", 1)
	via := good()
	via.Source.SkillMD = strings.Replace(goodMD, "next=interface-down", "next=acme-sibling", 1)
	req := request(via)
	if res, _ := g.Run(context.Background(), req); res.Passed {
		t.Fatal("without the sibling the hand-off dangles")
	}
	req.Siblings = map[string]Source{sib.Name: sib.Source}
	res, err := g.Run(context.Background(), req)
	if err != nil || !res.Passed {
		t.Fatalf("with the sibling: %+v %v", res, err)
	}
	// A sibling this runbook does not reach is not its problem, even if broken.
	req = request(good())
	req.Siblings = map[string]Source{"acme-broken": {SkillMD: "not a runbook"}}
	if res, err := g.Run(context.Background(), req); err != nil || !res.Passed {
		t.Fatalf("an unreached broken sibling: %+v %v", res, err)
	}
}

// The store hands the gate the tenant's own ACTIVE investigative texts: never a
// draft, never a MOP, never another tenant's.
func TestSiblingsAreTheTenantsActiveInvestigativeRunbooks(t *testing.T) {
	h := newFake()
	s := newMem(h)
	active := create(t, s, tA, alice, named("active-one"))
	activate(t, s, tA, active.ID, alice, bob)
	create(t, s, tA, alice, named("draft-one"))
	m := create(t, s, tA, alice, mop())
	activate(t, s, tA, m.ID, alice, bob)
	other := create(t, s, tB, alice, named("other-tenant"))
	activate(t, s, tB, other.ID, alice, bob)

	r := create(t, s, tA, alice, good())
	do(t, s, tA, r.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: alice})
	if h.last.Tenant != tA || h.last.Name != goodName || len(h.last.Siblings) != 1 {
		t.Fatalf("request: tenant %s name %s siblings %v", h.last.Tenant, h.last.Name, h.last.Siblings)
	}
	if _, ok := h.last.Siblings["active-one"]; !ok {
		t.Fatalf("siblings: %v", h.last.Siblings)
	}
}

func TestTheWallClockCapAndTheBoundOnRuns(t *testing.T) {
	g := realGate(t)
	g.timeout = 50 * time.Millisecond
	release := make(chan struct{})
	g.run = func(*ai.SkillSet, *ai.Skill) ai.HarnessReport {
		<-release
		return ai.HarnessReport{}
	}
	// A stuck run is refused at the cap and keeps its slot.
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentRuns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := g.Run(context.Background(), request(good()))
			if err != nil || res.Passed || !res.TimedOut || len(res.Problems) != 1 {
				t.Errorf("a run past the cap: %+v %v", res, err)
			}
		}()
	}
	wg.Wait()
	if _, err := g.Run(context.Background(), request(good())); !errors.Is(err, ErrHarnessBusy) {
		t.Fatalf("with every slot held by a stuck run: %v, want ErrHarnessBusy", err)
	}
	close(release)
	for i := 0; i < maxConcurrentRuns; i++ {
		g.slots <- struct{}{} // every stuck run gave its slot back
	}
	for i := 0; i < maxConcurrentRuns; i++ {
		<-g.slots
	}
}

// The cap bounds the run. A slow fingerprint on a loaded host used to spend it first,
// and a healthy submission was told the gate was busy.
func TestTheCapDoesNotCountTheFingerprint(t *testing.T) {
	g := realGate(t)
	g.timeout = 200 * time.Millisecond
	g.fingerprint = func() string {
		time.Sleep(2 * g.timeout)
		return "fp"
	}
	res, err := g.Run(context.Background(), request(good()))
	if err != nil || !res.Passed || res.Fingerprint != "fp" {
		t.Fatalf("a slow fingerprint must not spend the run's cap: %+v %v", res, err)
	}
}

func TestTheProductionCapIsTenSeconds(t *testing.T) {
	if HarnessTimeout != 10*time.Second || realGate(t).timeout != HarnessTimeout {
		t.Fatalf("cap: %s", HarnessTimeout)
	}
}

func TestACrashIsAFailedResultNotACrash(t *testing.T) {
	g := realGate(t)
	g.run = func(*ai.SkillSet, *ai.Skill) ai.HarnessReport { panic("boom") }
	res, err := g.Run(context.Background(), request(good()))
	if err != nil || res.Passed || !strings.Contains(res.Problems[0].Message, "crashed") {
		t.Fatalf("panic: %+v %v", res, err)
	}
}

// A stamped fingerprint is the one read before the run.
func TestAPlatformChangeDuringARunMakesItsResultStale(t *testing.T) {
	var n int
	var mu sync.Mutex
	g, err := NewCaseGate(func() string {
		mu.Lock()
		defer mu.Unlock()
		n++
		return "fp-" + strconv.Itoa(n)
	}, ai.ToolNames)
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.Run(context.Background(), request(good()))
	if err != nil || !res.Passed {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Fingerprint == g.Fingerprint() {
		t.Fatal("the fingerprint moved during the run, so the result must not match the current one")
	}
}

// failingTransport fails the test the moment anything leaves the process.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("the harness reached a provider: %s", r.URL)
	return nil, errors.New("no provider in the harness")
}

// The gate has no provider to call: nothing in its type can hold one and nothing
// is injected. These hold it there. Real cases run with the default transport
// tripped, and the gate's source imports nothing that could reach one.
func TestTheHarnessNeverTouchesAProvider(t *testing.T) {
	saved := http.DefaultTransport
	http.DefaultTransport = failingTransport{t}
	t.Cleanup(func() { http.DefaultTransport = saved })

	g := realGate(t)
	runs := 0
	g.run = func(set *ai.SkillSet, sk *ai.Skill) ai.HarnessReport {
		runs++
		return ai.RunCases(set, sk)
	}
	if res, err := g.Run(context.Background(), request(good())); err != nil || !res.Passed {
		t.Fatalf("%+v %v", res, err)
	}
	if runs != 1 {
		t.Fatalf("the real runner ran %d times", runs)
	}

	for _, file := range []string{"harnessgate.go", "store.go", "validate.go", "model.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			switch p := strings.Trim(imp.Path.Value, `"`); {
			case p == "net" || strings.HasPrefix(p, "net/") || strings.Contains(p, "golang.org/x/net"):
				t.Errorf("%s imports %s: the harness path reaches no network", file, p)
			}
		}
	}
}
