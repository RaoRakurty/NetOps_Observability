// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

import (
	"context"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
)

const (
	tA    = "t-a"
	tB    = "t-b"
	alice = "u-alice"
	bob   = "u-bob"
	carol = "u-carol"
)

const goodName = "acme-wan-check"

// goodMD and goodCases are a real runbook whose cases really pass under ai.RunCases.
const goodMD = `---
name: acme-wan-check
layer: path_seam
version: 2
when_to_use: acme wan brownout, acme carrier fault, acme circuit fault
symptom_kinds: acme-wan
tools: get_rca_verdict, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - search_logs(query=WAN, window=6h)
look_for:
  - the carrier ticket number
decisions:
  - next=log-confirmation when evidence:kind=log the logs name the carrier
  - next=interface-down when the handoff port is suspect
  - verdict=name the carrier circuit
  - escalate=the carrier NOC
---
First read the carrier portal, then compare the handoff counters.
`

const goodCases = `
case: logs naming the carrier hand off to Correlix's own log method
question: acme wan brownout on edge-1
ui:
  - correlation_id=case-1
evidence:
  - log
expect_chain:
  - acme-wan-check entry
  - log-confirmation rule
expect_selected: rule
expect_reason: the logs name the carrier
expect_verdict:
  - quote the message
expect_never:
  - mac-flap
expect_never_tools:
  - run_protocol_diagnostic
---
case: no routing fact stays in the runbook and says what was missing
question: acme carrier fault and acme circuit fault on edge-1
ui:
  - correlation_id=case-2
tools:
  - search_logs=not_wired
evidence:
  - finding
expect_chain:
  - acme-wan-check entry
expect_selected: none
expect_verdict:
  - carrier circuit
expect_notes:
  - is not available on this deployment
expect_select: acme-wan-check
`

const mopName = "acme-change"

const mopMD = `---
name: acme-change
layer: path_seam
version: 1
kind: mop
when_to_use: acme change window
symptom_kinds: acme-wan
tools: get_rca_verdict
gather:
  - get_rca_verdict(correlation_id)
look_for:
  - the change window is open
decisions:
  - verdict=state which step was reached
steps:
  - drain the circuit
  - swap the optic
---
A procedure for a human.
`

func good() NewRunbook {
	return NewRunbook{Name: goodName, Kind: KindInvestigative, Source: Source{SkillMD: goodMD, CasesYAML: goodCases}}
}

func mop() NewRunbook {
	return NewRunbook{Name: mopName, Kind: KindMOP, Source: Source{SkillMD: mopMD}}
}

// edited is a good text that differs from goodMD, for a second version.
func edited(say string) string {
	body, err := CanonicalBody(Source{SkillMD: goodMD + say + "\n", CasesYAML: goodCases})
	if err != nil {
		panic(err)
	}
	return body
}

// named is the fixture runbook under another name, with that name in its cases.
func named(name string) NewRunbook {
	return NewRunbook{Name: name, Kind: KindInvestigative, Source: Source{
		SkillMD:   strings.Replace(goodMD, "name: "+goodName, "name: "+name, 1),
		CasesYAML: strings.ReplaceAll(goodCases, goodName, name),
	}}
}

// fakeHarness is the store's view of the gate: every run counted, failure on demand.
type fakeHarness struct {
	mu       sync.Mutex
	fp       string
	fail     bool
	err      error
	calls    int
	last     HarnessRequest
	problems []CaseProblem
}

func newFake() *fakeHarness {
	return &fakeHarness{fp: "fp-1", problems: []CaseProblem{{Case: "the case", Message: "the verdict did not hold"}}}
}

func (f *fakeHarness) Fingerprint() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fp
}

func (f *fakeHarness) Run(_ context.Context, req HarnessRequest) (HarnessResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = req
	if f.err != nil {
		return HarnessResult{}, f.err
	}
	if f.fail {
		return HarnessResult{Problems: f.problems}, nil
	}
	if req.Kind == KindMOP {
		return HarnessResult{Passed: true, Fingerprint: FingerprintNotApplicable}, nil
	}
	return HarnessResult{Passed: true, Fingerprint: f.fp, Cases: 2}, nil
}

func (f *fakeHarness) set(fn func(*fakeHarness)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeHarness) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newMem(h Harness) *MemStore {
	return NewMemStore(Config{Harness: h, ToolNames: ai.ToolNames})
}

func create(t *testing.T, s Store, tenant, actor string, in NewRunbook) Runbook {
	t.Helper()
	r, err := s.Create(context.Background(), tenant, actor, in)
	if err != nil {
		t.Fatalf("create %s: %v", in.Name, err)
	}
	return r
}

func do(t *testing.T, s Store, tenant, id string, op orgcontext.Op) Runbook {
	t.Helper()
	r, err := s.Do(context.Background(), tenant, id, op)
	if err != nil {
		t.Fatalf("%s by %s: %v", op.Kind, op.Actor, err)
	}
	return r
}

// activate takes a runbook's open draft through submit + approve.
func activate(t *testing.T, s Store, tenant, id, author, approver string) Runbook {
	t.Helper()
	r := do(t, s, tenant, id, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: author})
	v, _ := r.Open()
	return do(t, s, tenant, id, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: approver, Version: v.Version, BodySHA256: v.BodySHA256})
}
