// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// harnessgate.go — the case harness as a gate. It holds no provider, no transport
// and no store: its inputs are texts, its output is a result. ai.RunCases replaces
// everything a case could reach with fixtures, and this file adds the wall-clock
// cap and the bound on concurrent runs that a synchronous request needs (§9, §15
// LLM04).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netops/backend/ai"
)

// HarnessTimeout is the wall-clock cap on one run.
const HarnessTimeout = 10 * time.Second

// maxConcurrentRuns bounds runs in flight. A run past its cap keeps its slot until
// it really finishes, because RunCases cannot be interrupted: a stuck run costs a
// slot, never an unbounded goroutine.
const maxConcurrentRuns = 4

// HarnessRequest is one run.
type HarnessRequest struct {
	Tenant string
	Name   string
	Kind   Kind
	Source Source
	// Siblings are the tenant's other runbooks' active texts, by name: a runbook
	// may hand off to one, so its cases have to be able to see it.
	Siblings map[string]Source
}

// HarnessResult is one run's outcome.
type HarnessResult struct {
	Passed      bool
	Fingerprint string
	Cases       int
	Problems    []CaseProblem
	TimedOut    bool
}

// Harness is the gate the stores call.
type Harness interface {
	// Fingerprint is the current value results are compared with.
	Fingerprint() string
	// Run proves a text. An error means it could not be decided (ErrHarnessBusy);
	// a text that failed is a result.
	Run(ctx context.Context, req HarnessRequest) (HarnessResult, error)
}

// CaseGate is the production Harness.
type CaseGate struct {
	fingerprint func() string
	tools       func() []string
	compiled    *ai.SkillSet
	run         func(*ai.SkillSet, *ai.Skill) ai.HarnessReport
	timeout     time.Duration
	slots       chan struct{}
}

// NewCaseGate builds the gate. fingerprint is the current ai.HarnessFingerprint,
// which needs the deployment's models; tools are the names prose may not mention.
func NewCaseGate(fingerprint func() string, tools func() []string) (*CaseGate, error) {
	if fingerprint == nil || tools == nil {
		return nil, errors.New("tenantrunbook: the case gate needs a fingerprint and a tool list")
	}
	set, err := ai.LoadSkills()
	if err != nil {
		return nil, fmt.Errorf("tenantrunbook: compiled skills: %w", err)
	}
	return &CaseGate{
		fingerprint: fingerprint,
		tools:       tools,
		compiled:    set,
		run:         ai.RunCases,
		timeout:     HarnessTimeout,
		slots:       make(chan struct{}, maxConcurrentRuns),
	}, nil
}

// Fingerprint implements Harness.
func (g *CaseGate) Fingerprint() string { return g.fingerprint() }

// Run implements Harness.
func (g *CaseGate) Run(ctx context.Context, req HarnessRequest) (HarnessResult, error) {
	sk, err := Parse(req.Tenant, req.Name, req.Kind, req.Source, g.tools())
	if err != nil {
		return refused(err.Error()), nil
	}
	if req.Kind == KindMOP {
		return HarnessResult{Passed: true, Fingerprint: FingerprintNotApplicable}, nil
	}
	// A result is stamped with the fingerprint read BEFORE the run: a platform
	// change during it makes the result stale, never the reverse. It is read before
	// the cap starts too, which bounds the run and the wait for a slot only.
	fp := g.fingerprint()
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	select {
	case g.slots <- struct{}{}:
	case <-ctx.Done():
		return HarnessResult{}, ErrHarnessBusy
	}
	done := make(chan HarnessResult, 1)
	go func() {
		defer func() { <-g.slots }()
		done <- g.prove(req, sk, fp)
	}()
	select {
	case res := <-done:
		return res, nil
	case <-ctx.Done():
		res := refused(fmt.Sprintf("the cases did not finish within %s", g.timeout))
		res.TimedOut = true
		return res, nil
	}
}

// prove builds the set the runbook would run in and runs its cases. A panic is a
// failed result: this text is customer input and must not take the process down.
func (g *CaseGate) prove(req HarnessRequest, sk *ai.Skill, fp string) (res HarnessResult) {
	defer func() {
		if r := recover(); r != nil {
			res = refused(fmt.Sprintf("the case runner crashed: %v", r))
		}
	}()
	set, err := g.compiled.Overlay(reachableSiblings(req, sk, g.tools()))
	if err != nil {
		return refused(err.Error())
	}
	rep := g.run(set, sk)
	out := HarnessResult{Passed: rep.Passed(), Fingerprint: fp, Cases: len(rep.Cases)}
	if rep.NotRun != "" {
		out.Problems = append(out.Problems, CaseProblem{Message: rep.NotRun})
	}
	for _, c := range rep.Cases {
		for _, f := range c.Failures {
			out.Problems = append(out.Problems, CaseProblem{Case: c.Name, Message: f})
		}
	}
	if !out.Passed && len(out.Problems) == 0 {
		out.Problems = []CaseProblem{{Message: "the cases did not pass"}}
	}
	return out
}

// reachableSiblings is sk plus the sibling runbooks it can reach. Only those: a
// sibling elsewhere whose own hand-off has since been retired is not this
// submission's problem. A sibling that no longer parses is left out, so a hand-off
// to it fails here and now.
func reachableSiblings(req HarnessRequest, sk *ai.Skill, tools []string) []*ai.Skill {
	out := []*ai.Skill{sk}
	seen := map[string]bool{sk.Name: true}
	var walk func(from *ai.Skill)
	walk = func(from *ai.Skill) {
		for _, name := range namedBy(from) {
			src, ok := req.Siblings[name]
			if !ok || seen[name] {
				continue
			}
			seen[name] = true
			next, err := Parse(req.Tenant, name, KindInvestigative, src, tools)
			if err != nil {
				continue
			}
			out = append(out, next)
			walk(next)
		}
	}
	walk(sk)
	return out
}

// namedBy lists every skill a runbook's decisions and cases name.
func namedBy(sk *ai.Skill) []string {
	names := sk.NextSkills()
	for _, c := range sk.Cases {
		for _, h := range c.ExpectChain {
			names = append(names, h.Skill)
		}
		names = append(names, c.ExpectNever...)
	}
	return names
}

func refused(msg string) HarnessResult {
	return HarnessResult{Problems: []CaseProblem{{Message: msg}}}
}
