// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"time"
)

// score.go — the PRODUCTION SCORECARD seam (Iris commercial programme item 19).
//
// This package measures nothing and stores nothing: it hands the server a small
// number of OBSERVATIONS and the server decides what to do with them. That keeps
// the metric registry (internal/aiscore) and the answering engine in separate
// bounded contexts with no import between them — the integrator owns the seam,
// exactly as it owns ToolAudit and RecordInvestigation above it.
//
// A nil sink is the default and changes nothing about any answer. Nothing in
// here can fail a turn: every call site is fire-and-forget after the answer is
// already built.
//
// WHAT MAY CROSS THIS SEAM. Counts, enums, booleans and durations. NEVER a
// tenant id, a device name, a correlation id, a citation id, question text or
// model output — the receiving metrics are scraped from a surface that is not
// tenant-scoped (§3a, and see internal/aiscore's package doc).

// ScoreSink receives production-scorecard observations. Implemented by the
// server; nil disables the whole layer.
type ScoreSink interface {
	// AnswerObserved is called once per finished answer, whichever path
	// produced it.
	AnswerObserved(AnswerScore)
	// InvestigationObserved is called once per finished SKILL-CHAIN turn, in
	// addition to AnswerObserved.
	InvestigationObserved(InvestigationScore)
	// GuardObserved is called once per firing of a deterministic grounding
	// guard, with the number of references or claims it removed.
	GuardObserved(guard string, removed int)
	// ProviderObserved is called once per model-provider completion attempt.
	ProviderObserved(ProviderScore)
}

// Grounding guard names. They are the sink's label values, so they are declared
// here beside the checks that raise them rather than spelled as literals at the
// call sites.
const (
	// GuardFabricatedCitation — VerifyGrounding stripped a bracketed evidence
	// id that was not in the bundle the model was given.
	GuardFabricatedCitation = "fabricated_citation"
	// GuardUncertainClaim — a certainty-marker post-check refused a narrative
	// asserting an established cause under an unconfirmed verdict. Declared
	// here so the metric family carries the series (as a zero) on a build where
	// the check is not wired: an absent series and a zero series mean different
	// things to an alert.
	GuardUncertainClaim = "uncertain_claim"
)

// AnswerScore is one finished answer. Duration covers the whole turn as the
// orchestrator saw it, including every tool read and the provider call.
type AnswerScore struct {
	// Citations is how many evidence citations the answer shipped. Grounding
	// COVERAGE is the share of answers with at least one.
	Citations int
	// Duration is the wall time of the turn.
	Duration time.Duration
}

// InvestigationScore is one finished skill-chain turn. Every field is something
// the chain already computed for its own routing or disclosure.
type InvestigationScore struct {
	// Outcome is "answered" when the chain produced a finding, "no_evidence"
	// when it ran and gathered nothing so the turn fell back.
	Outcome string
	// Duration is the wall time of the investigation.
	Duration time.Duration
	// Hops are the per-hop selection origins (ChainSelectedEntry / …Rule /
	// …Model), in order.
	Hops []string
	// HopsRejected counts model-proposed next skills refused because they were
	// not in the closed candidate set.
	HopsRejected int
	// ToolOutcomes are the per-call outcomes the chain recorded
	// (ok|error|not_found|not_wired|denied).
	ToolOutcomes []string
	// Cutoffs are the bounded budgets that ended the chain early
	// (rounds|tool_calls|time|evidence_chars).
	Cutoffs []string
	// EvidenceBacked is true when the finished answer carried a citation.
	EvidenceBacked bool
}

// Investigation outcome values.
const (
	InvestigationAnswered   = "answered"
	InvestigationNoEvidence = "no_evidence"
)

// Budget cut-off names, matching the bounds answerSkill already discloses.
const (
	CutoffRounds        = "rounds"
	CutoffToolCalls     = "tool_calls"
	CutoffTime          = "time"
	CutoffEvidenceChars = "evidence_chars"
)

// ProviderScore is one model-provider completion attempt.
type ProviderScore struct {
	// Usage is the PROVIDER'S OWN token accounting. A zero-value Usage
	// (Reported false) means the provider did not report any, and the tokens
	// are then not counted at all rather than estimated.
	Usage TokenUsage
	// Investigation is true when this call narrated a skill-chain turn.
	Investigation bool
}

// TokenUsage is a provider's own accounting for one completion. Reported is the
// load-bearing field: false means this platform does not know what that call
// cost, and saying so is the honest answer.
type TokenUsage struct {
	InputTokens  int64
	OutputTokens int64
	Reported     bool
}

// score returns the configured sink, or nil. Kept as a helper so every call
// site reads the same way and nobody re-derives the nil check.
func (o *Orchestrator) score() ScoreSink {
	if o == nil {
		return nil
	}
	return o.Score
}

// observeAnswer reports a finished answer. Called from exactly one place (Ask's
// wrapper) so no path can be counted twice — a metric that double-counts one
// mode is worse than one that counts none.
func (o *Orchestrator) observeAnswer(ans *Answer, started time.Time) {
	s := o.score()
	if s == nil || ans == nil {
		return
	}
	s.AnswerObserved(AnswerScore{Citations: len(ans.Citations), Duration: time.Since(started)})
}

// observeGuard reports one deterministic grounding-guard firing.
func (o *Orchestrator) observeGuard(guard string, removed int) {
	if s := o.score(); s != nil {
		s.GuardObserved(guard, removed)
	}
}

// LLMUsageClient is the OPTIONAL richer half of the LLMClient seam: a tiered
// client that can also report the provider's own token accounting for the
// completion it just made. It is a separate interface on purpose — LLMClient and
// TieredLLMClient stay exactly as they were, so MockLLM and every existing
// implementation keep compiling, and a client that cannot report usage simply
// does not implement this.
//
// Usage must be the PROVIDER'S OWN numbers. A client that cannot get them sets
// Reported false rather than estimating: the whole economics layer of the
// scorecard rests on never inventing a token.
type LLMUsageClient interface {
	TieredLLMClient
	CompleteTierWithUsage(ctx context.Context, tier ModelTier, system string, msgs []LLMMessage) (text string, provider string, usage TokenUsage, err error)
}
