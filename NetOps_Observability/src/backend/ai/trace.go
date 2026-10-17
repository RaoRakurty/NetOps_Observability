// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// trace.go — operational progress of one answer (tracker 337 N-E2): what the
// engine is DOING, never what it has found. The server streams these to the
// Iris panel while the answer is built.
//
// A TraceEvent has exactly three fields: a type from a closed set, a registry
// tool name, and an outcome from a closed set. It never carries model text,
// tool arguments or evidence — the answer itself carries those, after
// grounding (TestTraceCarriesNothingButTheVocabulary).

// TraceType is one kind of progress step.
type TraceType string

const (
	TracePlanning     TraceType = "planning"
	TraceToolStarted  TraceType = "tool_started"
	TraceToolFinished TraceType = "tool_finished"
	TraceNarrating    TraceType = "narrating" // a model call that writes the answer started (no text)
	TraceGrounding    TraceType = "grounding" // the answer's citations are being verified
)

// TraceEvent is one progress step.
type TraceEvent struct {
	Type    TraceType `json:"type"`
	Tool    string    `json:"tool,omitempty"`
	Outcome string    `json:"outcome,omitempty"`
}

// TraceSink receives progress. It must not block: the server's sink drops
// past its bound rather than slow the answer.
type TraceSink interface {
	Trace(TraceEvent)
}

// traceOutcome maps a gateway outcome onto the closed progress vocabulary.
func traceOutcome(outcome string) string {
	switch outcome {
	case OutcomeOK:
		return "ok"
	case OutcomePolicyDenied, OutcomeRateLimited:
		return "denied"
	case OutcomeNotRegistered, "not_implemented":
		return "not_wired"
	case "not_found":
		return "not_found"
	}
	return "error"
}

func emitTrace(s TraceSink, e TraceEvent) {
	if s != nil {
		s.Trace(e)
	}
}

// trace emits on the orchestrator's sink (nil = no-op).
func (o *Orchestrator) trace(t TraceType) {
	emitTrace(o.Trace, TraceEvent{Type: t})
}
