// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// data_route.go — the question router's DATA arm (tracker 337 N-G4).
//
// One Iris box: the operator never chooses a mode. Before this, a data
// question asked in the box ("show jitter on nyc-verizon-1 today", "is memory
// above 90% anywhere in Austin right now") met the classifier built for
// incident and product questions: of the 212 golden data questions, 94 got the
// "I can't answer that" clarification, 70 a generic outage summary, 2 were
// routed to product NAVIGATION, and 46 launched a full troubleshooting skill
// chain instead of showing the number asked for.
//
// The rule is conservative by construction. A question takes the data arm
// only when the deterministic NL compiler understands EVERY word of it (the
// coverage rule), its query validates against the caller's scope, and it
// carries no diagnostic cue — "why", "root cause", "troubleshoot", "not
// working" stay with the skills, which investigate instead of listing. A
// product question never compiles, so it can never be captured. Anything the
// data arm does not claim continues down the classic path unchanged.
//
// This package holds no query engine: the server injects NLQuery, bound to
// the caller's claims and gated like /api/ai/query (infrastructure:read). The
// answer text is a deterministic summary written by the server — no model is
// involved, so the arm works key-free.

import (
	"context"
	"encoding/json"
	"regexp"
)

// ModeDataQuery answers a data question from the NL query engine.
const ModeDataQuery AnswerMode = "data_query"

// Data-arm outcomes (closed).
const (
	DataAnswered = "answered" // the query ran; Text summarises the result
	DataClarify  = "clarify"  // a named entity is ambiguous; Text asks which
	DataNotData  = "not_data" // not (fully) a data question — the classic path answers
)

// DataAnswer is what the server's data arm returns.
type DataAnswer struct {
	Status string
	Intent string
	Text   string
	// Payload is the structured answer for the UI (the compile answer and the
	// result set), passed through verbatim as JSON. Never shown to a model.
	Payload   json.RawMessage
	Citations []Citation
	Notes     []string
}

// DataOpts steers one data-arm attempt.
type DataOpts struct {
	// AllowModel lets the server's model fallback try a question the grammar
	// could not parse. Off for questions the classifier already knows are
	// product help: those have a better answer than up to three model calls.
	AllowModel bool
	// BeforeModel, when set, is asked right before the model compile would
	// run (the grammar could not parse the question and a model is wired):
	// false skips the model and leaves the question to the classic path. Set
	// only for a CONTESTED question (route_tiebreak.go); nil = today's path.
	BeforeModel func(ctx context.Context) bool
	// IncidentRefOnly admits the question ONLY as an incident list about a
	// resolved entity ("what's wrong with edge-1"); anything else is not
	// data and the skills investigate it as before.
	IncidentRefOnly bool
	// ClassicIntent is the router's own intent for the question. When it is
	// an explicit one (not "capability"), a question the grammar could not
	// parse is recorded as not_data — the classic path answers it — and a
	// lookup that found nothing is left to that path too.
	ClassicIntent string
}

// NLQueryFunc answers a question with the NL query engine, in the caller's
// scope. Status DataNotData (or an error) means "not mine".
type NLQueryFunc func(ctx context.Context, p Principal, question string, opts DataOpts) (DataAnswer, error)

// diagnosticCue marks a question that asks for a diagnosis, not a listing.
var diagnosticCue = regexp.MustCompile(`(?i)\b(?:why|root cause|caused?|causing|troubleshoot\w*|diagnos\w*|investigat\w*|fix|explain)\b`)

// listingCue is a symptom phrasing that is a listing when it names a thing:
// "what's wrong with edge-1" is that device's incidents. The data arm takes
// it only as an incident list about a resolved entity (IncidentRefOnly);
// without one ("what is broken") the skills investigate, as before.
var listingCue = regexp.MustCompile(`(?i)\b(?:what'?s wrong|what is wrong|not working|broken)\b`)

// answerData runs the data arm; handled=false leaves the question to the
// classic path. A failing data arm is never fatal: the classic path answers.
func (o *Orchestrator) answerData(ctx context.Context, p Principal, question string, plan Plan, disc []string) (Answer, bool) {
	if o.NLQuery == nil || plan.Intent == "problem_explanation" || diagnosticCue.MatchString(question) {
		return Answer{}, false
	}
	emitTrace(o.Trace, TraceEvent{Type: TraceToolStarted, Tool: "nl_query"})
	opts := DataOpts{AllowModel: plan.Intent != "product_question" && plan.Intent != "product_navigation", ClassicIntent: plan.Intent}
	if listingCue.MatchString(question) {
		opts.IncidentRefOnly, opts.AllowModel = true, false
	}
	if method := o.contestedMethod(question, plan, opts.AllowModel); method != "" {
		// N-G4: the grammar may fail and a method also claims the question —
		// ask once, cheaply, before spending the model compile on it.
		opts.BeforeModel = func(ctx context.Context) bool { return o.routeTieBreak(ctx, question, method) }
	}
	d, err := o.NLQuery(ctx, p, question, opts)
	nlqOutcome := "ok"
	if err != nil || (d.Status != DataAnswered && d.Status != DataClarify) {
		nlqOutcome = "skipped" // the classic path answers instead
	}
	emitTrace(o.Trace, TraceEvent{Type: TraceToolFinished, Tool: "nl_query", Outcome: nlqOutcome})
	if err != nil || (d.Status != DataAnswered && d.Status != DataClarify) {
		return Answer{}, false
	}
	cits := d.Citations
	if cits == nil {
		cits = []Citation{}
	}
	return Answer{
		Mode: ModeDataQuery, Intent: d.Intent, Modules: []string{},
		Text: d.Text, Citations: cits, Disclaimers: nonEmptyList(append(append([]string{}, disc...), d.Notes...)),
		Data: d.Payload,
	}, true
}

func nonEmptyList(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
