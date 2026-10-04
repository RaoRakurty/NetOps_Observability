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
}

// NLQueryFunc answers a question with the NL query engine, in the caller's
// scope. Status DataNotData (or an error) means "not mine".
type NLQueryFunc func(ctx context.Context, p Principal, question string, opts DataOpts) (DataAnswer, error)

// diagnosticCue marks a question that asks for a diagnosis, not a listing.
var diagnosticCue = regexp.MustCompile(`(?i)\b(?:why|root cause|caused?|causing|troubleshoot\w*|diagnos\w*|investigat\w*|what'?s wrong|what is wrong|not working|broken|fix|explain)\b`)

// answerData runs the data arm; handled=false leaves the question to the
// classic path. A failing data arm is never fatal: the classic path answers.
func (o *Orchestrator) answerData(ctx context.Context, p Principal, question string, plan Plan, disc []string) (Answer, bool) {
	if o.NLQuery == nil || plan.Intent == "problem_explanation" || diagnosticCue.MatchString(question) {
		return Answer{}, false
	}
	d, err := o.NLQuery(ctx, p, question, DataOpts{AllowModel: plan.Intent != "product_question" && plan.Intent != "product_navigation"})
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
