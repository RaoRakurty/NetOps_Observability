// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package modelc is the MODEL half of the Iris NL query compiler (tracker 337
// N-C5; design: iris-natural-language-platform.md §4.1 decision 1,
// iris-nl-query-design.md §6). The deterministic grammar (package compile)
// runs first; only when it reports a question Unparsed does this package ask a
// model — for structured output against the AST JSON schema, with the relevant
// catalog fragments (schema-RAG) and a handful of worked examples
// (example-RAG), both chosen lexically (no vector store — standing decision).
//
// Everything the model returns is untrusted data (CLAUDE.md §3, §15 LLM02):
//
//   - it is decoded STRICTLY (ast.Decode — unknown fields, and so any tenant
//     field, are errors) and validated by the same validator, in the caller's
//     scope, as a grammar-built query;
//   - every entity id it emits must be one the caller's own resolver produced
//     for THIS question — an id from anywhere else (a guess, an example, another
//     tenant) is refused exactly like a missing one;
//   - a thing the question NAMES that the model then leaves out is refused
//     (silently widening "cpu on edge-9" to "cpu everywhere" is the failure the
//     grammar's coverage rule exists to prevent);
//   - validation errors go back for at most MaxRepairRounds repairs, as closed
//     codes, paths and catalog suggestions only; still invalid ⇒ Unparsed.
//
// The package never holds a key, never makes a network call and never sees a
// tenant: the root supplies Model (the tiered, budget-charged provider chain)
// and the caller-scoped Lookups and Scope.
package modelc

import (
	"context"
	"errors"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
)

// SourceModel marks a result the model compiled (the grammar's results carry
// no source). The UI says "interpreted by the model"; the router discloses it.
const SourceModel = "model"

// Bounds (LLM04). Output tokens are additionally capped for every provider call
// by the transport (ai.MaxOutputTokens); MaxReplyBytes bounds what is parsed.
const (
	MaxRepairRounds  = 2
	MaxQuestionChars = 1000
	MaxPromptChars   = 24000
	MaxReplyBytes    = ast.MaxBytes + 2048
	MaxExamples      = 4
	MaxMetrics       = 6
	MaxMentions      = 12
	DefaultTimeout   = 45 * time.Second
	DefaultCallLimit = 20 * time.Second
)

// Refusal reasons (closed vocabulary, for logs and the offline harness).
const (
	RefuseNotUnparsed    = "not_unparsed"    // the grammar answered, declined or asked
	RefuseUnavailable    = "unavailable"     // no model wired
	RefuseTooLarge       = "input_too_large" // question over MaxQuestionChars
	RefuseNoVocabulary   = "no_vocabulary"   // nothing in it the catalog knows
	RefuseReference      = "unbound_reference"
	RefuseUnresolvedName = "unresolved_name" // an identifier the caller's resolver did not find
	RefuseModelError     = "model_error"     // provider failed, timed out or budget spent
	RefuseModelDeclined  = "model_declined"  // the model said it cannot express it
	RefuseForbiddenField = "forbidden_field" // a tenant/org field in the reply
	RefuseStillInvalid   = "invalid_after_repair"
)

// Message is one turn to the model. Role is "user" or "assistant"; the system
// prompt is passed separately and is always this package's constant (LLM01).
type Message struct {
	Role    string
	Content string
}

// Model is the provider seam. The root binds it to the caller's tiered,
// budget-charged provider chain; tests bind a deterministic stub.
type Model interface {
	Complete(ctx context.Context, system string, msgs []Message) (string, error)
}

// Example is one worked question → AST pair for example-RAG. Entity ids in an
// example are placeholders; Resolved says which words they stand for.
type Example struct {
	ID       string          `json:"id"`
	Question string          `json:"question"`
	Resolved []ExampleEntity `json:"resolved,omitempty"`
	AST      jsonRaw         `json:"ast"`
}

// ExampleEntity is one resolved mention inside an example.
type ExampleEntity struct {
	Input string `json:"input"`
	Type  string `json:"type"`
	ID    string `json:"id"`
}

// Fallback compiles an Unparsed question with the model.
type Fallback struct {
	Cat   *catalog.Catalog
	L     resolve.Lookups // the CALLER's aliases and inventory
	Model Model           // nil ⇒ the fallback is unavailable
	// Examples is the example library; nil ⇒ the embedded one.
	Examples []Example
	// SkipExample excludes examples (the offline harness leaves a case's own
	// examples out so it measures generalisation, not recall).
	SkipExample func(id string) bool
	Timeout     time.Duration // whole fallback; 0 ⇒ DefaultTimeout
	CallTimeout time.Duration // one model call; 0 ⇒ DefaultCallLimit
}

// Outcome is the fallback's answer.
type Outcome struct {
	// Result is Unparsed (with the grammar's NotUnderstood) unless the model's
	// query was accepted; then AST is the model's decoded query.
	Result compile.Result
	// Checked and Validation are the validator's verdict on an accepted query.
	Checked    *ast.AST
	Validation validate.Result
	Source     string // SourceModel when accepted
	Calls      int    // model calls made (1 + repair rounds)
	Refusal    string // why the model path gave up (empty when accepted)
}

// Accepted reports whether the model's query was accepted.
func (o Outcome) Accepted() bool { return o.Source == SourceModel && o.Checked != nil }

// Compile runs the model fallback for one question the grammar left
// Unparsed. det is the grammar's result; any other result is returned as is.
// It never returns an error for a model failure — the answer is then the
// honest Unparsed the grammar gave; errors are the caller's own seams failing.
func (f Fallback) Compile(ctx context.Context, question string, cx compile.Context, sc validate.Scope, det compile.Result) (Outcome, error) {
	out := Outcome{Result: det}
	switch {
	case !det.Unparsed || det.AST != nil || det.Decline != "" || len(det.Clarify) > 0:
		out.Refusal = RefuseNotUnparsed
		return out, nil
	case f.Model == nil || f.Cat == nil || f.L == nil || sc == nil:
		out.Refusal = RefuseUnavailable
		return out, nil
	case len([]rune(question)) > MaxQuestionChars:
		out.Refusal = RefuseTooLarge
		return out, nil
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	text := normalizeQuestion(question)
	if reason := precheckReferences(text, det.NotUnderstood); reason != "" {
		out.Refusal = reason
		return out, nil
	}
	ments, err := scanMentions(ctx, f.Cat, f.L, text)
	if err != nil {
		return out, err
	}
	ments = mergeGrammarEntities(ments, det.Entities)
	frag := retrieveSchema(f.Cat, text)
	if len(frag.metrics) == 0 && len(frag.entities) == 0 && len(ments) == 0 {
		out.Refusal = RefuseNoVocabulary
		return out, nil
	}
	idents := identifierTokens(f.Cat, text, det.NotUnderstood, ments)
	idents = append(idents, properNames(f.Cat, question, ments)...)
	if len(idents) > 0 && !frag.entities["change"] && !frag.entities["incident"] {
		// Only a change or incident list can carry a name as a filter value; a
		// metric question naming something the caller's resolver cannot find
		// is about something they cannot see (or that does not exist).
		out.Refusal = RefuseUnresolvedName
		return out, nil
	}
	lib := f.Examples
	if lib == nil {
		lib = EmbeddedExamples()
	}
	exs := retrieveExamples(lib, text, frag, f.SkipExample)
	now := sc.Now()
	if !cx.Now.IsZero() {
		now = cx.Now
	}
	loc := cx.Loc
	if loc == nil {
		loc = time.UTC
	}
	user := buildPrompt(promptInput{question: question, now: now, loc: loc, incident: cx.IncidentID,
		mentions: ments, frag: frag, examples: exs, cat: f.Cat})
	g := guard{cat: f.Cat, mentions: ments, text: text, incident: cx.IncidentID, idents: idents}

	msgs := []Message{{Role: "user", Content: user}}
	for round := 0; round <= MaxRepairRounds; round++ {
		reply, err := f.call(ctx, msgs)
		out.Calls++
		if err != nil {
			out.Refusal = RefuseModelError
			return out, nil
		}
		q, problems, fatal := parseReply(reply)
		if fatal != "" {
			out.Refusal = fatal
			return out, nil
		}
		if q != nil {
			problems = append(problems, g.check(q)...)
			if len(problems) == 0 {
				checked, vr := validate.Validate(ctx, f.Cat, sc, q)
				if vr.Valid {
					out.Result = compile.Result{Intent: intentFor(q.Type), AST: q, Entities: g.usedRefs(q)}
					out.Checked, out.Validation, out.Source, out.Refusal = checked, vr, SourceModel, ""
					return out, nil
				}
				problems = vr.Errors
			}
		}
		if round == MaxRepairRounds {
			break
		}
		msgs = append(msgs, Message{Role: "assistant", Content: clipReply(reply)}, Message{Role: "user", Content: repairPrompt(problems)})
	}
	out.Refusal = RefuseStillInvalid
	return out, nil
}

// call makes one bounded model call.
func (f Fallback) call(ctx context.Context, msgs []Message) (string, error) {
	limit := f.CallTimeout
	if limit <= 0 {
		limit = DefaultCallLimit
	}
	cctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	reply, err := f.Model.Complete(cctx, SystemPrompt(), msgs)
	if err != nil {
		return "", err
	}
	if len(reply) > MaxReplyBytes {
		return "", errReplyTooLarge
	}
	return reply, nil
}

var errReplyTooLarge = errors.New("model reply is larger than the maximum")

// intentFor names the intent a query type answers (the grammar's vocabulary).
func intentFor(t ast.QueryType) string {
	switch t {
	case ast.MetricSeries:
		return "show_metric"
	case ast.MetricTopK:
		return "rank"
	case ast.MetricFilter:
		return "threshold"
	case ast.CompareWindows:
		return "compare"
	case ast.ChangeList:
		return "list_changes"
	case ast.IncidentList:
		return "list_incidents"
	case ast.IncidentExplain:
		return "explain_incident"
	}
	return ""
}

// clipReply bounds an echoed reply (it is the model's own output, sent back
// only so the repair turn has context).
func clipReply(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > ast.MaxBytes {
		return s[:ast.MaxBytes]
	}
	return s
}
