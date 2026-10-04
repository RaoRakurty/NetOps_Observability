// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// compile_query.go — the `compile_query` tool (tracker 337 N-C5): the agent
// loop can ask how Iris would INTERPRET a data question — the validated
// CorrelixQueryAST, the entities it resolved, what it did not understand —
// without running it. Read-only by construction: the seam compiles and
// validates in the caller's scope and never executes; running a query stays
// with /api/ai/query/execute and the router's data arm, which the operator
// sees.
//
// The question is the model's own argument, so it is treated like any other
// untrusted input: one line, bounded, and handed to the same compiler (and, when
// the grammar cannot parse it, the same guarded model fallback) an operator's
// question gets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// MaxCompileQuestionChars bounds the tool's question argument (the same bound
// as /api/ai/query/compile).
const MaxCompileQuestionChars = 1000

// QueryInterpretation is what compile_query returns: never a result set.
type QueryInterpretation struct {
	// Status is closed: compiled | invalid | clarify | declined | not_understood.
	Status string
	Intent string
	// Source is "model" when the model fallback interpreted the question.
	Source string
	// Query is the validated (constrained) query; for Status invalid, the query
	// as understood (never run), with ValidationCodes saying why.
	Query           json.RawMessage
	ValidationCodes []string
	Constraints     []string
	Entities        []string // resolved entity ids
	Clarify         []string // candidate ids of an ambiguous name
	NotUnderstood   []string
}

// Interpretation statuses.
const (
	QueryCompiled      = "compiled"
	QueryInvalid       = "invalid"
	QueryClarify       = "clarify"
	QueryDeclined      = "declined"
	QueryNotUnderstood = "not_understood"
)

type compileQueryTool struct{ deps TroubleshootDeps }

func (compileQueryTool) Name() string            { return "compile_query" }
func (compileQueryTool) Module() string          { return "telemetry" }
func (compileQueryTool) Capability() Capability  { return CapRead }
func (compileQueryTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (compileQueryTool) Freshness() Freshness    { return FreshnessLive }

// validQuestionArg bounds a free-text question argument: required, one line,
// printable, at most MaxCompileQuestionChars.
func validQuestionArg(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("question is required")
	}
	if len([]rune(v)) > MaxCompileQuestionChars {
		return "", fmt.Errorf("question is too long (max %d characters)", MaxCompileQuestionChars)
	}
	for _, r := range v {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return "", errors.New("question must be one line of printable text")
		}
	}
	return v, nil
}

func (t compileQueryTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	q, err := validQuestionArg(args["question"])
	if err != nil {
		return ToolResult{}, err
	}
	in, err := t.deps.CompileQuery(ctx, p, q)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{Notes: []string{"compile_query only interprets a question; it never runs the query or reads data"}}
	text := ""
	switch in.Status {
	case QueryCompiled:
		text = "Interpreted query (not run): " + string(in.Query)
	case QueryInvalid:
		text = "Understood as " + string(in.Query) + " but it would be refused: " + strings.Join(in.ValidationCodes, ", ")
	case QueryClarify:
		text = "Ambiguous name — candidates: " + strings.Join(in.Clarify, ", ")
	case QueryDeclined:
		text = "Declined: Iris NL reads data; it does not act or reach other workspaces"
	default:
		text = "Not understood: " + strings.Join(in.NotUnderstood, ", ")
	}
	if in.Source != "" {
		text += " [interpreted by the model]"
	}
	if len(in.Entities) > 0 {
		text += "; entities " + strings.Join(in.Entities, ", ")
	}
	for _, c := range in.Constraints {
		tr.Notes = append(tr.Notes, "adjusted: "+c)
	}
	tr.Items = []EvidenceItem{{CitationID: "query-plan:" + in.Status, Kind: "query", Text: clampText(text, 4*maxToolTextChars)}}
	return tr, nil
}

// AddCompileQueryTool registers compile_query when the NL query seam is wired.
func (r *ToolRegistry) AddCompileQueryTool(d TroubleshootDeps) {
	if r == nil || d.CompileQuery == nil {
		return
	}
	r.add(compileQueryTool{deps: d})
}
