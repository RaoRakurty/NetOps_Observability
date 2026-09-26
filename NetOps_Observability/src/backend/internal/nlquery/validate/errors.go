// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package validate is the gate every CorrelixQueryAST passes before anything
// reads data (tracker 337 N-C3; design: docs/architecture/iris-nl-query-design.md
// §3). It never trusts the query — a model wrote it — and it never trusts the
// caller's claim about what they may see: entity visibility is asked of the
// root, which answers from the authenticated principal.
//
// Two outcomes a caller must handle differently:
//   - a REJECTION (Result.Valid == false) — the query asks for something
//     unanswerable or unsafe; the structured errors go back to the compiler's
//     repair loop, never a raw backend exception;
//   - a CONSTRAINT — a missing bound or an oversized row limit is tightened
//     and reported, so the answer states what it did.
//
// An oversized WINDOW is rejected, not shrunk: silently answering a smaller
// question than the one asked is worse than asking again.
package validate

// Closed error codes. The compiler's repair loop and the golden corpus both
// key on these, so they are values, not prose.
const (
	CodeUnknownField           = "unknown_field"
	CodeUnknownQueryType       = "unknown_query_type"
	CodeMissingField           = "missing_field"
	CodeForbiddenFieldForType  = "forbidden_field_for_type"
	CodeUnknownMetric          = "unknown_metric"
	CodeMetricNotApplicable    = "metric_not_applicable"
	CodeInvalidEntityID        = "invalid_entity_id"
	CodeUnknownEntity          = "unknown_entity"
	CodeRelationshipNotAllowed = "relationship_not_allowed"
	CodeUnknownDimension       = "unknown_dimension"
	CodeOperatorNotAllowed     = "operator_not_allowed"
	CodeAggregationNotAllowed  = "aggregation_not_allowed"
	CodeInvalidValue           = "invalid_value"
	CodeInvalidTime            = "invalid_time"
	CodeWindowTooLarge         = "window_too_large"
	CodeTooBroad               = "too_broad"
	CodeUnsupportedQueryType   = "unsupported_query_type"
	CodeScopeUnavailable       = "scope_unavailable"
	CodeUnmappedProvider       = "unmapped_provider"
)

// Error is one structured validation failure.
type Error struct {
	Path        string   `json:"path"`
	Code        string   `json:"code"`
	Got         string   `json:"got,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// Constraint records a bound the validator applied instead of rejecting.
type Constraint struct {
	Path   string `json:"path"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

// Result is the validator's verdict.
type Result struct {
	Valid       bool         `json:"valid"`
	Errors      []Error      `json:"errors,omitempty"`
	Constraints []Constraint `json:"constraints_applied,omitempty"`
}

func clip(s string) string {
	r := []rune(s)
	if len(r) > 64 {
		return string(r[:64])
	}
	return s
}

func sortStrings(xs []string) []string {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
	return xs
}
