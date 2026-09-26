// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package ast is CorrelixQueryAST v1 — the closed, backend-neutral query form
// every natural-language question compiles to before anything reads data
// (tracker 337 N-C3; design: docs/architecture/iris-nl-query-design.md §2).
//
// What it deliberately CANNOT express is the point: there is no tenant field
// (the planner takes the tenant from the authenticated principal, never from
// a query), no raw label name, SQL, MetricsQL or search DSL, no regex or free
// text match, no arithmetic across metrics, no joins outside the catalog's
// relationships, no writes and no "all time". A model can only fill slots
// whose names the catalog already defines, and the validator re-checks every
// one of them.
package ast

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

// Version is the only AST version this build accepts.
const Version = 1

// MaxBytes bounds one encoded AST.
const MaxBytes = 16 << 10

// QueryType is the closed set of query shapes.
type QueryType string

const (
	MetricSeries    QueryType = "metric_series"
	MetricTopK      QueryType = "metric_topk"
	MetricFilter    QueryType = "metric_filter"
	CompareWindows  QueryType = "compare_windows"
	ChangeList      QueryType = "change_list"
	IncidentList    QueryType = "incident_list"
	IncidentExplain QueryType = "incident_explain"
	// Reserved: decodable so the validator can say "not yet" precisely.
	FlowTop   QueryType = "flow_top"
	LogSearch QueryType = "log_search"
)

// Known reports whether t is a query type this build recognises at all.
func (t QueryType) Known() bool {
	switch t {
	case MetricSeries, MetricTopK, MetricFilter, CompareWindows, ChangeList, IncidentList, IncidentExplain, FlowTop, LogSearch:
		return true
	}
	return false
}

// IsMetric reports whether the query reads metric series.
func (t QueryType) IsMetric() bool {
	return t == MetricSeries || t == MetricTopK || t == MetricFilter || t == CompareWindows
}

// AST is one query.
type AST struct {
	V          int         `json:"v"`
	Type       QueryType   `json:"query_type"`
	Target     string      `json:"target"`
	Metric     string      `json:"metric,omitempty"`
	Agg        string      `json:"aggregation,omitempty"`
	Refs       []EntityRef `json:"entities,omitempty"`
	Filters    []Filter    `json:"filters,omitempty"`
	Predicate  *Predicate  `json:"predicate,omitempty"`
	Time       TimeRange   `json:"time_range"`
	CompareTo  *TimeRange  `json:"compare_to,omitempty"`
	GroupBy    []string    `json:"group_by,omitempty"`
	OrderBy    []OrderKey  `json:"order_by,omitempty"`
	Limit      int         `json:"limit,omitempty"`
	IncidentID string      `json:"incident_id,omitempty"`
}

// EntityRef is a RESOLVED entity id (never a free-text name). Refs of one type
// are OR'd; refs of different types are AND'd.
type EntityRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Filter constrains a list dimension (change / incident).
type Filter struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// Predicate constrains a metric value.
type Predicate struct {
	Op     string  `json:"op"`
	Value  float64 `json:"value,omitempty"`
	Value2 float64 `json:"value2,omitempty"`
}

// OrderKey orders the result.
type OrderKey struct {
	Field string `json:"field"`
	Dir   string `json:"dir"`
}

// Time range kinds.
const (
	TimeAbsolute  = "absolute"
	TimeRelative  = "relative"
	TimeIncident  = "incident"
	TimeIncidents = "incidents"
)

// TimeRange is when the query looks. Calendar words ("yesterday") are turned
// into absolute times by the compiler before an AST exists.
type TimeRange struct {
	Kind   string     `json:"kind"`
	From   *time.Time `json:"from,omitempty"`
	To     *time.Time `json:"to,omitempty"`
	Last   string     `json:"last,omitempty"`
	Offset string     `json:"offset,omitempty"`
	Anchor *Anchor    `json:"anchor,omitempty"`
}

// Anchor ties a window to one incident, or to every incident of a set.
type Anchor struct {
	IncidentID string       `json:"incident_id,omitempty"`
	Incidents  *IncidentSet `json:"incidents,omitempty"`
	Before     string       `json:"before,omitempty"`
	After      string       `json:"after,omitempty"`
}

// IncidentSet selects the incidents an anchored window repeats around.
type IncidentSet struct {
	Filters []Filter    `json:"filters,omitempty"`
	Refs    []EntityRef `json:"entities,omitempty"`
	Time    TimeRange   `json:"time_range"`
	Max     int         `json:"max,omitempty"`
}

// ErrTooLarge is returned for an encoded AST over MaxBytes.
var ErrTooLarge = errors.New("query is larger than the maximum encoded size")

// Decode parses one AST STRICTLY: bounded size, no unknown fields (which is
// also what makes a smuggled `tenant`/`as_tenant` field an error), exactly one
// JSON value. It does not validate meaning — validate.Validate does.
func Decode(raw []byte) (*AST, error) {
	if len(raw) > MaxBytes {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a AST
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("query does not decode: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("query does not decode: trailing data after the query object")
	}
	return &a, nil
}

// Canonical is the deterministic encoding (stable field order from the struct,
// no whitespace). Hash is its SHA-256 — the ast_hash in provenance and the
// key the decision ledger records.
func (a *AST) Canonical() ([]byte, error) { return json.Marshal(a) }

// Hash returns the hex SHA-256 of the canonical encoding.
func (a *AST) Hash() string {
	b, err := a.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Clone deep-copies the AST (conversation follow-ups rewrite a COPY).
func (a *AST) Clone() *AST {
	b, err := a.Canonical()
	if err != nil {
		return nil
	}
	c, err := Decode(b)
	if err != nil {
		return nil
	}
	return c
}

var durationRe = regexp.MustCompile(`^([1-9][0-9]{0,3})([mhd])$`)

// ParseDuration parses the AST's closed duration token: 1–4 digits and m|h|d.
func ParseDuration(s string) (time.Duration, error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("duration %q must look like 15m, 2h or 7d", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, err
	}
	unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}
