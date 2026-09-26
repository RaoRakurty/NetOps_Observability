// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package mql builds MetricsQL expressions for the Iris NL planner (tracker
// 337 N-C4; design §4).
//
// Expr has an UNEXPORTED field, so only this package's constructors can make
// one; the root's VictoriaMetrics adapter accepts only an Expr. Model-written
// text therefore has no path to VictoriaMetrics through the NL query route —
// every expression is assembled here from catalog names, validated label
// names, escaped values, closed function names and parsed durations.
//
// Tenant scope is NOT added here and must never be: the root applies it
// server-side as VictoriaMetrics extra_filters (metricsScopeFiltersFor), which
// no expression can override.
package mql

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Expr is a built MetricsQL expression.
type Expr struct{ s string }

// String returns the expression text (for the executor and /explain).
func (e Expr) String() string { return e.s }

// IsZero reports an unbuilt expression.
func (e Expr) IsZero() bool { return e.s == "" }

var (
	metricNameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNameRe  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Matcher is one label constraint. Op "=" matches one value; "=~" matches any
// of Values exactly (they are regex-quoted, then string-escaped).
type Matcher struct {
	Label  string
	Op     string // "=" | "=~"
	Values []string
}

// quoteString escapes a value for a double-quoted MetricsQL string literal.
func quoteString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

// anyOf renders an exact-match alternation: each value regex-quoted, joined,
// anchored by MetricsQL's implicit full match, then string-escaped.
func anyOf(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, regexp.QuoteMeta(v))
	}
	return quoteString(strings.Join(parts, "|"))
}

// Selector builds `metric{matchers}`. Every name is validated; every value is
// escaped. An empty value list for "=~" is an error — a selector that silently
// matched everything would widen the query.
func Selector(metric string, ms ...Matcher) (Expr, error) {
	if !metricNameRe.MatchString(metric) {
		return Expr{}, fmt.Errorf("mql: invalid metric name %q", metric)
	}
	var parts []string
	for _, m := range ms {
		if !labelNameRe.MatchString(m.Label) {
			return Expr{}, fmt.Errorf("mql: invalid label name %q", m.Label)
		}
		switch m.Op {
		case "=":
			if len(m.Values) != 1 {
				return Expr{}, fmt.Errorf("mql: label %s: = takes exactly one value", m.Label)
			}
			parts = append(parts, m.Label+"="+quoteString(m.Values[0]))
		case "=~":
			if len(m.Values) == 0 {
				return Expr{}, fmt.Errorf("mql: label %s: no values to match", m.Label)
			}
			parts = append(parts, m.Label+"=~"+anyOf(m.Values))
		default:
			return Expr{}, fmt.Errorf("mql: label %s: operator %q is not allowed", m.Label, m.Op)
		}
	}
	if len(parts) == 0 {
		return Expr{s: metric}, nil
	}
	return Expr{s: metric + "{" + strings.Join(parts, ",") + "}"}, nil
}

// Dur renders a duration as a MetricsQL duration token (whole seconds).
func Dur(d time.Duration) string {
	sec := int64(d / time.Second)
	if sec < 1 {
		sec = 1
	}
	switch {
	case sec%86400 == 0:
		return strconv.FormatInt(sec/86400, 10) + "d"
	case sec%3600 == 0:
		return strconv.FormatInt(sec/3600, 10) + "h"
	case sec%60 == 0:
		return strconv.FormatInt(sec/60, 10) + "m"
	}
	return strconv.FormatInt(sec, 10) + "s"
}

// Num renders a finite number. NaN/Inf are refused at the caller by returning
// a zero Expr from Scalar.
func Num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// Scalar is a numeric literal expression.
func Scalar(f float64) Expr {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return Expr{}
	}
	return Expr{s: Num(f)}
}

// rangeFuncs and aggregations are the CLOSED function vocabularies.
var (
	rangeFuncs = map[string]bool{"rate": true, "increase": true, "changes": true, "avg_over_time": true,
		"max_over_time": true, "min_over_time": true, "sum_over_time": true, "last_over_time": true}
	aggFuncs = map[string]bool{"sum": true, "avg": true, "max": true, "min": true}
	cmpOps   = map[string]bool{">": true, ">=": true, "<": true, "<=": true, "==": true, "!=": true}
	binOps   = map[string]bool{"+": true, "-": true, "*": true, "/": true}
)

// Range applies a range-vector function over a window: fn(e[w]).
func Range(fn string, e Expr, w time.Duration) (Expr, error) {
	if !rangeFuncs[fn] || e.IsZero() {
		return Expr{}, fmt.Errorf("mql: range function %q not allowed", fn)
	}
	return Expr{s: fn + "(" + e.s + "[" + Dur(w) + "])"}, nil
}

// QuantileOverTime is quantile_over_time(q, e[w]).
func QuantileOverTime(q float64, e Expr, w time.Duration) (Expr, error) {
	if q <= 0 || q >= 1 || e.IsZero() {
		return Expr{}, fmt.Errorf("mql: quantile %v out of range", q)
	}
	return Expr{s: "quantile_over_time(" + Num(q) + ", " + e.s + "[" + Dur(w) + "])"}, nil
}

// Agg applies an aggregation, optionally by labels: fn by (l1,l2) (e).
func Agg(fn string, e Expr, by ...string) (Expr, error) {
	if !aggFuncs[fn] || e.IsZero() {
		return Expr{}, fmt.Errorf("mql: aggregation %q not allowed", fn)
	}
	for _, l := range by {
		if !labelNameRe.MatchString(l) {
			return Expr{}, fmt.Errorf("mql: invalid label name %q", l)
		}
	}
	if len(by) == 0 {
		return Expr{s: fn + "(" + e.s + ")"}, nil
	}
	return Expr{s: fn + " by (" + strings.Join(by, ", ") + ") (" + e.s + ")"}, nil
}

// Bin is a binary arithmetic expression (a op b).
func Bin(a Expr, op string, b Expr) (Expr, error) {
	if !binOps[op] || a.IsZero() || b.IsZero() {
		return Expr{}, fmt.Errorf("mql: operator %q not allowed", op)
	}
	return Expr{s: "(" + a.s + " " + op + " " + b.s + ")"}, nil
}

// Cmp is a filtering comparison (a op b), which keeps series where it holds.
func Cmp(a Expr, op string, b Expr) (Expr, error) {
	if !cmpOps[op] || a.IsZero() || b.IsZero() {
		return Expr{}, fmt.Errorf("mql: comparison %q not allowed", op)
	}
	return Expr{s: "(" + a.s + " " + op + " " + b.s + ")"}, nil
}

// TopK is topk(k, e); LimitK is limitk(k, e) — the series-count safety net.
func TopK(k int, e Expr) (Expr, error)   { return kFunc("topk", k, e) }
func LimitK(k int, e Expr) (Expr, error) { return kFunc("limitk", k, e) }

func kFunc(fn string, k int, e Expr) (Expr, error) {
	if k <= 0 || k > 10000 || e.IsZero() {
		return Expr{}, fmt.Errorf("mql: %s k=%d out of range", fn, k)
	}
	return Expr{s: fn + "(" + strconv.Itoa(k) + ", " + e.s + ")"}, nil
}

// Abs is abs(e).
func Abs(e Expr) (Expr, error) {
	if e.IsZero() {
		return Expr{}, fmt.Errorf("mql: abs of nothing")
	}
	return Expr{s: "abs(" + e.s + ")"}, nil
}

// Offset shifts an expression back in time: (e offset d). Applied to a
// selector or range expression by re-rendering with the modifier.
func Offset(e Expr, d time.Duration) (Expr, error) {
	if e.IsZero() || d <= 0 {
		return Expr{}, fmt.Errorf("mql: invalid offset")
	}
	return Expr{s: "(" + e.s + " offset " + Dur(d) + ")"}, nil
}

// Subquery applies a range function over an EXPRESSION sampled at step:
// fn(e[w:step]) — used when the inner expression is itself a function (a rate
// or a ratio) rather than a raw selector.
func Subquery(fn string, e Expr, w, step time.Duration) (Expr, error) {
	if !rangeFuncs[fn] || e.IsZero() || step <= 0 {
		return Expr{}, fmt.Errorf("mql: subquery function %q not allowed", fn)
	}
	return Expr{s: fn + "(" + e.s + "[" + Dur(w) + ":" + Dur(step) + "])"}, nil
}

// QuantileSubquery is quantile_over_time(q, e[w:step]).
func QuantileSubquery(q float64, e Expr, w, step time.Duration) (Expr, error) {
	if q <= 0 || q >= 1 || e.IsZero() || step <= 0 {
		return Expr{}, fmt.Errorf("mql: quantile %v out of range", q)
	}
	return Expr{s: "quantile_over_time(" + Num(q) + ", " + e.s + "[" + Dur(w) + ":" + Dur(step) + "])"}, nil
}

// Greatest is the per-series, per-point maximum of two expressions with the
// same label sets: ((a >= b) or b).
func Greatest(a, b Expr) (Expr, error) {
	if a.IsZero() || b.IsZero() {
		return Expr{}, fmt.Errorf("mql: greatest of nothing")
	}
	return Expr{s: "((" + a.s + " >= " + b.s + ") or " + b.s + ")"}, nil
}
