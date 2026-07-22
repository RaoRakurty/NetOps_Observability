package main

import (
	"math"
	"strconv"
	"strings"
	"sync/atomic"
)

// metric_float.go — the parse boundary for metric-store values (F-21).
//
// strconv.ParseFloat("NaN", 64) SUCCEEDS. So does "+Inf", "-Inf", "inf".
// VictoriaMetrics and ClickHouse both emit those strings for ordinary
// conditions — stddev_over_time over a single sample, a 0/0 rate, an
// increase() across a counter reset. Every call site parsed them with the error
// discarded and put the result straight into a response struct.
//
// Two things then happen, both silent:
//
//  1. encoding/json REFUSES to marshal NaN/±Inf. Before the writeJSON fix that
//     was a 200 OK with an empty body; after it, it is an honest 500 — but a
//     500 on a dashboard poll because one series went NaN is still a fault we
//     should not create. Sanitising at the parse boundary is what keeps the
//     endpoint serving the other series.
//  2. NaN compares false against EVERY threshold (NaN > x, NaN < x, NaN == x
//     are all false). Any logic that reads the value silently decides "not
//     breaching" — the exact shape of an alert that never fires.
//
// So: non-finite is not a number, it is MISSING DATA, and it is counted.

// metricNonFinite counts samples rejected as non-finite. Write-only atomic, no
// configuration — see the note on jsonEncodeFailures for why it is package-level.
var metricNonFinite atomic.Uint64

// parseMetricFloat parses a metric-store value string. ok is false when the
// value is malformed OR non-finite; v is then 0. Callers that can distinguish
// "missing" from "zero" MUST branch on ok — a NaN silently becoming 0 is a
// different lie from a NaN silently becoming a 200 with no body.
func parseMetricFloat(s string) (v float64, ok bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		metricNonFinite.Add(1)
		return 0, false
	}
	return f, true
}

// finiteOrZero is parseMetricFloat for the call sites whose response field is a
// plain float64 with no "missing" representation: a non-finite value becomes 0
// and is counted, rather than travelling into the JSON encoder where it would
// fail the whole response.
func finiteOrZero(s string) float64 {
	v, _ := parseMetricFloat(s)
	return v
}

// sanitizeFloat is the last-line guard for a float that was COMPUTED rather than
// parsed (a division, an average, a forecast slope): the same non-finite values
// arise from 0/0 and overflow, and the same encoder refuses them.
func sanitizeFloat(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		metricNonFinite.Add(1)
		return 0
	}
	return f
}
