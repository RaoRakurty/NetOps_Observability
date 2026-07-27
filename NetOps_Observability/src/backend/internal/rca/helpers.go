package rca

// helpers.go — small pure conversions this package needs.
//
// These are duplicated from package main (asString from health_score.go,
// parseChTS/fmtUTC from rca_report.go) rather than shared through a common
// package, because CLAUDE.md §2 forbids a "utils" dumping ground outright and
// three one-liners do not justify inventing a package to hold them. If a fourth
// consumer appears, that is the signal to give them a real home with a real
// name (e.g. a chtime package), not to grow this file.

import (
	"strings"
	"time"
)

// asString returns v when it is a string, otherwise "".
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// parseChTS accepts both the RFC 3339 form chISO now emits and the legacy
// zone-less ClickHouse rendering, so mixed fleets during rollout stay readable.
func parseChTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// fmtUTC renders an instant for operators, always in UTC and always labelled.
func fmtUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }
