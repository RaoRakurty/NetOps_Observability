package rca

// helpers.go — small pure conversions this package needs.
//
// parseChTS and FmtUTC arrived with the wave-1 files as duplicates of the
// rca_report.go originals; the wave-2 move brought the originals home, so
// these ARE now the single definitions. asString/asFloat (health_score.go),
// orDefault (ticketing_store.go) and envDuration (report_pipeline.go) are
// duplicated one-liners rather than shared through a common package, because
// CLAUDE.md §2 forbids a "utils" dumping ground outright and one-liners do not
// justify inventing a package to hold them. If a shared helper grows real
// behavior, that is the signal to give it a real home with a real name
// (asFloat's F-21 sanitisation already has one: internal/metricval).

import (
	"os"
	"strings"
	"time"

	"netops/backend/internal/metricval"
)

// asString returns v when it is a string, otherwise "".
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// asFloat reads a numeric value that may arrive as a float, a numeric string,
// or garbage — non-finite values sanitise to 0 (F-21) via metricval.
func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		// ClickHouse can hand back a non-finite float directly (nan/inf in a
		// JSON number position); sanitise it here too, not just the string form.
		return metricval.Sanitize(x)
	case string:
		// F-21: ParseFloat("NaN") succeeds and the NaN would land in a report
		// field, failing the JSON encode and comparing false everywhere.
		return metricval.FiniteOrZero(x)
	}
	return 0
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

// FmtUTC renders an instant for operators, always in UTC and always labelled.
func FmtUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }

// ParseFmtUTC is the exact inverse of FmtUTC. The deterministic-regeneration
// path uses it to turn a recorded revision's GeneratedAt stamp back into the
// build clock the revision was generated with (FmtUTC is second-granular, so
// the round-trip is lossless for clocks truncated to the second).
func ParseFmtUTC(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02 15:04:05 UTC", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// orDefault returns s when non-empty, else def.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// envDuration reads a positive duration knob from the environment, falling
// back to def — the package owns its own coverage-window knobs.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
