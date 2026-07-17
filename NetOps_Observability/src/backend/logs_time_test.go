package main

import (
	"testing"
	"time"
)

// parseTimeFlexible is the single entry point for caller-supplied time
// bounds on the log-search API. It must (a) accept RFC 3339 with any
// offset and normalize to UTC, (b) infer the epoch unit correctly for
// seconds / milliseconds / microseconds / nanoseconds, and (c) reject
// zoneless strings — a naive "2026-07-17T12:00:00" is ambiguous and must
// not be silently interpreted in any zone.
func TestParseTimeFlexible(t *testing.T) {
	// One reference instant, 2026-07-17T06:30:00Z, expressed every way.
	ref := time.Date(2026, 7, 17, 6, 30, 0, 0, time.UTC)

	cases := []struct {
		name string
		in   string
		want time.Time
	}{
		{"rfc3339 utc", "2026-07-17T06:30:00Z", ref},
		// Explicit-offset inputs must resolve to the same UTC instant.
		{"rfc3339 IST +05:30", "2026-07-17T12:00:00+05:30", ref},
		{"rfc3339 Nepal +05:45", "2026-07-17T12:15:00+05:45", ref},
		{"rfc3339 UTC-6 (device local)", "2026-07-17T00:30:00-06:00", ref},
		{"rfc3339 fractional", "2026-07-17T06:30:00.500Z", ref.Add(500 * time.Millisecond)},
		{"epoch seconds", "1784269800", ref},
		{"epoch milliseconds", "1784269800000", ref},
		{"epoch microseconds", "1784269800000000", ref},
		{"epoch nanoseconds", "1784269800000000000", ref},
		// A future-dated event (year 2033) must still round-trip; future
		// times are surfaced, never clamped or "corrected".
		{"future epoch ms", "2005798200000", time.Date(2033, 7, 24, 6, 10, 0, 0, time.UTC)},
		{"future rfc3339", "2033-07-24T06:10:00Z", time.Date(2033, 7, 24, 6, 10, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseTimeFlexible(c.in)
			if err != nil {
				t.Fatalf("parseTimeFlexible(%q): unexpected error %v", c.in, err)
			}
			if !got.Equal(c.want) {
				t.Fatalf("parseTimeFlexible(%q) = %v, want %v", c.in, got, c.want)
			}
			if got.Location() != time.UTC {
				t.Fatalf("parseTimeFlexible(%q) location = %v, want UTC", c.in, got.Location())
			}
		})
	}
}

// The regression this guards: collectors emit UnixMilli timestamps; the old
// heuristic (split at 1e15 for ns, else seconds) read epoch-ms as SECONDS,
// producing a year-~58500 bound and an absurd query window with no error.
func TestParseTimeFlexibleEpochMillisNotSeconds(t *testing.T) {
	got, err := parseTimeFlexible("1784269800000") // 2026-07-17T06:30:00Z in ms
	if err != nil {
		t.Fatal(err)
	}
	if y := got.Year(); y != 2026 {
		t.Fatalf("epoch-ms parsed to year %d, want 2026 (unit inference regressed)", y)
	}
}

func TestParseTimeFlexibleRejectsAmbiguous(t *testing.T) {
	for _, in := range []string{
		"",
		"yesterday",
		"2026-07-17T06:30:00", // zoneless — ambiguous, must be rejected
		"2026-07-17 06:30:00", // zoneless with space
		"17/07/2026 06:30",    // locale format
	} {
		if _, err := parseTimeFlexible(in); err == nil {
			t.Fatalf("parseTimeFlexible(%q): want error, got none", in)
		}
	}
}

// chTsUTC must render ClickHouse timestamps as RFC 3339 UTC with an explicit
// Z suffix — the SPA contract. Guard the expression so a refactor back to a
// bare toString(ts) (server-zone, zoneless string) fails loudly.
func TestChTsUTCExpression(t *testing.T) {
	got := chTsUTC("ts")
	want := `concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z')`
	if got != want {
		t.Fatalf("chTsUTC(\"ts\") = %q, want %q", got, want)
	}
}
