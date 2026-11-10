// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"strings"
	"testing"
	"time"
)

func TestParseTime(t *testing.T) {
	loc, _ := time.LoadLocation("America/Chicago")
	now := time.Date(2026, 9, 24, 15, 0, 0, 0, time.UTC) // Thu 10:00 CDT
	cases := map[string]string{
		"loss in the last 2 hours":  "relative 2h",
		"cpu past 15 minutes":       "relative 15m",
		"changes last 3 days":       "relative 3d",
		"errors over the last week": "relative 7d",
		"changes last hour":         "relative 1h",
		"a month of loss":           "relative 30d",
		"45 days of changes":        "relative 45d",
		"all time cpu":              "relative 9999d",
		"cpu right now":             "relative 5m",
		"changes today":             "absolute 2026-09-24T05:00:00Z 2026-09-24T15:00:00Z",
		"changes yesterday":         "absolute 2026-09-23T05:00:00Z 2026-09-24T05:00:00Z",
		"incidents this week":       "absolute 2026-09-21T05:00:00Z 2026-09-24T15:00:00Z",
		"cpu tomorrow":              "absolute 2026-09-25T05:00:00Z 2026-09-26T05:00:00Z",
	}
	for text, want := range cases {
		tp, ok := parseTime(text, now, loc)
		got := "none"
		if ok {
			got = tp.tr.Kind + " " + tp.tr.Last
			if tp.tr.Kind == "absolute" {
				got = "absolute " + tp.tr.From.Format(time.RFC3339) + " " + tp.tr.To.Format(time.RFC3339)
			}
		}
		if got != want {
			t.Errorf("parseTime(%q) = %q, want %q", text, got, want)
		}
	}
	if _, ok := parseTime("show cpu on edge-1", now, loc); ok {
		t.Error("no time phrase must parse as none")
	}
}

// "since <day>" is from that local day's midnight until now; the most recent
// such day is meant.
func TestSinceADay(t *testing.T) {
	loc, _ := time.LoadLocation("America/Chicago")
	now := time.Date(2026, 9, 24, 15, 0, 0, 0, time.UTC) // Thursday 10:00 CDT
	for _, c := range []struct {
		text string
		from time.Time
	}{
		{"cpu since midnight", time.Date(2026, 9, 24, 0, 0, 0, 0, loc)},
		{"cpu since yesterday", time.Date(2026, 9, 23, 0, 0, 0, 0, loc)},
		{"cpu since monday", time.Date(2026, 9, 21, 0, 0, 0, 0, loc)},
		{"cpu since thursday", time.Date(2026, 9, 24, 0, 0, 0, 0, loc)},
		{"cpu since friday", time.Date(2026, 9, 18, 0, 0, 0, 0, loc)},
	} {
		tp, ok := parseTime(c.text, now, loc)
		if !ok || tp.tr.Kind != "absolute" || !tp.tr.From.Equal(c.from) || !tp.tr.To.Equal(now) {
			t.Errorf("%q → %+v (ok=%v), want from %v to now", c.text, tp.tr, ok, c.from)
		}
		if !strings.HasPrefix(tp.span, "since ") {
			t.Errorf("%q: the span must include \"since\" so the word is explained: %q", c.text, tp.span)
		}
	}
}
