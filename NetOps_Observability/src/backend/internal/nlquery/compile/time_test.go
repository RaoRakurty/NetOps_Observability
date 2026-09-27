// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
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
