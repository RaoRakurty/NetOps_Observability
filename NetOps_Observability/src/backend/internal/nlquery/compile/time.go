// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
)

// timePhrase is one recognised time expression and the text it consumed.
type timePhrase struct {
	tr   ast.TimeRange
	span string
}

var (
	relRe  = regexp.MustCompile(`\b(?:last|past|previous|over the last|in the last|for the last)\s+(\d{1,4}|an?|one|two|three|four|five|six|seven|eight|nine|ten|twelve|fifteen|thirty|sixty|twenty four)\s*(minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)\b`)
	unitRe = regexp.MustCompile(`\b(?:last|past|previous|over the last|in the last|for the last|this)\s+(minute|hour|day|week)\b`)
	// Words for small numbers an operator types.
	unboundedRe = regexp.MustCompile(`\b(?:ever|all time|since the beginning|since forever|complete (?:change )?history|full (?:\w+ )?history|entire history|past quarter|last quarter|this quarter|past year|last year)\b`)
	spanRe      = regexp.MustCompile(`\b(\d{1,4}|an?|one|two|three|four|five|six|seven|eight|nine|ten)\s+(months?|days?|weeks?|hours?)\s+of\b`)
	futureRe    = regexp.MustCompile(`\b(?:tomorrow|next week|forecast|predict|will be|going to be)\b`)
	numberWords = map[string]int{"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
		"eight": 8, "nine": 9, "ten": 10, "twelve": 12, "fifteen": 15, "thirty": 30, "sixty": 60, "twenty four": 24}
)

func unitToken(u string) (string, int) {
	switch {
	case strings.HasPrefix(u, "mo"): // month(s) — checked before minutes
		return "d", 30
	case strings.HasPrefix(u, "m"):
		return "m", 1
	case strings.HasPrefix(u, "h"):
		return "h", 1
	case strings.HasPrefix(u, "d"):
		return "d", 1
	case strings.HasPrefix(u, "w"):
		return "d", 7
	}
	return "", 0
}

// parseTime finds the (first) time expression in normalized text. Calendar
// words are resolved against now in loc; the result is always an AST time
// range the validator can check.
func parseTime(text string, now time.Time, loc *time.Location) (timePhrase, bool) {
	if m := relRe.FindStringSubmatch(text); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			n = numberWords[m[1]]
		}
		unit, mult := unitToken(m[2])
		if n > 0 && unit != "" {
			n *= mult
			if unit == "h" && n%24 == 0 && n >= 24 && strings.HasPrefix(m[2], "d") {
				unit = "d"
			}
			return timePhrase{tr: ast.TimeRange{Kind: ast.TimeRelative, Last: strconv.Itoa(n) + unit}, span: m[0]}, true
		}
	}
	if m := unitRe.FindStringSubmatch(text); m != nil && !strings.HasPrefix(m[0], "this") {
		last := map[string]string{"minute": "1m", "hour": "1h", "day": "24h", "week": "7d"}[m[1]]
		return timePhrase{tr: ast.TimeRange{Kind: ast.TimeRelative, Last: last}, span: m[0]}, true
	}
	// Understood but unanswerable windows compile to ranges the validator
	// refuses with the precise code — never to a silent default.
	if m := unboundedRe.FindString(text); m != "" {
		return timePhrase{tr: ast.TimeRange{Kind: ast.TimeRelative, Last: "9999d"}, span: m}, true
	}
	if m := spanRe.FindStringSubmatch(text); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			n = numberWords[m[1]]
		}
		unit, mult := unitToken(m[2])
		if n > 0 && unit != "" {
			return timePhrase{tr: ast.TimeRange{Kind: ast.TimeRelative, Last: strconv.Itoa(n*mult) + unit}, span: m[0]}, true
		}
	}
	local := now.In(loc)
	if m := futureRe.FindString(text); m != "" {
		mid := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		f, t := mid.AddDate(0, 0, 1).UTC(), mid.AddDate(0, 0, 2).UTC()
		return timePhrase{tr: ast.TimeRange{Kind: ast.TimeAbsolute, From: &f, To: &t}, span: m}, true
	}
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	abs := func(from, to time.Time, span string) (timePhrase, bool) {
		f, t := from.UTC(), to.UTC()
		return timePhrase{tr: ast.TimeRange{Kind: ast.TimeAbsolute, From: &f, To: &t}, span: span}, true
	}
	switch {
	case strings.Contains(text, "right now") || strings.Contains(text, "currently") || hasWord(text, "now"):
		return timePhrase{tr: ast.TimeRange{Kind: ast.TimeRelative, Last: "5m"}, span: "now"}, true
	case strings.Contains(text, "yesterday"):
		return abs(midnight.AddDate(0, 0, -1), midnight, "yesterday")
	case strings.Contains(text, "this morning"):
		return abs(midnight, now, "this morning")
	case strings.Contains(text, "today"):
		return abs(midnight, now, "today")
	case strings.Contains(text, "this month"):
		return abs(time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc), now, "this month")
	case strings.Contains(text, "this week"):
		wd := (int(local.Weekday()) + 6) % 7 // Monday = 0
		return abs(midnight.AddDate(0, 0, -wd), now, "this week")
	}
	return timePhrase{}, false
}

func hasWord(text, w string) bool {
	for _, f := range strings.Fields(text) {
		if f == w {
			return true
		}
	}
	return false
}
