// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Iris flow tools (tracker 406): the window an assistant tool may ask for.
//
// A tool argument is model-supplied, so it gets a NARROWER grammar than the
// page: a named window from a closed list, or an explicit from+to pair, never
// an arbitrary duration. Everything else is refused with a reason the model
// can act on, the same way a page request with a bad window gets a 400.

// ToolWindows is the closed list of named windows a tool may ask for.
var ToolWindows = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// ToolLimits bound an explicit from+to pair: five minutes to seven days. The
// default (no window named) is the last 24 hours — what the tools always read
// before they took arguments, so an argument-less call answers as it did.
var ToolLimits = Limits{Min: 5 * time.Minute, Max: 7 * 24 * time.Hour, Default: 24 * time.Hour}

// ToolWindowNames lists ToolWindows shortest first, for messages and schemas.
func ToolWindowNames() []string {
	names := make([]string, 0, len(ToolWindows))
	for k := range ToolWindows {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return ToolWindows[names[i]] < ToolWindows[names[j]] })
	return names
}

// ParseToolWindow reads a tool's window arguments: `window` (one of
// ToolWindows), or `from` + `to` (RFC 3339 or unix seconds/milliseconds, at
// most seven days apart), or neither (the last 24 hours). Both forms
// together, one of from/to alone, an unknown window name and an out-of-range
// pair are errors.
func ParseToolWindow(window, from, to string, now time.Time) (Window, error) {
	window = strings.ToLower(strings.TrimSpace(window))
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if window != "" && (from != "" || to != "") {
		return Window{}, errors.New("use either window, or from and to, not both")
	}
	if window != "" {
		d, ok := ToolWindows[window]
		if !ok {
			return Window{}, fmt.Errorf("window must be one of %s", strings.Join(ToolWindowNames(), ", "))
		}
		now = now.UTC().Truncate(time.Second)
		return Window{From: now.Add(-d), To: now}, nil
	}
	q := url.Values{}
	if from != "" {
		q.Set("from", from)
	}
	if to != "" {
		q.Set("to", to)
	}
	return ParseWindow(q, now, ToolLimits)
}

// Phrase says the window in words for an answer: "the last 24 hours", or the
// explicit range in UTC.
func (w Window) Phrase() string {
	if w.Explicit {
		return w.From.UTC().Format("2006-01-02 15:04") + "–" + w.To.UTC().Format("2006-01-02 15:04") + " UTC"
	}
	return "the last " + spanWords(w.Span())
}

// Flows page tabs a deep link can open (src/frontend/src/lib/flowsLink.ts).
const (
	TabNow      = ""         // Right now
	TabTalking  = "talking"  // Who is talking
	TabCapacity = "capacity" // Capacity
)

// DeepLink is the Flows page link the frontend reads back
// (#/explore/flows[/<tab>]?device=<exporter>&if=<ifIndex>&from=<iso>&to=<iso>):
// exporter is the parsed exporter address ("" for the whole view), ifIndex 0
// for the whole device. The window is always explicit, so the page opens on
// the span the answer read.
func DeepLink(tab, exporter string, ifIndex uint32, w Window) string {
	q := url.Values{}
	if exporter != "" {
		q.Set("device", exporter)
		if ifIndex != 0 {
			q.Set("if", strconv.FormatUint(uint64(ifIndex), 10))
		}
	}
	q.Set("from", w.From.UTC().Format(time.RFC3339))
	q.Set("to", w.To.UTC().Format(time.RFC3339))
	h := "#/explore/flows"
	if tab != "" {
		h += "/" + tab
	}
	return h + "?" + q.Encode()
}

// spanWords renders a span the way an operator says it: "15 minutes",
// "1 hour", "6 hours", "7 days".
func spanWords(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	default:
		return plural(int64(d/time.Minute), "minute")
	}
}
