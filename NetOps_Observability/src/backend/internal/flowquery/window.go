// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package flowquery is the pure core of the link-level flow APIs (tracker 400,
// Flows page P2): the window, link and step parsing every route shares, the
// ClickHouse statements they run, and the Go-side shaping of what comes back
// (zero-fill, previous-window contrast, movers, export basis, capacity fit).
//
// Nothing here does IO or knows about principals. The root handlers in flows.go
// authorise the caller, derive the tenant clause (flowTenantClause and its
// stricter links form) and hand it in as an opaque, already-safe fragment; this
// package only ever renders integers, parsed addresses and its own literals into
// SQL, so no caller-supplied text reaches a statement.
//
// Parsing is FAIL-CLOSED: a malformed, out-of-range or contradictory parameter
// is an error the handler answers with 400. The older routes' durationQuery
// silently replaces a bad `since` with the default, which makes a request for
// "the last 45 days" quietly answer for one hour; nothing here does that.
package flowquery

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Limits bound a window: its shortest and longest span and the span used when
// the caller names none.
type Limits struct {
	Min, Max, Default time.Duration
}

// DefaultLimits are the page's own bounds (flowsModel.ts MIN_WINDOW_S and
// MAX_WINDOW_S): five minutes to thirty days, one hour by default.
var DefaultLimits = Limits{Min: 5 * time.Minute, Max: 30 * 24 * time.Hour, Default: time.Hour}

// Window is a half-open time range [From, To) in UTC, whole seconds.
type Window struct {
	From, To time.Time
	// Explicit is true when the caller named from and to, false for "the last
	// <since>" (which moves with the clock).
	Explicit bool
}

// ParseWindow reads either `since` (a Go duration such as 1h, or whole seconds)
// or `from` + `to` (RFC 3339, or 10-digit unix seconds, or 13-digit unix
// milliseconds). Both forms together, one of from/to alone, from not before to,
// and a span outside lim are all errors. `to` in the future is clamped to now,
// so a deep link whose problem is still open reads up to the present.
func ParseWindow(q url.Values, now time.Time, lim Limits) (Window, error) {
	now = now.UTC().Truncate(time.Second)
	since := strings.TrimSpace(q.Get("since"))
	fromS, toS := strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to"))
	if since != "" && (fromS != "" || toS != "") {
		return Window{}, errors.New("use either since, or from and to, not both")
	}
	if fromS != "" || toS != "" {
		if fromS == "" || toS == "" {
			return Window{}, errors.New("from and to must be given together")
		}
		from, err := parseInstant(fromS)
		if err != nil {
			return Window{}, fmt.Errorf("from: %w", err)
		}
		to, err := parseInstant(toS)
		if err != nil {
			return Window{}, fmt.Errorf("to: %w", err)
		}
		if to.After(now) {
			to = now
		}
		if !from.Before(to) {
			return Window{}, errors.New("from must be before to, and before now")
		}
		if err := checkSpan(to.Sub(from), lim); err != nil {
			return Window{}, err
		}
		return Window{From: from, To: to, Explicit: true}, nil
	}
	d := lim.Default
	if since != "" {
		parsed, err := parseSpan(since)
		if err != nil {
			return Window{}, err
		}
		d = parsed
	}
	if err := checkSpan(d, lim); err != nil {
		return Window{}, err
	}
	return Window{From: now.Add(-d), To: now}, nil
}

// parseSpan reads a positive duration: a Go duration string, or whole seconds.
func parseSpan(v string) (time.Duration, error) {
	if isDigits(v) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n > int64(365*24*3600) {
			return 0, errors.New("since must be a duration such as 1h, or a number of seconds")
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, errors.New("since must be a duration such as 1h, or a number of seconds")
	}
	return d.Truncate(time.Second), nil
}

func checkSpan(d time.Duration, lim Limits) error {
	if d < lim.Min || d > lim.Max {
		return fmt.Errorf("the window must be between %s and %s", human(lim.Min), human(lim.Max))
	}
	return nil
}

// parseInstant reads one bound: RFC 3339, 10-digit unix seconds or 13-digit
// unix milliseconds. Sub-second precision is dropped (windows are whole seconds).
func parseInstant(v string) (time.Time, error) {
	if isDigits(v) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, errors.New("not a time")
		}
		switch len(v) {
		case 10:
			return time.Unix(n, 0).UTC(), nil
		case 13:
			return time.UnixMilli(n).UTC().Truncate(time.Second), nil
		}
		return time.Time{}, errors.New("a unix time must have 10 digits (seconds) or 13 (milliseconds)")
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, errors.New("use RFC 3339, for example 2026-11-13T06:00:00Z, or unix seconds")
	}
	return t.UTC().Truncate(time.Second), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// human renders a limit for an error message: "5m", "30d".
func human(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return strings.TrimSuffix(strings.TrimSuffix(d.String(), "0s"), "0m")
}

// Span is the window's length.
func (w Window) Span() time.Duration { return w.To.Sub(w.From) }

// PrevFrom is the start of the previous window of the same length, which ends
// where this one starts.
func (w Window) PrevFrom() time.Time { return w.From.Add(-w.Span()) }

// TSLit renders an instant as a ClickHouse DateTime64 literal built from an
// integer only.
func TSLit(t time.Time) string {
	return "toDateTime64(" + strconv.FormatInt(t.Unix(), 10) + ", 3, 'UTC')"
}

// Predicate restricts ts to [From, To).
func (w Window) Predicate() string {
	return "ts >= " + TSLit(w.From) + " AND ts < " + TSLit(w.To)
}

// ScanPredicate restricts ts to [PrevFrom, To): the current window and the
// previous one, read in one scan and told apart by CurCond.
func (w Window) ScanPredicate() string {
	return "ts >= " + TSLit(w.PrevFrom()) + " AND ts < " + TSLit(w.To)
}

// CurCond is true for a row of the current window inside a ScanPredicate scan.
func (w Window) CurCond() string { return "ts >= " + TSLit(w.From) }

// WindowEcho is what every response says about the window it answered for.
type WindowEcho struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Seconds  int64  `json:"seconds"`
	Explicit bool   `json:"explicit"`
	PrevFrom string `json:"prev_from"`
	// RetentionDays is how long flow records are kept (CH_FLOWS_RETENTION_DAYS).
	RetentionDays int `json:"retention_days"`
	// StartsBeforeRetention: part of the window is older than the oldest kept
	// record, so its totals read low for a reason that is not the network.
	StartsBeforeRetention bool `json:"starts_before_retention"`
	// PrevBeforeRetention: the previous window is partly older than retention,
	// so no "change" figure is given.
	PrevBeforeRetention bool `json:"prev_before_retention"`
}

// Echo describes w for a response. retentionDays <= 0 means unknown, in which
// case nothing is said to start before it.
func (w Window) Echo(now time.Time, retentionDays int) WindowEcho {
	e := WindowEcho{
		From: w.From.UTC().Format(time.RFC3339), To: w.To.UTC().Format(time.RFC3339),
		Seconds: int64(w.Span() / time.Second), Explicit: w.Explicit,
		PrevFrom: w.PrevFrom().UTC().Format(time.RFC3339), RetentionDays: retentionDays,
	}
	if retentionDays > 0 {
		horizon := now.UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		e.StartsBeforeRetention = w.From.Before(horizon)
		e.PrevBeforeRetention = w.PrevFrom().Before(horizon)
	}
	return e
}
