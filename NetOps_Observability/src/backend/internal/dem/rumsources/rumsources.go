// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package rumsources answers the real-user setup page's "Is it working?" step:
// which apps sent real-user (RUM) events in the last 24 hours, and which went
// quiet after sending some in the last week.
//
// Pure: it builds the query for ONE tenant and folds the rows. The caller runs
// the query at that tenant's ClickHouse scope (the STRICT row policy on
// netops.experience_events), so this package never decides who sees what; it
// also filters on tenant_id itself, as a second line.
package rumsources

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Window is how recent an event must be for an app to count as reporting.
const Window = 24 * time.Hour

// Lookback is how far back an app is remembered, so one that stopped is listed
// as quiet instead of vanishing.
const Lookback = 7 * 24 * time.Hour

// MaxSources caps the apps returned; the response says when more exist.
const MaxSources = 500

// States of one app.
const (
	StateReporting = "reporting" // events in the last 24 h
	StateQuiet     = "quiet"     // events in the last 7 days, none in the last 24 h
)

// Source is one app's real-user feed.
type Source struct {
	App string `json:"app"`
	// AppSource is how the app was labelled: "attribute" (the page set
	// data-app), "hostname" (the snippet used the page's host), or "".
	AppSource    string    `json:"app_source"`
	State        string    `json:"state"`
	Events24h    int64     `json:"events_24h"`
	PageViews24h int64     `json:"page_views_24h"`
	Errors24h    int64     `json:"errors_24h"`
	LastSeen     time.Time `json:"last_seen"`
}

// Response is the endpoint's body.
type Response struct {
	// Status is "ok", or "unavailable" when the store could not be read (never
	// an empty list that reads as "nothing installed").
	Status     string   `json:"status"`
	WindowS    int      `json:"window_s"`
	LookbackS  int      `json:"lookback_s"`
	Reporting  int      `json:"reporting"`
	Quiet      int      `json:"quiet"`
	Sources    []Source `json:"sources"`
	Truncated  bool     `json:"truncated"`
	Restricted bool     `json:"restricted,omitempty"`
}

// tenantRe is the tenant-id shape the query will embed. Anything else is
// refused rather than escaped: a tenant id is ours, never the caller's text.
var tenantRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

// Query is the one read, for one tenant. ok=false for a tenant id that is not
// of the platform's own shape.
func Query(tenant string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if !tenantRe.MatchString(t) {
		return "", false
	}
	within := "event_at >= now64(3) - INTERVAL " + strconv.Itoa(int(Window.Hours())) + " HOUR"
	return "SELECT tenant_id, app, argMax(app_source, event_at) AS app_source, " +
		"countIf(" + within + ") AS events_24h, " +
		"countIf(event_type = 'page_view' AND " + within + ") AS page_views_24h, " +
		"countIf(event_type = 'error' AND " + within + ") AS errors_24h, " +
		"toString(toUnixTimestamp64Milli(max(event_at))) AS last_seen_ms " +
		"FROM netops.experience_events " +
		"WHERE tenant_id = '" + t + "' AND app != '' " +
		"AND event_at >= now64(3) - INTERVAL " + strconv.Itoa(int(Lookback.Hours()/24)) + " DAY " +
		"GROUP BY tenant_id, app ORDER BY max(event_at) DESC LIMIT " + strconv.Itoa(MaxSources+1) + " FORMAT JSON", true
}

// Unavailable is the answer when the store could not be read.
func Unavailable() Response {
	return Response{Status: "unavailable", WindowS: int(Window.Seconds()), LookbackS: int(Lookback.Seconds()), Sources: []Source{}}
}

// Restricted is the answer for a tenant hidden from this caller: nothing, said
// as nothing — not an error that would confirm the tenant has data.
func Restricted() Response {
	r := Unavailable()
	r.Status, r.Restricted = "ok", true
	return r
}

// FromRows folds the query's rows for tenant. Rows are untrusted input: a
// malformed one is skipped, never guessed at, and a row stamped with any other
// tenant is dropped even if the store returned it (zero trust: the row policy
// and the query's own filter are not the only line).
func FromRows(tenant string, rows []map[string]any) Response {
	out := Response{Status: "ok", WindowS: int(Window.Seconds()), LookbackS: int(Lookback.Seconds()), Sources: []Source{}}
	want := strings.ToLower(strings.TrimSpace(tenant))
	for _, row := range rows {
		if strings.ToLower(strings.TrimSpace(str(row["tenant_id"]))) != want || want == "" {
			continue
		}
		app := str(row["app"])
		if app == "" || len(app) > 256 {
			continue
		}
		ms, err := strconv.ParseInt(str(row["last_seen_ms"]), 10, 64)
		if err != nil || ms <= 0 {
			continue
		}
		s := Source{
			App: app, AppSource: appSource(str(row["app_source"])),
			Events24h: num(row["events_24h"]), PageViews24h: num(row["page_views_24h"]), Errors24h: num(row["errors_24h"]),
			LastSeen: time.UnixMilli(ms).UTC(),
		}
		s.State = StateQuiet
		if s.Events24h > 0 {
			s.State = StateReporting
		}
		out.Sources = append(out.Sources, s)
	}
	if len(out.Sources) > MaxSources {
		out.Sources, out.Truncated = out.Sources[:MaxSources], true
	}
	// Quiet first (what needs a look), then the most recently seen.
	sort.SliceStable(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		if a.State != b.State {
			return a.State == StateQuiet
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.App < b.App
	})
	for _, s := range out.Sources {
		if s.State == StateReporting {
			out.Reporting++
		} else {
			out.Quiet++
		}
	}
	return out
}

func appSource(s string) string {
	switch s {
	case "attribute", "hostname":
		return s
	}
	return ""
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// num reads a ClickHouse count, which FORMAT JSON quotes as a string for
// 64-bit integers. A malformed or negative value is 0.
func num(v any) int64 {
	var n int64
	switch x := v.(type) {
	case float64:
		n = int64(x)
	case string:
		p, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0
		}
		n = p
	}
	if n < 0 {
		return 0
	}
	return n
}
