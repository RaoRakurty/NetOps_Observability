// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var toolNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func TestParseToolWindowNamedAndDefault(t *testing.T) {
	for name, want := range ToolWindows {
		w, err := ParseToolWindow(name, "", "", toolNow)
		if err != nil || w.Span() != want || w.Explicit || !w.To.Equal(toolNow) {
			t.Fatalf("window %q: %+v %v", name, w, err)
		}
	}
	w, err := ParseToolWindow("", "", "", toolNow)
	if err != nil || w.Span() != 24*time.Hour {
		t.Fatalf("no window must default to the last 24 hours (the tools' old behaviour): %+v %v", w, err)
	}
	if w, err := ParseToolWindow(" 6H ", "", "", toolNow); err != nil || w.Span() != 6*time.Hour {
		t.Fatalf("a named window is case- and space-insensitive: %+v %v", w, err)
	}
}

func TestParseToolWindowExplicitPair(t *testing.T) {
	w, err := ParseToolWindow("", "2026-11-13T08:00:00Z", "2026-11-13T09:30:00Z", toolNow)
	if err != nil || !w.Explicit || w.Span() != 90*time.Minute {
		t.Fatalf("explicit pair: %+v %v", w, err)
	}
	if w, err := ParseToolWindow("", "2026-11-13T11:00:00Z", "2026-11-14T00:00:00Z", toolNow); err != nil || !w.To.Equal(toolNow) {
		t.Fatalf("a future end clamps to now: %+v %v", w, err)
	}
}

func TestParseToolWindowRefusals(t *testing.T) {
	for name, c := range map[string][3]string{
		"unknown name":         {"2h", "", ""},
		"arbitrary duration":   {"90d", "", ""},
		"both forms":           {"1h", "2026-11-13T08:00:00Z", "2026-11-13T09:00:00Z"},
		"from alone":           {"", "2026-11-13T08:00:00Z", ""},
		"to alone":             {"", "", "2026-11-13T08:00:00Z"},
		"over seven days":      {"", "2026-11-01T00:00:00Z", "2026-11-13T00:00:00Z"},
		"under five minutes":   {"", "2026-11-13T08:00:00Z", "2026-11-13T08:01:00Z"},
		"reversed":             {"", "2026-11-13T09:00:00Z", "2026-11-13T08:00:00Z"},
		"injection in instant": {"", "2026-11-13T08:00:00Z' OR 1=1", "2026-11-13T09:00:00Z"},
	} {
		if _, err := ParseToolWindow(c[0], c[1], c[2], toolNow); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	_, err := ParseToolWindow("2h", "", "", toolNow)
	if err == nil || !strings.Contains(err.Error(), "15m, 1h, 6h, 24h, 7d") {
		t.Fatalf("the refusal must list the allowed windows, shortest first: %v", err)
	}
}

func TestWindowPhrase(t *testing.T) {
	for name, want := range map[string]string{"15m": "the last 15 minutes", "1h": "the last 1 hour", "6h": "the last 6 hours", "7d": "the last 7 days"} {
		w, _ := ParseToolWindow(name, "", "", toolNow)
		if got := w.Phrase(); got != want {
			t.Errorf("%s: phrase %q, want %q", name, got, want)
		}
	}
	w, _ := ParseToolWindow("", "2026-11-13T08:00:00Z", "2026-11-13T09:30:00Z", toolNow)
	if got := w.Phrase(); got != "2026-11-13 08:00–2026-11-13 09:30 UTC" {
		t.Errorf("explicit phrase %q", got)
	}
}

func TestDeepLinkMatchesTheFrontendShape(t *testing.T) {
	w, _ := ParseToolWindow("", "2026-11-13T08:00:00Z", "2026-11-13T09:00:00Z", toolNow)
	got := DeepLink(TabTalking, "10.1.0.1", 7, w)
	if !strings.HasPrefix(got, "#/explore/flows/talking?") {
		t.Fatalf("tab segment: %q", got)
	}
	q, err := url.ParseQuery(strings.SplitN(got, "?", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("device") != "10.1.0.1" || q.Get("if") != "7" || q.Get("from") != "2026-11-13T08:00:00Z" || q.Get("to") != "2026-11-13T09:00:00Z" {
		t.Fatalf("deep link params %v", q)
	}
	whole := DeepLink(TabNow, "", 0, w)
	if !strings.HasPrefix(whole, "#/explore/flows?") || strings.Contains(whole, "device=") || strings.Contains(whole, "if=") {
		t.Fatalf("whole-view link %q", whole)
	}
	if strings.ContainsAny(got, " \t\r\n\\") || strings.Contains(got, "://") {
		t.Fatalf("an Iris href must stay an in-app link (toolcontract): %q", got)
	}
	if DeepLink(TabNow, "10.1.0.1", 0, w) == got {
		t.Fatal("no interface must leave if= out")
	}
}

func TestToolSQLShapes(t *testing.T) {
	w, _ := ParseToolWindow("1h", "", "", toolNow)
	scope := " AND (tenant_id = 'acme')"
	for name, sql := range map[string]string{
		"talkers":  TalkersSQL(w, scope, 8),
		"services": ServicesSQL(w, scope, 8),
		"totals":   TotalsSQL(w, scope),
	} {
		if !strings.Contains(sql, w.Predicate()+scope) && !strings.Contains(sql, w.Predicate()+" AND dst_port > 0"+scope) {
			t.Errorf("%s: window and scope not applied:\n%s", name, sql)
		}
		if !strings.Contains(sql, "FROM netops.flows") || !strings.Contains(sql, "FORMAT JSON") {
			t.Errorf("%s: not the allowlisted flows read:\n%s", name, sql)
		}
		for _, alias := range []string{"AS bytes,", "AS packets,", "AS ts,", "AS bytes\n", "AS packets\n", "AS ts\n"} {
			if strings.Contains(sql, alias) {
				t.Errorf("%s: an output aliased %q (ClickHouse code 184):\n%s", name, alias, sql)
			}
		}
		if strings.Contains(sql, "WITH FILL") {
			t.Errorf("%s: WITH FILL fails on DateTime64 bounds:\n%s", name, sql)
		}
		if !strings.Contains(sql, ScaledBytes) || !strings.Contains(sql, RateReported) {
			t.Errorf("%s: totals must scale only by the reported rate and count it:\n%s", name, sql)
		}
	}
	if !strings.Contains(TalkersSQL(w, "", 999), "LIMIT 8") || !strings.Contains(TalkersSQL(w, "", 25), "LIMIT 25") {
		t.Fatal("limits are capped at MaxToolRows (out of range → 8)")
	}
}

func TestSamplingNote(t *testing.T) {
	if SamplingNote(SamplingOf(10, 10)) != "" || SamplingNote(SamplingOf(0, 0)) != "" {
		t.Fatal("reported or no flows says nothing")
	}
	if !strings.Contains(SamplingNote(SamplingOf(10, 0)), "1:1") || !strings.Contains(SamplingNote(SamplingOf(10, 3)), "part of") {
		t.Fatal("not-reported and mixed bases must be said")
	}
}
