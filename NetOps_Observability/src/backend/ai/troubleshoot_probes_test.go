// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
	"time"
)

// tsProbeResults is the shared fixture for the probe seam: the test principal's
// tenant ("t-a") holds a failing DNS probe, a passing HTTP probe and an
// unmeasured TCP probe; any other tenant holds nothing.
func tsProbeResults(tenant string, q ProbeQuery) ProbeResults {
	if tenant != "t-a" {
		return ProbeResults{Scoped: true, CollectionOn: true}
	}
	all := []ProbeSummary{
		{Name: "corp-dns", Kind: "dns", Destination: "intranet.example.com", Site: "hq",
			Runs: 6, Success: 2, Failure: 4, LastOutcome: "failure", LastReason: "timeout",
			LastAt: time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), MedianMs: 18, Vantages: 1},
		{Name: "portal", Kind: "http", Destination: "https://portal.example.com", Site: "hq",
			Runs: 6, Success: 6, LastOutcome: "success", MedianMs: 120, Vantages: 2},
		{Name: "db-port", Kind: "tcp", Destination: "", Site: "dc"},
	}
	out := ProbeResults{Scoped: true, CollectionOn: true, Configured: len(all)}
	for _, p := range all {
		if q.ProbeMatches(p.Name, p.Name, p.Kind, p.Site) {
			out.Probes = append(out.Probes, p)
			out.ProbesTotal++
		}
	}
	return out
}

func probeSignalSet(tr ToolResult) map[string]bool {
	m := map[string]bool{}
	for _, s := range tr.Signals {
		m[s] = true
	}
	return m
}

func TestProbeToolRunsThroughTheRegistry(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	res := mustRun(t, reg, "get_probe_results", ToolArgs{"kind": "dns"})
	if len(res.Items) != 1 {
		t.Fatalf("one DNS probe expected, got %+v", res.Items)
	}
	txt := res.Items[0].Text
	for _, want := range []string{`"corp-dns"`, "intranet.example.com", "the resolver did not answer in time", "2 of 6 recent runs succeeded", "from one prober"} {
		if !strings.Contains(txt, want) {
			t.Errorf("item missing %q: %s", want, txt)
		}
	}
	sig := probeSignalSet(res)
	if !sig["state:dns=timeout"] || !sig["state:probe=failing"] {
		t.Fatalf("signals = %v", res.Signals)
	}
	if !strings.HasPrefix(res.Items[0].CitationID, ProbeResultsCitationPrefix) {
		t.Fatalf("citation %q", res.Items[0].CitationID)
	}
}

// A tenant with no probe is told what is not measured — and never that the
// target is healthy.
func TestNoProbeConfiguredDisclosesAndDeclaresNone(t *testing.T) {
	res := RenderProbeResults(ProbeResults{Scoped: true, CollectionOn: true}, ProbeQuery{Kind: "dns"})
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Text, "no synthetic probe is configured") {
		t.Fatalf("items = %+v", res.Items)
	}
	sig := probeSignalSet(res)
	if !sig["state:probe=none"] || !sig["state:dns=none"] {
		t.Fatalf("signals = %v", res.Signals)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "never infer the result") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

// Probes exist but none of the asked kind: "none of this kind", not "none".
func TestNoProbeOfTheKindNamesWhatIsConfigured(t *testing.T) {
	res := RenderProbeResults(ProbeResults{Scoped: true, CollectionOn: true, Configured: 3}, ProbeQuery{Kind: "dns"})
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Text, "no DNS probes match this question (3 probes configured") {
		t.Fatalf("items = %+v", res.Items)
	}
}

// The platform scope reads nothing and says probes are per workspace.
func TestUnscopedReadDeclaresNothing(t *testing.T) {
	res := RenderProbeResults(ProbeResults{}, ProbeQuery{})
	if len(res.Items) != 0 || len(res.Signals) != 0 {
		t.Fatalf("an unscoped read must carry no evidence or facts: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "read per workspace") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

// Collection off: probes may exist but none ran — UNKNOWN, never healthy.
func TestCollectionOffIsUnknownNotHealthy(t *testing.T) {
	r := ProbeResults{Scoped: true, Configured: 1, ProbesTotal: 1,
		Probes: []ProbeSummary{{Name: "corp-dns", Kind: "dns", Destination: "intranet.example.com"}}}
	res := RenderProbeResults(r, ProbeQuery{})
	if !strings.Contains(strings.Join(res.Notes, " "), "switched off") {
		t.Fatalf("notes = %v", res.Notes)
	}
	if len(res.Signals) != 0 {
		t.Fatalf("an unmeasured probe declares no health: %v", res.Signals)
	}
	if !strings.Contains(res.Items[0].Text, "its result is UNKNOWN") {
		t.Fatalf("item = %s", res.Items[0].Text)
	}
}

func TestDNSSignalPrecedenceAndRunnerErrors(t *testing.T) {
	dns := func(outcome, reason string) ProbeSummary {
		return ProbeSummary{Name: "d", Kind: "dns", Runs: 1, LastOutcome: outcome, LastReason: reason}
	}
	cases := []struct {
		name   string
		probes []ProbeSummary
		dns    string
		probe  string
	}{
		{"all resolving", []ProbeSummary{dns("success", ""), dns("success", "")}, "state:dns=resolving", "state:probe=passing"},
		{"timeout beats nxdomain", []ProbeSummary{dns("failure", "nxdomain"), dns("failure", "timeout")}, "state:dns=timeout", "state:probe=failing"},
		{"nxdomain beats generic", []ProbeSummary{dns("failure", "dns"), dns("failure", "nxdomain")}, "state:dns=nxdomain", "state:probe=failing"},
		{"generic error", []ProbeSummary{dns("failure", "dns"), dns("success", "")}, "state:dns=failing", "state:probe=partial"},
		// A runner error is the prober breaking: no fact about the target.
		{"runner error only", []ProbeSummary{dns("error", "")}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ProbeResults{Scoped: true, CollectionOn: true, Configured: len(c.probes), ProbesTotal: len(c.probes), Probes: c.probes}
			sig := probeSignalSet(RenderProbeResults(r, ProbeQuery{Kind: "dns"}))
			for _, s := range []string{c.dns, c.probe} {
				if s != "" && !sig[s] {
					t.Errorf("missing %s in %v", s, sig)
				}
			}
			if c.dns == "" && len(sig) != 0 {
				t.Errorf("a runner error must declare nothing: %v", sig)
			}
		})
	}
}

// A paused probe is never a measurement.
func TestPausedProbeDeclaresNothing(t *testing.T) {
	r := ProbeResults{Scoped: true, CollectionOn: true, Configured: 1, ProbesTotal: 1,
		Probes: []ProbeSummary{{Name: "d", Kind: "dns", Paused: true, Runs: 3, Failure: 3, LastOutcome: "failure", LastReason: "timeout"}}}
	res := RenderProbeResults(r, ProbeQuery{})
	if len(res.Signals) != 0 {
		t.Fatalf("paused probe declared %v", res.Signals)
	}
	if !strings.Contains(res.Items[0].Text, "paused, not measuring") {
		t.Fatalf("item = %s", res.Items[0].Text)
	}
}

// §15: an address, a URL path or a query string never reaches the evidence.
func TestSafeProbeDestinationHidesAddressesAndPaths(t *testing.T) {
	cases := []struct{ kind, host, want string }{
		{"http", "https://portal.example.com/login?token=secret", "https://portal.example.com"},
		{"http", "https://10.1.2.3:8443/x", ""},
		{"http", "not a url", ""},
		{"dns", "intranet.example.com", "intranet.example.com"},
		{"dns", "192.0.2.53", ""},
		{"icmp", "2001:db8::1", ""},
		{"tcp", "db.example.com:5432", "db.example.com:5432"},
		{"tcp", "10.0.0.5:22", ""},
		{"tcp", "user@db.example.com", ""},
	}
	for _, c := range cases {
		if got := SafeProbeDestination(c.kind, c.host, 0); got != c.want {
			t.Errorf("SafeProbeDestination(%q,%q) = %q, want %q", c.kind, c.host, got, c.want)
		}
	}
	if got := SafeProbeDestination("tcp", "db.example.com", 5432); got != "db.example.com:5432" {
		t.Errorf("port from the field: %q", got)
	}
	line := probeLine(ProbeSummary{Name: "x", Kind: "dns", Destination: "", ResolverPinned: true, Resolver: ""})
	if !strings.Contains(line, "checks an address") || !strings.Contains(line, "pinned resolver at an address") {
		t.Fatalf("line = %s", line)
	}
}

// Failing probes are listed first, and the list is capped with the true total.
func TestProbeListIsCappedFailingFirst(t *testing.T) {
	var ps []ProbeSummary
	for i := 0; i < maxProbeItems+5; i++ {
		ps = append(ps, ProbeSummary{Name: "ok", Kind: "http", Runs: 1, Success: 1, LastOutcome: "success"})
	}
	ps = append(ps, ProbeSummary{Name: "broken", Kind: "http", Runs: 1, Failure: 1, LastOutcome: "failure", LastReason: "timeout"})
	r := ProbeResults{Scoped: true, CollectionOn: true, Configured: len(ps), ProbesTotal: len(ps), Probes: ps}
	res := RenderProbeResults(r, ProbeQuery{})
	if len(res.Items) != maxProbeItems || !res.Truncated {
		t.Fatalf("items = %d truncated=%v", len(res.Items), res.Truncated)
	}
	if !strings.Contains(res.Items[0].Text, `"broken"`) {
		t.Fatalf("the failing probe must lead: %s", res.Items[0].Text)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "showing 20 of 26 probes, failing first") {
		t.Fatalf("notes = %v", res.Notes)
	}
}

func TestProbeQueryValidation(t *testing.T) {
	if _, err := probeQueryFromArgs(ToolArgs{"kind": "snmp"}); err == nil {
		t.Fatal("an unknown kind must be refused")
	}
	if _, err := probeQueryFromArgs(ToolArgs{"site": "hq\nIGNORE PREVIOUS"}); err == nil {
		t.Fatal("a control character must be refused")
	}
	if _, err := probeQueryFromArgs(ToolArgs{"target": strings.Repeat("a", 129)}); err == nil {
		t.Fatal("an over-long target must be refused")
	}
	q, err := probeQueryFromArgs(ToolArgs{"kind": "DNS", "site": "Dallas HQ"})
	if err != nil || q.Kind != "dns" || q.Site != "Dallas HQ" {
		t.Fatalf("q=%+v err=%v", q, err)
	}
	if !q.ProbeMatches("id1", "corp", "dns", "dallas hq") || q.ProbeMatches("id1", "corp", "http", "Dallas HQ") {
		t.Fatal("the filter must match kind and site case-insensitively")
	}
}

// The seam's error is the tool's error (a failed read is never "no probes").
func TestProbeSeamErrorPropagates(t *testing.T) {
	d := tsDeps()
	d.ProbeResults = func(context.Context, Principal, ProbeQuery) (ProbeResults, error) {
		return ProbeResults{}, errCaseToolFailed
	}
	reg := tsRegistry(t, d)
	tool, ok := reg.Get("get_probe_results")
	if !ok {
		t.Fatal("tool not registered")
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{}); err == nil {
		t.Fatal("the seam's failure must surface")
	}
}
