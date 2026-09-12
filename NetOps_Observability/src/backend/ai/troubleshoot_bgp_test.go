// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_bgp_test.go — the read-only BGP-operations tools (IRIS Phase A4).
//
// What is pinned: the tools are read-only and argument-bounded, an unwired or
// tenant-less source is DISCLOSED rather than answered as "nothing happened",
// and an empty answer never reads as a healthy one.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func bgpTool(t *testing.T, d TroubleshootDeps, name string) AITool {
	t.Helper()
	tool, ok := tsRegistry(t, d).Get(name)
	if !ok {
		t.Fatalf("%s must register with a wired seam", name)
	}
	return tool
}

func TestBGPWatchlistTool(t *testing.T) {
	res, err := bgpTool(t, tsDeps(), "get_bgp_watchlist").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("want one watched resource, got %+v", res.Items)
	}
	it := res.Items[0]
	if it.CitationID != "bgpwatch:203.0.113.0/24" {
		t.Errorf("citation = %q", it.CitationID)
	}
	for _, want := range []string{"203.0.113.0/24", "prefix", "announced by AS64500", "customer block"} {
		if !strings.Contains(it.Text, want) {
			t.Errorf("row %q is missing %q", it.Text, want)
		}
	}
}

// An empty watchlist is EMPTY, not healthy — and a missing store is unknown.
func TestBGPWatchlistHonesty(t *testing.T) {
	d := tsDeps()
	d.BGPWatchlist = func(context.Context, Principal) (BGPWatchlistReport, error) {
		return BGPWatchlistReport{Scope: "t-a"}, nil
	}
	res, err := bgpTool(t, d, "get_bgp_watchlist").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "EMPTY") {
		t.Fatalf("an empty watchlist must say so: %+v", res)
	}

	d.BGPWatchlist = func(context.Context, Principal) (BGPWatchlistReport, error) {
		return BGPWatchlistReport{NotWired: "the BGP watchlist is not enabled on this deployment"}, nil
	}
	res, err = bgpTool(t, d, "get_bgp_watchlist").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "not enabled") {
		t.Fatalf("an unwired store must be disclosed: %+v", res)
	}
}

func TestBGPRPKITool(t *testing.T) {
	res, err := bgpTool(t, tsDeps(), "get_bgp_rpki").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("want one verdict, got %+v", res.Items)
	}
	if !strings.Contains(res.Items[0].Text, "RPKI valid") || !strings.Contains(res.Items[0].Text, "AS64500") {
		t.Errorf("verdict row = %q", res.Items[0].Text)
	}

	// No verdict at all must read as UNKNOWN, never as valid.
	d := tsDeps()
	d.BGPRPKI = func(context.Context, Principal) (BGPRPKIReport, error) { return BGPRPKIReport{}, nil }
	res, err = bgpTool(t, d, "get_bgp_rpki").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "UNKNOWN") {
		t.Fatalf("an unvalidated tenant must read as unknown: %v", res.Notes)
	}

	// A capped sweep must say the unlisted prefixes are UNVALIDATED.
	d.BGPRPKI = func(context.Context, Principal) (BGPRPKIReport, error) {
		return BGPRPKIReport{Truncated: true, Items: []BGPRPKIItem{{Prefix: "198.51.100.0/24", State: "invalid", Reason: "origin mismatch"}}}, nil
	}
	res, err = bgpTool(t, d, "get_bgp_rpki").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || !strings.Contains(strings.Join(res.Notes, " "), "UNVALIDATED") {
		t.Fatalf("a capped sweep must disclose the gap: %+v", res)
	}
}

func TestBGPFeedToolArgsAndHonesty(t *testing.T) {
	tool := bgpTool(t, tsDeps(), "get_bgp_feed_recent")
	for _, args := range []ToolArgs{
		{"limit": "0"}, {"limit": "31"}, {"limit": "many"}, {"limit": "-3"},
		{"prefix": "not a prefix"}, {"prefix": "203.0.113.0/24; show run"},
	} {
		if _, err := tool.Run(context.Background(), tsPrincipal(), args); err == nil {
			t.Errorf("%v must be refused", args)
		}
	}
	res, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"prefix": "203.0.113.0/24", "limit": "5"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].CitationID != "bgpfeed:7" {
		t.Fatalf("want one cited update, got %+v", res.Items)
	}
	if !strings.Contains(res.Items[0].Text, "withdrawn") {
		t.Errorf("a type-W update must read as withdrawn: %q", res.Items[0].Text)
	}

	// Feed off ⇒ churn is UNKNOWN, not absent.
	d := tsDeps()
	d.BGPFeedRecent = func(context.Context, Principal, string, int) (BGPFeedReport, error) {
		return BGPFeedReport{NotWired: "the near-live BGP update feed is not enabled on this deployment"}, nil
	}
	res, err = bgpTool(t, d, "get_bgp_feed_recent").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "UNKNOWN, not absent") {
		t.Fatalf("an off feed must not read as a stable table: %v", res.Notes)
	}

	// Nothing watched and nothing recorded are DIFFERENT answers.
	d.BGPFeedRecent = func(context.Context, Principal, string, int) (BGPFeedReport, error) {
		return BGPFeedReport{Scope: "t-a"}, nil
	}
	res, _ = bgpTool(t, d, "get_bgp_feed_recent").Run(context.Background(), tsPrincipal(), ToolArgs{})
	if !strings.Contains(strings.Join(res.Notes, " "), "follows no resource") {
		t.Fatalf("an empty watchlist must be named as the reason: %v", res.Notes)
	}
	d.BGPFeedRecent = func(context.Context, Principal, string, int) (BGPFeedReport, error) {
		return BGPFeedReport{Scope: "t-a", Resources: []string{"203.0.113.0/24"}, Gap: true}, nil
	}
	res, _ = bgpTool(t, d, "get_bgp_feed_recent").Run(context.Background(), tsPrincipal(), ToolArgs{})
	notes := strings.Join(res.Notes, " ")
	if !strings.Contains(notes, "no update was recorded") || !strings.Contains(notes, "overwrote entries") {
		t.Fatalf("an empty-but-watching feed must say both facts: %v", res.Notes)
	}
}

// The BGP tools are RESOURCE-scoped, so they register with no device seam at all
// — and a seam error is never swallowed.
func TestBGPToolsRegisterWithoutDeviceResolution(t *testing.T) {
	full := tsDeps()
	reg := &ToolRegistry{byName: map[string]AITool{}}
	reg.AddTroubleshootTools(nil, TroubleshootDeps{
		BGPWatchlist: full.BGPWatchlist, BGPRPKI: full.BGPRPKI, BGPFeedRecent: full.BGPFeedRecent,
	})
	for _, n := range []string{"get_bgp_watchlist", "get_bgp_rpki", "get_bgp_feed_recent"} {
		if _, ok := reg.Get(n); !ok {
			t.Errorf("%s must register without ResolveDevice", n)
		}
	}
	if _, ok := reg.Get("get_device_state"); ok {
		t.Error("get_device_state must NOT register without device resolution")
	}

	d := tsDeps()
	d.BGPRPKI = func(context.Context, Principal) (BGPRPKIReport, error) { return BGPRPKIReport{}, ErrForbidden }
	if _, err := bgpTool(t, d, "get_bgp_rpki").Run(context.Background(), tsPrincipal(), ToolArgs{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}
