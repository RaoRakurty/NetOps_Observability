// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// tsNetworkTopology is the whole-network fixture per tenant, shaped like the
// lab (2026-11-12): eight SD-WAN edges in a full mesh over two transports, the
// two same-site pairs holding no tunnel. Tenant t-b runs a small leaf-spine
// fabric with LLDP; any other tenant has nothing collected.
func tsNetworkTopology(tenant string) NetworkTopology {
	switch tenant {
	case "t-a":
		return NetworkTopology{
			Collected: true, DevicesTotal: 8, OverlayRead: true,
			Roles: []NamedCount{{"wan_edge", 8}}, Sites: []NamedCount{{"SD-WAN site 50", 2}, {"SD-WAN site 80", 2}, {"SD-WAN site 20", 1}},
			Vendors: []NamedCount{{"cisco", 8}},
			Devices: []NetworkDevice{
				{Name: "vEdge-51", Role: "wan_edge", RoleConfidence: "strong", Vendor: "cisco", Model: "vedge-cloud", Site: "SD-WAN site 50", Health: "ok", OverlayPeers: 6},
				{Name: "cEdge-80", Role: "wan_edge", RoleConfidence: "strong", Vendor: "cisco", Model: "c8000v", Site: "SD-WAN site 80", Health: "warning", OverlayPeers: 6},
			},
			Overlay: &NetworkOverlay{
				Members: 8, Pairs: 26, PossiblePairs: 26, SameSitePairs: 2, Shape: "full_mesh",
				Transports:       []NetworkTransport{{Name: "biz-internet", Members: 8, Sessions: 52, Up: 52, Health: "ok"}, {Name: "mpls", Members: 8, Sessions: 52, Up: 50, Health: "warning"}},
				SameSiteNoTunnel: []NetworkPair{{A: "cEdge-80", B: "cEdge-81", Site: "SD-WAN site 80"}, {A: "vEdge-51", B: "vEdge-52", Site: "SD-WAN site 50"}},
				NotUp:            []NetworkPairStatus{{A: "cEdge-80", B: "vEdge-20", Status: "degraded", Sessions: 4, Up: 2, Colors: []string{"mpls"}}},
				NotUpTotal:       1,
			},
			RoleNotes: []NetworkRoleNote{{Role: "wan_edge", Members: []string{"cEdge-80", "vEdge-51"}, MembersTotal: 8,
				Likely: "SD-WAN edge routers: likely terminate encrypted overlay tunnels"}},
		}
	case "t-b":
		return NetworkTopology{
			Collected: true, DevicesTotal: 3, OverlayRead: true,
			Roles:         []NamedCount{{"dc_leaf", 2}, {"dc_spine", 1}},
			LinkProtocols: []NamedCount{{"lldp", 2}},
			Devices:       []NetworkDevice{{Name: "spine-1", Role: "dc_spine"}, {Name: "leaf-2", Role: "dc_leaf"}, {Name: "leaf-3", Role: "dc_leaf"}},
			Links:         []NetworkLink{{A: "leaf-2", APort: "Eth1", B: "spine-1", BPort: "Eth2", Protocol: "lldp", Status: "up"}, {A: "leaf-3", B: "spine-1", Protocol: "lldp", Status: "up"}},
			LinksTotal:    2,
		}
	}
	return NetworkTopology{OverlayRead: true}
}

func netItem(t *testing.T, res ToolResult, id string) EvidenceItem {
	t.Helper()
	for _, it := range res.Items {
		if it.CitationID == NetworkTopologyCitationPrefix+id {
			return it
		}
	}
	t.Fatalf("no item %s%s in %+v", NetworkTopologyCitationPrefix, id, res.Items)
	return EvidenceItem{}
}

func TestNetworkTopologyIsExplainedInNetworkTerms(t *testing.T) {
	res := mustRun(t, tsRegistry(t, tsDeps()), "get_network_topology", ToolArgs{})
	if got := res.Items[0].CitationID; got != "topo-net:scope" {
		t.Fatalf("the scope must come first (a caller keeping the first N keeps it): %s", got)
	}
	scope := netItem(t, res, "scope").Text
	for _, want := range []string{"8 managed devices", "3 sites", "wan_edge 8", "SD-WAN overlay of 8 edges"} {
		if !strings.Contains(scope, want) {
			t.Errorf("scope %q lacks %q", scope, want)
		}
	}
	if ov := netItem(t, res, "overlay"); !strings.Contains(ov.Text, "FULL MESH") || !strings.Contains(ov.Text, "26 of 26") || ov.Class != ClassDerived {
		t.Errorf("the overlay shape must be stated, with coverage, as DERIVED: %+v", ov)
	}
	if ss := netItem(t, res, "overlay-same-site").Text; !strings.Contains(ss, "cEdge-80 ↔ cEdge-81") || !strings.Contains(ss, "same site") {
		t.Errorf("same-site pairs without a tunnel must be named as expected, not as gaps: %q", ss)
	}
	if tr := netItem(t, res, "transport:mpls").Text; !strings.Contains(tr, "50 of 52") {
		t.Errorf("transport line: %q", tr)
	}
	if dn := netItem(t, res, "overlay-down:1").Text; !strings.Contains(dn, "degraded") || !strings.Contains(dn, "cEdge-80") {
		t.Errorf("a pair not fully up must be listed: %q", dn)
	}
	if rn := netItem(t, res, "role:wan_edge"); rn.Class != ClassDerived || !strings.Contains(rn.Text, "inferred") || !strings.Contains(rn.Text, "and 6 more") {
		t.Errorf("a role's likely function must be DERIVED and say it is inferred: %+v", rn)
	}
	if d := netItem(t, res, "dev:1"); d.Class != "" || !strings.Contains(d.Text, "vEdge-51 — wan_edge (strong), cisco vedge-cloud, site SD-WAN site 50") {
		t.Errorf("device line: %+v", d)
	}
	notes := strings.Join(res.Notes, " | ")
	if !strings.Contains(notes, "cause wording") || !strings.Contains(notes, "no physical adjacency") {
		t.Errorf("notes must forbid cause wording and say cabling is unknown without links: %s", notes)
	}
}

func TestNetworkTopologyNotCollectedIsSaidNotInvented(t *testing.T) {
	p := tsPrincipal()
	p.Tenant = "t-empty"
	tool, _ := tsRegistry(t, tsDeps()).Get("get_network_topology")
	res, err := tool.Run(context.Background(), p, ToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Text, "NOT YET COLLECTED") {
		t.Fatalf("an empty topology must say it is not collected: %+v", res.Items)
	}
}

func TestNetworkTopologyOverlayUnreadIsUnknownNotAbsent(t *testing.T) {
	nt := tsNetworkTopology("t-b")
	nt.OverlayRead = false
	res := RenderNetworkTopology(nt)
	if !strings.Contains(strings.Join(res.Notes, " "), "UNKNOWN here, not absent") {
		t.Fatalf("an unread overlay must be unknown: %v", res.Notes)
	}
}

func TestNetworkTopologyIsBounded(t *testing.T) {
	nt := tsNetworkTopology("t-b")
	nt.DevicesTotal, nt.LinksTotal = 500, 900
	for i := 0; i < 60; i++ {
		nt.Devices = append(nt.Devices, NetworkDevice{Name: strings.Repeat("d", 600)})
		nt.Links = append(nt.Links, NetworkLink{A: "a", B: "b", Protocol: "lldp"})
	}
	res := RenderNetworkTopology(nt)
	c, _ := ContractFor("get_network_topology")
	if err := c.Output.Validate(res); err != nil {
		t.Fatalf("the rendered result must fit its contract: %v", err)
	}
	if !res.Truncated {
		t.Fatal("a cut list must set Truncated")
	}
	for _, it := range res.Items {
		if len(it.Text) > maxToolTextChars+len(" …") || !utf8.ValidString(it.Text) {
			t.Fatalf("item over the per-line bound or cut mid-rune: %d %q", len(it.Text), it.Text)
		}
	}
	// A cut that lands inside a multi-byte rune backs off to its start.
	if s := clampRunes(strings.Repeat("a", maxToolTextChars-1)+"↔↔", maxToolTextChars); !utf8.ValidString(s) {
		t.Fatalf("clampRunes cut a rune: %q", s)
	}
}

// §3a: the tool takes no argument a model could aim elsewhere, and what it
// returns is the seam's answer for the CALLER — tenant t-b never sees t-a's
// overlay or devices, and an argument naming another tenant changes nothing.
func TestNetworkTopologyIsTheCallersOwn(t *testing.T) {
	tool, _ := tsRegistry(t, tsDeps()).Get("get_network_topology")
	pb := tsPrincipal()
	pb.Tenant = "t-b"
	res, err := tool.Run(context.Background(), pb, ToolArgs{"as_tenant": "t-a", "tenant": "t-a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		for _, leak := range []string{"vEdge", "cEdge", "SD-WAN", "biz-internet"} {
			if strings.Contains(it.Text, leak) {
				t.Fatalf("tenant t-b received tenant t-a's topology (%q): %+v", leak, it)
			}
		}
	}
	if !strings.Contains(netItem(t, res, "scope").Text, "3 managed devices") {
		t.Fatalf("t-b must get its own fabric: %+v", res.Items)
	}
}

func TestNetworkTopologyStatementClasses(t *testing.T) {
	res := mustRun(t, tsRegistry(t, tsDeps()), "get_network_topology", ToolArgs{})
	sc := &statementContext{}
	for _, it := range res.Items {
		sc.stamp(it, "get_network_topology")
	}
	if c := sc.classOf("topo-net:overlay"); c != ClassDerived {
		t.Errorf("overlay shape class = %s, want DERIVED", c)
	}
	if c := sc.classOf("topo-net:dev:1"); c != ClassObserved {
		t.Errorf("device line class = %s, want OBSERVED", c)
	}
	// A per-item class can only DOWNGRADE: an item claiming a stronger class
	// than its tool keeps the tool's.
	sc.stamp(EvidenceItem{CitationID: "x:1", Class: ClassCorrelixRCA}, "get_network_topology")
	if c := sc.classOf("x:1"); c != ClassObserved {
		t.Errorf("an item must not upgrade its class: %s", c)
	}
	// An unknown tool supports nothing, even with a per-item class.
	sc.stamp(EvidenceItem{CitationID: "x:2", Class: ClassDerived}, "no_such_tool")
	if c := sc.classOf("x:2"); c != "" {
		t.Errorf("an unknown tool's item must carry no class: %s", c)
	}

	text := "The overlay appears to be a full mesh over both transports [topo-net:overlay]. " +
		"vEdge-51 is an SD-WAN edge in site 50 [topo-net:dev:1]. " +
		"These edges likely run IPsec tunnels with BFD to every other site [topo-net:role:wan_edge]. " +
		"Every edge builds tunnels over both transports, resulting in a full mesh [topo-net:overlay]."
	out := groundStatements(text, sc)
	if len(out.statements) != 3 {
		t.Fatalf("want 3 kept statements (the unhedged cause-worded one is removed), got %+v", out.statements)
	}
	want := []string{ClassDerived, ClassObserved, ClassDerived}
	for i, st := range out.statements {
		if st.Class != want[i] || !st.Grounded {
			t.Errorf("statement %d: class=%s grounded=%v, want %s grounded: %q", i, st.Class, st.Grounded, want[i], st.Text)
		}
	}
	if strings.Contains(out.text, "resulting in") {
		t.Error("unhedged cause wording about topology must not stand (that is why the tool tells the model to describe, not diagnose)")
	}
}

var reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// The grounded model path: a topology question puts the whole-network read in
// the evidence block (bounded), the caller's own; another question does not.
func TestModelEvidenceCarriesTheTopologyForATopologyQuestion(t *testing.T) {
	for _, tc := range []struct {
		q, tenant string
		perm      bool
		want      bool
	}{
		{"explain the network topology", "t-a", true, true},
		{"how is my network connected?", "t-a", true, true},
		{"is it a full mesh or hub-and-spoke?", "t-a", true, true},
		{"what is wrong right now?", "t-a", true, false},
		{"explain the network topology", "t-a", false, false}, // no infrastructure:read → policy denies the tool
	} {
		llm := &captureLLM{reply: "The overlay appears to be a full mesh [topo-net:overlay]."}
		o := &Orchestrator{DS: newMockDS(), LLM: llm, Flags: func(string) bool { return true },
			Scope: &ScopeFacts{TenantID: tc.tenant}, Tools: tsRegistry(t, tsDeps())}
		p := tsPrincipal()
		p.Tenant = tc.tenant
		if !tc.perm {
			delete(p.Perms, "infrastructure:read")
		}
		ev, _ := o.modelEvidence(context.Background(), p, tc.q)
		n := 0
		for _, e := range ev {
			if strings.HasPrefix(e.CitationID, NetworkTopologyCitationPrefix) {
				n++
				if reIPv4.MatchString(e.Text) || net.ParseIP(strings.TrimSpace(e.Text)) != nil {
					t.Errorf("an address reached the evidence: %q", e.Text)
				}
			}
		}
		if (n > 0) != tc.want {
			t.Errorf("%q (perm=%v): topology items=%d, want present=%v", tc.q, tc.perm, n, tc.want)
		}
		if n > maxTopologyEvidence {
			t.Errorf("%q: %d topology items, bound is %d", tc.q, n, maxTopologyEvidence)
		}
		if len(ev) > maxModelEvidence {
			t.Errorf("%q: %d evidence items, bound is %d", tc.q, len(ev), maxModelEvidence)
		}
	}
}

func TestTopologyQuestionReachesTheModelWithTheTopology(t *testing.T) {
	llm := &captureLLM{reply: "The overlay appears to be a full mesh over two transports [topo-net:overlay]."}
	o := &Orchestrator{DS: newMockDS(), LLM: llm, Flags: func(string) bool { return true },
		Scope: &ScopeFacts{TenantID: "t-a"}, Tools: tsRegistry(t, tsDeps())}
	ans, err := o.Ask(context.Background(), tsPrincipal(), "explain the network topology", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(llm.user, "[topo-net:overlay]") || !strings.Contains(llm.user, "FULL MESH") || !strings.Contains(llm.user, "not a diagnosis") {
		t.Fatalf("the model prompt must carry the topology and the describe-not-diagnose rule:\n%s", llm.user)
	}
	found := false
	for _, st := range ans.Statements {
		if strings.Contains(st.Text, "full mesh") {
			found = true
			if st.Class != ClassDerived || !st.Grounded {
				t.Errorf("the shape sentence must be DERIVED and grounded: %+v", st)
			}
		}
	}
	if !found {
		t.Fatalf("the answer lost the topology sentence: %+v", ans)
	}
}

func TestTopologyQuestionCue(t *testing.T) {
	for q, want := range map[string]bool{
		"explain the network topology":                true,
		"describe our topology":                       true,
		"how are the sites connected":                 true,
		"how is my network connected":                 true,
		"show me the network design":                  true,
		"what connects to what":                       true,
		"is the overlay healthy":                      true,
		"why is edge-1 down":                          false,
		"list my devices":                             false,
		"what changed on the core router last night?": false,
	} {
		if got := reTopologyQuestion.MatchString(q); got != want {
			t.Errorf("%q: cue=%v, want %v", q, got, want)
		}
	}
}
