// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
)

// ── a lab-shaped estate generator ───────────────────────────────────────────
//
// Edge i has system-ip 10.255.255.<i+1> and one transport address per colour,
// 198.51.<c>.<i+1>. "Reporting" edges publish overlay facts (the vEdges on the
// lab); "silent" edges answer no SD-WAN MIB but their transport addresses are
// in the interface map (the lab cEdges). Every reporting edge holds a session
// to every other edge on every colour.

type estate struct {
	tenant    string
	reporting int
	silent    int
	colors    []string
	down      map[[2]int]bool // pairs (i<j) whose sessions are down
	peerOnly  bool            // facts carry no system-ip of their own (lab vEdge)
}

func devID(tenant string, i int) string { return fmt.Sprintf("%s-edge-%03d", tenant, i) }

func sysIP(i int) string { return fmt.Sprintf("10.255.%d.%d", (i+1)/250, (i+1)%250+1) }

func tlocAddr(c, i int) string { return fmt.Sprintf("198.%d.%d.%d", 51+c, (i+1)/250, (i+1)%250+1) }

func colorEnum(name string) string { return name }

func (e estate) build(in *OverlayInput) {
	if in.DevTenant == nil {
		in.DevTenant = map[string]string{}
		in.Facts = map[string]collectors.OverlayDeviceFacts{}
		in.IfAddrs = map[string][]string{}
	}
	n := e.reporting + e.silent
	for i := 0; i < n; i++ {
		in.DevTenant[devID(e.tenant, i)] = e.tenant
	}
	for i := e.reporting; i < n; i++ { // silent edges: interface addresses only
		for c := range e.colors {
			in.IfAddrs[devID(e.tenant, i)] = append(in.IfAddrs[devID(e.tenant, i)], tlocAddr(c, i))
		}
	}
	for i := 0; i < e.reporting; i++ {
		f := collectors.OverlayDeviceFacts{DeviceID: devID(e.tenant, i), MIB: "viptela", Capability: collectors.OverlayAvailable, DetailRead: true}
		if !e.peerOnly {
			f.SystemIP = sysIP(i)
		}
		for c := range e.colors {
			f.LocalTLOCAddrs = append(f.LocalTLOCAddrs, tlocAddr(c, i))
		}
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			p := collectors.OverlayPeer{SystemIP: sysIP(j)}
			a, b := i, j
			if a > b {
				a, b = b, a
			}
			for c, color := range e.colors {
				up := 1
				if e.down[[2]int{a, b}] {
					up = 0
				}
				st := "up"
				if up == 0 {
					st = "down"
				}
				p.ColorPairs = append(p.ColorPairs, collectors.OverlayColorPairs{LocalColor: colorEnum(color), RemoteColor: color, Proto: "ipsec", Sessions: 1, Up: up, State: st})
				p.TLOCAddrs = append(p.TLOCAddrs, tlocAddr(c, j))
			}
			f.Peers = append(f.Peers, p)
		}
		in.Facts[devID(e.tenant, i)] = f
	}
}

func overlayEdges(r OverlayResult, rel string) map[string]Edge {
	out := map[string]Edge{}
	for _, e := range r.Edges {
		if e.Relationship == rel {
			out[e.ID] = e
		}
	}
	return out
}

// ── the lab shape ───────────────────────────────────────────────────────────

// 4 reporting vEdges with NO system-ip answer + 4 silent cEdges, two colours:
// exactly the 2026-10-10 lab. Everything resolves through the tunnels.
func TestInferOverlayOnTheLabShape(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 4, silent: 4, colors: []string{"biz-internet", "mpls"}, peerOnly: true}.build(&in)
	r := InferOverlay(in)

	if r.Stats.Unresolved != 0 || r.Stats.Ambiguous != 0 {
		t.Fatalf("stats %+v", r.Stats)
	}
	if got := len(r.SystemIPs["t1"]); got != 8 {
		t.Fatalf("resolved %d system-ips, want 8 (4 by triangulation, 4 by interface address)", got)
	}
	if r.Stats.ResolvedByPeer != 4 {
		t.Fatalf("resolved-by-peer = %d, want the 4 silent edges", r.Stats.ResolvedByPeer)
	}
	// Pairs: 6 among the reporting edges + 4×4 reporting↔silent. Silent↔silent
	// pairs are not observable (neither end reports).
	pairs := overlayEdges(r, RelOverlay)
	if len(pairs) != 22 || r.Stats.Shape["t1"] != OverlayShapePairs {
		t.Fatalf("pairs=%d shape=%s", len(pairs), r.Stats.Shape["t1"])
	}
	both := pairs["sdwan|"+devID("t1", 0)+"|"+devID("t1", 1)]
	if both.Status != StatusUp || both.Confidence != 0.95 || both.Tags["colors"] != "biz-internet,mpls" ||
		!strings.Contains(both.Evidence[0].Detail, "both ends") {
		t.Fatalf("reporting pair: %+v", both)
	}
	one := pairs["sdwan|"+devID("t1", 0)+"|"+devID("t1", 4)]
	if one.Confidence != 0.85 || !strings.Contains(one.Evidence[0].Detail, "one end") {
		t.Fatalf("reporting↔silent pair: %+v", one)
	}
	// Transports: one node per colour, every edge attached to both.
	var transports []Node
	for _, n := range r.Nodes {
		if n.Kind == KindWAN {
			transports = append(transports, n)
		}
	}
	if len(transports) != 2 || transports[0].Health != HealthOK || transports[0].Tags["provenance"] != "inferred" {
		t.Fatalf("transports: %+v", transports)
	}
	if m := overlayEdges(r, RelInferred); len(m) != 16 {
		t.Fatalf("membership edges = %d, want 8 edges × 2 colours", len(m))
	}
	for _, e := range r.Edges {
		if e.Relationship == RelInferred && e.Status != StatusUnknown {
			t.Fatalf("an inferred attachment claims a state: %+v", e)
		}
	}
}

func TestInferOverlayPairStatus(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 3, colors: []string{"mpls"}, down: map[[2]int]bool{{0, 2}: true}}.build(&in)
	pairs := overlayEdges(InferOverlay(in), RelOverlay)
	if s := pairs["sdwan|"+devID("t1", 0)+"|"+devID("t1", 2)].Status; s != StatusDown {
		t.Fatalf("all sessions down: %s", s)
	}
	if s := pairs["sdwan|"+devID("t1", 0)+"|"+devID("t1", 1)].Status; s != StatusUp {
		t.Fatalf("all sessions up: %s", s)
	}
	// One colour up, one down → degraded.
	var in2 OverlayInput
	estate{tenant: "t1", reporting: 2, colors: []string{"mpls", "lte"}}.build(&in2)
	f := in2.Facts[devID("t1", 0)]
	f.Peers[0].ColorPairs[1].Up, f.Peers[0].ColorPairs[1].State = 0, "down"
	in2.Facts[devID("t1", 0)] = f
	g := in2.Facts[devID("t1", 1)]
	g.Peers[0].ColorPairs[1].Up, g.Peers[0].ColorPairs[1].State = 0, "down"
	in2.Facts[devID("t1", 1)] = g
	r := InferOverlay(in2)
	if s := overlayEdges(r, RelOverlay)["sdwan|"+devID("t1", 0)+"|"+devID("t1", 1)].Status; s != StatusDegraded {
		t.Fatalf("one colour down: %s", s)
	}
	for _, n := range r.Nodes {
		if n.Tags["color"] == "lte" && n.Health != HealthCritical {
			t.Fatalf("lte transport with every session down: %s", n.Health)
		}
	}
}

// ── resolution safety ───────────────────────────────────────────────────────

// Two devices claiming the same address (overlapping private ranges across
// sites) must never resolve through it.
func TestInferOverlayAmbiguousAddressIsNotResolved(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 2, silent: 1, colors: []string{"mpls"}, peerOnly: true}.build(&in)
	silent := devID("t1", 2)
	in.DevTenant["t1-other"] = "t1"
	in.IfAddrs["t1-other"] = append([]string{}, in.IfAddrs[silent]...) // same address, another device
	r := InferOverlay(in)
	if _, ok := r.SystemIPs["t1"][sysIP(2)]; ok {
		t.Fatalf("an ambiguous address resolved %s", sysIP(2))
	}
	for _, e := range r.Edges {
		if e.Source == silent || e.Target == silent || e.Source == "t1-other" || e.Target == "t1-other" {
			t.Fatalf("drew an edge through an ambiguous address: %+v", e)
		}
	}
	if r.Stats.Unresolved == 0 {
		t.Fatal("the unresolvable peer was not counted")
	}
}

func TestInferOverlayConflictingSystemIPIsAmbiguous(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 3, colors: []string{"mpls"}}.build(&in)
	f := in.Facts[devID("t1", 1)]
	f.SystemIP = sysIP(0) // claims device 0's system-ip
	in.Facts[devID("t1", 1)] = f
	r := InferOverlay(in)
	if r.Stats.Ambiguous == 0 {
		t.Fatalf("a system-ip claimed twice was not ambiguous: %+v", r.Stats)
	}
	if _, ok := r.SystemIPs["t1"][sysIP(0)]; ok {
		t.Fatal("an ambiguous system-ip was resolved")
	}
}

func TestInferOverlayIgnoresDevicesTheCallerCannotSee(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 2, silent: 1, colors: []string{"mpls"}, peerOnly: true}.build(&in)
	delete(in.DevTenant, devID("t1", 2)) // not visible to this caller
	r := InferOverlay(in)
	for _, e := range r.Edges {
		if e.Source == devID("t1", 2) || e.Target == devID("t1", 2) {
			t.Fatalf("an invisible device appears: %+v", e)
		}
	}
}

// §3a: two tenants with IDENTICAL colours, system-ips and transport addresses.
// Nothing crosses: separate transport nodes, no cross-tenant pair, and a
// tenant-B address never resolves a tenant-A peer.
func TestInferOverlayIsTenantIsolated(t *testing.T) {
	var in OverlayInput
	estate{tenant: "acme", reporting: 2, silent: 1, colors: []string{"mpls"}, peerOnly: true}.build(&in)
	estate{tenant: "globex", reporting: 2, silent: 1, colors: []string{"mpls"}, peerOnly: true}.build(&in)
	r := InferOverlay(in)
	tenantOf := func(id string) string {
		if strings.HasPrefix(id, "wan:") {
			for _, n := range r.Nodes {
				if n.ID == id {
					return "transport"
				}
			}
		}
		return in.DevTenant[id]
	}
	for _, e := range r.Edges {
		if e.Relationship != RelOverlay {
			continue
		}
		if tenantOf(e.Source) != tenantOf(e.Target) {
			t.Fatalf("cross-tenant overlay edge: %+v", e)
		}
	}
	if TransportNodeID("acme", "mpls") == TransportNodeID("globex", "mpls") {
		t.Fatal("two tenants share a transport node id")
	}
	ids := map[string]bool{}
	for _, n := range r.Nodes {
		ids[n.ID] = true
	}
	if !ids[TransportNodeID("acme", "mpls")] || !ids[TransportNodeID("globex", "mpls")] || len(ids) != 2 {
		t.Fatalf("transport nodes %v", ids)
	}
	for _, e := range r.Edges {
		if e.Relationship == RelInferred {
			want := TransportNodeID(in.DevTenant[e.Source], "mpls")
			if e.Target != want {
				t.Fatalf("%s attached to another tenant's transport %s", e.Source, e.Target)
			}
		}
	}
	if len(r.SystemIPs["acme"]) != 3 || len(r.SystemIPs["globex"]) != 3 {
		t.Fatalf("per-tenant resolution: %v", r.SystemIPs)
	}
}

// ── scale ───────────────────────────────────────────────────────────────────

// A dense mesh is drawn as EXCEPTIONS: the healthy pairs are summarised on the
// transport node, only the broken ones are edges. Never N² edges.
func TestInferOverlayDenseMeshDrawsOnlyExceptions(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 40, colors: []string{"biz-internet", "mpls"}, down: map[[2]int]bool{{3, 7}: true, {10, 11}: true}}.build(&in)
	r := InferOverlay(in)
	if r.Stats.Shape["t1"] != OverlayShapeExceptions || r.Stats.PairsObserved != 40*39/2 {
		t.Fatalf("stats %+v", r.Stats)
	}
	pairs := overlayEdges(r, RelOverlay)
	if len(pairs) != 2 {
		t.Fatalf("drew %d pair edges, want only the 2 exceptions", len(pairs))
	}
	for _, e := range pairs {
		if e.Status == StatusUp {
			t.Fatalf("a healthy pair was drawn in exceptions mode: %+v", e)
		}
	}
}

func TestInferOverlayPairCap(t *testing.T) {
	var in OverlayInput
	estate{tenant: "t1", reporting: 10, colors: []string{"mpls"}}.build(&in)
	in.MaxPairEdges = 20 // 45 pairs > cap
	in.DenseMeshMin = 1000
	if r := InferOverlay(in); r.Stats.Shape["t1"] != OverlayShapeExceptions || len(overlayEdges(r, RelOverlay)) != 0 {
		t.Fatalf("cap not applied: %+v", r.Stats)
	}
}

// 1,000 edges in a 2-colour full mesh (~1M BFD session aggregates) projects in
// bounded time and draws O(N) edges.
func TestInferOverlayAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	var in OverlayInput
	estate{tenant: "t1", reporting: 1000, colors: []string{"biz-internet", "mpls"}, down: map[[2]int]bool{{1, 2}: true}}.build(&in)
	start := time.Now()
	r := InferOverlay(in)
	took := time.Since(start)
	if r.Stats.PairsObserved != 1000*999/2 || r.Stats.Shape["t1"] != OverlayShapeExceptions {
		t.Fatalf("stats %+v", r.Stats)
	}
	if len(r.Edges) > 1000*2+10 {
		t.Fatalf("drew %d edges for 1,000 devices — not O(N)", len(r.Edges))
	}
	if took > 20*time.Second {
		t.Fatalf("inference over 1,000 edges took %s", took)
	}
	t.Logf("1,000-edge full mesh: %d pairs observed, %d edges drawn, %s", r.Stats.PairsObserved, len(r.Edges), took)
}

func BenchmarkInferOverlay1000HubSpoke(b *testing.B) {
	// 10 hubs, 990 spokes: each spoke peers with every hub on 2 colours.
	in := OverlayInput{DevTenant: map[string]string{}, Facts: map[string]collectors.OverlayDeviceFacts{}, IfAddrs: map[string][]string{}}
	colors := []string{"biz-internet", "mpls"}
	for i := 0; i < 1000; i++ {
		in.DevTenant[devID("t", i)] = "t"
		f := collectors.OverlayDeviceFacts{SystemIP: sysIP(i)}
		for c := range colors {
			f.LocalTLOCAddrs = append(f.LocalTLOCAddrs, tlocAddr(c, i))
		}
		peers := []int{}
		if i < 10 {
			for j := 10; j < 1000; j++ {
				peers = append(peers, j)
			}
		} else {
			for j := 0; j < 10; j++ {
				peers = append(peers, j)
			}
		}
		for _, j := range peers {
			p := collectors.OverlayPeer{SystemIP: sysIP(j)}
			for c, color := range colors {
				p.ColorPairs = append(p.ColorPairs, collectors.OverlayColorPairs{LocalColor: color, RemoteColor: color, Sessions: 1, Up: 1, State: "up"})
				p.TLOCAddrs = append(p.TLOCAddrs, tlocAddr(c, j))
			}
			f.Peers = append(f.Peers, p)
		}
		in.Facts[devID("t", i)] = f
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		InferOverlay(in)
	}
}
