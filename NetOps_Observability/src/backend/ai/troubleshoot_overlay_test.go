// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---- fixtures (tsDeps wires these for the troubleshoot tests) --------------

var tsOverlayAt = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)

func tsOverlayState(deviceID string) OverlayState {
	return OverlayState{
		DeviceName: "edge-1", Read: true, Member: true, Source: "snmp", ReadAt: tsOverlayAt, Site: "50",
		DataRead: true, ControlRead: true, OMPUp: 2, OMPNotUp: 0,
		Transports: []OverlayTransportState{
			{Color: "mpls", Sessions: 6, Up: 6},
			{Color: "biz-internet", Sessions: 6, Up: 0},
		},
		TransportsTotal: 2, Peers: 6,
		PeersDown: []string{"vEdge-52", "10.255.255.81"}, PeersDownTotal: 2,
	}
}

func tsTunnelState(deviceID string) TunnelState {
	return TunnelState{
		DeviceName: "edge-1", Read: true, Total: 3, Up: 2, Down: 1,
		Tunnels: []TunnelEntry{
			{Type: "ipsec", Remote: "", Interface: "Tunnel100", Status: "down"},
			{Type: "gre", Remote: "core-1", Interface: "Tunnel200", Status: "up"},
			{Type: "sdwan", Remote: "vEdge-52", Transport: "mpls to mpls", Status: "up"},
		},
	}
}

func tsPathEvidence(deviceID string) PathEvidence {
	return PathEvidence{
		DeviceName: "edge-1", Enabled: true, Total: 2,
		Paths: []PathEvidencePath{
			{Label: "edge-1 → 8.8.8.8 (icmp)", Status: "complete", At: tsOverlayAt, Hops: 7,
				FirstLossHop: 4, LossAtFirst: 12, LossPersists: true, FinalLossPct: 11, SeamAtLoss: "seam-isp", MaxRTTms: 41},
			{Label: "edge-1 → 10.9.9.9 (tcp)", Status: "complete", At: tsOverlayAt, Hops: 5},
		},
	}
}

// ---- overlay ----------------------------------------------------------------

func TestOverlayStateRendersBothPlanesAndNeverAnAddress(t *testing.T) {
	tr := RenderOverlayState(tsOverlayState("dev-a"), DeviceRef{ID: "dev-a", Name: "edge-1"})
	text := joinItems(tr)
	for _, want := range []string{
		"SD-WAN overlay member", "site 50", "control plane: 2 of 2 OMP sessions to the controllers up",
		"transport biz-internet: 0 of 6 BFD sessions up (every session down)",
		"transport mpls: 6 of 6 BFD sessions up (all up)",
		"every session to vEdge-52 is down", "every session to unnamed edge 1 is down",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("overlay answer is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "10.255.255.81") {
		t.Fatalf("a system-ip leaked into the answer:\n%s", text)
	}
	if !slices.Equal(tr.Signals, []string{"state:overlay_ctl=up", "state:overlay_bfd=partial"}) {
		t.Fatalf("signals = %v", tr.Signals)
	}
	for _, it := range tr.Items {
		if !strings.HasPrefix(it.CitationID, OverlayStateCitationPrefix) || it.Kind != "topology" {
			t.Fatalf("item %+v", it)
		}
	}
}

func TestOverlaySignalsAreCountsAndUnreadDeclaresNothing(t *testing.T) {
	base := OverlayState{Read: true, Member: true, ControlRead: true, DataRead: true}
	cases := []struct {
		name string
		mut  func(*OverlayState)
		want []string
	}{
		{"controllers lost, tunnels down", func(s *OverlayState) {
			s.OMPNotUp = 2
			s.Transports = []OverlayTransportState{{Color: "mpls", Sessions: 4}}
		}, []string{"state:overlay_ctl=down", "state:overlay_bfd=down"}},
		{"no sessions at all", func(*OverlayState) {}, []string{"state:overlay_ctl=none", "state:overlay_bfd=none"}},
		{"some controllers down", func(s *OverlayState) {
			s.OMPUp, s.OMPNotUp = 1, 1
			s.Transports = []OverlayTransportState{{Color: "mpls", Sessions: 2, Up: 2}}
		}, []string{"state:overlay_ctl=partial", "state:overlay_bfd=up"}},
		{"control table unread", func(s *OverlayState) {
			s.ControlRead = false
			s.Transports = []OverlayTransportState{{Color: "mpls", Sessions: 2, Up: 2}}
		}, []string{"state:overlay_bfd=up"}},
		{"bfd table unread", func(s *OverlayState) { s.DataRead = false; s.OMPUp = 2 }, []string{"state:overlay_ctl=up"}},
		{"not a member", func(s *OverlayState) { s.Member = false }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			tc.mut(&st)
			if got := overlaySignals(st); !slices.Equal(got, tc.want) {
				t.Fatalf("signals = %v, want %v", got, tc.want)
			}
			for _, s := range overlaySignals(st) {
				facet, value, _ := strings.Cut(strings.TrimPrefix(s, CondStatePrefix), "=")
				if !validStateFact(facet, value) {
					t.Fatalf("%s is outside the closed vocabulary", s)
				}
			}
		})
	}
}

func TestOverlayUnreadAndNonMemberAreSaidHonestly(t *testing.T) {
	dev := DeviceRef{ID: "dev-a", Name: "edge-1"}
	unread := RenderOverlayState(OverlayState{DeviceName: "edge-1"}, dev)
	if len(unread.Items) != 0 || len(unread.Signals) != 0 || !strings.Contains(strings.Join(unread.Notes, " "), "UNKNOWN") {
		t.Fatalf("an unread overlay must say UNKNOWN and declare nothing: %+v", unread)
	}
	nonMember := RenderOverlayState(OverlayState{DeviceName: "edge-1", Read: true}, dev)
	if !strings.Contains(joinItems(nonMember), "not an overlay member") || len(nonMember.Signals) != 0 {
		t.Fatalf("a non-member must be said and declare nothing: %+v", nonMember)
	}
}

// ---- tunnels ----------------------------------------------------------------

func TestTunnelStateListsDownFirstAndKeepsAddressesOut(t *testing.T) {
	st := tsTunnelState("dev-a")
	st.Tunnels = append(st.Tunnels, TunnelEntry{Type: "tunnel", Remote: "192.0.2.10:500", Status: "up"})
	st.Total, st.Up = 4, 3
	tr := RenderTunnelState(st, DeviceRef{ID: "dev-a", Name: "edge-1"})
	if len(tr.Items) < 2 || !strings.Contains(tr.Items[1].Text, "IPsec tunnel to unnamed endpoint 1 on interface Tunnel100 — down") {
		t.Fatalf("the down tunnel must lead: %+v", tr.Items)
	}
	text := joinItems(tr)
	if strings.Contains(text, "192.0.2.10") {
		t.Fatalf("an endpoint address leaked:\n%s", text)
	}
	for _, want := range []string{"4 tunnels: 3 up, 1 down", "GRE tunnel to core-1 on interface Tunnel200 — up", "SD-WAN tunnel to vEdge-52 over transport mpls to mpls — up", "path quality not measured"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(strings.Join(tr.Notes, " "), "IKE (phase 1) and IPsec (phase 2) are not read separately") {
		t.Fatal("the read must disclose that it cannot tell negotiation from traffic")
	}
	want := []string{"state:tunnel=partial", "state:tunnel_type=gre", "state:tunnel_type=ipsec", "state:tunnel_type=other", "state:tunnel_type=sdwan"}
	if !slices.Equal(tr.Signals, want) {
		t.Fatalf("signals = %v, want %v", tr.Signals, want)
	}
}

func TestTunnelSignals(t *testing.T) {
	if got := tunnelSignals(TunnelState{}); got != nil {
		t.Fatalf("an unread inventory declares nothing, got %v", got)
	}
	if got := tunnelSignals(TunnelState{Read: true}); !slices.Equal(got, []string{"state:tunnel=none"}) {
		t.Fatalf("no tunnels = %v", got)
	}
	down := TunnelState{Read: true, Total: 2, Down: 2, Tunnels: []TunnelEntry{{Type: "ipsec", Status: "down"}, {Type: "ipsec", Status: "down"}}}
	if got := tunnelSignals(down); !slices.Equal(got, []string{"state:tunnel=down", "state:tunnel_type=ipsec"}) {
		t.Fatalf("all down = %v", got)
	}
	unread := RenderTunnelState(TunnelState{}, DeviceRef{ID: "dev-a", Name: "edge-1"})
	if len(unread.Items) != 0 || !strings.Contains(strings.Join(unread.Notes, " "), "UNKNOWN") {
		t.Fatalf("an unread inventory must say UNKNOWN: %+v", unread)
	}
}

// ---- paths ------------------------------------------------------------------

func TestPathEvidenceTellsPersistentLossFromAnArtefact(t *testing.T) {
	pe := tsPathEvidence("dev-a")
	pe.Paths = append(pe.Paths, PathEvidencePath{Label: "edge-1 → 1.1.1.1", Status: "complete", Hops: 6, FirstLossHop: 3, LossAtFirst: 40})
	pe.Total = 3
	tr := RenderPathEvidence(pe, DeviceRef{ID: "dev-a", Name: "edge-1"})
	text := joinItems(tr)
	for _, want := range []string{
		"loss first appears at hop 4 (12.0%) and PERSISTS to the destination (11.0% at the last hop), on seam seam-isp",
		"hop 3 reports 40.0% loss that does NOT continue to the destination",
		"no hop reports loss",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
	for _, addr := range []string{"8.8.8.8", "10.9.9.9", "1.1.1.1"} {
		if strings.Contains(text, addr) {
			t.Fatalf("a destination address leaked (%s):\n%s", addr, text)
		}
	}
	if !strings.Contains(tr.Items[0].Text, "PERSISTS") {
		t.Fatalf("the worst path must lead: %s", tr.Items[0].Text)
	}
	if !slices.Equal(tr.Signals, []string{"state:path=loss_persistent"}) {
		t.Fatalf("signals = %v", tr.Signals)
	}
}

func TestPathSignalsWorstWinsAndUnmeasuredIsNeverClean(t *testing.T) {
	cases := []struct {
		name  string
		paths []PathEvidencePath
		want  string
	}{
		{"no path at all", nil, "not_measured"},
		{"defined but never measured", []PathEvidencePath{{Label: "p"}}, "not_measured"},
		{"clean", []PathEvidencePath{{Status: "complete", Hops: 4}}, "clean"},
		{"artefact only", []PathEvidencePath{{Status: "complete", FirstLossHop: 2}}, "loss_transient"},
		{"changed beats an artefact", []PathEvidencePath{{Status: "complete", FirstLossHop: 2}, {Status: "partial", Changed: true}}, "changed"},
		{"persistent loss beats a change", []PathEvidencePath{{Status: "complete", Changed: true}, {Status: "complete", FirstLossHop: 3, LossPersists: true}}, "loss_persistent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pathSignals(PathEvidence{Enabled: true, Paths: tc.paths})
			if !slices.Equal(got, []string{"state:path=" + tc.want}) {
				t.Fatalf("signals = %v, want path=%s", got, tc.want)
			}
		})
	}
	if got := pathSignals(PathEvidence{}); got != nil {
		t.Fatalf("path measurement not enabled must declare nothing, got %v", got)
	}
	off := RenderPathEvidence(PathEvidence{}, DeviceRef{ID: "dev-a", Name: "edge-1"})
	if !strings.Contains(strings.Join(off.Notes, " "), "UNMEASURED") {
		t.Fatalf("an unwired path read must say UNMEASURED: %+v", off)
	}
	none := RenderPathEvidence(PathEvidence{Enabled: true}, DeviceRef{ID: "dev-a", Name: "edge-1"})
	if !strings.Contains(strings.Join(none.Notes, " "), "UNMEASURED here, not clean") {
		t.Fatalf("no measured path must be said: %+v", none)
	}
}

// ---- the tools through the registry ----------------------------------------

func TestWANToolsResolveTheDeviceThroughTheCallersInventory(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	own := Principal{Tenant: "t-a", Perms: map[string]bool{"infrastructure:read": true}}
	other := Principal{Tenant: "t-b", Perms: map[string]bool{"infrastructure:read": true}}
	for _, name := range []string{"get_overlay_state", "get_tunnel_state", "get_path_evidence"} {
		tool, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if tool.Capability() != CapRead {
			t.Fatalf("%s must be read-only", name)
		}
		res, err := tool.Run(context.Background(), own, ToolArgs{"device_id": "edge-1"})
		if err != nil || len(res.Items) == 0 {
			t.Fatalf("%s for the caller's own device: %v %+v", name, err, res)
		}
		// Another tenant's device is not found — the same answer an unknown
		// name gets, so its existence never leaks.
		if _, err := tool.Run(context.Background(), other, ToolArgs{"device_id": "edge-1"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s for another tenant's device = %v, want ErrNotFound", name, err)
		}
		if _, err := tool.Run(context.Background(), own, ToolArgs{}); err == nil {
			t.Fatalf("%s without a device must be refused", name)
		}
		c, ok := ContractFor(name)
		if !ok {
			t.Fatalf("%s has no tool contract", name)
		}
		if len(res.Items) > c.Output.MaxItems {
			t.Fatalf("%s returned %d items, its contract allows %d", name, len(res.Items), c.Output.MaxItems)
		}
	}
}

func joinItems(tr ToolResult) string {
	var b strings.Builder
	for _, it := range tr.Items {
		b.WriteString(it.Text)
		b.WriteByte('\n')
	}
	return b.String()
}
