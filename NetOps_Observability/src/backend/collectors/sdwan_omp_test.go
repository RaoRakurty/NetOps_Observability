// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOMPPeerAddrBothEncodingsAndTheCEdgeTenantArc(t *testing.T) {
	for _, c := range []struct {
		idx  string
		lead int
		want string
		ok   bool
	}{
		{"4.10.255.255.1", 0, "10.255.255.1", true},   // vEdge, length-prefixed
		{"10.255.255.1", 0, "10.255.255.1", true},     // vEdge, bare
		{"0.4.10.255.255.2", 1, "10.255.255.2", true}, // cEdge {TenantId, Peer}
		{"0.10.255.255.2", 1, "10.255.255.2", true},
		{"3.10.255.255.1", 0, "", false}, // lying length octet
		{"4.10.255.300.1", 0, "", false}, // arc > 255
		{"1.2.3", 0, "", false},          // too short
		{"", 1, "", false},
	} {
		got, ok := ompPeerAddr(c.idx, c.lead)
		if got != c.want || ok != c.ok {
			t.Errorf("ompPeerAddr(%q,%d) = %q,%v want %q,%v", c.idx, c.lead, got, ok, c.want, c.ok)
		}
	}
}

func TestReadOMPBothFamilies(t *testing.T) {
	for _, mib := range []string{"viptela", "cisco-sdwan"} {
		l := ompLayouts[mib]
		pre := ""
		if l.leadingArcs == 1 {
			pre = "0."
		}
		m := newFakeMIB()
		m.set(col(l.entry, l.colState), pre+"4.10.255.255.1", intVal(3))
		m.set(col(l.entry, l.colState), pre+"4.10.255.255.2", intVal(4))
		m.set(col(l.entry, l.colState), pre+"4.10.255.255.9", intVal(42)) // outside the enum: dropped
		m.set(col(l.entry, l.colType), pre+"4.10.255.255.1", intVal(3))
		m.set(col(l.entry, l.colType), pre+"4.10.255.255.2", intVal(3))
		m.set(col(l.entry, l.colSite), pre+"4.10.255.255.1", intVal(1000))
		m.set(col(l.entry, l.colRoutesRcvd), pre+"4.10.255.255.1", intVal(27))
		peers, _, err := readOMP(context.Background(), m.walk, "x", v2c("c"), mib, 100)
		if err != nil || len(peers) != 2 {
			t.Fatalf("%s: %+v %v", mib, peers, err)
		}
		if p := peers[0]; p.SystemIP != "10.255.255.1" || p.Type != "vsmart" || p.SiteID != "1000" || !p.Up() || p.RoutesReceived != 27 {
			t.Errorf("%s: %+v", mib, p)
		}
		if peers[1].Up() {
			t.Errorf("%s: down(4) read as up", mib)
		}
	}
	// A table that errors is an error, not "no controllers".
	m := newFakeMIB()
	m.failOn[oidStr(col(ompLayouts["viptela"].entry, 5))] = errors.New("timeout")
	if _, _, err := readOMP(context.Background(), m.walk, "x", v2c("c"), "viptela", 100); err == nil {
		t.Fatal("walk error swallowed")
	}
}

// Up-in-graceful-restart (8) counts as up; a controller gets counts only.
func TestOMPLinesEdgeAndController(t *testing.T) {
	peers := []OverlayOMPPeer{
		{SystemIP: "10.255.255.1", Type: "vsmart", State: 8},
		{SystemIP: "10.255.255.2", Type: "vsmart", State: 2},
	}
	edge := strings.Join(ompLines("vedge-51", "viptela", "vedge", peers, 5), "\n")
	for _, want := range []string{
		`device_omp_peer_state{device="vedge-51",peer="10.255.255.1",type="vsmart",site_id="",mib="viptela"} 8 5`,
		`device_omp_peers{device="vedge-51",state="up"} 1 5`,
		`device_omp_peers{device="vedge-51",state="not_up"} 1 5`,
	} {
		if !strings.Contains(edge, want) {
			t.Errorf("missing %s\n%s", want, edge)
		}
	}
	if strings.Contains(edge, "source=") || strings.Contains(edge, "hostname=") {
		t.Error("OMP series must carry device=, never a source/hostname label (metrics scope rule)")
	}
	ctrl := strings.Join(ompLines("vsmart-1", "viptela", "vsmart", peers, 5), "\n")
	if strings.Contains(ctrl, "device_omp_peer_state") || !strings.Contains(ctrl, `device_omp_peers{device="vsmart-1",state="up"} 1 5`) {
		t.Errorf("controller must carry counts only:\n%s", ctrl)
	}
}
