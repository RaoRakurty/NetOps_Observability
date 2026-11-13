// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_wan_reads_isolation_test.go — CLAUDE.md §3a rule 5 for Iris's three WAN
// reads of one device (NetClaw ingestion Batch 2): get_overlay_state,
// get_tunnel_state and get_path_evidence. org_isolation_test.go is the
// template; iris_network_topology_isolation_test.go is the sibling.
//
// The adversarial fixture: two tenants whose SD-WAN overlays use the SAME
// colour, system-ips and transport addresses (twoTenantOverlay), a hostile
// ClickHouse that returns EVERY tenant's tunnel rows whatever it is asked, and
// a path graph in which the other tenant's path names the caller's device as
// its vantage. Every read must stay inside the caller, a foreign device is
// not found, and no address leaves the seam.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/pathgraph"
)

// wanPathFixture seeds one measured path per tenant, both with the vantage
// named "acme-e0": globex's must never reach acme.
func wanPathFixture(t *testing.T) pathgraph.Store {
	t.Helper()
	ctx := context.Background()
	st := pathgraph.NewMemStore()
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	for _, tn := range []string{"acme", "globex"} {
		prov := pathgraph.Provenance{TenantID: tn, DataClass: pathgraph.DataClassLive, Environment: "test", ProducerID: "test", ProvenanceID: "prov-" + tn, RunID: "run-" + tn}
		def := pathgraph.PathDefinition{
			PathID: "pd-" + tn, SrcEndpointRef: "acme-e0", DstEndpointRef: "203.0.113.9", DstAddress: "203.0.113.9",
			Direction: "forward", Protocol: "icmp", VantageID: "acme-e0", NetworkContext: "default", Provenance: prov,
		}
		if err := st.UpsertPathDefinition(ctx, def); err != nil {
			t.Fatalf("seed def %s: %v", tn, err)
		}
		hop := func(i int, loss float64) pathgraph.PathHop {
			return pathgraph.PathHop{HopIndex: i, State: pathgraph.HopResponding, ObservedAddress: fmt.Sprintf("192.0.2.%d", i),
				LossPct: loss, RTTms: float64(5 * i), Transformation: pathgraph.TransformNone, TenantID: tn, SeamID: "seam-" + tn}
		}
		// acme: loss appears at hop 2 and persists; globex: a clean path. The
		// previous acme observation had a different hop count (a re-route).
		obs := func(id string, at time.Time, hops int) pathgraph.PathObservation {
			return pathgraph.PathObservation{ObservationID: id, PathID: def.PathID, ObservedAt: at, Method: pathgraph.MethodTracerouteICMP,
				VantageID: "acme-e0", Status: pathgraph.StatusComplete, HopCount: hops, Provenance: prov}
		}
		if err := st.AppendObservation(ctx, def, obs("o1-"+tn, now.Add(-time.Hour), 4), nil); err != nil {
			t.Fatalf("seed prev obs %s: %v", tn, err)
		}
		hops := []pathgraph.PathHop{hop(1, 0), hop(2, 0), hop(3, 0)}
		if tn == "acme" {
			hops = []pathgraph.PathHop{hop(1, 0), hop(2, 8), hop(3, 9)}
		}
		if err := st.AppendObservation(ctx, def, obs("o2-"+tn, now, 3), hops); err != nil {
			t.Fatalf("seed obs %s: %v", tn, err)
		}
	}
	return st
}

// hostileTunnelCH answers EVERY tunnel row of both tenants whatever it is
// asked, and records what it was asked.
func hostileTunnelCH(t *testing.T) (gotSQL, gotScope *string) {
	t.Helper()
	var sql, scope string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read query body: %v", err)
		}
		sql, scope = string(body), r.URL.Query().Get("tenant_scope")
		_, _ = w.Write([]byte(`{"data":[` + // the response write failing means the client is gone
			`{"id":"acme-e0/Tunnel100","type":"ipsec","local_device":"acme-e0","remote_device":"","status":"down","latency_ms":0,"loss_pct":0,"qoe":0}` +
			`]}`))
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	return &sql, &scope
}

func TestIrisWANReadsAreTheCallersOwn(t *testing.T) {
	gotSQL, gotScope := hostileTunnelCH(t)
	s := netTopoServer(t)
	s.pathGraph = wanPathFixture(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name             string
		claims           jwtClaims
		own, other       string
		ownDev, otherDev string
	}{
		{"acme", acme(), "acme", "globex", "acme-e0", "globex-e0"},
		{"globex", globex(), "globex", "acme", "globex-e0", "acme-e0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := aiTSDeps(t, s, tc.claims)
			if deps.OverlayState == nil || deps.TunnelState == nil || deps.PathEvidence == nil {
				t.Fatal("the three WAN reads must be wired when there is an inventory")
			}
			p := aiTSPrincipal()

			// A foreign device is not found on every read — never a leaked
			// existence signal, never a read of its rows.
			if _, err := deps.OverlayState(ctx, p, tc.otherDev); !errors.Is(err, ai.ErrNotFound) {
				t.Fatalf("overlay of another tenant's device = %v, want ErrNotFound", err)
			}
			if _, err := deps.TunnelState(ctx, p, tc.otherDev); !errors.Is(err, ai.ErrNotFound) {
				t.Fatalf("tunnels of another tenant's device = %v, want ErrNotFound", err)
			}
			if _, err := deps.PathEvidence(ctx, p, tc.otherDev); !errors.Is(err, ai.ErrNotFound) {
				t.Fatalf("paths of another tenant's device = %v, want ErrNotFound", err)
			}

			// Overlay: own edge, peers resolved only to the caller's own names.
			ov, err := deps.OverlayState(ctx, p, tc.ownDev)
			if err != nil {
				t.Fatalf("OverlayState: %v", err)
			}
			if !ov.Read || !ov.Member || ov.Peers != 2 || len(ov.Transports) != 1 || ov.Transports[0].Up != 2 {
				t.Fatalf("own overlay: %+v", ov)
			}
			ovText := fmt.Sprintf("%+v", ai.RenderOverlayState(ov, ai.DeviceRef{ID: tc.ownDev, Name: tc.ownDev}))
			if strings.Contains(ovText, tc.other) || strings.Contains(ovText, "10.255.0.") || strings.Contains(ovText, "198.51.100.") {
				t.Fatalf("TENANT/ADDRESS LEAK in the overlay answer: %s", ovText)
			}

			// Tunnels: the read is scoped by the caller's tenant and the device.
			tn, err := deps.TunnelState(ctx, p, tc.ownDev)
			if err != nil {
				t.Fatalf("TunnelState: %v", err)
			}
			if *gotScope != tc.own {
				t.Fatalf("the tunnel read did not carry the caller's tenant_scope: got %q, want %q", *gotScope, tc.own)
			}
			if !strings.Contains(*gotSQL, "'"+tc.ownDev+"'") || strings.Contains(*gotSQL, tc.other) {
				t.Fatalf("the tunnel read is not scoped to the caller's device:\n%s", *gotSQL)
			}
			if !strings.Contains(*gotSQL, "tenant_id") {
				t.Fatalf("the tunnel read carries no tenant clause:\n%s", *gotSQL)
			}
			if !tn.Read || tn.Total < 2 {
				t.Fatalf("own tunnels (SD-WAN pairs at least): %+v", tn)
			}
			tnText := fmt.Sprintf("%+v", ai.RenderTunnelState(tn, ai.DeviceRef{ID: tc.ownDev, Name: tc.ownDev}))
			if strings.Contains(tnText, "10.255.0.") || strings.Contains(tnText, "198.51.100.") {
				t.Fatalf("ADDRESS LEAK in the tunnel answer: %s", tnText)
			}
			// The hostile store returned acme's IPsec row to globex too; the
			// second layer must drop it (it names globex's device at neither end).
			for _, e := range tn.Tunnels {
				if e.Interface == "Tunnel100" && tc.own != "acme" {
					t.Fatalf("TENANT LEAK: acme's tunnel row reached %s: %+v", tc.own, e)
				}
			}
			if tc.own == "acme" && tn.Down != 1 {
				t.Fatalf("acme's own IPsec tunnel (down) must be counted: %+v", tn)
			}

			// Paths: only the caller's own path graph rows, never the other
			// tenant's path that names the same vantage.
			pe, err := deps.PathEvidence(ctx, p, tc.ownDev)
			if err != nil {
				t.Fatalf("PathEvidence: %v", err)
			}
			if !pe.Enabled {
				t.Fatal("path measurement is wired in this fixture")
			}
			peText := fmt.Sprintf("%+v", ai.RenderPathEvidence(pe, ai.DeviceRef{ID: tc.ownDev, Name: tc.ownDev}))
			if strings.Contains(peText, "seam-"+tc.other) || strings.Contains(peText, "192.0.2.") || strings.Contains(peText, "203.0.113.9") {
				t.Fatalf("TENANT/ADDRESS LEAK in the path answer: %s", peText)
			}
		})
	}
}

// TestIrisPathEvidenceReadsLossAndChange pins the hop fold on the stored
// shape: acme's latest observation shows loss from hop 2 to the end (real
// loss, on acme's own seam), and its hop count changed from 4 to 3.
func TestIrisPathEvidenceReadsLossAndChange(t *testing.T) {
	hostileTunnelCH(t)
	s := netTopoServer(t)
	s.pathGraph = wanPathFixture(t)
	deps := aiTSDeps(t, s, acme())
	pe, err := deps.PathEvidence(context.Background(), aiTSPrincipal(), "acme-e0")
	if err != nil {
		t.Fatalf("PathEvidence: %v", err)
	}
	if len(pe.Paths) != 1 {
		t.Fatalf("acme has exactly one path whose vantage is acme-e0: %+v", pe.Paths)
	}
	got := pe.Paths[0]
	if got.FirstLossHop != 2 || !got.LossPersists || got.FinalLossPct != 9 || got.SeamAtLoss != "seam-acme" {
		t.Fatalf("loss fold: %+v", got)
	}
	if !got.Changed || got.PrevHops != 4 || got.Hops != 3 {
		t.Fatalf("change fold: %+v", got)
	}
	tr := ai.RenderPathEvidence(pe, ai.DeviceRef{ID: "acme-e0", Name: "acme-e0"})
	if len(tr.Signals) != 1 || tr.Signals[0] != "state:path=loss_persistent" {
		t.Fatalf("signals = %v", tr.Signals)
	}
}

// TestIrisWANReadsWithoutSourcesSayUnknown: before the overlay is read and
// without a path graph, each read says so instead of describing absence.
func TestIrisWANReadsWithoutSourcesSayUnknown(t *testing.T) {
	hostileTunnelCH(t)
	s := netTopoServer(t)
	s.sdwanOverlay.Store(nil)
	deps := aiTSDeps(t, s, acme())
	ctx := context.Background()
	ov, err := deps.OverlayState(ctx, aiTSPrincipal(), "acme-e0")
	if err != nil || ov.Read {
		t.Fatalf("an unread overlay must read as not read: %+v %v", ov, err)
	}
	pe, err := deps.PathEvidence(ctx, aiTSPrincipal(), "acme-e0")
	if err != nil || pe.Enabled {
		t.Fatalf("no path graph must read as not enabled: %+v %v", pe, err)
	}
	tn, err := deps.TunnelState(ctx, aiTSPrincipal(), "acme-e0")
	if err != nil {
		t.Fatalf("TunnelState: %v", err)
	}
	if !strings.Contains(strings.Join(tn.Notes, " "), "SD-WAN tunnels are UNKNOWN") {
		t.Fatalf("an unread overlay must be disclosed on the tunnel read: %+v", tn.Notes)
	}
}
