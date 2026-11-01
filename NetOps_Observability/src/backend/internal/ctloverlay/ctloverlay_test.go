// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ctloverlay

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/nms"
	"netops/backend/topology"
)

// tenantResolver resolves a system-ip within ONE tenant only, like
// nms.InventoryResolver does.
type tenantResolver map[string]map[string]string // tenant → system-ip → device id

func (r tenantResolver) ResolveDevice(tenant string, _ nms.KeyKind, key, _ string) (string, bool) {
	id, ok := r[tenant][key]
	return id, ok
}

type fakeSessions struct {
	ints []nms.Integration
	recs map[string][]nms.StateRecord
	err  error
}

func (f fakeSessions) ListEnabled(context.Context) ([]nms.Integration, error) { return f.ints, nil }
func (f fakeSessions) OverlaySessions(_ context.Context, tenant string, since time.Time, limit int) ([]nms.StateRecord, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	var out []nms.StateRecord
	for _, r := range f.recs[tenant] {
		if !r.LastSeen.Before(since) {
			out = append(out, r)
		}
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

var t4now = time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC)

func bfdRec(local, lcol, peer, pcol, state string, age time.Duration) nms.StateRecord {
	return nms.StateRecord{EntityKey: local + "-" + lcol + "-" + peer + "-" + pcol + "-ipsec", StateKind: "bfd",
		CurrentState: state, LastSeen: t4now.Add(-age), DeviceID: local, PeerID: peer,
		TunnelID: nms.CanonicalTunnelID(local, lcol, peer, pcol), LocalColor: lcol, RemoteColor: pcol}
}

// The lab case: four IOS XE cEDGE-style edges that answer no SD-WAN MIB, fully
// reported by the controller, must draw their tunnels and transports.
func TestControllerSessionsDrawTheOverlayWithoutSNMP(t *testing.T) {
	res := tenantResolver{"t_w": {"10.0.0.20": "ctl-a", "10.0.0.51": "ctl-b", "10.0.0.81": "ctl-c"}}
	st := fakeSessions{ints: []nms.Integration{{ID: "nmsi-1", Tenant: "t_w"}}, recs: map[string][]nms.StateRecord{"t_w": {
		bfdRec("10.0.0.20", "mpls", "10.0.0.51", "mpls", "up", time.Minute),
		bfdRec("10.0.0.51", "mpls", "10.0.0.20", "mpls", "up", time.Minute),
		bfdRec("10.0.0.20", "biz-internet", "10.0.0.51", "biz-internet", "down", time.Minute),
		bfdRec("10.0.0.51", "biz-internet", "10.0.0.20", "biz-internet", "down", time.Minute),
		// cEDGE-81 was not polled this cycle; only vEdge-20 reports the session.
		bfdRec("10.0.0.20", "mpls", "10.0.0.81", "mpls", "up", 2*time.Minute),
	}}}
	facts, stats, err := Facts(context.Background(), st, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Sessions != 5 || stats.Unresolved != 0 || stats.Malformed != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	if facts["ctl-c"].SystemIP != "10.0.0.81" || len(facts["ctl-c"].Peers) != 0 {
		t.Fatalf("an unpolled far end must get an explicit system-ip and no sessions of its own: %+v", facts["ctl-c"])
	}
	out := topology.InferOverlay(topology.OverlayInput{
		DevTenant:    map[string]string{"ctl-a": "t_w", "ctl-b": "t_w", "ctl-c": "t_w"},
		Facts:        facts,
		DrawAllPairs: true,
	})
	if out.Stats.Unresolved != 0 || out.Stats.PairsObserved != 2 {
		t.Fatalf("both pairs must resolve: %+v", out.Stats)
	}
	edges := map[string]topology.Edge{}
	for _, e := range out.Edges {
		if e.Relationship == topology.RelOverlay {
			edges[e.ID] = e
		}
	}
	ab, ac := edges["sdwan|ctl-a|ctl-b"], edges["sdwan|ctl-a|ctl-c"]
	if ab.ID == "" || ac.ID == "" {
		t.Fatalf("edges missing: %+v", edges)
	}
	if ab.Status != topology.StatusDegraded || ab.Tags["colors"] != "biz-internet,mpls" || ab.Tags["sources"] != "controller" {
		t.Fatalf("a↔b: one transport down, both colours, controller-sourced: %+v", ab)
	}
	if ac.Status != topology.StatusUp || ac.Confidence != 0.85 {
		t.Fatalf("a↔c: up, reported by one end: %+v", ac)
	}
	transports := 0
	for _, n := range out.Nodes {
		if n.Kind == topology.KindWAN {
			transports++
		}
	}
	if transports != 2 {
		t.Fatalf("want the two transports (mpls, biz-internet), got %d", transports)
	}
}

// §3a: two tenants with the SAME overlay addressing and the SAME tunnel ids
// never share a device, an edge or a transport node.
func TestControllerOverlayIsTenantIsolated(t *testing.T) {
	res := tenantResolver{
		"t_a": {"10.0.0.1": "ctl-a1", "10.0.0.2": "ctl-a2"},
		"t_b": {"10.0.0.1": "ctl-b1", "10.0.0.2": "ctl-b2"},
	}
	st := fakeSessions{
		ints: []nms.Integration{{ID: "nmsi-a", Tenant: "t_a"}, {ID: "nmsi-b", Tenant: "t_b"}},
		recs: map[string][]nms.StateRecord{
			"t_a": {bfdRec("10.0.0.1", "mpls", "10.0.0.2", "mpls", "up", time.Minute)},
			"t_b": {bfdRec("10.0.0.1", "mpls", "10.0.0.2", "mpls", "down", time.Minute)},
		},
	}
	facts, _, err := Facts(context.Background(), st, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	out := topology.InferOverlay(topology.OverlayInput{
		DevTenant:    map[string]string{"ctl-a1": "t_a", "ctl-a2": "t_a", "ctl-b1": "t_b", "ctl-b2": "t_b"},
		Facts:        facts,
		DrawAllPairs: true,
	})
	for _, e := range out.Edges {
		a, b := e.Source[:5], e.Target
		if e.Relationship == topology.RelOverlay && a[4] != b[4] {
			t.Fatalf("CROSS-TENANT EDGE: %s ↔ %s", e.Source, e.Target)
		}
	}
	for _, id := range []string{"sdwan|ctl-a1|ctl-a2", "sdwan|ctl-b1|ctl-b2"} {
		found := false
		for _, e := range out.Edges {
			found = found || e.ID == id
		}
		if !found {
			t.Fatalf("missing %s", id)
		}
	}
	if topology.TransportNodeID("t_a", "mpls") == topology.TransportNodeID("t_b", "mpls") {
		t.Fatal("transport nodes must be tenant-namespaced")
	}
	// A tenant's sessions never resolve through another tenant's inventory.
	only := tenantResolver{"t_b": {"10.0.0.1": "ctl-b1", "10.0.0.2": "ctl-b2"}}
	facts, stats, _ := Facts(context.Background(), st, only, t4now)
	if stats.Unresolved != 1 {
		t.Fatalf("t_a's session must be unresolved when only t_b owns those system-ips: %+v", stats)
	}
	for id := range facts {
		if id[:5] != "ctl-b" {
			t.Fatalf("t_a's session attached to %s", id)
		}
	}
}

func TestControllerOverlayRefusesWhatItCannotPlace(t *testing.T) {
	res := tenantResolver{"t_w": {"10.0.0.1": "ctl-a", "10.0.0.2": "ctl-b"}}
	bad := bfdRec("10.0.0.1", "mpls", "10.0.0.2", "mpls", "up", time.Minute)
	bad.TunnelID = "not-a-tunnel"
	wrongPeer := bfdRec("10.0.0.1", "mpls", "10.0.0.2", "mpls", "up", time.Minute)
	wrongPeer.PeerID = "10.9.9.9"
	stale := bfdRec("10.0.0.1", "mpls", "10.0.0.2", "mpls", "up", Window+time.Minute)
	unknown := bfdRec("10.0.0.7", "mpls", "10.0.0.2", "mpls", "up", time.Minute)
	st := fakeSessions{ints: []nms.Integration{{ID: "i", Tenant: "t_w"}}, recs: map[string][]nms.StateRecord{"t_w": {bad, wrongPeer, stale, unknown}}}
	facts, stats, err := Facts(context.Background(), st, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Malformed != 2 || stats.Unresolved != 1 || stats.Sessions != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(facts["ctl-a"].Peers) != 0 {
		t.Fatalf("a stale or malformed session must not draw: %+v", facts["ctl-a"])
	}
}

// An unreadable session store is an error, never "no overlay" — the caller
// keeps the previous snapshot (tracker 307).
func TestControllerOverlayStoreErrorIsReturned(t *testing.T) {
	st := fakeSessions{ints: []nms.Integration{{ID: "i", Tenant: "t_w"}}, err: errors.New("pg down")}
	if _, _, err := Facts(context.Background(), st, tenantResolver{}, t4now); err == nil {
		t.Fatal("a store error must reach the caller")
	}
}

func TestTunnelEnds(t *testing.T) {
	tid := nms.CanonicalTunnelID("10.0.0.1", "mpls", "10.0.0.2", "lte")
	if l, r, ok := TunnelEnds(tid, "10.0.0.2"); !ok || l != "10.0.0.1" || r != "10.0.0.2" {
		t.Fatalf("%s %s %v", l, r, ok)
	}
	if l, r, ok := TunnelEnds(tid, "10.0.0.1"); !ok || l != "10.0.0.2" || r != "10.0.0.1" {
		t.Fatalf("%s %s %v", l, r, ok)
	}
	for _, c := range [][2]string{{tid, "10.0.0.3"}, {"x", "10.0.0.1"}, {"10.0.0.1/a|10.0.0.1/b", "10.0.0.1"}, {"", ""}} {
		if _, _, ok := TunnelEnds(c[0], c[1]); ok {
			t.Errorf("TunnelEnds%v accepted", c)
		}
	}
}
