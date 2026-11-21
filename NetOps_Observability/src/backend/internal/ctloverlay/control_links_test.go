// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ctloverlay

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/nms"
)

// fakeControl serves ControlSessions per tenant, honouring since and limit.
type fakeControl struct {
	ints []nms.Integration
	recs map[string][]nms.StateRecord
	err  error
}

func (f fakeControl) ListEnabled(context.Context) ([]nms.Integration, error) { return f.ints, nil }
func (f fakeControl) ControlSessions(_ context.Context, tenant string, since time.Time, limit int) ([]nms.StateRecord, bool, error) {
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

// ccRec is a vManage control-connection state record as the connector stores it:
// device_id is the reporting device's engine id (an inventory id for an edge, the
// raw system-ip for a controller), the entity key starts with its system-ip, and
// peer_id is the far end's system-ip.
func ccRec(integration, device, sysIP, peer, color string, age time.Duration) nms.StateRecord {
	return nms.StateRecord{IntegrationID: integration, StateKind: "control_conn", CurrentState: "up",
		DeviceID: device, PeerID: peer, LastSeen: t4now.Add(-age),
		EntityKey: sysIP + "-0-" + color + "-" + peer + "-default"}
}

const (
	vSmart  = "10.255.255.2"
	vManage = "10.255.255.1"
)

var labIC = nms.Integration{ID: "nmsi-1", Tenant: "t_w", Vendor: "vmanage", BaseURL: "https://200.250.250.1"}

// The lab shape: two edges report their vSmart and vManage sessions over two
// colours, and the vSmart reports the same sessions from its side. Every session
// collapses to ONE row per device pair, its ends are the engine's device ids and
// the keys are the system-ips signals.controller_peer returns.
func TestControlLinksOneRowPerPairWithEngineIDsAndKeys(t *testing.T) {
	res := tenantResolver{"t_w": {"10.255.255.20": "vedge-20", "10.255.255.81": "cedge-81"}}
	recs := []nms.StateRecord{
		ccRec("nmsi-1", "vedge-20", "10.255.255.20", vSmart, "mpls", time.Minute),
		ccRec("nmsi-1", "vedge-20", "10.255.255.20", vSmart, "biz-internet", time.Minute),
		ccRec("nmsi-1", "vedge-20", "10.255.255.20", vManage, "mpls", time.Minute),
		ccRec("nmsi-1", "cedge-81", "10.255.255.81", vSmart, "mpls", time.Minute),
		// the controller's own view of the same sessions (device id = raw address)
		ccRec("nmsi-1", vSmart, vSmart, "10.255.255.20", "default", time.Minute),
		ccRec("nmsi-1", vSmart, vSmart, "10.255.255.81", "default", time.Minute),
	}
	st := fakeControl{ints: []nms.Integration{labIC}, recs: map[string][]nms.StateRecord{"t_w": recs}}
	rows, stats, err := ControlLinks(context.Background(), st, vmSpec, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	want := []SessionLink{
		{TenantID: "t_w", SA: vManage, SAKey: vManage, SB: "vedge-20", SBKey: "10.255.255.20"},
		{TenantID: "t_w", SA: vSmart, SAKey: vSmart, SB: "cedge-81", SBKey: "10.255.255.81"},
		{TenantID: "t_w", SA: vSmart, SAKey: vSmart, SB: "vedge-20", SBKey: "10.255.255.20"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %d", rows, len(want))
	}
	for i, w := range want {
		g := rows[i]
		g.Integrations = 0
		if g != w {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], w)
		}
		if rows[i].SA >= rows[i].SB {
			t.Errorf("row %d not ordered sa < sb: %+v", i, rows[i])
		}
	}
	if stats.Sessions != len(recs) || stats.Malformed != 0 || stats.Collisions != 0 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestControlLinksSkipsWhatItCannotPlace(t *testing.T) {
	res := tenantResolver{"t_w": {"10.255.255.20": "vedge-20"}}
	noKey := ccRec("nmsi-1", "vedge-20", "x", vSmart, "mpls", time.Minute)
	noKey.EntityKey = "not-an-address"
	badPeer := ccRec("nmsi-1", "vedge-20", "10.255.255.20", "vsmart-name", "mpls", time.Minute)
	self := ccRec("nmsi-1", "vedge-20", "10.255.255.20", "10.255.255.20", "mpls", time.Minute)
	stale := ccRec("nmsi-1", "vedge-20", "10.255.255.20", vSmart, "mpls", ControlWindow+time.Minute)
	orphan := ccRec("nmsi-gone", "vedge-20", "10.255.255.20", vSmart, "mpls", time.Minute)
	st := fakeControl{ints: []nms.Integration{labIC}, recs: map[string][]nms.StateRecord{
		"t_w": {noKey, badPeer, self, stale, orphan}}}
	rows, stats, err := ControlLinks(context.Background(), st, vmSpec, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("nothing placeable, got %+v", rows)
	}
	if stats.Malformed != 3 {
		t.Fatalf("stats: %+v (want 3 malformed: no key, non-address peer, one box at both ends)", stats)
	}
}

func TestControlLinksNeedAControllerInstance(t *testing.T) {
	ic := nms.Integration{ID: "nmsi-x", Tenant: "t_w", Vendor: "no-such-vendor", BaseURL: "https://x"}
	st := fakeControl{ints: []nms.Integration{ic}, recs: map[string][]nms.StateRecord{
		"t_w": {ccRec("nmsi-x", vSmart, vSmart, "10.255.255.20", "default", time.Minute)}}}
	rows, stats, err := ControlLinks(context.Background(), st, vmSpec, tenantResolver{}, t4now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || stats.NoInstance != 1 {
		t.Fatalf("rows %+v stats %+v", rows, stats)
	}
}

// Two vManage fabrics in ONE tenant both reporting the raw address 10.255.255.2:
// it may be two boxes, and a device node carries no "@instance" to tell them
// apart, so that end gets no row (counted). Resolved ends are unaffected.
func TestControlLinksRawAddressClaimedByTwoInstancesGetsNoRow(t *testing.T) {
	res := tenantResolver{"t_w": {"10.255.255.20": "vedge-20", "10.255.255.30": "vedge-30", "10.255.255.40": "vedge-40"}}
	other := nms.Integration{ID: "nmsi-2", Tenant: "t_w", Vendor: "vmanage", BaseURL: "https://fabric-b.example.net"}
	recs := []nms.StateRecord{
		ccRec("nmsi-1", "vedge-20", "10.255.255.20", vSmart, "mpls", time.Minute),
		ccRec("nmsi-2", "vedge-30", "10.255.255.30", vSmart, "mpls", time.Minute),
		ccRec("nmsi-2", "vedge-30", "10.255.255.30", "10.255.255.40", "mpls", time.Minute), // resolved both ends
	}
	st := fakeControl{ints: []nms.Integration{labIC, other}, recs: map[string][]nms.StateRecord{"t_w": recs}}
	rows, stats, err := ControlLinks(context.Background(), st, vmSpec, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Collisions != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(rows) != 1 || rows[0].SA != "vedge-30" || rows[0].SB != "vedge-40" {
		t.Fatalf("only the fully resolved pair survives: %+v", rows)
	}
}

// §3a: each tenant's rows come from its own read and resolver; an end resolves
// only within its own tenant; a platform integration's rows are owned by
// "global", never "" (the engine merges "" rows into every tenant).
func TestControlLinksAreTenantScoped(t *testing.T) {
	res := tenantResolver{
		"t_a": {"10.255.255.20": "a-edge"},
		"t_b": {"10.255.255.20": "b-edge"},
		"":    {"10.255.255.20": "p-edge"},
	}
	icA := nms.Integration{ID: "ia", Tenant: "t_a", Vendor: "vmanage", BaseURL: "https://a.example.net"}
	icB := nms.Integration{ID: "ib", Tenant: "t_b", Vendor: "vmanage", BaseURL: "https://b.example.net"}
	icP := nms.Integration{ID: "ip", Tenant: "", Vendor: "vmanage", BaseURL: "https://p.example.net"}
	st := fakeControl{ints: []nms.Integration{icA, icB, icP}, recs: map[string][]nms.StateRecord{
		"t_a": {ccRec("ia", "a-edge", "10.255.255.20", vSmart, "mpls", time.Minute)},
		"t_b": {ccRec("ib", "b-edge", "10.255.255.20", vSmart, "mpls", time.Minute)},
		"":    {ccRec("ip", "p-edge", "10.255.255.20", vSmart, "mpls", time.Minute)},
	}}
	rows, _, err := ControlLinks(context.Background(), st, vmSpec, res, t4now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		if r.TenantID == "" {
			t.Fatalf("a row with tenant \"\" grounds in every tenant: %+v", r)
		}
		got[r.TenantID] = r.SB
	}
	want := map[string]string{"t_a": "a-edge", "t_b": "b-edge", "global": "p-edge"}
	for tenant, dev := range want {
		if got[tenant] != dev {
			t.Fatalf("tenant %q: got %q, want %q (rows %+v)", tenant, got[tenant], dev, rows)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("one row per tenant, got %+v", rows)
	}
}

func TestControlLinksCountTruncationAndReturnStoreErrors(t *testing.T) {
	res := tenantResolver{"t_w": {"10.255.255.20": "vedge-20"}}
	var recs []nms.StateRecord
	for i := 0; i < ControlRowCap+1; i++ {
		recs = append(recs, ccRec("nmsi-1", "vedge-20", "10.255.255.20", vSmart, "mpls", time.Minute))
	}
	st := fakeControl{ints: []nms.Integration{labIC}, recs: map[string][]nms.StateRecord{"t_w": recs}}
	_, stats, err := ControlLinks(context.Background(), st, vmSpec, res, t4now)
	if err != nil || stats.Truncated != 1 {
		t.Fatalf("err %v stats %+v", err, stats)
	}
	bad := fakeControl{ints: []nms.Integration{labIC}, err: errors.New("pg down")}
	if _, _, err := ControlLinks(context.Background(), bad, vmSpec, res, t4now); err == nil {
		t.Fatal("a store error must reach the writer, which then keeps the previous file")
	}
}

func TestLinksCountsATruncatedRead(t *testing.T) {
	var recs []nms.StateRecord
	for i := 0; i < RowCap+1; i++ {
		r := bfdRec("10.0.0.20", "mpls", "10.0.0.51", "mpls", "up", time.Minute)
		r.IntegrationID = "nmsi-1"
		recs = append(recs, r)
	}
	st := fakeSessions{ints: []nms.Integration{labIC}, recs: map[string][]nms.StateRecord{"t_w": recs}}
	_, stats, err := Links(context.Background(), st, vmSpec, tenantResolver{}, t4now)
	if err != nil || stats.Truncated != 1 {
		t.Fatalf("a capped read must be counted, not silently partial: err %v stats %+v", err, stats)
	}
}

func TestReportingKey(t *testing.T) {
	cases := []struct {
		dev, key, want string
	}{
		{vSmart, "anything", vSmart},
		{"vedge-20", "10.255.255.20-0-mpls-10.255.255.2-default", "10.255.255.20"},
		{"vedge-20", "garbage", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := reportingKey(nms.StateRecord{DeviceID: c.dev, EntityKey: c.key}); got != c.want {
			t.Errorf("reportingKey(%q, %q) = %q, want %q", c.dev, c.key, got, c.want)
		}
	}
}
