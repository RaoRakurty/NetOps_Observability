// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tunnelview

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/nms"
)

// pyTunnelID is the id src/correlation/test_controller_events.py pins as the
// nms.CanonicalTunnelID shape: the engine and this fold must agree byte for byte.
const pyTunnelID = "10.255.255.20/mpls|10.255.255.51/mpls"

func cp(lc, rc string, sessions, up int) collectors.OverlayColorPairs {
	return collectors.OverlayColorPairs{LocalColor: lc, RemoteColor: rc, Sessions: sessions, Up: up}
}

func peer(ip, addr string, pairs ...collectors.OverlayColorPairs) collectors.OverlayPeer {
	p := collectors.OverlayPeer{SystemIP: ip, ColorPairs: pairs}
	if addr != "" {
		p.TLOCAddrs = []string{addr}
	}
	return p
}

// twoEdges: e20 (10.255.255.20) and e51 (10.255.255.51) in one tenant.
func twoEdges(tenant string, aUp, bUp int, bReports bool) FoldInput {
	in := FoldInput{
		DevTenant: map[string]string{"e20": tenant, "e51": tenant},
		Facts: map[string]collectors.OverlayDeviceFacts{
			"e20": {DeviceID: "e20", SystemIP: "10.255.255.20", Source: "controller",
				Peers: []collectors.OverlayPeer{peer("10.255.255.51", "198.51.100.51", cp("mpls", "mpls", 1, aUp))}},
		},
		SystemIPs: map[string]map[string]string{tenant: {"10.255.255.20": "e20", "10.255.255.51": "e51"}},
	}
	if bReports {
		in.Facts["e51"] = collectors.OverlayDeviceFacts{DeviceID: "e51", SystemIP: "10.255.255.51",
			Peers: []collectors.OverlayPeer{peer("10.255.255.20", "198.51.100.20", cp("mpls", "mpls", 1, bUp))}}
	}
	return in
}

func all(ids ...string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func TestBothEndsFoldIntoOneRowWithTheEngineID(t *testing.T) {
	got, st := Fold(twoEdges("acme", 1, 1, true))
	ts := got["acme"]
	if len(ts) != 1 || st.Folded != 1 || st.Unfolded != 0 {
		t.Fatalf("want one folded tunnel, got %+v (%+v)", ts, st)
	}
	tun := ts[0]
	if tun.TunnelID != pyTunnelID || tun.TunnelID != nms.CanonicalTunnelID("10.255.255.51", "mpls", "10.255.255.20", "mpls") {
		t.Fatalf("tunnel id %q is not the engine's %q", tun.TunnelID, pyTunnelID)
	}
	if tun.A.DeviceID != "e20" || tun.B.DeviceID != "e51" || !tun.A.Reported || !tun.B.Reported {
		t.Fatalf("A must be the first TLOC (e20) and both ends reported: %+v", tun)
	}
	if tun.State() != StateUp || tun.Status() != StateUp || tun.EndsReported() != 2 {
		t.Fatalf("state %s status %s ends %d", tun.State(), tun.Status(), tun.EndsReported())
	}
	if tun.A.Addr != "198.51.100.20" || tun.B.Addr != "198.51.100.51" {
		t.Fatalf("each end's address comes from the other end's report: %+v", tun)
	}
}

func TestOneEndOnlyStillFoldsAndNamesTheOtherEnd(t *testing.T) {
	got, _ := Fold(twoEdges("acme", 1, 0, false))
	tun := got["acme"][0]
	if tun.TunnelID != pyTunnelID || tun.EndsReported() != 1 || tun.B.Reported || tun.B.DeviceID != "e51" {
		t.Fatalf("an unreported end is still resolved and named: %+v", tun)
	}
	if tun.State() != StateUp {
		t.Fatalf("one up report reads up: %s", tun.State())
	}
}

func TestAsymmetricStateIsDisagreeAndLegacyDown(t *testing.T) {
	cases := []struct {
		a, b          int
		state, status string
	}{
		{1, 0, StateDisagree, StateDown},
		{0, 1, StateDisagree, StateDown},
		{1, 1, StateUp, StateUp},
		{0, 0, StateDown, StateDown},
	}
	for _, c := range cases {
		got, _ := Fold(twoEdges("acme", c.a, c.b, true))
		tun := got["acme"][0]
		if tun.State() != c.state || tun.Status() != c.status {
			t.Errorf("a=%d b=%d: state %s status %s, want %s %s", c.a, c.b, tun.State(), tun.Status(), c.state, c.status)
		}
	}
}

func TestMixedColoursMirrorToOneRowAndStayDistinctFromTheReverse(t *testing.T) {
	in := twoEdges("acme", 1, 1, true)
	// e20 mpls→e51 biz-internet, mirrored by e51 biz-internet→e20 mpls; plus the
	// REVERSE pair e20 biz-internet→e51 mpls, a different tunnel.
	in.Facts["e20"] = collectors.OverlayDeviceFacts{DeviceID: "e20", SystemIP: "10.255.255.20",
		Peers: []collectors.OverlayPeer{peer("10.255.255.51", "", cp("mpls", "biz-internet", 1, 1), cp("biz-internet", "mpls", 1, 0))}}
	in.Facts["e51"] = collectors.OverlayDeviceFacts{DeviceID: "e51", SystemIP: "10.255.255.51",
		Peers: []collectors.OverlayPeer{peer("10.255.255.20", "", cp("biz-internet", "mpls", 1, 1), cp("mpls", "biz-internet", 1, 0))}}
	got, _ := Fold(in)
	ts := got["acme"]
	if len(ts) != 2 {
		t.Fatalf("want 2 tunnels, got %d: %+v", len(ts), ts)
	}
	for _, tun := range ts {
		if tun.EndsReported() != 2 {
			t.Fatalf("each colour pair must meet its mirror: %+v", tun)
		}
	}
	if ts[0].TunnelID == ts[1].TunnelID {
		t.Fatal("A mpls↔B biz and A biz↔B mpls are different tunnels")
	}
}

func TestNoCanonicalIDKeepsThePerEndRowNeverAGuess(t *testing.T) {
	for name, mut := range map[string]func(*FoldInput){
		"no system-ip anywhere": func(in *FoldInput) {
			f := in.Facts["e20"]
			f.SystemIP = ""
			in.Facts["e20"] = f
			in.SystemIPs = map[string]map[string]string{}
		},
		"ipv6 system-ip": func(in *FoldInput) {
			f := in.Facts["e20"]
			f.SystemIP = "2001:db8::20"
			in.Facts["e20"] = f
			in.SystemIPs = map[string]map[string]string{}
		},
		"bad colour": func(in *FoldInput) {
			f := in.Facts["e20"]
			f.Peers = []collectors.OverlayPeer{peer("10.255.255.51", "", cp("MPLS!", "mpls", 1, 1))}
			in.Facts["e20"] = f
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := twoEdges("acme", 1, 1, false)
			mut(&in)
			got, st := Fold(in)
			ts := got["acme"]
			if len(ts) != 1 || ts[0].TunnelID != "" || st.Unfolded != 1 {
				t.Fatalf("want one unfolded row, got %+v", ts)
			}
			if !strings.HasPrefix(ts[0].ID(), "sdwan|e20|10.255.255.51|") {
				t.Fatalf("unfolded row keeps the legacy per-end id: %s", ts[0].ID())
			}
		})
	}
}

func TestTheOwnSystemIPComesFromTheOverlayOwnersWhenFactsLackIt(t *testing.T) {
	in := twoEdges("acme", 1, 1, true)
	for _, id := range []string{"e20", "e51"} {
		f := in.Facts[id]
		f.SystemIP = ""
		in.Facts[id] = f
	}
	got, _ := Fold(in)
	if len(got["acme"]) != 1 || got["acme"][0].TunnelID != pyTunnelID {
		t.Fatalf("the inverted owner map must give the same fold: %+v", got["acme"])
	}
}

func TestSameSystemIPsInTwoTenantsNeverFold(t *testing.T) {
	a, b := twoEdges("acme", 1, 1, true), twoEdges("globex", 0, 0, true)
	in := FoldInput{DevTenant: map[string]string{}, Facts: map[string]collectors.OverlayDeviceFacts{},
		SystemIPs: map[string]map[string]string{"acme": {}, "globex": {}}}
	for _, src := range []struct {
		in     FoldInput
		prefix string
		tenant string
	}{{a, "acme-", "acme"}, {b, "globex-", "globex"}} {
		for id, f := range src.in.Facts {
			nid := src.prefix + id
			f.DeviceID = nid
			in.Facts[nid] = f
			in.DevTenant[nid] = src.tenant
		}
		for ip, dev := range src.in.SystemIPs[src.tenant] {
			in.SystemIPs[src.tenant][ip] = src.prefix + dev
		}
	}
	got, _ := Fold(in)
	if len(got["acme"]) != 1 || len(got["globex"]) != 1 {
		t.Fatalf("want one tunnel per tenant: %+v", got)
	}
	if got["acme"][0].State() != StateUp || got["globex"][0].State() != StateDown {
		t.Fatal("two tenants' identical tunnels mixed their state")
	}
	if got["acme"][0].ID() == got["globex"][0].ID() {
		t.Fatal("two tenants' identical tunnels share a row id")
	}
	if got["acme"][0].A.DeviceID != "acme-e20" || got["globex"][0].B.DeviceID != "globex-e51" {
		t.Fatalf("an end resolved into the other tenant: %+v", got)
	}
}

func TestFactsFromAnUnknownDeviceAreNotShown(t *testing.T) {
	in := twoEdges("acme", 1, 1, true)
	delete(in.DevTenant, "e51")
	got, st := Fold(in)
	if st.NoTenant != 1 || got["acme"][0].EndsReported() != 1 {
		t.Fatalf("a device with no tenant reports nothing: %+v %+v", got, st)
	}
}

func TestASecondClaimOnAnEndIsCountedAndTheFirstStands(t *testing.T) {
	in := twoEdges("acme", 1, 1, true)
	// e00 claims e20's system-ip too.
	in.Facts["e00"] = collectors.OverlayDeviceFacts{DeviceID: "e00", SystemIP: "10.255.255.20",
		Peers: []collectors.OverlayPeer{peer("10.255.255.51", "", cp("mpls", "mpls", 1, 0))}}
	in.DevTenant["e00"] = "acme"
	got, st := Fold(in)
	tun := got["acme"][0]
	if st.Conflicts != 1 || tun.A.DeviceID != "e00" {
		t.Fatalf("sorted order: e00 claims first and the second claim is counted: %+v %+v", tun, st)
	}
}

func TestVisibleHidesAnEndAndDropsATunnelWithNoVisibleReport(t *testing.T) {
	got, _ := Fold(twoEdges("acme", 1, 0, true))
	// Only e20 visible: its report stays, e51's is dropped and e51 is named by
	// system-ip only.
	vs := Visible(got, all("e20"))
	if len(vs) != 1 {
		t.Fatalf("want 1, got %d", len(vs))
	}
	tun := vs[0]
	if tun.B.DeviceID != "" || tun.B.Reported || tun.B.SystemIP != "10.255.255.51" || tun.State() != StateUp {
		t.Fatalf("a hidden end keeps only its system-ip and its report is dropped: %+v", tun)
	}
	row := RowOf(tun, func(id string) string { return "name-" + id }, nil, nil, nil, time.Unix(0, 0))
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), "e51") || row.RemoteDevice != "10.255.255.51" {
		t.Fatalf("a hidden device's id or name leaked: %s", raw)
	}
	if none := Visible(got, all()); len(none) != 0 {
		t.Fatalf("neither end visible must drop the tunnel: %+v", none)
	}
	// The fold itself is not modified: the next caller still sees both reports.
	if !got["acme"][0].B.Reported || got["acme"][0].B.DeviceID != "e51" {
		t.Fatal("Visible mutated the fold")
	}
}

func TestVisibleOrderIsWorstFirstAndDeterministic(t *testing.T) {
	in := twoEdges("acme", 1, 1, true)
	in.DevTenant["e77"] = "acme"
	in.SystemIPs["acme"]["10.255.255.77"] = "e77"
	in.Facts["e77"] = collectors.OverlayDeviceFacts{DeviceID: "e77", SystemIP: "10.255.255.77",
		Peers: []collectors.OverlayPeer{peer("10.255.255.20", "", cp("mpls", "mpls", 1, 0))}}
	got, _ := Fold(in)
	a := Visible(got, all("e20", "e51", "e77"))
	b := Visible(got, all("e77", "e51", "e20"))
	if len(a) != 2 || a[0].State() != StateDown {
		t.Fatalf("down first: %+v", a)
	}
	for i := range a {
		if a[i].ID() != b[i].ID() {
			t.Fatal("order depends on input order")
		}
	}
}

// ── quality ─────────────────────────────────────────────────────────────────

func series(name, tenant, rep, lc, peer, rc string, v float64) Sample {
	return Sample{Labels: map[string]string{"__name__": name, "tenant_id": tenant, "controller_device": rep,
		"device": "dev-" + rep, "local_color": lc, "peer": peer, "remote_color": rc}, Value: v}
}

func dirSeries(tenant, rep, peer string, lat, jit, loss, qoe float64) []Sample {
	return []Sample{
		series("controller_metric_tunnel_latency_ms", tenant, rep, "mpls", peer, "mpls", lat),
		series("controller_metric_tunnel_jitter_ms", tenant, rep, "mpls", peer, "mpls", jit),
		series("controller_metric_tunnel_loss_pct", tenant, rep, "mpls", peer, "mpls", loss),
		series("controller_metric_tunnel_qoe", tenant, rep, "mpls", peer, "mpls", qoe),
	}
}

func asOf(tenant, rep, peer string, unix int64) Sample {
	s := series("", tenant, rep, "mpls", peer, "mpls", float64(unix))
	delete(s.Labels, "__name__")
	return s
}

func foldedVisible(t *testing.T, tenant string) Tunnel {
	t.Helper()
	got, _ := Fold(twoEdges(tenant, 1, 1, true))
	return Visible(got, all("e20", "e51"))[0]
}

func TestQualityIsWorstOfBothDirectionsAsOfTheOlderEnd(t *testing.T) {
	tun := foldedVisible(t, "acme")
	vals := append(dirSeries("acme", "10.255.255.20", "10.255.255.51", 10, 2, 0.5, 9),
		dirSeries("acme", "10.255.255.51", "10.255.255.20", 30, 1, 0.1, 7)...)
	qi := NewQualityIndex(vals, []Sample{asOf("acme", "10.255.255.20", "10.255.255.51", 2000),
		asOf("acme", "10.255.255.51", "10.255.255.20", 1000)})
	q := qi.For(tun)
	if q == nil || q.Ends != 2 || q.LatencyMs != 30 || q.JitterMs != 2 || q.LossPct != 0.5 || q.QoE != 7 {
		t.Fatalf("worst-of: %+v", q)
	}
	if !q.AsOf.Equal(time.Unix(1000, 0).UTC()) {
		t.Fatalf("as_of is the older end's newest sample: %v", q.AsOf)
	}
	row := RowOf(tun, nil, nil, q, nil, time.Unix(5000, 0))
	if !row.Measured || row.LatencyMs != 30 || row.Quality == nil {
		t.Fatalf("legacy fields carry the reading: %+v", row)
	}
}

func TestQualityFromOneDirectionAndFromNone(t *testing.T) {
	tun := foldedVisible(t, "acme")
	qi := NewQualityIndex(dirSeries("acme", "10.255.255.51", "10.255.255.20", 12, 1, 0, 8), nil)
	if q := qi.For(tun); q == nil || q.Ends != 1 || q.LatencyMs != 12 || !q.AsOf.IsZero() {
		t.Fatalf("one direction: %+v", q)
	}
	if q := NewQualityIndex(nil, nil).For(tun); q != nil {
		t.Fatalf("no series is no quality, never zeros: %+v", q)
	}
	row := RowOf(tun, nil, nil, nil, nil, time.Unix(0, 0))
	if row.Measured || row.Quality != nil || row.LatencyMs != 0 {
		t.Fatalf("unmeasured: %+v", row)
	}
}

func TestQualityLabelsAreNormalisedAndDeviceIsTheFallbackReporter(t *testing.T) {
	tun := foldedVisible(t, "acme")
	s := series("controller_metric_tunnel_loss_pct", "ACME", "", "MPLS", "10.255.255.51", "Mpls", 4)
	s.Labels["device"] = "10.255.255.20" // no controller_device: an IPv4 device names the reporter
	if q := NewQualityIndex([]Sample{s}, nil).For(tun); q == nil || q.LossPct != 4 {
		t.Fatalf("case-folded labels and the device fallback must join: %+v", q)
	}
	s.Labels["device"] = "vedge-20" // a non-IP device with no controller_device names nobody
	if q := NewQualityIndex([]Sample{s}, nil).For(tun); q != nil {
		t.Fatalf("an unnamed reporter must not join: %+v", q)
	}
}

func TestQualityNeverJoinsAnotherTenantsSeries(t *testing.T) {
	tun := foldedVisible(t, "acme")
	qi := NewQualityIndex(dirSeries("globex", "10.255.255.20", "10.255.255.51", 99, 9, 50, 1), nil)
	if q := qi.For(tun); q != nil {
		t.Fatalf("a foreign tenant's series with the same key joined: %+v", q)
	}
}

func TestQualityFromAHiddenEndIsNotUsed(t *testing.T) {
	got, _ := Fold(twoEdges("acme", 1, 1, true))
	tun := Visible(got, all("e20"))[0]
	qi := NewQualityIndex(dirSeries("acme", "10.255.255.51", "10.255.255.20", 50, 5, 5, 1), nil)
	if q := qi.For(tun); q != nil {
		t.Fatalf("the hidden end's reading reached the caller: %+v", q)
	}
}

func TestOctetSeriesAreNeverJoined(t *testing.T) {
	tun := foldedVisible(t, "acme")
	s := series("controller_metric_tunnel_rx_octets_total", "acme", "10.255.255.20", "mpls", "10.255.255.51", "mpls", 123)
	if q := NewQualityIndex([]Sample{s}, nil).For(tun); q != nil {
		t.Fatalf("a counter series became quality: %+v", q)
	}
}

// ── cases ───────────────────────────────────────────────────────────────────

func TestCaseMatchesTheBareIDAndTheControllerSpelling(t *testing.T) {
	tun := foldedVisible(t, "acme")
	at := time.Unix(1000, 0)
	for _, path := range []string{pyTunnelID, pyTunnelID + "@ci-aaaaaaaaaaaaaaaa"} {
		ci := NewCaseIndex([]OpenObject{{ID: "c1", Tier: "suspected", Tenant: "acme", CreatedAt: at, Paths: []string{path}}})
		if c := ci.For(tun); c == nil || c.ID != "c1" || c.EntityID != path {
			t.Fatalf("path %q must match: %+v", path, c)
		}
	}
}

func TestCaseNeverMatchesADeviceOrAnotherTenantOrAPrefixLookAlike(t *testing.T) {
	tun := foldedVisible(t, "acme")
	at := time.Unix(1000, 0)
	for name, o := range map[string]OpenObject{
		"device-id path": {ID: "c", Tenant: "acme", CreatedAt: at, Paths: []string{"e20"}},
		"other tenant":   {ID: "c", Tenant: "globex", CreatedAt: at, Paths: []string{pyTunnelID}},
		"longer id":      {ID: "c", Tenant: "acme", CreatedAt: at, Paths: []string{pyTunnelID + "x"}},
	} {
		if c := NewCaseIndex([]OpenObject{o}).For(tun); c != nil {
			t.Errorf("%s matched: %+v", name, c)
		}
	}
}

func TestCaseTieBreakIsNewestThenSmallestID(t *testing.T) {
	tun := foldedVisible(t, "acme")
	old, recent := time.Unix(1000, 0), time.Unix(2000, 0)
	objs := []OpenObject{
		{ID: "b", Tenant: "acme", CreatedAt: recent, Paths: []string{pyTunnelID}},
		{ID: "z", Tenant: "acme", CreatedAt: old, Paths: []string{pyTunnelID}},
		{ID: "a", Tenant: "acme", CreatedAt: recent, Paths: []string{pyTunnelID + "@ci-x"}},
	}
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
		var in []OpenObject
		for _, i := range order {
			in = append(in, objs[i])
		}
		if c := NewCaseIndex(in).For(tun); c == nil || c.ID != "a" {
			t.Fatalf("order %v: %+v", order, c)
		}
	}
}

func TestPlatformTenantSpellingsMeet(t *testing.T) {
	got, _ := Fold(twoEdges("", 1, 1, true))
	tun := Visible(got, all("e20", "e51"))[0]
	ci := NewCaseIndex([]OpenObject{{ID: "c", Tenant: "global", CreatedAt: time.Unix(1, 0), Paths: []string{pyTunnelID}}})
	if ci.For(tun) == nil {
		t.Fatal("the engine's 'global' and a device's empty tenant are one realm")
	}
}

// ── matrix ──────────────────────────────────────────────────────────────────

func siteMap(m map[string]Site) SiteOf {
	return func(id string) (Site, bool) { s, ok := m[id]; return s, ok }
}

func threeSiteFold() ([]Tunnel, SiteOf) {
	in := FoldInput{DevTenant: map[string]string{}, Facts: map[string]collectors.OverlayDeviceFacts{},
		SystemIPs: map[string]map[string]string{"acme": {}}}
	add := func(id, ip string, peers ...collectors.OverlayPeer) {
		in.DevTenant[id] = "acme"
		in.SystemIPs["acme"][ip] = id
		in.Facts[id] = collectors.OverlayDeviceFacts{DeviceID: id, SystemIP: ip, Peers: peers}
	}
	add("hq1", "10.0.0.1", peer("10.0.0.2", "", cp("mpls", "mpls", 1, 1)), peer("10.0.0.3", "", cp("mpls", "mpls", 1, 0), cp("biz-internet", "biz-internet", 1, 1)))
	add("hq2", "10.0.0.2")
	add("br1", "10.0.0.3", peer("10.0.0.1", "", cp("mpls", "mpls", 1, 1)))
	add("lost", "10.0.0.9", peer("10.0.0.1", "", cp("mpls", "mpls", 1, 1)))
	got, _ := Fold(in)
	ts := Visible(got, all("hq1", "hq2", "br1", "lost"))
	return ts, siteMap(map[string]Site{
		"hq1": {Key: "hq", Label: "HQ", Source: "manual"},
		"hq2": {Key: "hq", Label: "HQ", Source: "manual"},
		"br1": {Key: "br", Label: "Branch 1", Source: "label"},
	})
}

func TestMatrixWorstStatePerCellAndPerTransport(t *testing.T) {
	ts, so := threeSiteFold()
	m := BuildMatrix(ts, so, QualityIndex{}, CaseIndex{})
	if m.SitesTotal != 2 || len(m.Sites) != 2 || m.UnplacedTunnels != 1 || m.Truncated {
		t.Fatalf("sites/unplaced: %+v", m)
	}
	// Worst site first: HQ ↔ Branch carries the disagreeing mpls tunnel.
	byPair := map[string]Cell{}
	for _, c := range m.Cells {
		byPair[c.A+"-"+c.B] = c
	}
	if m.Sites[0].Devices != 2 || m.Sites[0].Label != "HQ" {
		t.Fatalf("site order or device count: %+v", m.Sites)
	}
	cross := byPair["s1-s2"]
	if cross.Tunnels != 2 || cross.State != StateDisagree || cross.Disagree != 1 || cross.Up != 1 {
		t.Fatalf("cross-site cell: %+v", cross)
	}
	if len(cross.Transports) != 2 || cross.Transports[0].Color != "biz-internet" || cross.Transports[0].State != StateUp ||
		cross.Transports[1].Color != "mpls" || cross.Transports[1].State != StateDisagree {
		t.Fatalf("per-transport worst state: %+v", cross.Transports)
	}
	diag := byPair["s1-s1"]
	if diag.Tunnels != 1 || diag.State != StateUp {
		t.Fatalf("intra-site diagonal: %+v", diag)
	}
}

func TestMatrixNeverMergesTheSameSlugInTwoTenants(t *testing.T) {
	a := Tunnel{Tenant: "acme", TunnelID: "10.0.0.1/mpls|10.0.0.2/mpls",
		A: End{DeviceID: "a1", SystemIP: "10.0.0.1", Color: "mpls", Reported: true, Up: 1},
		B: End{DeviceID: "a2", SystemIP: "10.0.0.2", Color: "mpls"}}
	g := a
	g.Tenant = "globex"
	g.A.DeviceID, g.B.DeviceID = "g1", "g2"
	so := siteMap(map[string]Site{"a1": {Key: "hq", Label: "HQ"}, "a2": {Key: "hq", Label: "HQ"},
		"g1": {Key: "hq", Label: "HQ"}, "g2": {Key: "hq", Label: "HQ"}})
	m := BuildMatrix([]Tunnel{a, g}, so, QualityIndex{}, CaseIndex{})
	if m.SitesTotal != 2 || len(m.Cells) != 2 {
		t.Fatalf("two tenants' 'hq' must stay two sites: %+v", m)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), `"hq"`) {
		t.Fatalf("a tenant's slug leaked as a matrix key: %s", raw)
	}
}

func TestMatrixSitesCap(t *testing.T) {
	var ts []Tunnel
	sites := map[string]Site{}
	for i := 0; i < MaxMatrixSites+5; i++ {
		a, b := "d"+itoa(i)+"a", "d"+itoa(i)+"b"
		sites[a] = Site{Key: "k" + itoa(i), Label: "Site " + itoa(i)}
		sites[b] = Site{Key: "k" + itoa(i), Label: "Site " + itoa(i)}
		ts = append(ts, Tunnel{Tenant: "acme", TunnelID: "x" + itoa(i),
			A: End{DeviceID: a, Reported: true, Up: 1}, B: End{DeviceID: b}})
	}
	m := BuildMatrix(ts, siteMap(sites), QualityIndex{}, CaseIndex{})
	if !m.Truncated || len(m.Sites) != MaxMatrixSites || m.SitesTotal != MaxMatrixSites+5 || len(m.Cells) != MaxMatrixSites {
		t.Fatalf("cap: truncated=%v sites=%d total=%d cells=%d", m.Truncated, len(m.Sites), m.SitesTotal, len(m.Cells))
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestMatrixCarriesQualityAndCases(t *testing.T) {
	ts, so := threeSiteFold()
	var hqBr Tunnel
	for _, tun := range ts {
		if tun.TunnelID == "10.0.0.1/mpls|10.0.0.3/mpls" {
			hqBr = tun
		}
	}
	qi := NewQualityIndex(dirSeries("acme", "10.0.0.1", "10.0.0.3", 140, 3, 2.1, 5),
		[]Sample{asOf("acme", "10.0.0.1", "10.0.0.3", 1000)})
	ci := NewCaseIndex([]OpenObject{{ID: "case-1", Tenant: "acme", CreatedAt: time.Unix(1, 0), Paths: []string{hqBr.TunnelID + "@ci-1"}}})
	m := BuildMatrix(ts, so, qi, ci)
	var cross Cell
	for _, c := range m.Cells {
		if c.A != c.B {
			cross = c
		}
	}
	if cross.Measured != 1 || cross.WorstLossPct == nil || *cross.WorstLossPct != 2.1 || *cross.WorstLatencyMs != 140 ||
		cross.QualityAsOf == nil || len(cross.Cases) != 1 || cross.Cases[0] != "case-1" {
		t.Fatalf("cell quality/cases: %+v", cross)
	}
}

func TestRowShape(t *testing.T) {
	tun := foldedVisible(t, "acme")
	so := siteMap(map[string]Site{"e20": {Key: "hq", Label: "HQ", Source: "manual"}})
	r := RowOf(tun, func(id string) string { return "N-" + id }, so, nil,
		&Case{ID: "c1", Tier: "suspected", EntityID: pyTunnelID}, time.Unix(0, 0))
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"id", "type", "tunnel_id", "status", "state", "ends_reported", "a", "b",
		"local_device", "local_addr", "remote_device", "remote_addr", "latency_ms", "jitter_ms", "loss_pct",
		"qoe", "uptime_s", "measured", "ts", "quality", "case", "sources"} {
		if _, ok := m[k]; !ok {
			t.Errorf("row lacks %q: %s", k, raw)
		}
	}
	if r.LocalDevice != "N-e20" || r.A.Site == nil || r.A.Site.Label != "HQ" || r.B.Site != nil {
		t.Fatalf("names and sites: %+v", r)
	}
	if strings.Contains(string(raw), `"hq"`) {
		t.Fatalf("a site key is internal: %s", raw)
	}
}
