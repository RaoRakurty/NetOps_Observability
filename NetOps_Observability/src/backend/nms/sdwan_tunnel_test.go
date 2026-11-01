// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"os"
	"strings"
	"testing"
	"time"
)

func loadBFD(t *testing.T, name string) []ControllerState {
	t.Helper()
	raw, err := os.ReadFile("fixtures/vmanage/" + name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vmanageBFDTransform("t-a", "nmsi-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.States) == 0 {
		t.Fatalf("%s produced no BFD states", name)
	}
	return b.States
}

// The recorded halves of one session (both ends, two edge platforms) must name
// the SAME tunnel — the whole point of the canonical id.
func TestBothEndsOfARecordedBFDSessionShareOneTunnelID(t *testing.T) {
	byEnds := map[string]map[string]string{} // "reporter>peer/colour" → tunnel id
	for _, f := range []string{"bfd_sessions_vedge20.json", "bfd_sessions_vedge51.json", "bfd_sessions_cedge81.json"} {
		for _, s := range loadBFD(t, f) {
			if s.TunnelID == "" {
				t.Fatalf("%s: session %s has no tunnel id", f, s.EntityKey)
			}
			if strings.Contains(s.TunnelID, ":") || strings.Contains(s.TunnelID, "->") {
				t.Fatalf("tunnel id %q carries a character the engine gives structure to", s.TunnelID)
			}
			if s.PeerID == "" || s.PeerID == s.DeviceID {
				t.Fatalf("%s: peer id %q must name the far end (device %q)", f, s.PeerID, s.DeviceID)
			}
			col, _ := s.Data["local_color"].(string)
			if byEnds[s.DeviceID] == nil {
				byEnds[s.DeviceID] = map[string]string{}
			}
			byEnds[s.DeviceID][s.PeerID+"/"+col] = s.TunnelID
		}
	}
	for _, c := range []struct{ a, b, col string }{
		{"10.255.255.20", "10.255.255.51", "mpls"},
		{"10.255.255.20", "10.255.255.51", "biz-internet"},
		{"10.255.255.20", "10.255.255.81", "mpls"}, // vEdge ↔ IOS XE cEDGE
	} {
		ab, ba := byEnds[c.a][c.b+"/"+c.col], byEnds[c.b][c.a+"/"+c.col]
		if ab == "" || ba == "" {
			t.Fatalf("fixture lacks the %s↔%s %s pair (%q / %q)", c.a, c.b, c.col, ab, ba)
		}
		if ab != ba {
			t.Fatalf("the two ends of %s↔%s %s disagree: %q vs %q", c.a, c.b, c.col, ab, ba)
		}
	}
	if byEnds["10.255.255.20"]["10.255.255.51/mpls"] == byEnds["10.255.255.20"]["10.255.255.51/biz-internet"] {
		t.Fatal("two transports between the same pair must be two tunnels")
	}
}

func TestCanonicalTunnelIDRefusesWhatCouldBreakIdentity(t *testing.T) {
	ok := CanonicalTunnelID("10.0.0.2", "MPLS", "10.0.0.1", "biz-internet")
	if ok != "10.0.0.1/biz-internet|10.0.0.2/mpls" {
		t.Fatalf("not canonical (sorted, lower-cased): %q", ok)
	}
	if ok != CanonicalTunnelID("10.0.0.1", "biz-internet", "10.0.0.2", "mpls") {
		t.Fatal("order of the ends changed the id")
	}
	for _, c := range [][4]string{
		{"", "mpls", "10.0.0.1", "mpls"},
		{"10.0.0.1", "", "10.0.0.2", "mpls"},
		{"vedge-1", "mpls", "10.0.0.2", "mpls"},     // not an address
		{"2001:db8::1", "mpls", "10.0.0.2", "mpls"}, // ':' would split the entity
		{"10.0.0.1", "mp:ls", "10.0.0.2", "mpls"},   // ':' in a colour
		{"10.0.0.1", "a->b", "10.0.0.2", "mpls"},    // a probe-path arrow
		{"10.0.0.1", "mpls", "10.0.0.1", "mpls"},    // a tunnel to itself
		{"10.0.0.1", "mpls|x", "10.0.0.2", "mpls"},  // the separator
		{"10.0.0.1", strings.Repeat("a", 49), "10.0.0.2", "mpls"},
	} {
		if got := CanonicalTunnelID(c[0], c[1], c[2], c[3]); got != "" {
			t.Errorf("CanonicalTunnelID%v = %q, want refusal", c, got)
		}
	}
}

func bfdChange(from, to string) StateChange {
	rec := StateRecord{EntityKey: "10.0.0.1-mpls-10.0.0.2-mpls-ipsec", StateKind: "bfd", DeviceID: "10.0.0.1",
		TunnelID: CanonicalTunnelID("10.0.0.1", "mpls", "10.0.0.2", "mpls"), PeerID: "10.0.0.2",
		LastSeen: time.Unix(1700000000, 0).UTC(), FlapCount: 1}
	return StateChange{Record: rec, From: from, To: to}
}

// A recovery is the engine's *_clear, never the fault kind: under the fault
// kind it joined the fault's node and kept a recovered tunnel looking failed.
func TestSDWANRecoveryIsAClearAndAFaultCarriesTheTunnel(t *testing.T) {
	spec := Specs()["vmanage"]
	evs := SDWANStateChangeEvents(spec, "t-a", "nmsi-1", []StateChange{bfdChange("up", "down"), bfdChange("down", "up")})
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	down, up := evs[0], evs[1]
	if down.NormalizedEventType != "controller_bfd_down" || down.Severity != "high" || down.EvidenceRole != RoleDiscriminating {
		t.Fatalf("fault: %+v", down)
	}
	if up.NormalizedEventType != "controller_bfd_down_clear" || up.Severity != "info" || up.EvidenceRole != RoleSupporting {
		t.Fatalf("recovery must be the clear kind at info: %+v", up)
	}
	if up.CorrelationHints["transition"] != "recovery" || down.CorrelationHints["transition"] != "fault" {
		t.Fatalf("transition hints: %v / %v", down.CorrelationHints, up.CorrelationHints)
	}
	for _, e := range evs {
		if e.TunnelID == "" || e.TunnelID != down.TunnelID || e.PeerID != "10.0.0.2" || e.CorrelationHints["tunnel_scheme"] != "tloc_pair" {
			t.Fatalf("path identity missing: %+v", e)
		}
	}
	if down.DedupeKey == up.DedupeKey {
		t.Fatal("the fault and its recovery must dedupe separately")
	}
	deg := SDWANStateChangeEvents(spec, "t-a", "nmsi-1", []StateChange{bfdChange("up", "yellow")})
	if len(deg) != 1 || deg[0].NormalizedEventType != "controller_bfd_down" || deg[0].Severity != "warn" {
		t.Fatalf("down-to-yellow stays a (warn) fault: %+v", deg)
	}
}

// Vendor and product name the maker the connector speaks for — never a
// hard-coded "cisco" on a Versa or Prime transition.
func TestSDWANTransitionVendorComesFromTheSpec(t *testing.T) {
	for conn, want := range map[string]string{"vmanage": "cisco", "prime": "cisco", "versa_director": "versa", "generic": ""} {
		spec := Specs()[conn]
		ch := bfdChange("up", "down")
		ch.Record.StateKind = "reachability"
		evs := SDWANStateChangeEvents(spec, "t-a", "i", []StateChange{ch})
		if len(evs) != 1 {
			t.Fatalf("%s: no event", conn)
		}
		if evs[0].Vendor != want || evs[0].Product != spec.Product || evs[0].SourceSystem != spec.SourceSystem {
			t.Errorf("%s: vendor=%q product=%q source=%q", conn, evs[0].Vendor, evs[0].Product, evs[0].SourceSystem)
		}
	}
}

func TestEverySpecDeclaresItsMakerOrIsGeneric(t *testing.T) {
	for id, s := range Specs() {
		if s.Maker == "" && id != "generic" {
			t.Errorf("connector %s has no Maker: its events would carry no vendor", id)
		}
	}
}

// A cleared vManage alarm is a recovery at info, deduped apart from the alarm.
func TestInactiveVManageAlarmIsAClear(t *testing.T) {
	raw := []byte(`{"data":[
	 {"uuid":"u-1","type":"bfd_session_down","component":"BFD","eventname":"bfd-state-change","severity":"Critical","rule_name_display":"BFD down","entry_time":1700000000000,"system_ip":"10.0.0.1","host_name":"e1","site_id":"10","active":true,"values":[]},
	 {"uuid":"u-1","type":"bfd_session_down","component":"BFD","eventname":"bfd-state-change","severity":"Critical","rule_name_display":"BFD down","entry_time":1700000060000,"system_ip":"10.0.0.1","host_name":"e1","site_id":"10","active":false,"values":[]}]}`)
	b, err := VManageTransformer{}.Transform("t-a", "nmsi-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 2 {
		t.Fatalf("want 2 events, got %d", len(b.Events))
	}
	act, clr := b.Events[0], b.Events[1]
	if strings.HasSuffix(act.NormalizedEventType, "_clear") || act.Severity != "crit" {
		t.Fatalf("active alarm: %+v", act)
	}
	if clr.NormalizedEventType != act.NormalizedEventType+"_clear" || clr.Severity != "info" || clr.EvidenceRole != RoleSupporting {
		t.Fatalf("a cleared Critical must not arrive as crit evidence: %+v", clr)
	}
	if clr.DedupeKey == act.DedupeKey {
		t.Fatal("the clear reused the alarm's dedupe key and would be dropped as a duplicate")
	}
}

// The far end resolves to its inventory id; the tunnel id stays native so the
// other end's report still matches it.
func TestCanonicalizeResolvesPeerButNeverTheTunnel(t *testing.T) {
	tid := CanonicalTunnelID("10.0.0.1", "mpls", "10.0.0.2", "mpls")
	b := Batch{Events: []ControllerEvent{{TenantID: "t-a", IntegrationID: "i", EventID: "e1",
		DeviceID: "10.0.0.1", PeerID: "10.0.0.2", TunnelID: tid}}}
	var names deviceNames
	out := canonicalize(&mapResolver{m: map[string]string{"t-a|10.0.0.1": "dev-a", "t-a|10.0.0.2": "dev-b"}}, KeySystemIP, &names, b)
	e := out.Events[0]
	if e.DeviceID != "dev-a" || e.PeerID != "dev-b" {
		t.Fatalf("device/peer not resolved: %+v", e)
	}
	if e.TunnelID != tid {
		t.Fatalf("tunnel id rewritten to %q", e.TunnelID)
	}
	if e.CorrelationHints["controller_peer_id"] != "10.0.0.2" || e.CorrelationHints["controller_device_id"] != "10.0.0.1" {
		t.Fatalf("native keys not kept: %v", e.CorrelationHints)
	}
}

func TestControllerInstanceIsTheControllerNotTheIntegration(t *testing.T) {
	spec := Specs()["vmanage"]
	a, basis, err := ControllerInstanceID(spec, "https://VManage.Example.com.:443/")
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := ControllerInstanceID(spec, "https://vmanage.example.com")
	if a == "" || a != b || basis != "host" {
		t.Fatalf("same controller, two spellings: %q %q (%s)", a, b, basis)
	}
	if c, _, _ := ControllerInstanceID(spec, "https://other.example.com"); c == a {
		t.Fatal("two controllers share an instance id")
	}
	if c, _, _ := ControllerInstanceID(Specs()["versa_director"], "https://vmanage.example.com"); c == a {
		t.Fatal("instance id must include the connector: a different product at one host is another controller")
	}
	for _, bad := range []string{"not a url", "https://", "://bad"} {
		if id, _, err := ControllerInstanceID(spec, bad); err == nil || id != "" {
			t.Fatalf("base URL %q: want an error and no id, got %q, %v", bad, id, err)
		}
	}
	if err := stampControllerInstance([]ControllerEvent{{EventID: "z"}}, spec, Integration{BaseURL: "https://"}); err == nil {
		t.Fatal("an underivable instance must be reported, not swallowed")
	}
	evs := []ControllerEvent{{EventID: "x", CorrelationHints: map[string]string{"k": "v"}}, {EventID: "y"}}
	shared := evs[0].CorrelationHints
	if err := stampControllerInstance(evs, spec, Integration{ID: "nmsi-1", BaseURL: "https://vmanage.example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.ControllerInstance != a || e.CorrelationHints["controller_instance_basis"] != "host" {
			t.Fatalf("not stamped: %+v", e)
		}
	}
	if _, leaked := shared["controller_instance_basis"]; leaked {
		t.Fatal("stamping mutated a hints map a transformer may share")
	}
}
