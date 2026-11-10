// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func clause(syntax ...string) OIDNode {
	n := OIDNode{Kind: "column"}
	for i, s := range syntax {
		n.Index = append(n.Index, "c"+string(rune('a'+i)))
		n.IndexOIDs = append(n.IndexOIDs, "9.9."+string(rune('1'+i)))
		n.IndexSyntax = append(n.IndexSyntax, s)
	}
	return n
}

func TestDecodeTrapIndex_Values(t *testing.T) {
	v6 := "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	cases := []struct {
		node   OIDNode
		suffix string
		want   []string // Text of each part; nil = must fail
	}{
		{clause("ipv4"), "192.168.200.34", []string{"192.168.200.34"}},
		{clause("ipv4"), "192.168.200", nil},
		{clause("ipv4"), "192.168.200.34.1", nil},
		{clause("ipv4"), "192.168.300.34", nil},
		{clause("int"), "7", []string{"7"}},
		{clause("int"), "4294967296", nil},
		{clause("inet_type", "inet_address"), "1.4.10.0.0.1", []string{"ipv4", "10.0.0.1"}},
		{clause("inet_type", "inet_address"), "2.16." + v6, []string{"ipv6", "2001:db8::1"}},
		{clause("inet_type", "inet_address"), "3.8.10.0.0.1.0.0.0.5", []string{"ipv4z", "10.0.0.1%5"}},
		{clause("inet_type", "inet_address"), "4.20." + v6 + ".0.0.1.0", []string{"ipv6z", "2001:db8::1%256"}},
		{clause("inet_type", "inet_address"), "16.3.97.98.99", []string{"dns", "abc"}},
		{clause("inet_type", "inet_address"), "0.0", []string{"unknown", ""}},
		{clause("inet_type", "inet_address"), "1.16." + v6, nil}, // ipv4 cannot be 16 octets
		{clause("inet_type", "inet_address"), "2.4.10.0.0.1", nil},
		{clause("inet_type", "inet_address"), "5.4.10.0.0.1", nil}, // no such type
		{clause("inet_type", "inet_address"), "1.4.10.0.0", nil},
		{clause("int", "inet_type", "inet_address"), "3.1.4.10.0.0.1", []string{"3", "ipv4", "10.0.0.1"}},
		{clause("string"), "3.97.98.99", []string{"abc"}},
		{clause("fixed:6"), "0.17.34.51.68.85", []string{"0x001122334455"}},
		{clause("fixed:4"), "10.0.0.9", []string{"10.0.0.9"}},
		{clause("unknown"), "1", nil},
		{clause("ipv4"), "", nil},
		{clause("ipv4"), "1..2.3", nil},
		{clause("ipv4"), "a.b.c.d", nil},
	}
	for _, c := range cases {
		parts, err := decodeTrapIndex(c.node, c.suffix)
		if c.want == nil {
			if err == nil {
				t.Errorf("%v %q: decoded %+v, want an error", c.node.IndexSyntax, c.suffix, parts)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v %q: %v", c.node.IndexSyntax, c.suffix, err)
			continue
		}
		var got []string
		for _, p := range parts {
			got = append(got, p.Text)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v %q: got %v, want %v", c.node.IndexSyntax, c.suffix, got, c.want)
		}
	}
	// IMPLIED: the last string takes every remaining arc, with no length arc.
	n := clause("int", "string")
	n.IndexImplied = true
	parts, err := decodeTrapIndex(n, "1.97.98")
	if err != nil || parts[1].Text != "ab" {
		t.Errorf("implied: %+v %v", parts, err)
	}
	// A clause the index lists inconsistently decodes nothing.
	bad := clause("ipv4")
	bad.IndexOIDs = nil
	if _, err := decodeTrapIndex(bad, "10.0.0.1"); err == nil {
		t.Error("an inconsistent clause must not decode")
	}
}

func TestDecodeBareAddressIndex(t *testing.T) {
	for suffix, want := range map[string]string{
		"192.168.200.34":                      "192.168.200.34",
		"32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1": "2001:db8::1",
		"1.4.10.0.0.1":                        "", // the MIB's own form is not bare
		"10.0.0":                              "",
		"10.0.0.256":                          "",
	} {
		got, _, err := decodeBareAddressIndex(suffix)
		if (err != nil) != (want == "") || got != want {
			t.Errorf("%q: got %q %v, want %q", suffix, got, err, want)
		}
	}
}

// The checked-in OID index carries the INDEX clauses a trap needs (gen_index.py
// INDEX_ASSERTIONS mirrors this).
func TestOIDIndex_CarriesTheBGPIndexClauses(t *testing.T) {
	cases := map[string][]string{
		"1.3.6.1.2.1.15.3.1.2":               {"ipv4"},                                                          // bgpPeerState
		"1.3.6.1.4.1.9.9.187.1.2.1.1.8":      {"ipv4"},                                                          // cbgpPeerPrevState (AUGMENTS bgpPeerEntry)
		"1.3.6.1.4.1.9.9.187.1.2.5.1.3":      {"inet_type", "inet_address"},                                     // cbgpPeer2State
		"1.3.6.1.4.1.30065.4.1.1.2.1.13":     {"int", "inet_type", "inet_address"},                              // aristaBgp4V2PeerState
		"1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2":   {"int", "inet_type", "inet_address", "inet_type", "inet_address"}, // jnxBgpM2PeerState
		"1.3.6.1.4.1.6527.3.1.2.14.4.7.1.59": {"int", "inet_type", "inet_address"},                              // tBgpPeerNgConnState
		"1.3.6.1.2.1.2.2.1.8":                {"int"},                                                           // ifOperStatus
	}
	for oid, want := range cases {
		n, ok := oidIdx.Nodes[oid]
		if !ok || !reflect.DeepEqual(n.IndexSyntax, want) || len(n.IndexOIDs) != len(want) {
			t.Errorf("%s (%s): index %v %v, want %v", oid, n.Name, n.IndexSyntax, n.IndexOIDs, want)
		}
	}
}

func TestClassifyBGPTransition_PinnedForBothSides(t *testing.T) {
	b, err := os.ReadFile("testdata/bgp_transition_classes.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rows []struct{ Prev, State, Class string } `json:"rows"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) != 42 {
		t.Fatalf("rows %d", len(doc.Rows))
	}
	for _, r := range doc.Rows {
		if got := classifyBGPTransition(r.Prev, r.State); got != r.Class {
			t.Errorf("%q -> %q: %q, want %q", r.Prev, r.State, got, r.Class)
		}
	}
	// The owner's rule, said plainly.
	if classifyBGPTransition("active", "idle") == bgpSessionLost || classifyBGPTransition("idle", "active") == bgpSessionLost {
		t.Error("an oscillation below established is never a session failure")
	}
}

func TestNormalizeBGPState(t *testing.T) {
	for _, c := range []struct{ label, raw, want string }{
		{"active", "3", "active"}, {"", "6", "established"}, {"", "idle(1)", "idle"},
		{"none", "0", ""}, {"clearing", "6", ""}, {"", "7", ""}, {"", "0", ""},
		// VIPTELA numbers from 0: a label is always read by its word.
		{"established", "5", "established"},
	} {
		if got := normalizeBGPState(c.label, c.raw); got != c.want {
			t.Errorf("%q/%q: %q, want %q", c.label, c.raw, got, c.want)
		}
	}
}

func TestBGPLastError(t *testing.T) {
	for raw, want := range map[string]string{
		"0x0400": "Hold Timer Expired", "0x0602": "Cease / Administrative Shutdown",
		"0x0202": "OPEN Message Error / Bad Peer AS", "0x0663": "Cease / subcode 99",
		"0x0900": "error code 9", "0x0000": "",
	} {
		code, sub, ok := parseBGPLastError(raw)
		if !ok {
			t.Fatalf("%s did not parse", raw)
		}
		if got := bgpErrorName(code, sub); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
	for _, bad := range []string{"0x04", "0x040000", "1024", "0xZZZZ", ""} {
		if _, _, ok := parseBGPLastError(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestRenderTitleTemplate(t *testing.T) {
	vals := map[string]string{"device": "cEDGE-81", "peer": "10.0.0.1", "state": "Active", "condition": "raised"}
	for _, c := range []struct{ tpl, want string }{
		{"BGP neighbour {peer}[ (AS {peer_as})] on {device}", "BGP neighbour 10.0.0.1 on cEDGE-81"},
		{"{peer} [AS {peer_as}]x", "10.0.0.1 x"},
		{"{missing} on {device}", ""},
		{"{condition=raised}up on {device}", "up on cEDGE-81"},
		{"{condition=cleared}down on {device}", ""},
		{"a[ b{condition=cleared}] c", "a c"},
		{"[{peer_as}]", ""},
	} {
		got, ok := renderTitleTemplate(c.tpl, vals)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%q: %q %v, want %q", c.tpl, got, ok, c.want)
		}
	}
	for _, bad := range []string{"[a[b]]", "a]", "{a", "a}", "{a[b]}", "  "} {
		if compileTitleTemplate(bad) == nil {
			t.Errorf("%q must not compile", bad)
		}
	}
	if got := titleValue("a\nb\x00c" + strings.Repeat("x", 200)); strings.ContainsAny(got, "\n\x00") || len([]rune(got)) > 96 {
		t.Errorf("titleValue %q", got)
	}
}

func TestCompileTrapPackData_SemanticSectionsAreStrict(t *testing.T) {
	base := `{"schema":1,"pack":"p","source":"s","objects":%s,"notifications":{}%s}`
	for name, c := range map[string][2]string{
		"unknown attr":           {`{"1.2":{"name":"x","attr":"peer_colour"}}`, ``},
		"extract field":          {`{"1.2":{"name":"x","extract":[{"pattern":"(\\d+)","field":"anything"}]}}`, ``},
		"extract without group":  {`{"1.2":{"name":"x","extract":[{"pattern":"\\d+","field":"threshold_reported_percent"}]}}`, ``},
		"bad template":           {`{}`, `,"title_templates":{"k":["{a"]}`},
		"empty wording":          {`{}`, `,"title_templates":{"k":[]}`},
		"title names no wording": {`{}`, `,"titles":{"1.2":{"name":"n","template":"none"}}`},
		"derived op":             {`{}`, `,"derived":[{"field":"a","op":"sum","of":"b","base":1,"formula":"f"}]}`},
		"guidance empty":         {`{}`, `,"guidance":{"cpu":{"impact":[],"next_checks":["x"]}}`},
		"table without fidelity": {`{}`, `,"tables":{"1.2":{"name":"t","bare_address_index":true}}`},
		"unknown key":            {`{}`, `,"wording":{}`},
	} {
		raw := []byte(strings.Replace(strings.Replace(base, "%s", c[0], 1), "%s", c[1], 1))
		if _, err := compileTrapPackData(raw); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

func TestTrapPacks_EveryTitleAndTableNamesWhatTheIndexSays(t *testing.T) {
	sem, err := compileTrapPacks(trapPackFS, "mibs/packs")
	if err != nil {
		t.Fatal(err)
	}
	if len(sem.titles) < 39 {
		t.Errorf("only %d titled notifications", len(sem.titles))
	}
	for oid, r := range sem.titles {
		n, ok := oidIdx.Nodes[oid]
		if !ok || n.Name != r.Name || n.Kind != "notification" {
			t.Errorf("title %s: pack says %q, index says %+v", oid, r.Name, n)
		}
	}
	for oid, r := range sem.tables {
		if n, ok := oidIdx.Nodes[oid]; !ok || n.Name != r.Name {
			t.Errorf("table %s: pack says %q, index says %+v", oid, r.Name, n)
		}
	}
	for fam, g := range sem.guidance {
		for _, s := range append(append([]string{}, g.Impact...), g.NextChecks...) {
			low := strings.ToLower(s)
			for _, claim := range []string{"root cause", "is caused by", "the cause is"} {
				if strings.Contains(low, claim) {
					t.Errorf("guidance %s presents a diagnosis: %q", fam, s)
				}
			}
		}
	}
}

func TestTrapTransitions_BoundsAndScope(t *testing.T) {
	tg := newTrapTransitions(3)
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	mk := func(dev, peer, state, prev string, at time.Duration) *TrapEvent {
		ev := &TrapEvent{Device: dev, Family: "bgp", BGP: &TrapBGP{PeerAddress: peer, PeerAFI: "ipv4", State: state}}
		if prev != "" {
			ev.BGP.PrevState, ev.BGP.PrevStateBasis = prev, bgpPrevFromTrap
		}
		ev.CorrelationKey = correlationKey(ev)
		tg.observeTransition(ev, t0.Add(at))
		return ev
	}
	for i := 0; i < 10; i++ {
		mk("d", "10.0.0."+string(rune('0'+i)), "idle", "active", 0)
	}
	if tg.Len() != 3 {
		t.Errorf("bounded: %d", tg.Len())
	}
	a := mk("d", "10.9.9.9", "idle", "active", 0)
	b := mk("d", "10.9.9.9", "idle", "", 4*time.Second)
	eq(t, "inside the window", b.TransitionID, a.TransitionID)
	c := mk("d", "10.9.9.9", "idle", "", 6*time.Second)
	if c.TransitionID == a.TransitionID {
		t.Error("past the window is a new transition")
	}
	// A different device never shares a group or a history.
	other := mk("e", "10.9.9.9", "idle", "", 6*time.Second)
	if other.TransitionID == c.TransitionID || other.BGP.PrevState != "" {
		t.Errorf("cross-device leak: %+v", other.BGP)
	}
	// Unattributed: no key, no group.
	u := mk("", "10.9.9.9", "idle", "", 0)
	if u.CorrelationKey != "" || u.TransitionID != "" {
		t.Errorf("unattributed trap keyed: %q %q", u.CorrelationKey, u.TransitionID)
	}
	// History older than the horizon is not used.
	h := newTrapTransitions(0)
	ev1 := &TrapEvent{Device: "d", Family: "bgp", BGP: &TrapBGP{PeerAddress: "1.1.1.1", PeerAFI: "ipv4", State: "active", PrevState: "idle", PrevStateBasis: bgpPrevFromTrap}}
	ev1.CorrelationKey = correlationKey(ev1)
	h.observeTransition(ev1, t0)
	ev2 := &TrapEvent{Device: "d", Family: "bgp", BGP: &TrapBGP{PeerAddress: "1.1.1.1", PeerAFI: "ipv4", State: "idle"}}
	ev2.CorrelationKey = correlationKey(ev2)
	h.observeTransition(ev2, t0.Add(peerHistoryHorizon+time.Minute))
	eq(t, "stale history", ev2.BGP.PrevState, "")
	// A different sysUpTime inside the window is a different event.
	k := newTrapTransitions(0)
	e1 := &TrapEvent{Device: "d", Family: "bgp", UptimeSeconds: 100, BGP: &TrapBGP{PeerAddress: "1.1.1.1", PeerAFI: "ipv4", State: "idle"}}
	e1.CorrelationKey = correlationKey(e1)
	k.observeTransition(e1, t0)
	e2 := &TrapEvent{Device: "d", Family: "bgp", UptimeSeconds: 110, BGP: &TrapBGP{PeerAddress: "1.1.1.1", PeerAFI: "ipv4", State: "idle"}}
	e2.CorrelationKey = correlationKey(e2)
	k.observeTransition(e2, t0.Add(time.Second))
	if e1.TransitionID == e2.TransitionID {
		t.Error("10 s of device uptime apart is not one transition")
	}
}

func TestTrapReceiver_DeviceNameFromInventory(t *testing.T) {
	r := &trapReceiver{targets: func() []Target {
		return []Target{{ID: "vedge-51-0a0b4db5", Name: "vEdge-51"}, {ID: "plain", Name: "plain"}}
	}}
	eq(t, "named", r.deviceName("vedge-51-0a0b4db5"), "vEdge-51")
	eq(t, "named only by id", r.deviceName("plain"), "")
	eq(t, "unknown", r.deviceName("nope"), "")
	eq(t, "empty", r.deviceName(""), "")
}
