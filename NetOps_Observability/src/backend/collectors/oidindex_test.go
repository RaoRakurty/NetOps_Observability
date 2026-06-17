package collectors

import "testing"

// Locks the MIB-index contract: the seed must resolve the OIDs the old curated
// maps did (regression guard for the #26 cutover), enum-decode columns, handle the
// v1-form BGP trap OID, and leave un-vendored enterprise OIDs honestly raw.

func TestOIDIndex_SeedLoaded(t *testing.T) {
	if oidIndexVersion() == "" {
		t.Fatal("oid index version empty — embedded oididx.json failed to load")
	}
	if len(oidIdx.Nodes) == 0 {
		t.Fatal("oid index has no nodes")
	}
}

func TestLookupOID_ColumnPrefixAndScalar(t *testing.T) {
	// column: ifOperStatus.<ifIndex> resolves by longest-prefix, suffix = row index
	n, suffix, ok := lookupOID("1.3.6.1.2.1.2.2.1.8.7")
	if !ok || n.Name != "ifOperStatus" || suffix != "7" {
		t.Fatalf("ifOperStatus column lookup = %q suffix=%q ok=%v", n.Name, suffix, ok)
	}
	// scalar: exact match, no suffix
	s, suf, ok := lookupOID("1.3.6.1.2.1.1.5.0")
	if !ok || s.Name != "sysName" || suf != "" {
		t.Fatalf("sysName scalar lookup = %q suffix=%q ok=%v", s.Name, suf, ok)
	}
	// Arista BGP trap now decodes (ARISTA-BGP4V2-MIB vendored into the index)
	if a, _, ok := lookupOID("1.3.6.1.4.1.30065.4.1.0.2"); !ok || a.Name != "aristaBgp4V2BackwardTransitionNotification" {
		t.Fatalf("Arista BGP backward-transition trap = %q ok=%v, want aristaBgp4V2BackwardTransitionNotification", a.Name, ok)
	}
	// a genuinely un-vendored enterprise OID stays honestly unresolved (raw)
	if _, _, ok := lookupOID("1.3.6.1.4.1.99999.7.1"); ok {
		t.Fatal("expected un-vendored enterprise OID to be unresolved")
	}
}

func TestResolveVarbind_EnumDecode(t *testing.T) {
	name, disp := resolveVarbind("1.3.6.1.2.1.2.2.1.8.7", "2")
	if name != "ifOperStatus" || disp != "down(2)" {
		t.Fatalf("resolveVarbind ifOperStatus=2 → %q / %q, want ifOperStatus / down(2)", name, disp)
	}
	name, disp = resolveVarbind("1.3.6.1.2.1.15.3.1.2.10.0.0.5", "6")
	if name != "bgpPeerState" || disp != "established(6)" {
		t.Fatalf("resolveVarbind bgpPeerState=6 → %q / %q, want bgpPeerState / established(6)", name, disp)
	}
	if n, _ := resolveVarbind("1.3.6.1.4.1.99999.1", "x"); n != "" {
		t.Fatalf("unknown varbind OID should resolve to empty name, got %q", n)
	}
}

func TestDeriveEnvelope(t *testing.T) {
	// decoded Arista trap, inventory-matched → full envelope
	ev := &TrapEvent{TrapOID: "1.3.6.1.4.1.30065.4.1.0.2", TrapName: "aristaBgp4V2BackwardTransitionNotification", Device: "spine1", Host: "10.0.0.1"}
	deriveEnvelope(ev)
	if ev.Vendor != "arista" {
		t.Errorf("vendor = %q, want arista", ev.Vendor)
	}
	if ev.EventType != "arista_bgp4_v2_backward_transition" {
		t.Errorf("event_type = %q", ev.EventType)
	}
	if ev.ParserStatus != "decoded" || ev.EnrichmentStatus != "inventory_matched" {
		t.Errorf("status = %q/%q", ev.ParserStatus, ev.EnrichmentStatus)
	}
	if ev.MessageKey != "snmptrap:spine1:ARISTA-BGP4V2-MIB:arista_bgp4_v2_backward_transition" {
		t.Errorf("message_key = %q", ev.MessageKey)
	}
	// undecoded enterprise trap, no inventory match → honest raw_only / missing
	ev2 := &TrapEvent{TrapOID: "1.3.6.1.4.1.99999.1", TrapName: "enterpriseSpecific", Host: "10.0.0.9"}
	deriveEnvelope(ev2)
	if ev2.ParserStatus != "raw_only" || ev2.EnrichmentStatus != "inventory_missing" {
		t.Errorf("undecoded status = %q/%q, want raw_only/inventory_missing", ev2.ParserStatus, ev2.EnrichmentStatus)
	}
	if ev2.MessageKey != "snmptrap:10.0.0.9:enterprise_specific" {
		t.Errorf("undecoded message_key = %q", ev2.MessageKey)
	}
}

func TestTrapMeta_FromIndex(t *testing.T) {
	for _, tc := range []struct{ oid, name, sev string }{
		{"1.3.6.1.6.3.1.1.5.3", "linkDown", "warning"},
		{"1.3.6.1.2.1.15.0.2", "bgpBackwardTransition", "warning"}, // v1-form BGP
		{"1.3.6.1.2.1.15.7.1", "bgpEstablished", "info"},
		{"1.3.6.1.4.1.30065.4.1.0.2", "aristaBgp4V2BackwardTransitionNotification", "notice"}, // Arista MIB vendored
	} {
		name, sev := trapMeta(tc.oid)
		if name != tc.name || sev != tc.sev {
			t.Errorf("trapMeta(%s) = %q/%q, want %q/%q", tc.oid, name, sev, tc.name, tc.sev)
		}
	}
}
