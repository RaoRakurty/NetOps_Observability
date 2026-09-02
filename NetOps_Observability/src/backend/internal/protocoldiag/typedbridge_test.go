package protocoldiag

// typedbridge_test.go — the typed-first / regex-fallback proofs.
//
// Two things must hold at once and they pull in opposite directions:
//
//	1. every EXISTING signature verdict is unchanged (analyze_test.go is the
//	   authority and stays green untouched — this file adds the cases that
//	   distinguish the two paths);
//	2. on a platform whose summary parses, a verdict is decided by the FIELD, so
//	   the word "Idle" or "Active" appearing elsewhere in the capture can no
//	   longer fire it.

import (
	"strings"
	"testing"

	"netops/backend/internal/showparse"
)

// bgpCollection builds a bgp-session-down Collection for a device platform with
// the given per-spec outputs.
func bgpCollection(t *testing.T, platform string, outputs map[string]string) *Collection {
	t.Helper()
	dev := Device{ID: "dev-1", Hostname: "core-01", Platform: platform, TenantID: "acme"}
	return collectFor(t, DefaultCatalog(), dev, stdTarget, "bgp-session-down", outputs)
}

// TestTypedBridge_DialectResolution proves the bridge reads the PLATFORM, not
// the catalog's collapsed three-value Vendor — an NX-OS capture must not be
// handed to the IOS-XE parser.
func TestTypedBridge_DialectResolution(t *testing.T) {
	cases := []struct {
		platform string
		want     showparse.Dialect
		ok       bool
	}{
		{"Cisco IOS-XE 17.9", showparse.DialectCiscoIOSXE, true},
		{"Cisco NX-OS 10.2", showparse.DialectCiscoNXOS, true},
		{"Arista EOS 4.30.2F", showparse.DialectAristaEOS, true},
		{"Acme MysteryOS", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		col := &Collection{Platform: tc.platform}
		got, ok := collectionDialect(col)
		if got != tc.want || ok != tc.ok {
			t.Errorf("collectionDialect(%q) = (%q,%v), want (%q,%v)", tc.platform, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := collectionDialect(nil); ok {
		t.Error("a nil collection must not resolve to a dialect")
	}
}

// TestTypedBridge_FiresOnTheField is the headline gain: a capture in which the
// word "Idle" appears ONLY outside the state column must NOT fire the
// idle-unreachable verdict, even though the old regex would have matched it.
func TestTypedBridge_FiresOnTheField(t *testing.T) {
	an := DefaultAnalyzer()

	// A healthy, Established session whose neighbour DESCRIPTION contains the
	// word "idle" — the classic false tell.
	decoy := `BGP router identifier 10.255.0.1, local AS number 65001
Description for 10.0.0.2: backup link, idle most of the day

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65002    1234    1235     1234    0    0 02:31:11       12
`
	col := bgpCollection(t, "Cisco IOS-XE 17.9", map[string]string{
		"bgp-summary":    decoy,
		"bgp-peer-route": "% Network not in table",
	})
	res := an.Analyze(col)
	if hasFinding(res, "bgp-idle-unreachable") {
		t.Error("the typed path fired on the word 'idle' outside the state column")
	}

	// The same shape for Active/Connect: "Active Route" prose in the capture.
	decoy2 := `Active Route legend: * = best
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65002    1234    1235     1234    0    0 02:31:11       12
`
	col = bgpCollection(t, "Cisco IOS-XE 17.9", map[string]string{
		"bgp-summary":    decoy2,
		"bgp-peer-route": "O 10.0.0.2/32 [110/2] via 10.0.0.1, 00:10:00, GigabitEthernet0/0",
	})
	if hasFinding(an.Analyze(col), "bgp-tcp-blocked") {
		t.Error("the typed path fired on the words 'Active Route' outside the state column")
	}
}

// TestTypedBridge_StillFiresOnRealState proves the tightening did not cost a
// true positive: a genuinely Idle / Active row still fires, on every dialect
// whose summary the library parses.
func TestTypedBridge_StillFiresOnRealState(t *testing.T) {
	an := DefaultAnalyzer()
	cases := []struct {
		name     string
		platform string
		summary  string
		route    string
		wantSig  string
	}{
		{
			name: "cisco idle, peer unreachable", platform: "Cisco IOS-XE 17.9",
			summary: "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
				"10.0.0.2        4        65002       0       0        1    0    0 never    Idle\n",
			route: "% Network not in table", wantSig: "bgp-idle-unreachable",
		},
		{
			name: "cisco active, peer reachable", platform: "Cisco IOS-XE 17.9",
			summary: "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
				"10.0.0.2        4        65002       0       0        1    0    0 00:00:12 Active\n",
			route:   "O 10.0.0.2/32 [110/2] via 10.0.0.1, 00:10:00, GigabitEthernet0/0",
			wantSig: "bgp-tcp-blocked",
		},
		{
			name: "nxos idle", platform: "Cisco NX-OS 10.2",
			summary: "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
				"10.0.0.2        4 65002       0       0        1    0    0 never    Idle\n",
			route: "% Network not in table", wantSig: "bgp-idle-unreachable",
		},
		{
			name: "arista idle with a zero prefix count", platform: "Arista EOS 4.30.2F",
			summary: "Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc\n" +
				"10.0.0.2         4  65002              0         0    0    0 00:00:00 Idle    0      0\n",
			route: "% Network not in table", wantSig: "bgp-idle-unreachable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			col := bgpCollection(t, tc.platform, map[string]string{
				"bgp-summary": tc.summary, "bgp-peer-route": tc.route,
			})
			res := an.Analyze(col)
			if !hasFinding(res, tc.wantSig) {
				t.Fatalf("want %s, got %v", tc.wantSig, findingIDs(res))
			}
			for _, f := range res.Findings {
				if f.SignatureID != tc.wantSig {
					continue
				}
				if f.Evidence.Line == "" {
					t.Error("a typed finding must still cite the device's own line")
				}
				if !strings.Contains(f.Evidence.Line, "10.0.0.2") {
					t.Errorf("the cited line is not the peer row: %q", f.Evidence.Line)
				}
			}
		})
	}
}

// TestTypedBridge_FallsBackWhenUnparseable proves the fallback: on a platform we
// cannot resolve (or a layout we cannot parse) the regex matcher still decides,
// so no device becomes LESS diagnosable than it was before the bridge.
func TestTypedBridge_FallsBackWhenUnparseable(t *testing.T) {
	an := DefaultAnalyzer()
	// An unassessed platform: no dialect ⇒ no typed view ⇒ regex path.
	col := bgpCollection(t, "Acme MysteryOS 1.0", map[string]string{
		"bgp-summary":    "peer 10.0.0.2 state Idle",
		"bgp-peer-route": "% Network not in table",
	})
	if !hasFinding(an.Analyze(col), "bgp-idle-unreachable") {
		t.Error("the regex fallback did not fire on an unassessed platform")
	}
	// A known platform whose summary layout the parser does not recognize.
	col = bgpCollection(t, "Cisco IOS-XE 17.9", map[string]string{
		"bgp-summary":    "BGP neighbor 10.0.0.2 is in state Idle (no summary table captured)",
		"bgp-peer-route": "% Network not in table",
	})
	if !hasFinding(an.Analyze(col), "bgp-idle-unreachable") {
		t.Error("the regex fallback did not fire on an unrecognized layout")
	}
}

// TestTypedBridge_TypedRefusalDoesNotFallBack proves the third arm of the
// contract: when the parser HAS answered and no row matches, the regex must NOT
// get a second chance to fire on a stray word.
func TestTypedBridge_TypedRefusalDoesNotFallBack(t *testing.T) {
	col := bgpCollection(t, "Cisco IOS-XE 17.9", map[string]string{
		"bgp-summary": "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
			"10.0.0.2        4        65002    1234    1235     1234    0    0 02:31:11       12\n" +
			"note: this session was Idle earlier today\n",
		"bgp-peer-route": "% Network not in table",
	})
	_, fired, typed := typedBGPStateEvidence(col, "bgp-summary", bgpStateIs("Idle"))
	if !typed {
		t.Fatal("the capture should have produced a typed view")
	}
	if fired {
		t.Fatal("no peer row is Idle — the typed path must refuse")
	}
	if hasFinding(DefaultAnalyzer().Analyze(col), "bgp-idle-unreachable") {
		t.Error("the regex fired after the typed path had already refused")
	}
}

// TestTypedBridge_NoOutputNoVerdict keeps the fail-closed property: a command
// that errored is absent output and can never produce a typed row.
func TestTypedBridge_NoOutputNoVerdict(t *testing.T) {
	col := bgpCollection(t, "Cisco IOS-XE 17.9", map[string]string{})
	col.Commands[0].Err = "connect: connection refused"
	if _, ok := typedBGPPeers(col, "bgp-summary"); ok {
		t.Error("an errored command must not yield typed rows")
	}
	if _, _, typed := typedBGPStateEvidence(col, "no-such-spec", bgpStateIs("Idle")); typed {
		t.Error("an unknown spec id must not yield a typed view")
	}
}

// TestBGPStateIs_NormalizedVocabulary proves a caller names a state once and
// gets every dialect's spelling of it.
func TestBGPStateIs_NormalizedVocabulary(t *testing.T) {
	want := bgpStateIs("Established")
	for _, s := range []string{"Established", "established", "Estab", "Establ"} {
		peers, err := showparse.Parse(showparse.CmdBGPSummary, showparse.DialectAristaEOS,
			"Neighbor         V  AS           MsgRcvd   MsgSent  InQ OutQ  Up/Down State   PfxRcd PfxAcc\n"+
				"10.0.0.2         4  65002           1234      1235    0    0 02:31:11 "+s+"   12     12\n")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(peers.BGPPeers) != 1 {
			t.Fatalf("%q: got %d peers", s, len(peers.BGPPeers))
		}
		if !want(peers.BGPPeers[0]) {
			t.Errorf("%q did not normalize onto Established (got %q)", s, peers.BGPPeers[0].State)
		}
	}
	if bgpStateIs("Idle")(showparse.BGPPeer{State: "Established"}) {
		t.Error("bgpStateIs matched the wrong state")
	}
}
