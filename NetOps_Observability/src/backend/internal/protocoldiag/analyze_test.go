// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"context"
	"strings"
	"testing"
)

// Representative (Cisco IOS-XE) output fixtures, keyed by spec id.

// TestAnalyze_PerIssueSignatures drives every issue with a collected-output
// fixture that trips its signature and asserts the verdict + remediation.
func TestAnalyze_PerIssueSignatures(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()

	cases := []struct {
		name     string
		issue    string
		outputs  map[string]string
		wantSig  string
		wantConf Confidence
	}{
		{
			name:  "ospf EXSTART + interface MTU (multi-condition, high)",
			issue: "ospf-neighbor-stuck",
			outputs: map[string]string{
				"ospf-neighbor":  "Neighbor ID    Pri State        Dead Time Address    Interface\n10.0.0.2         1 EXSTART/DR   00:00:35  10.0.0.2   GigabitEthernet0/0",
				"ospf-interface": "GigabitEthernet0/0 is up, line protocol is up\n  Internet Address 10.0.0.1/30, Area 0\n  Network Type BROADCAST, Cost: 1\n  MTU is 1500 bytes",
			},
			wantSig: "ospf-exstart-mtu", wantConf: ConfidenceHigh,
		},
		{
			name:  "ospf EXSTART without interface MTU (medium)",
			issue: "ospf-neighbor-stuck",
			outputs: map[string]string{
				"ospf-neighbor": "10.0.0.2  1 EXSTART/DR  00:00:35 10.0.0.2 Gi0/0",
			},
			wantSig: "ospf-exstart-only", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf INIT one-way",
			issue: "ospf-neighbor-stuck",
			outputs: map[string]string{
				"ospf-neighbor": "10.0.0.2  1 INIT/DROTHER 00:00:31 10.0.0.2 Gi0/0",
			},
			wantSig: "ospf-init-oneway", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf parameter mismatch",
			issue: "ospf-adjacency-nonform",
			outputs: map[string]string{
				"ospf-logging": "Aug 27 12:00:01: %OSPF-4-ERRRCV: Received invalid packet: mismatched area ID from 10.0.0.2 on Gi0/0",
			},
			wantSig: "ospf-param-mismatch", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf stub area filters externals",
			issue: "ospf-routes-missing",
			outputs: map[string]string{
				"ospf-summary": "Area 10\n  Number of interfaces in this area is 2\n  It is a stub area",
			},
			wantSig: "ospf-stub-area", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf max-metric stub-router",
			issue: "ospf-routes-missing",
			outputs: map[string]string{
				"ospf-summary": "Originating router-LSAs with maximum metric",
			},
			wantSig: "ospf-max-metric", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf flapping driven by L1 errors (multi, high)",
			issue: "ospf-flapping",
			outputs: map[string]string{
				"ospf-logging": "%OSPF-5-ADJCHG: from FULL to DOWN\n%OSPF-5-ADJCHG: from DOWN to FULL\n%OSPF-5-ADJCHG: from FULL to DOWN",
				"iface":        "GigabitEthernet0/0 is up\n  12345 input errors, 200 CRC, 0 frame",
			},
			wantSig: "ospf-flap-l1", wantConf: ConfidenceHigh,
		},
		{
			name:  "ospf flapping, no L1 error captured (medium)",
			issue: "ospf-flapping",
			outputs: map[string]string{
				"ospf-logging": "%OSPF-5-ADJCHG: from FULL to DOWN\n%OSPF-5-ADJCHG: from DOWN to FULL\n%OSPF-5-ADJCHG: from FULL to DOWN",
				"iface":        "GigabitEthernet0/0 is up\n  0 input errors, 0 CRC, 0 frame",
			},
			wantSig: "ospf-flap", wantConf: ConfidenceMedium,
		},
		{
			name:  "ospf reference-bandwidth default",
			issue: "ospf-suboptimal",
			outputs: map[string]string{
				"ospf-summary": "Routing Process \"ospf 1\"\n  Reference bandwidth unit is 100 mbps",
			},
			wantSig: "ospf-refbw-default", wantConf: ConfidenceMedium,
		},

		{
			name:  "bgp Idle + peer unreachable (multi, high)",
			issue: "bgp-session-down",
			outputs: map[string]string{
				"bgp-summary":    "Neighbor    V   AS MsgRcvd MsgSent Up/Down State/PfxRcd\n10.0.0.2    4 65002       0       0 never   Idle",
				"bgp-peer-route": "% Network not in table",
			},
			wantSig: "bgp-idle-unreachable", wantConf: ConfidenceHigh,
		},
		{
			name:  "bgp Active + peer reachable => TCP/179 blocked (multi, high)",
			issue: "bgp-session-down",
			outputs: map[string]string{
				"bgp-summary":    "10.0.0.2    4 65002 0 0 never Active",
				"bgp-peer-route": "O 10.0.0.2/32 [110/2] via 10.0.0.1, 00:10:00, GigabitEthernet0/0",
			},
			wantSig: "bgp-tcp-blocked", wantConf: ConfidenceHigh,
		},
		{
			name:  "bgp neighbor administratively shut",
			issue: "bgp-session-down",
			outputs: map[string]string{
				"bgp-neighbor": "BGP neighbor is 10.0.0.2, remote AS 65002\n  BGP state = Idle (Admin), administratively shut down",
			},
			wantSig: "bgp-admin-shut", wantConf: ConfidenceMedium,
		},
		{
			name:  "bgp nothing advertised",
			issue: "bgp-prefix-not-exchanged",
			outputs: map[string]string{
				"bgp-advertised": "Total number of prefixes 0",
			},
			wantSig: "bgp-nothing-advertised", wantConf: ConfidenceMedium,
		},
		{
			name:  "bgp next-hop inaccessible",
			issue: "bgp-route-not-best",
			outputs: map[string]string{
				"bgp-prefix": "BGP routing table entry for 192.0.2.0/24\n  100 200\n    10.9.9.9 (inaccessible) from 10.0.0.2 (10.0.0.2)",
			},
			wantSig: "bgp-nexthop-inaccessible", wantConf: ConfidenceHigh,
		},
		{
			name:  "bgp session flapped",
			issue: "bgp-flapping",
			outputs: map[string]string{
				"bgp-neighbor": "  Connections established 6; dropped 5\n  Last reset 00:00:20, due to BGP Notification",
			},
			wantSig: "bgp-session-flapped", wantConf: ConfidenceMedium,
		},
		{
			name:  "bgp route dampened",
			issue: "bgp-flapping",
			outputs: map[string]string{
				"bgp-dampening": "192.0.2.0/24  10.0.0.2  suppressed  00:30:00",
			},
			wantSig: "bgp-dampened", wantConf: ConfidenceMedium,
		},
		{
			name:  "bgp no-export community",
			issue: "bgp-wrong-path",
			outputs: map[string]string{
				"bgp-prefix": "  100 200\n    Community: no-export 65000:100",
			},
			wantSig: "bgp-community-no-export", wantConf: ConfidenceMedium,
		},

		{
			name:  "isis adjacency not up",
			issue: "isis-adjacency-down",
			outputs: map[string]string{
				"isis-neighbors": "System Id  Type Interface  IP Address  State Holdtime Circuit Id\nR2         L2   Gi0/0      10.0.0.2    Init  27       01",
			},
			wantSig: "isis-adjacency-not-up", wantConf: ConfidenceMedium,
		},
		{
			name:  "isis stuck in INIT",
			issue: "isis-adjacency-init",
			outputs: map[string]string{
				"clns-neighbors-detail": "System Id: R2\n  Interface: Gi0/0, State: Init, Type: L2",
			},
			wantSig: "isis-init-stuck", wantConf: ConfidenceMedium,
		},
		{
			name:  "isis overload bit -> routes missing",
			issue: "isis-routes-missing",
			outputs: map[string]string{
				"isis-database": "R1.00-00  * 0x0000000A  0xABCD  1199  1/0/1  LSP set with overload bit",
			},
			wantSig: "isis-overload-routes", wantConf: ConfidenceMedium,
		},
		{
			name:  "isis adjacency flapping",
			issue: "isis-flapping",
			outputs: map[string]string{
				"isis-logging": "%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 Up\n%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 Down\n%CLNS-5-ADJCHANGE: ISIS: Adjacency to R2 Up",
			},
			wantSig: "isis-adjacency-flap", wantConf: ConfidenceMedium,
		},
		{
			name:  "isis narrow metric-style",
			issue: "isis-overload-suboptimal",
			outputs: map[string]string{
				"isis-summary": "IS-IS Router: null\n  Metric-style: narrow",
			},
			wantSig: "isis-narrow-metric", wantConf: ConfidenceMedium,
		},
		{
			name:  "isis overload bit -> suboptimal",
			issue: "isis-overload-suboptimal",
			outputs: map[string]string{
				"isis-database-detail": "R1.00-00  LSP is set with overload bit",
			},
			wantSig: "isis-overload-suboptimal", wantConf: ConfidenceMedium,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			col := collectFor(t, cat, ciscoDev, stdTarget, tc.issue, tc.outputs)
			res := an.Analyze(col)
			if !hasFinding(res, tc.wantSig) {
				t.Fatalf("signature %q did not fire; fired: %v", tc.wantSig, findingIDs(res))
			}
			for _, f := range res.Findings {
				if f.SignatureID != tc.wantSig {
					continue
				}
				if f.Confidence != tc.wantConf {
					t.Errorf("%s confidence = %q, want %q", tc.wantSig, f.Confidence, tc.wantConf)
				}
				if f.Remediation == "" || f.Verdict == "" || f.Cause == "" {
					t.Errorf("%s missing verdict/cause/remediation", tc.wantSig)
				}
				if f.Evidence.Line == "" {
					t.Errorf("%s fired with no evidence line", tc.wantSig)
				}
			}
		})
	}
}

// TestAnalyze_FailClosed drives every issue with benign, healthy output and
// asserts NOTHING fires — the honest "raw output for TAC" message is set, no
// cause invented.
func TestAnalyze_FailClosed(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()

	benign := map[string]map[string]string{
		"ospf-neighbor-stuck": {
			"ospf-neighbor":  "10.0.0.2  1 FULL/DR 00:00:35 10.0.0.2 Gi0/0",
			"ospf-interface": "GigabitEthernet0/0 is up\n  MTU is 1500 bytes",
		},
		"ospf-adjacency-nonform": {"ospf-logging": "%OSPF-5-ADJCHG: from LOADING to FULL"},
		"ospf-routes-missing":    {"ospf-summary": "It is an area border router\n  Normal area"},
		"ospf-flapping":          {"ospf-logging": "%OSPF-5-ADJCHG: from LOADING to FULL"},
		"ospf-suboptimal":        {"ospf-summary": "  Reference bandwidth unit is 100000 mbps"},
		"bgp-session-down": {
			"bgp-summary":    "10.0.0.2 4 65002 100 100 01:23:45 12",
			"bgp-peer-route": "O 10.0.0.2/32 [110/2] via 10.0.0.1, 00:10:00, Gi0/0",
		},
		"bgp-prefix-not-exchanged": {"bgp-advertised": "Total number of prefixes 12"},
		"bgp-route-not-best":       {"bgp-prefix": "  10.0.0.2 from 10.0.0.2 (10.0.0.2)\n    Best path"},
		"bgp-flapping":             {"bgp-neighbor": "  Connections established 1; dropped 0"},
		"bgp-wrong-path":           {"bgp-prefix": "  Community: 65000:100"},
		"isis-adjacency-down":      {"isis-neighbors": "R2  L2 Gi0/0 10.0.0.2 Up 27 01"},
		"isis-adjacency-init":      {"clns-neighbors-detail": "System Id: R2\n  State: Up"},
		"isis-routes-missing":      {"isis-database": "R1.00-00 * 0x0A 0xABCD 1199 1/0/0"},
		"isis-flapping":            {"isis-logging": "%CLNS-5-ADJCHANGE: Adjacency to R2 Up"},
		"isis-overload-suboptimal": {"isis-database-detail": "R1.00-00 normal", "isis-summary": "  Metric-style: wide"},
	}

	for issueID, outputs := range benign {
		t.Run(issueID, func(t *testing.T) {
			col := collectFor(t, cat, ciscoDev, stdTarget, issueID, outputs)
			res := an.Analyze(col)
			if res.Matched() {
				t.Fatalf("benign %s tripped %v (must fail closed)", issueID, findingIDs(res))
			}
			if !strings.Contains(res.Unmatched, "no known signature matched") {
				t.Errorf("%s missing honest unmatched message: %q", issueID, res.Unmatched)
			}
		})
	}
}

// TestAnalyze_NoSourceNoVerdict proves that when the command source is entirely
// unavailable (every command errors), NO signature fires — a verdict is never
// invented from an empty capture.
func TestAnalyze_NoSourceNoVerdict(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()
	c, err := NewCollector(cat, FailingRunner{}, WithClock(fixedClock()))
	if err != nil {
		t.Fatal(err)
	}
	// Use an issue whose fixture WOULD trip if output were present.
	col, err := c.Collect(context.Background(), ciscoDev, "ospf-neighbor-stuck", stdTarget)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, cc := range col.Commands {
		if cc.Err == "" {
			t.Fatalf("expected every command to carry a source error, %q did not", cc.SpecID)
		}
	}
	res := an.Analyze(col)
	if res.Matched() {
		t.Fatalf("verdict invented from an all-error capture: %v", findingIDs(res))
	}
}

// TestAnalyze_DeterministicOrder proves multiple findings sort stably (confidence
// desc, then signature id).
func TestAnalyze_DeterministicOrder(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()
	// Both isis-overload-suboptimal signatures fire together.
	outputs := map[string]string{
		"isis-database-detail": "R1.00-00 LSP is set with overload bit",
		"isis-summary":         "  Metric-style: narrow",
	}
	col := collectFor(t, cat, ciscoDev, stdTarget, "isis-overload-suboptimal", outputs)
	var first []string
	for i := 0; i < 5; i++ {
		got := findingIDs(an.Analyze(col))
		if len(got) < 2 {
			t.Fatalf("expected >=2 findings, got %v", got)
		}
		if first == nil {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("finding order not deterministic: %v vs %v", got, first)
		}
	}
	// Both Medium → alphabetical by id: isis-narrow-metric before isis-overload-suboptimal.
	if first[0] != "isis-narrow-metric" {
		t.Errorf("order = %v, want isis-narrow-metric first", first)
	}
}
