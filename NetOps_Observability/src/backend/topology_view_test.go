// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import "testing"

// resolveLinkMetric is the pure fold of per-interface telemetry onto a link.
// These tests pin the zero-trust honesty rules: never invent a reading, keep
// measured-idle distinct from unmeasured, and let any down endpoint win.
// Metric maps are keyed by CANONICAL interface (as the handler pre-normalizes
// them); the link ports use varied vendor spellings to prove normalization.
func TestResolveLinkMetric(t *testing.T) {
	const dev1, dev2 = "r1", "r2"
	// link advertises abbreviated/long forms; maps hold the canonical "et1"/"et2".
	link := topoLink{Source: dev1, Target: dev2, LocalPort: "Ethernet1", RemotePort: "Et2"}
	srcK := [2]string{dev1, "et1"}
	dstK := [2]string{dev2, "et2"}

	cases := []struct {
		name          string
		oper, in, out map[[2]string]float64
		link          topoLink
		wantUtil      float64
		wantHasUtil   bool
		wantStatus    string
	}{
		{
			name:        "no telemetry → unmeasured, unknown status",
			link:        link,
			wantHasUtil: false,
			wantStatus:  "",
		},
		{
			name:       "both endpoints up → up (across spelling variants)",
			oper:       map[[2]string]float64{srcK: 1, dstK: 1},
			link:       link,
			wantStatus: "up",
		},
		{
			name:       "one endpoint oper-down wins → down",
			oper:       map[[2]string]float64{srcK: 1, dstK: 2},
			link:       link,
			wantStatus: "down",
		},
		{
			name:        "measured idle stays HasUtil with 0%",
			in:          map[[2]string]float64{srcK: 0},
			link:        link,
			wantUtil:    0,
			wantHasUtil: true,
		},
		{
			name:        "busiest direction/endpoint wins, converted to percent",
			in:          map[[2]string]float64{srcK: 0.20, dstK: 0.55},
			out:         map[[2]string]float64{srcK: 0.42, dstK: 0.10},
			link:        link,
			wantUtil:    55, // dst in-util 0.55 → 55%
			wantHasUtil: true,
		},
		{
			// ext side has no port → its (down) reading is ignored; only the
			// local interface contributes.
			name:        "unresolved target contributes only the local side",
			oper:        map[[2]string]float64{srcK: 1, {"ext:peer", ""}: 2},
			in:          map[[2]string]float64{srcK: 0.30},
			link:        topoLink{Source: dev1, Target: "ext:peer", LocalPort: "Ethernet1", RemotePort: ""},
			wantUtil:    30,
			wantHasUtil: true,
			wantStatus:  "up",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			util, hasUtil, status := resolveLinkMetric(tc.link, tc.oper, tc.in, tc.out)
			if d := util - tc.wantUtil; d > 1e-6 || d < -1e-6 {
				t.Errorf("util = %v, want %v", util, tc.wantUtil)
			}
			if hasUtil != tc.wantHasUtil {
				t.Errorf("hasUtil = %v, want %v", hasUtil, tc.wantHasUtil)
			}
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
		})
	}
}

func TestCanonIface(t *testing.T) {
	cases := map[string]string{
		"Ethernet1":          "et1",
		"Et1":                "et1",
		"eth1":               "et1",
		"GigabitEthernet0/1": "gi0/1",
		"Gi0/1":              "gi0/1",
		"GigE0/1":            "gi0/1",
		"TenGigE0/0/1":       "te0/0/1",
		"Te0/0/1":            "te0/0/1",
		"FortyGigE1/1":       "fo1/1",
		"HundredGigE1/2":     "hu1/2",
		"FastEthernet0":      "fa0",
		"Port-channel10":     "po10",
		"Bundle-Ether5":      "be5",
		"Management1":        "ma1",
		"mgmt0":              "ma0",
		"Loopback0":          "lo0",
		"Vlan100":            "vl100",
		"ethernet-1/1":       "et1/1",   // Nokia SRL
		"ge-0/0/0":           "ge0/0/0", // Juniper (unknown prefix kept)
		"xe-1/0/0":           "xe1/0/0",
		"":                   "",
		"  Et1  ":            "et1",
	}
	for in, want := range cases {
		if got := canonIface(in); got != want {
			t.Errorf("canonIface(%q) = %q, want %q", in, got, want)
		}
	}
}
