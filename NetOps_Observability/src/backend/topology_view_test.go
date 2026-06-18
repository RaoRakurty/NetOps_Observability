package main

import "testing"

// resolveLinkMetric is the pure fold of per-interface telemetry onto a link.
// These tests pin the zero-trust honesty rules: never invent a reading, keep
// measured-idle distinct from unmeasured, and let any down endpoint win.
func TestResolveLinkMetric(t *testing.T) {
	const (
		dev1, if1 = "r1", "Ethernet1"
		dev2, if2 = "r2", "Ethernet2"
	)
	link := topoLink{Source: dev1, Target: dev2, LocalPort: if1, RemotePort: if2}
	srcK := [2]string{dev1, if1}
	dstK := [2]string{dev2, if2}

	cases := []struct {
		name                       string
		oper, in, out              map[[2]string]float64
		link                       topoLink
		wantUtil                   float64
		wantHasUtil                bool
		wantStatus                 string
	}{
		{
			name:       "no telemetry → unmeasured, unknown status",
			link:       link,
			wantHasUtil: false,
			wantStatus: "",
		},
		{
			name:       "both endpoints up → up",
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
			name:        "unresolved target contributes only the local side",
			oper:        map[[2]string]float64{srcK: 1, {"ext:peer", ""}: 2},
			in:          map[[2]string]float64{srcK: 0.30},
			link:        topoLink{Source: dev1, Target: "ext:peer", LocalPort: if1, RemotePort: ""},
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
