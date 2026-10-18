// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"strings"
	"testing"

	"netops/backend/models"
	"netops/backend/nms"
)

// Lab-shaped inventory (2026-10-18): SNMP ids, mgmt addresses that are NOT the
// system-ips, a shared 192.168.1.1 on two cEdges, vEdges whose system-ip the
// overlay learned from the device itself.
func labIndex() *nmsDeviceIndex {
	devs := []models.Device{
		{ID: "vedge-20-1e95f00f", Name: "vEdge-20", Address: "192.168.222.104", TenantID: "t_lab"},
		{ID: "cedge-40-b99e47eb", Name: "cEDGE-40", Address: "192.168.222.107", TenantID: "t_lab", SerialNumber: "9IPEKO8TEJJ"},
		{ID: "cedge-60-2199eef8", Name: "cEDGE-60", Address: "192.168.222.108", TenantID: "t_lab"},
	}
	sys := map[string]map[string]string{"t_lab": {"10.255.255.20": "vedge-20-1e95f00f"}}
	ifs := map[string]map[string]string{
		"cedge-40-b99e47eb": {"192.168.1.1": "Gi2", "10.255.255.40": "Loopback0"},
		"cedge-60-2199eef8": {"192.168.1.1": "Gi2"},
	}
	return buildNMSDeviceIndex(devs, sys, ifs)
}

func TestNMSResolverLadder(t *testing.T) {
	idx := labIndex()
	cases := []struct {
		name, key, host string
		kind            nms.KeyKind
		want            string
		out             resolveOutcome
	}{
		{"device-reported system-ip", "10.255.255.20", "", nms.KeySystemIP, "vedge-20-1e95f00f", resolveMatched},
		{"system-ip on an interface", "10.255.255.40", "", nms.KeySystemIP, "cedge-40-b99e47eb", resolveMatched},
		{"hostname only, case-insensitive", "10.255.255.60", "cedge-60", nms.KeySystemIP, "cedge-60-2199eef8", resolveMatched},
		{"tiers agree", "10.255.255.40", "CEDGE-40", nms.KeySystemIP, "cedge-40-b99e47eb", resolveMatched},
		{"tiers disagree → abstain", "10.255.255.40", "cEDGE-60", nms.KeySystemIP, "", resolveConflict},
		{"address two devices share → abstain", "192.168.1.1", "", nms.KeySystemIP, "", resolveAmbiguous},
		{"unknown", "10.255.255.99", "edge-x", nms.KeySystemIP, "", resolveNoMatch},
		{"serial", "9ipeko8tejj", "", nms.KeySerial, "cedge-40-b99e47eb", resolveMatched},
		{"name kind", "vEdge-20", "", nms.KeyName, "vedge-20-1e95f00f", resolveMatched},
		{"mgmt address", "192.168.222.108", "", nms.KeyIP, "cedge-60-2199eef8", resolveMatched},
		{"opaque kind never matches", "vedge-20-1e95f00f", "vEdge-20", nms.KeyNone, "", resolveNoMatch},
		{"non-IP system-ip key falls to name only", "not-an-ip", "", nms.KeySystemIP, "", resolveNoMatch},
	}
	for _, c := range cases {
		got, out := idx.lookup("t_lab", c.kind, c.key, c.host)
		if got != c.want || out != c.out {
			t.Errorf("%s: got (%q,%s) want (%q,%s)", c.name, got, out, c.want, c.out)
		}
	}
}

func TestNMSResolverCountsAndExposition(t *testing.T) {
	r := &nmsDeviceResolver{}
	if _, ok := r.ResolveDevice("t_lab", nms.KeySystemIP, "10.255.255.20", ""); ok {
		t.Fatal("no index yet: must keep the controller key")
	}
	r.idx.Store(labIndex())
	if id, ok := r.ResolveDevice("t_lab", nms.KeySystemIP, "10.255.255.20", ""); !ok || id != "vedge-20-1e95f00f" {
		t.Fatal(id)
	}
	r.ResolveDevice("t_lab", nms.KeySystemIP, "192.168.1.1", "")
	var b bytes.Buffer
	r.write(&b)
	for _, want := range []string{`result="matched"} 1`, `result="no_index"} 1`, `result="ambiguous"} 1`, `result="conflict"} 0`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("exposition missing %q:\n%s", want, b.String())
		}
	}
}
