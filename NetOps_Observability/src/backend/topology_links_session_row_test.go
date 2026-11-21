// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"testing"
)

// Tracker 397: a control-session row reaches topology_links.json with its own
// fields and NO a/b — an engine that does not know the proto must skip it, never
// read it as a device adjacency (which would weld the fabric). The existing row
// shapes are unchanged.
func TestTopologyLinkExportSessionRowCarriesNoAB(t *testing.T) {
	sess, err := json.Marshal(topologyLinkExport{TenantID: "t_w", Proto: "sdwan_control",
		SA: "10.255.255.2", SAKey: "10.255.255.2", SB: "vedge-20", SBKey: "10.255.255.20"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(sess, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["a"]; ok {
		t.Fatalf("session row carries a: %s", sess)
	}
	if _, ok := m["b"]; ok {
		t.Fatalf("session row carries b: %s", sess)
	}
	for k, want := range map[string]string{"tenant_id": "t_w", "proto": "sdwan_control", "sa": "10.255.255.2",
		"sa_key": "10.255.255.2", "sb": "vedge-20", "sb_key": "10.255.255.20"} {
		if m[k] != want {
			t.Fatalf("%s = %v, want %q (%s)", k, m[k], want, sess)
		}
	}
	link, err := json.Marshal(topologyLinkExport{TenantID: "", A: "r1", B: "r2", Proto: "lldp"})
	if err != nil {
		t.Fatal(err)
	}
	if string(link) != `{"tenant_id":"","a":"r1","b":"r2","proto":"lldp"}` {
		t.Fatalf("an LLDP row's shape moved: %s", link)
	}
}
