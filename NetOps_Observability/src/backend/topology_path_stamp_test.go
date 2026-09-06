// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/topology"
)

func TestEnrichPathStamp(t *testing.T) {
	view := topology.View{
		Path: []string{"a", "b", "c"},
		Nodes: []topology.Node{
			{ID: "a", MgmtIP: "10.0.0.1"},
			{ID: "b", MgmtIP: "10.0.0.2"},
			{ID: "c", MgmtIP: "10.0.0.3"},
			{ID: "x", MgmtIP: "10.0.0.1"}, // same IP but NOT on the path — must be untouched
		},
	}
	byDst := map[string]stampSample{
		"10.0.0.1":      {rtt: 0.7, pdv: 0.4, owd: 0.3, loss: 0, hasRTT: true, hasPDV: true, hasOWD: true, hasLoss: true},
		"10.0.0.2:8620": {rtt: 2.1, hasRTT: true}, // dst with a port — won't match bare "10.0.0.2"
		// 10.0.0.3 has no probe → hop c stays bare
	}

	enrichPathStamp(&view, byDst)

	// hop a: full STAMP attached
	a := view.Nodes[0]
	if a.Metrics["stamp_rtt_ms"] != 0.7 || a.Metrics["stamp_pdv_ms"] != 0.4 ||
		a.Metrics["stamp_owd_ms"] != 0.3 || a.Metrics["stamp_loss_pct"] != 0 {
		t.Fatalf("hop a missing STAMP metrics: %+v", a.Metrics)
	}
	// hop b: dst was keyed with a port ("10.0.0.2:8620"); a bare-IP node must NOT match
	// (the map key is normalised by the caller, here it is intentionally un-normalised).
	if _, ok := view.Nodes[1].Metrics["stamp_rtt_ms"]; ok {
		t.Fatalf("hop b should have no STAMP (port-keyed dst must not match bare IP)")
	}
	// hop c: no probe → no stamp keys
	if len(view.Nodes[2].Metrics) != 0 {
		t.Fatalf("hop c should carry no STAMP metrics, got %+v", view.Nodes[2].Metrics)
	}
	// node x: shares hop a's IP but is OFF the path → must be untouched
	if view.Nodes[3].Metrics != nil {
		t.Fatalf("off-path node must not be enriched, got %+v", view.Nodes[3].Metrics)
	}
}

func TestEnrichPathStampNoOp(t *testing.T) {
	// No path, or no samples → no panic, no mutation.
	v := topology.View{Nodes: []topology.Node{{ID: "a", MgmtIP: "10.0.0.1"}}}
	enrichPathStamp(&v, map[string]stampSample{"10.0.0.1": {rtt: 1, hasRTT: true}})
	if v.Nodes[0].Metrics != nil {
		t.Fatalf("no path → must not enrich")
	}
	enrichPathStamp(nil, nil) // must not panic
}
