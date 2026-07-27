package rca

import (
	"strings"
	"testing"
)

// (Test 9) a RESPONDING path hop that carries the case's causal mark is rendered
// as the last responding hop with a failure/visibility boundary AFTER it — never
// a red BREAK POINT on the responding object (P1 path-boundary rendering).
func TestPathBoundaryRespondingHopNotStyledFailed(t *testing.T) {
	// classifier: a responding hop with any causal/visibility mark is "last
	// responding", never failed.
	if !rcaHopRespondingWithMark(SpineHopView{State: "responding", Fault: "broken"}) {
		t.Fatal("responding + broken must classify as last-responding, not failed")
	}
	if rcaHopRespondingWithMark(SpineHopView{State: "down", Fault: "broken"}) {
		t.Fatal("a genuinely down hop is a failed hop, not last-responding")
	}

	rep := buildTestReport(t,
		testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
			testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
				[]string{"probe_loss"}, nil, nil, "netops", false)),
		[]map[string]any{
			testSig("probe_loss", "active_probe", "prober", "path", "prober->10.60.10.10", "crit",
				"2026-07-12 18:12:00", true, map[string]any{"probe_scope": "customer_path"}),
		})
	// the responding NVA carries the causal mark; the next hop did not respond.
	rep.Topology = TopologyView{
		Available: true, VantageID: "lan-vantage-1", ObservedAt: "2026-07-12 18:13:00",
		Hops: []SpineHopView{
			{Index: 1, Label: "nva-responding", Address: "10.60.1.10", Kind: "cloud",
				State: "responding", Fault: "broken", Boundary: "provider", Provider: "aws"},
			{Index: 2, Label: "", Address: "", Kind: "unknown", State: "unknown"},
		},
		DropPoint: "The last responding hop was nva-responding.",
	}
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if strings.Contains(doc, "BREAK POINT") {
		t.Fatal("a responding hop must never render a red BREAK POINT badge")
	}
	if !strings.Contains(strings.ToLower(doc), "last responding hop") {
		t.Fatal("the responding hop must be labelled 'last responding hop'")
	}
	if !strings.Contains(strings.ToLower(doc), "boundary") {
		t.Fatal("a failure/visibility boundary must be drawn after the responding hop")
	}
}
