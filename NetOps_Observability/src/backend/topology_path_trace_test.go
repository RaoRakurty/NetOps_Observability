package backend

import (
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/topology"
)

func TestFoldTraceByHop(t *testing.T) {
	now := time.Now()
	vm := []vmSample{
		{Labels: map[string]string{"hop": "10.0.0.1"}, Value: 2.5},
		{Labels: map[string]string{"hop": "10.0.0.2"}, Value: 8.0},
		{Labels: map[string]string{"hop": ""}, Value: 1.0},       // no hop label → dropped
		{Labels: map[string]string{"hop": "10.0.0.9"}, Value: 0}, // non-positive → dropped
	}
	paths := []collectors.PathResult{
		{ // fresh trace: fills loss everywhere, improves RTT where lower
			Dst: "10.0.0.3", Method: "icmp", TS: now.Add(-time.Minute),
			Hops: []collectors.Hop{
				{TTL: 1, IP: "10.0.0.1", RTTms: 3.0, Loss: 0},    // RTT worse than VM → VM's 2.5 kept
				{TTL: 2, IP: "10.0.0.2", RTTms: 6.0, Loss: 33.3}, // RTT better than VM → 6.0 wins
				{TTL: 3, IP: "10.0.0.3", RTTms: 9.0, Loss: 0},    // hop VM never saw → store fills RTT
				{TTL: 4, IP: "", Loss: 100},                      // "*" hop → skipped
			},
		},
		{ // second trace crossing 10.0.0.2 with zero loss → min-loss folding clears it
			Dst: "10.0.0.4", Method: "tcp", TS: now.Add(-2 * time.Minute),
			Hops: []collectors.Hop{{TTL: 2, IP: "10.0.0.2", RTTms: 7.0, Loss: 0}},
		},
		{ // stale trace → ignored entirely
			Dst: "10.0.0.5", Method: "icmp", TS: now.Add(-time.Hour),
			Hops: []collectors.Hop{{TTL: 1, IP: "10.0.0.8", RTTms: 1.0, Loss: 0}},
		},
	}

	got := foldTraceByHop(vm, paths, now)

	h1 := got["10.0.0.1"]
	if !h1.hasRTT || h1.rtt != 2.5 || !h1.hasLoss || h1.loss != 0 {
		t.Fatalf("hop .1: want rtt=2.5 (VM min) loss=0, got %+v", h1)
	}
	h2 := got["10.0.0.2"]
	if !h2.hasRTT || h2.rtt != 6.0 {
		t.Fatalf("hop .2: want rtt=6.0 (store beats VM 8.0), got %+v", h2)
	}
	if !h2.hasLoss || h2.loss != 0 {
		t.Fatalf("hop .2: want loss=0 (min across the two traces), got %+v", h2)
	}
	h3 := got["10.0.0.3"]
	if !h3.hasRTT || h3.rtt != 9.0 || !h3.hasLoss {
		t.Fatalf("hop .3: want store-filled rtt=9.0 + loss, got %+v", h3)
	}
	if _, ok := got["10.0.0.8"]; ok {
		t.Fatalf("stale trace must not contribute samples")
	}
	if _, ok := got["10.0.0.9"]; ok {
		t.Fatalf("non-positive VM sample must not contribute")
	}
	if _, ok := got[""]; ok {
		t.Fatalf("empty hop key must never exist")
	}
}

func TestFoldTraceByHopZeroTS(t *testing.T) {
	// A PathResult without a timestamp (legacy publisher) is accepted, not dropped.
	got := foldTraceByHop(nil, []collectors.PathResult{
		{Dst: "d", Hops: []collectors.Hop{{TTL: 1, IP: "10.0.0.1", RTTms: 4.0, Loss: 66.7}}},
	}, time.Now())
	h := got["10.0.0.1"]
	if !h.hasRTT || h.rtt != 4.0 || !h.hasLoss || h.loss != 66.7 {
		t.Fatalf("zero-TS trace must still fold, got %+v", h)
	}
}

func TestEnrichPathTrace(t *testing.T) {
	view := topology.View{
		Path: []string{"a", "b", "c"},
		Nodes: []topology.Node{
			{ID: "a", MgmtIP: "10.0.0.1", Metrics: map[string]float64{"stamp_rtt_ms": 0.7}},
			{ID: "b", MgmtIP: "10.0.0.2"},
			{ID: "c", MgmtIP: "10.0.0.3"},
			{ID: "x", MgmtIP: "10.0.0.2"}, // same IP but NOT on the path — untouched
		},
	}
	byHop := map[string]traceSample{
		"10.0.0.1": {rtt: 2.5, loss: 0, hasRTT: true, hasLoss: true},
		"10.0.0.2": {rtt: 6.0, hasRTT: true}, // RTT only (no loss folded)
		// 10.0.0.3: no trace ever saw it → hop c stays bare
	}

	enrichPathTrace(&view, byHop)

	// hop a: trace keys land NEXT TO the existing stamp key (UI decides precedence)
	a := view.Nodes[0]
	if a.Metrics["stamp_rtt_ms"] != 0.7 {
		t.Fatalf("stamp key must be preserved, got %+v", a.Metrics)
	}
	if a.Metrics["trace_rtt_ms"] != 2.5 || a.Metrics["trace_loss_pct"] != 0 {
		t.Fatalf("hop a missing trace metrics: %+v", a.Metrics)
	}
	// hop b: RTT only; no fabricated loss key
	b := view.Nodes[1]
	if b.Metrics["trace_rtt_ms"] != 6.0 {
		t.Fatalf("hop b missing trace rtt: %+v", b.Metrics)
	}
	if _, ok := b.Metrics["trace_loss_pct"]; ok {
		t.Fatalf("hop b must not carry a loss it never measured: %+v", b.Metrics)
	}
	// hop c: untouched (honest "—" downstream)
	if len(view.Nodes[2].Metrics) != 0 {
		t.Fatalf("hop c should carry no trace metrics, got %+v", view.Nodes[2].Metrics)
	}
	// node x: shares hop b's IP but is OFF the path → untouched
	if view.Nodes[3].Metrics != nil {
		t.Fatalf("off-path node must not be enriched, got %+v", view.Nodes[3].Metrics)
	}
}

func TestEnrichPathTraceNoOp(t *testing.T) {
	v := topology.View{Nodes: []topology.Node{{ID: "a", MgmtIP: "10.0.0.1"}}}
	enrichPathTrace(&v, map[string]traceSample{"10.0.0.1": {rtt: 1, hasRTT: true}})
	if v.Nodes[0].Metrics != nil {
		t.Fatalf("no path → must not enrich")
	}
	enrichPathTrace(nil, nil) // must not panic
}
