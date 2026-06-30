package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vmVec renders a VictoriaMetrics instant-query vector response for dst→value.
func vmVec(pairs map[string]float64) string {
	var b strings.Builder
	b.WriteString(`{"data":{"result":[`)
	first := true
	for dst, v := range pairs {
		if !first {
			b.WriteString(",")
		}
		first = false
		fmt.Fprintf(&b, `{"metric":{"dst":%q},"value":[0,"%g"]}`, dst, v)
	}
	b.WriteString(`]}}`)
	return b.String()
}

// fakeVM routes each query to canned samples by the metric it references, so we
// can drive the resolver's cascade deterministically.
func fakeVM(t *testing.T, byMetric map[string]map[string]float64) *server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		for metric, pairs := range byMetric {
			if strings.Contains(q, metric) {
				fmt.Fprint(w, vmVec(pairs))
				return
			}
		}
		fmt.Fprint(w, `{"data":{"result":[]}}`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	return &server{}
}

func TestResolveCurrentByDstCascade(t *testing.T) {
	s := fakeVM(t, map[string]map[string]float64{
		// dst .1 measured by STAMP (all three).
		"probe_rtt_ms":   {"10.0.0.1": 20},
		"probe_pdv_ms":   {"10.0.0.1": 3},
		"probe_loss_pct": {"10.0.0.1": 0.5},
		// dst .2 measured by wan-echo (STAMP absent).
		"circuit_latency_ms": {"10.0.0.2": 15},
		"circuit_jitter_ms":  {"10.0.0.2": 2},
		"circuit_loss_pct":   {"10.0.0.2": 1},
		"circuit_qoe":        {"10.0.0.2": 8},
		// dst .3 only synthetic ICMP (latency + loss, no jitter).
		"synthetic_icmp_rtt_ms":   {"10.0.0.3": 30},
		"synthetic_icmp_loss_pct": {"10.0.0.3": 2},
	})

	res := s.resolveCurrentByDst(context.Background())

	// .1 → STAMP wins every field.
	a := res["10.0.0.1"]
	if a == nil || a.LatencySource != SrcSTAMP || a.Latency != 20 {
		t.Fatalf(".1 latency: %+v want stamp/20", a)
	}
	if a.JitterSource != SrcSTAMP || a.LossSource != SrcSTAMP || a.Source() != SrcSTAMP {
		t.Errorf(".1 sources: jit=%v loss=%v primary=%v want all stamp", a.JitterSource, a.LossSource, a.Source())
	}

	// .2 → echo wins (STAMP absent), incl. QoE which only echo scores.
	b := res["10.0.0.2"]
	if b == nil || b.LatencySource != SrcEcho || b.Latency != 15 {
		t.Fatalf(".2 latency: %+v want echo/15", b)
	}
	if b.JitterSource != SrcEcho || b.LossSource != SrcEcho || b.Source() != SrcEcho {
		t.Errorf(".2 sources: jit=%v loss=%v primary=%v want echo", b.JitterSource, b.LossSource, b.Source())
	}
	if !b.HasQoE || b.QoE != 8 {
		t.Errorf(".2 qoe: has=%v val=%v want 8", b.HasQoE, b.QoE)
	}

	// .3 → synthetic ICMP for latency+loss; jitter genuinely absent (honest).
	c := res["10.0.0.3"]
	if c == nil || c.LatencySource != SrcSynthetic || c.Latency != 30 {
		t.Fatalf(".3 latency: %+v want icmp/30", c)
	}
	if c.HasJitter {
		t.Errorf(".3 should have NO jitter (ICMP doesn't measure it), got %v", c.Jitter)
	}
	if c.LossSource != SrcSynthetic || c.Source() != SrcSynthetic {
		t.Errorf(".3 sources: loss=%v primary=%v want icmp", c.LossSource, c.Source())
	}
}

func TestResolveSTAMPBeatsEchoSamePath(t *testing.T) {
	// Both STAMP and echo measure the same dst — STAMP (higher tier) must win.
	s := fakeVM(t, map[string]map[string]float64{
		"probe_rtt_ms":       {"10.0.0.9": 12},
		"circuit_latency_ms": {"10.0.0.9": 99},
	})
	res := s.resolveCurrentByDst(context.Background())
	a := res["10.0.0.9"]
	if a == nil || a.LatencySource != SrcSTAMP || a.Latency != 12 {
		t.Fatalf("STAMP must beat echo: %+v want stamp/12", a)
	}
}

func TestResolvedSourcesPriorityOrder(t *testing.T) {
	ms := map[string]*ResolvedPathMetric{
		"a": {HasLatency: true, LatencySource: SrcSynthetic},
		"b": {HasLatency: true, LatencySource: SrcSTAMP},
		"c": {HasLatency: true, LatencySource: SrcEcho},
	}
	got := resolvedSources(ms)
	want := []PathSource{SrcSTAMP, SrcEcho, SrcSynthetic}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

func TestPathSourceLabel(t *testing.T) {
	if SrcEcho.Label() != "Active echo" || SrcSTAMP.Label() != "STAMP" || SrcNone.Label() != "—" {
		t.Errorf("labels: echo=%q stamp=%q none=%q", SrcEcho.Label(), SrcSTAMP.Label(), SrcNone.Label())
	}
}
