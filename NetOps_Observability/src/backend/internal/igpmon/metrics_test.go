package igpmon

// metrics_test.go — §10: every served read is counted, and the scrape text is
// byte-stable so a dashboard built on it does not flap with map iteration order.

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestMetricsCountsPerProtocolAndOperation(t *testing.T) {
	m := NewMetrics()
	m.Query(ProtoOSPF, "summary")
	m.Query(ProtoOSPF, "summary")
	m.Query(ProtoISIS, "health")

	var b strings.Builder
	m.Write(&b)
	got := b.String()
	for _, want := range []string{
		"# HELP netops_igpmon_queries_total",
		"# TYPE netops_igpmon_queries_total counter",
		`netops_igpmon_queries_total{proto="isis",op="health"} 1`,
		`netops_igpmon_queries_total{proto="ospf",op="summary"} 2`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("scrape missing %q:\n%s", want, got)
		}
	}
	// Labels are written in sorted order — isis before ospf.
	if strings.Index(got, `proto="isis"`) > strings.Index(got, `proto="ospf"`) {
		t.Errorf("scrape is not label-sorted:\n%s", got)
	}
	// And the same counters render identically on a second scrape.
	var b2 strings.Builder
	m.Write(&b2)
	if b2.String() != got {
		t.Errorf("scrape is not byte-stable:\n%s\n---\n%s", got, b2.String())
	}
}

func TestMetricsEmptyAndNilAreSafe(t *testing.T) {
	var b strings.Builder
	NewMetrics().Write(&b)
	if b.String() != "" {
		t.Errorf("an empty counter set emitted %q, want nothing", b.String())
	}
	var nilM *Metrics
	nilM.Query(ProtoOSPF, "summary") // must not panic
	nilM.Write(&b)                   // must not panic
	if b.String() != "" {
		t.Errorf("a nil counter set emitted %q", b.String())
	}
	// The zero value is not usable but must still not panic or lose a count.
	z := &Metrics{}
	z.Query(ProtoISIS, "adjacencies")
	var zb strings.Builder
	z.Write(&zb)
	if !strings.Contains(zb.String(), `proto="isis",op="adjacencies"} 1`) {
		t.Errorf("the zero value lost a count: %q", zb.String())
	}
}

func TestMetricsIsConcurrencySafe(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Query(ProtoOSPF, "adjacencies")
			var b strings.Builder
			m.Write(&b)
		}()
	}
	wg.Wait()
	var b strings.Builder
	m.Write(&b)
	if !strings.Contains(b.String(), `proto="ospf",op="adjacencies"} 50`) {
		t.Errorf("lost counts under concurrency: %q", b.String())
	}
}

// TestEveryServedReadIsCounted — the counter must move on the real handler path,
// and must NOT move for a request the gate or the validators refused.
func TestEveryServedReadIsCounted(t *testing.T) {
	h := newHarness(t)
	h.seedDevice("leaf1", "leaf1", "acme")
	for _, rt := range allRoutes {
		if w, _ := h.get(pathFor(rt.proto, rt.op)); w.Code != http.StatusOK {
			t.Fatalf("%s/%s = %d", rt.proto, rt.op, w.Code)
		}
	}
	var b strings.Builder
	h.api.Metrics().Write(&b)
	for _, rt := range allRoutes {
		want := `netops_igpmon_queries_total{proto="` + rt.proto + `",op="` + rt.op + `"} 1`
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}

	// Refused requests are not served reads.
	before := b.String()
	h.get("/api/protocols/ospf/summary?since=99d")  // bounds
	h.get("/api/protocols/ospf/health?device=nope") // 404
	h.get("/api/protocols/bgp/summary")             // unknown protocol
	h.authzOK = false
	h.get("/api/protocols/ospf/summary") // gate
	var after strings.Builder
	h.api.Metrics().Write(&after)
	if after.String() != before {
		t.Errorf("a refused request was counted as a served read:\n%s\n---\n%s", before, after.String())
	}
}
