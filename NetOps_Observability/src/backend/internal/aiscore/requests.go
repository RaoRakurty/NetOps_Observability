// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

// requests.go — Iris requests by PERFORMANCE CLASS (tracker 337 N-H4). Four
// classes with different latency expectations: a product question, a
// deterministic data query, a grounded RCA answer, an investigation. Each
// answered request lands in its class's histogram; p50/p95 per class are
// histogram_quantile over netops_ai_request_seconds{class}. Refusals and
// errors are counted, not timed — they would flatter the latency.

import (
	"fmt"
	"io"
	"sync/atomic"
)

// The closed vocabularies (ai.ClassFor produces the class).
var (
	RequestClasses  = []string{"product", "data", "rca", "investigation"}
	RequestOutcomes = []string{"answered", "refused", "error"}
)

// RequestBuckets are finer at the bottom than LatencyBuckets: a product or a
// data answer is expected in well under a second.
var RequestBuckets = []float64{0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120}

type requestMetrics struct {
	secs  map[string]*histogram
	count map[string]*atomic.Int64 // class|outcome
}

func newRequestMetrics() *requestMetrics {
	r := &requestMetrics{secs: map[string]*histogram{}, count: map[string]*atomic.Int64{}}
	for _, c := range RequestClasses {
		r.secs[c] = newHistogramWith(RequestBuckets)
		for _, o := range RequestOutcomes {
			r.count[c+"|"+o] = new(atomic.Int64)
		}
	}
	return r
}

// ObserveRequest records one Iris request. An unknown class or outcome is
// dropped, never bucketed into a neighbour. Only answered requests are timed.
func (m *Metrics) ObserveRequest(class, outcome string, seconds float64) {
	if m == nil || m.requests == nil {
		return
	}
	c, ok := m.requests.count[class+"|"+outcome]
	if !ok {
		return
	}
	c.Add(1)
	if outcome == "answered" {
		m.requests.secs[class].observe(seconds)
	}
}

// RequestCount is the counter for one class and outcome (tests, the scorecard).
func (m *Metrics) RequestCount(class, outcome string) int64 {
	if m == nil || m.requests == nil {
		return 0
	}
	if c, ok := m.requests.count[class+"|"+outcome]; ok {
		return c.Load()
	}
	return 0
}

func (r *requestMetrics) write(w io.Writer) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_ai_request_seconds Wall time of one answered Iris request, by performance class (product, data, rca, investigation). p50/p95 via histogram_quantile.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_request_seconds histogram\n")
	for _, c := range RequestClasses {
		r.secs[c].series(w, "netops_ai_request_seconds", fmt.Sprintf("class=%q,", c))
	}
	fmt.Fprintf(w, "# HELP netops_ai_requests_total Iris requests by performance class and outcome; refused and error requests are not in the latency histogram.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_requests_total counter\n")
	for _, c := range RequestClasses {
		for _, o := range RequestOutcomes {
			fmt.Fprintf(w, "netops_ai_requests_total{class=%q,outcome=%q} %d\n", c, o, r.count[c+"|"+o].Load())
		}
	}
}
