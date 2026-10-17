// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequestMetricsByClass(t *testing.T) {
	m := NewMetrics(Price{})
	m.ObserveRequest("data", "answered", 0.03)
	m.ObserveRequest("data", "answered", 0.4)
	m.ObserveRequest("rca", "refused", 9)
	m.ObserveRequest("tenant-a", "answered", 1) // unknown class: dropped
	m.ObserveRequest("data", "maybe", 1)        // unknown outcome: dropped
	var b bytes.Buffer
	m.Write(&b)
	out := b.String()
	for _, want := range []string{
		`netops_ai_request_seconds_bucket{class="data",le="0.025"} 0`,
		`netops_ai_request_seconds_bucket{class="data",le="0.05"} 1`,
		`netops_ai_request_seconds_bucket{class="data",le="0.5"} 2`,
		`netops_ai_request_seconds_count{class="data"} 2`,
		`netops_ai_request_seconds_count{class="rca"} 0`, // a refusal is counted, not timed
		`netops_ai_request_seconds_count{class="investigation"} 0`,
		`netops_ai_requests_total{class="rca",outcome="refused"} 1`,
		`netops_ai_requests_total{class="product",outcome="error"} 0`, // zeros are emitted
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, "tenant-a") || strings.Contains(out, "maybe") {
		t.Fatal("an unknown label reached the exposition")
	}
	if m.RequestCount("data", "answered") != 2 {
		t.Fatal("count")
	}
	// The unlabelled families keep their exact shape.
	if !strings.Contains(out, "netops_ai_answer_seconds_bucket{le=\"0.1\"} 0") || !strings.Contains(out, "netops_ai_answer_seconds_count 0") {
		t.Fatal("the existing histogram changed shape")
	}
	var nilM *Metrics
	nilM.ObserveRequest("data", "answered", 1) // nil-safe
}
