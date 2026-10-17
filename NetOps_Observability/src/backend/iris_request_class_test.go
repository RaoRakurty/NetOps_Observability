// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_request_class_test.go — tracker 337 N-H4: every ask is observed ONCE
// in its performance class, on the JSON path and the streamed path alike, by
// the answer actually shipped; the NL query routes are the data class.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aiscore"
)

func classTotal(m *aiscore.Metrics) int64 {
	var n int64
	for _, c := range aiscore.RequestClasses {
		for _, o := range aiscore.RequestOutcomes {
			n += m.RequestCount(c, o)
		}
	}
	return n
}

func TestEveryAskIsObservedOnceInItsClass(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	s.aiScore = aiscore.NewMetrics(aiscore.Price{})
	const q = "show cpu on edge-a for the last hour"
	w := httptest.NewRecorder()
	s.handleAIAsk(w, askReq(a, q, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("json ask: %d %s", w.Code, w.Body.String())
	}
	if n := classTotal(s.aiScore); n != 1 {
		t.Fatalf("one JSON ask must be one observation, got %d", n)
	}
	w = httptest.NewRecorder()
	s.handleAIAsk(w, askReq(a, q, "text/event-stream"))
	if n := classTotal(s.aiScore); n != 2 {
		t.Fatalf("one streamed ask must be one more observation, got %d total", n)
	}
	// A cpu question is answered by the data arm: class data.
	if s.aiScore.RequestCount(string(ai.ClassData), "answered") != 2 {
		t.Fatalf("expected two answered data requests: data=%d rca=%d product=%d inv=%d",
			s.aiScore.RequestCount("data", "answered"), s.aiScore.RequestCount("rca", "answered"),
			s.aiScore.RequestCount("product", "answered"), s.aiScore.RequestCount("investigation", "answered"))
	}
}

func TestDataTimerOutcomes(t *testing.T) {
	s := &server{aiScore: aiscore.NewMetrics(aiscore.Price{})}
	for code, outcome := range map[int]string{200: "answered", 404: "refused", 503: "error"} {
		w, done := s.irisDataTimer(httptest.NewRecorder())
		w.WriteHeader(code)
		done()
		if s.aiScore.RequestCount("data", outcome) != 1 {
			t.Errorf("status %d should count as %s", code, outcome)
		}
	}
}
