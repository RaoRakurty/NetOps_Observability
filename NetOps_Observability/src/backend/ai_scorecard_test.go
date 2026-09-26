// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_scorecard_test.go — the server side of the production Iris scorecard
// (tracker 337 N-A3): the sink adapter maps every observation onto
// internal/aiscore, the orchestrator is built WITH the sink, the price is read
// honestly, and the families reach the /metrics exposition.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/alerts"
	"netops/backend/internal/aiscore"
)

func TestAIScoreSinkMapsEveryObservation(t *testing.T) {
	_, s := newTestServerState(t)
	s.aiScore = aiscore.NewMetrics(aiscore.Price{})
	sink := s.aiScoreSink()
	if sink == nil {
		t.Fatal("a server with a scorecard must hand the orchestrator a sink")
	}
	sink.AnswerObserved(ai.AnswerScore{Citations: 2, Duration: time.Second})
	sink.GuardObserved(ai.GuardFabricatedCitation, 1)
	sink.InvestigationObserved(ai.InvestigationScore{Outcome: ai.InvestigationAnswered, Hops: []string{"entry"}, ToolOutcomes: []string{"error"}, EvidenceBacked: true})
	sink.ProviderObserved(ai.ProviderScore{Usage: ai.TokenUsage{InputTokens: 10, OutputTokens: 5, Reported: true}, Investigation: true})

	var b strings.Builder
	s.aiScore.Write(&b)
	out := b.String()
	for _, want := range []string{
		`netops_ai_answers_total{grounded="yes"} 1`,
		`netops_ai_citations_total 2`,
		`netops_ai_grounding_guard_total{guard="fabricated_citation"} 1`,
		`netops_ai_tool_error_recovery_total{result="recovered"} 1`,
		`netops_ai_investigation_tokens_total{direction="input"} 10`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("scorecard is missing %q", want)
		}
	}
}

func TestAIScoreSinkNilWithoutAScorecard(t *testing.T) {
	_, s := newTestServerState(t)
	s.aiScore = nil
	if s.aiScoreSink() != nil {
		t.Fatal("no scorecard → nil sink (the layer is disabled, nothing changes)")
	}
}

func TestNewOrchestratorCarriesTheSink(t *testing.T) {
	_, s := newTestServerState(t)
	s.aiScore = aiscore.NewMetrics(aiscore.Price{})
	claims := jwtClaims{Sub: "u", Tenant: "t-a", Role: "operator"}
	o := s.newOrchestrator(newAITestRequest(t, claims), claims)
	if o.Score == nil {
		t.Fatal("the grounded engine must be built with the scorecard sink")
	}
}

func TestAIScorePriceIsReadHonestly(t *testing.T) {
	t.Setenv("AI_PRICE_INPUT_USD_PER_MTOK", "3")
	t.Setenv("AI_PRICE_OUTPUT_USD_PER_MTOK", "-4") // nonsense → not configured for that half
	p := aiScorePrice()
	if p.InputUSDPerMTok != 3 || p.OutputUSDPerMTok != 0 {
		t.Fatalf("price = %+v", p)
	}
	t.Setenv("AI_PRICE_INPUT_USD_PER_MTOK", "abc")
	t.Setenv("AI_PRICE_OUTPUT_USD_PER_MTOK", "")
	if aiScorePrice().Configured() {
		t.Fatal("an unparsable price must not be a configured price")
	}
}

func TestPromMetricsExposesTheScorecard(t *testing.T) {
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil) // the exporter reads it; the harness leaves it nil
	if s.aiScore == nil {
		s.aiScore = aiscore.NewMetrics(aiscore.Price{})
	}
	rec := httptest.NewRecorder()
	s.handlePromMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{"netops_ai_answers_total", "netops_ai_scorecard_censored", "netops_ai_scorecard_sample_age_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing the %s family", want)
		}
	}
}
