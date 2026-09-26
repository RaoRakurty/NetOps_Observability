// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

// aiscore_test.go — the production scorecard's honesty contract.
//
// Pinned: every family renders on every scrape (zeros, never gaps); an unknown
// label is dropped, never emitted; tokens count only when the provider reported
// them; the recovery rate's population is turns that actually hit a failing
// tool; a store that could not be read emits NO value gauges and a censor with
// the reason; cost is censored until a price is configured; and nothing the
// exposition emits carries a tenant or entity label.

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func render(m *Metrics) string {
	var b bytes.Buffer
	m.Write(&b)
	return b.String()
}

func mustContain(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l+"\n") {
			t.Errorf("exposition is missing %q", l)
		}
	}
}

func mustNotContain(t *testing.T, out string, frags ...string) {
	t.Helper()
	for _, f := range frags {
		if strings.Contains(out, f) {
			t.Errorf("exposition must not contain %q", f)
		}
	}
}

func TestEveryFamilyRendersAsZeroBeforeAnyObservation(t *testing.T) {
	out := render(NewMetrics(Price{}))
	mustContain(t, out,
		`netops_ai_answers_total{grounded="yes"} 0`,
		`netops_ai_answers_total{grounded="no"} 0`,
		`netops_ai_citations_total 0`,
		`netops_ai_grounding_guard_total{guard="fabricated_citation"} 0`,
		`netops_ai_grounding_guard_total{guard="uncertain_claim"} 0`,
		`netops_ai_investigations_total{outcome="answered"} 0`,
		`netops_ai_tool_calls_total{outcome="denied"} 0`,
		`netops_ai_provider_calls_total{usage_reported="no"} 0`,
		`netops_ai_model_price_configured 0`,
		`netops_ai_scorecard_sample_age_seconds -1`,
	)
	// Never sampled: no value gauges, and the censor says why.
	mustNotContain(t, out, "netops_corr_objects ", "netops_corr_compression_ratio", "netops_ai_model_cost_usd_total")
	mustContain(t, out,
		`netops_ai_scorecard_censored{metric="alert_compression_ratio",reason="`+ReasonNeverSampled+`"} 1`,
		`netops_ai_scorecard_available{metric="alert_compression_ratio"} 0`,
		`netops_ai_scorecard_censored{metric="ai_cost_per_investigation",reason="`+ReasonNoTokenPrice+`"} 1`,
	)
}

func TestAnswersGuardsAndUnknownLabelsDropped(t *testing.T) {
	m := NewMetrics(Price{})
	m.ObserveAnswer(true, 3, 0.4)
	m.ObserveAnswer(false, 0, 1.2)
	m.ObserveGuard("fabricated_citation", 2)
	m.ObserveGuard("made_up_guard", 5)
	out := render(m)
	mustContain(t, out,
		`netops_ai_answers_total{grounded="yes"} 1`,
		`netops_ai_answers_total{grounded="no"} 1`,
		`netops_ai_citations_total 3`,
		`netops_ai_grounding_guard_total{guard="fabricated_citation"} 1`,
		`netops_ai_unsupported_claims_total{guard="fabricated_citation"} 2`,
	)
	mustNotContain(t, out, "made_up_guard")
}

func TestRecoveryPopulationIsOnlyTurnsThatHitAFailure(t *testing.T) {
	m := NewMetrics(Price{})
	m.ObserveInvestigation(Investigation{Outcome: "answered", ToolCalls: []string{"ok", "ok"}, EvidenceBacked: true, Hops: []string{"entry", "rule"}})
	m.ObserveInvestigation(Investigation{Outcome: "answered", ToolCalls: []string{"ok", "error"}, EvidenceBacked: true, Hops: []string{"entry", "model"}, HopsRejected: 1})
	m.ObserveInvestigation(Investigation{Outcome: "no_evidence", ToolCalls: []string{"not_wired"}, Cutoffs: []string{"time"}})
	out := render(m)
	mustContain(t, out,
		`netops_ai_investigations_total{outcome="answered"} 2`,
		`netops_ai_investigations_total{outcome="no_evidence"} 1`,
		`netops_ai_tool_error_recovery_total{result="recovered"} 1`,
		`netops_ai_tool_error_recovery_total{result="unrecovered"} 1`,
		`netops_ai_tool_calls_total{outcome="ok"} 3`,
		`netops_ai_skill_hops_total{selected="model"} 1`,
		`netops_ai_skill_hops_rejected_total 1`,
		`netops_ai_investigation_cutoffs_total{budget="time"} 1`,
	)
}

func TestTokensCountOnlyWhenTheProviderReportedThem(t *testing.T) {
	m := NewMetrics(Price{InputUSDPerMTok: 3, OutputUSDPerMTok: 15})
	m.ObserveProviderCall(ProviderCall{InputTokens: 999, OutputTokens: 999, Reported: false})
	out := render(m)
	mustContain(t, out,
		`netops_ai_provider_calls_total{usage_reported="no"} 1`,
		`netops_ai_model_tokens_total{direction="input"} 0`,
		`netops_ai_scorecard_censored{metric="ai_cost_per_investigation",reason="`+ReasonNoProviderUsage+`"} 1`,
	)
	m.ObserveProviderCall(ProviderCall{InputTokens: 1_000_000, OutputTokens: 100_000, Reported: true, Investigation: true})
	out = render(m)
	mustContain(t, out,
		`netops_ai_model_tokens_total{direction="input"} 1000000`,
		`netops_ai_investigation_tokens_total{direction="output"} 100000`,
		`netops_ai_model_price_configured 1`,
		`netops_ai_model_cost_usd_total 4.500000`,
		`netops_ai_scorecard_available{metric="ai_cost_per_investigation"} 1`,
	)
}

func TestPriceConfiguredRejectsNonsense(t *testing.T) {
	nan := func() float64 { var z float64; return z / z }()
	for _, p := range []Price{{}, {InputUSDPerMTok: -1, OutputUSDPerMTok: 5}, {InputUSDPerMTok: nan}} {
		if p.Configured() {
			t.Errorf("%+v must not be a configured price", p)
		}
	}
	if !(Price{OutputUSDPerMTok: 1}).Configured() {
		t.Error("an output-only price is a configured price")
	}
}

// fakeQuery answers the two sampler queries by recognising their FROM clause.
func fakeQuery(objects []map[string]any, signals []map[string]any, err error) Query {
	return func(_ context.Context, sql string) ([]map[string]any, error) {
		if err != nil {
			return nil, err
		}
		if strings.Contains(sql, "netops.corr_current") {
			return objects, nil
		}
		return signals, nil
	}
}

func TestSamplerSuccessRendersCompressionAndCensorsHonestly(t *testing.T) {
	m := NewMetrics(Price{})
	s := NewSampler(m, Deps{Query: fakeQuery(
		[]map[string]any{{"objects": "10", "signals_folded": float64(200), "tier_undetermined": 4, "tier_suspected": 5, "tier_confirmed": 1, "evidence_backed": 0, "single_modality": 10}},
		[]map[string]any{{"signals": "1000"}}, nil)})
	got := s.Sample(context.Background())
	if got.Err != "" || got.Objects != 10 || got.SignalsIngested != 1000 {
		t.Fatalf("sample = %+v", got)
	}
	out := render(m)
	mustContain(t, out,
		`netops_corr_objects 10`,
		`netops_corr_compression_ratio{basis="ingest"} 100.0000`,
		`netops_corr_compression_ratio{basis="folded"} 20.0000`,
		`netops_corr_objects_by_tier{tier="confirmed"} 1`,
		`netops_ai_scorecard_available{metric="alert_compression_ratio"} 1`,
		// Zero evidence-backed objects: the headline KPI is censored for the
		// WORKLOAD reason first, not the store-shape one.
		`netops_ai_scorecard_censored{metric="time_to_evidence_backed_diagnosis",reason="`+ReasonSingleModalityWorkload+`"} 1`,
		`netops_ai_scorecard_censored{metric="rca_top3_accuracy",reason="`+ReasonNoRankLabelledGroundTruth+`"} 1`,
	)
}

func TestSamplerFailureEmitsNoValueGauges(t *testing.T) {
	cases := map[string]Deps{
		"nil query":   {},
		"query error": {Query: fakeQuery(nil, nil, errors.New("boom"))},
		"wrong shape": {Query: fakeQuery([]map[string]any{{}, {}}, nil, nil)},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			m := NewMetrics(Price{})
			if got := NewSampler(m, d).Sample(context.Background()); got.Err == "" {
				t.Fatal("a failed pass must carry Err")
			}
			out := render(m)
			mustNotContain(t, out, "netops_corr_objects ", "netops_corr_compression_ratio", "netops_corr_signals_ingested")
			mustContain(t, out, `netops_ai_scorecard_censored{metric="alert_compression_ratio",reason="`+ReasonStoreUnreadable+`"} 1`)
		})
	}
}

func TestSamplerSQLIsNarrowAndWindowBounded(t *testing.T) {
	sql := objectsSQL(3600)
	for _, want := range []string{"netops.corr_current FINAL", "INTERVAL 3600 SECOND", "state != 'merged'", "debug_excluded = 0", "chaos_fixture = ''"} {
		if !strings.Contains(sql, want) {
			t.Errorf("objects SQL missing %q", want)
		}
	}
	if strings.Contains(sql, "hypotheses") {
		t.Error("the sampler must never read the hypotheses blob")
	}
	if !strings.Contains(signalsSQL(60), "INTERVAL 60 SECOND") {
		t.Error("signals SQL must be window-bounded")
	}
}

func TestRunSamplerStopsOnCancel(t *testing.T) {
	m := NewMetrics(Price{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewSampler(m, Deps{SampleEvery: time.Hour}).RunSampler(ctx)
		close(done)
	}()
	deadline := time.After(2 * time.Second)
	for {
		if _, _, passes := m.Snapshot(); passes > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("RunSampler must sample once immediately")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunSampler must return on cancel")
	}
}

func TestNilMetricsIsANoOp(t *testing.T) {
	var m *Metrics
	m.ObserveAnswer(true, 1, 1)
	m.ObserveGuard("fabricated_citation", 1)
	m.ObserveInvestigation(Investigation{Outcome: "answered"})
	m.ObserveProviderCall(ProviderCall{Reported: true})
	if out := render(m); out != "" {
		t.Fatalf("a nil scorecard must render nothing, got %q", out)
	}
	NewSampler(nil, Deps{}).RunSampler(context.Background()) // returns immediately
}

// §3a: the exposition is scraped from a surface that is not tenant-scoped, so no
// series may carry a tenant/device/entity label.
func TestExpositionCarriesNoTenantOrEntityLabel(t *testing.T) {
	m := NewMetrics(Price{InputUSDPerMTok: 1})
	m.ObserveAnswer(true, 1, 1)
	m.ObserveInvestigation(Investigation{Outcome: "answered", ToolCalls: []string{"error"}})
	m.ObserveProviderCall(ProviderCall{InputTokens: 1, Reported: true})
	NewSampler(m, Deps{Query: fakeQuery(
		[]map[string]any{{"objects": 1, "signals_folded": 1, "evidence_backed": 1}},
		[]map[string]any{{"signals": 1}}, nil)}).Sample(context.Background())
	labelKey := regexp.MustCompile(`[{,]([a-z_]+)=`)
	allowed := map[string]bool{"grounded": true, "guard": true, "outcome": true, "selected": true, "result": true,
		"budget": true, "usage_reported": true, "direction": true, "tier": true, "basis": true, "metric": true, "reason": true, "le": true}
	for _, mt := range labelKey.FindAllStringSubmatch(render(m), -1) {
		if !allowed[mt[1]] {
			t.Errorf("label %q is not in the closed, entity-free label set", mt[1])
		}
	}
}
