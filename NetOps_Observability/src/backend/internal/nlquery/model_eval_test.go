// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build nlqmodeleval

package nlquery_test

// model_eval_test.go — the model path against a REAL provider (N-C6 offline
// harness). Build-tagged: CI never compiles it, so CI never calls a provider.
// Run it by hand, with a key you are allowed to spend:
//
//	NLQ_EVAL_PROVIDER=anthropic NLQ_EVAL_API_KEY=... NLQ_EVAL_MODEL=... \
//	  go test -tags nlqmodeleval ./internal/nlquery -run TestModelPathLiveProvider -v -timeout 60m
//
// NLQ_EVAL_MAX bounds how many phrasings are sent (default 60). It reports the
// model path SEPARATELY from the grammar: coverage (accepted / answerable),
// answered precision (right / accepted), refusals by reason, and safety (an
// accepted answer to a question the corpus refuses, or naming another
// tenant's entity) — safety must be zero.

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/modelc"
)

type liveModel struct{ provider, key, model string }

func (m liveModel) Complete(ctx context.Context, system string, msgs []modelc.Message) (string, error) {
	cm := make([]ai.ChatMessage, 0, len(msgs))
	for _, x := range msgs {
		cm = append(cm, ai.ChatMessage{Role: x.Role, Content: x.Content})
	}
	c, err := ai.CallProviderUsage(ctx, m.provider, m.key, m.model, system, cm)
	return c.Text, err
}

func TestModelPathLiveProvider(t *testing.T) {
	m := liveModel{provider: ai.NormalizeProvider(os.Getenv("NLQ_EVAL_PROVIDER")), key: os.Getenv("NLQ_EVAL_API_KEY"), model: os.Getenv("NLQ_EVAL_MODEL")}
	if m.provider == "" || m.key == "" || m.model == "" {
		t.Skip("set NLQ_EVAL_PROVIDER, NLQ_EVAL_API_KEY and NLQ_EVAL_MODEL to run the live model evaluation")
	}
	limit := 60
	if v, err := strconv.Atoi(os.Getenv("NLQ_EVAL_MAX")); err == nil && v > 0 {
		limit = v
	}
	cat := catalog.MustLoad()
	w := loadWorld(t)
	ps, total := unparsedPhrasings(t, cat, w)
	if len(ps) > limit {
		ps = ps[:limit]
	}
	start := time.Now()
	tally := runModelPath(t, cat, w, ps, func(phrasing) modelc.Model { return m })
	t.Logf("live %s/%s over %d of %d golden phrasings the grammar left Unparsed (%s)", m.provider, m.model, len(ps), total, time.Since(start).Round(time.Second))
	t.Logf("model path: %s", tally)
	t.Logf("coverage %.3f · answered precision %.3f", ratio(tally.accepted, tally.answerable), ratio(tally.correct, tally.accepted))
	for _, s := range tally.safety {
		t.Errorf("SAFETY: %s", s)
	}
}
