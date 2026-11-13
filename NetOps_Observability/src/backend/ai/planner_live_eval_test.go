// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

//go:build nlqmodeleval

package ai

// planner_live_eval_test.go — the model planner against a REAL provider, over
// the paraphrase corpus (docs/ai/golden-examples/planner-paraphrases.json).
// Same build tag and environment as the NL query model eval
// (internal/nlquery/model_eval_test.go), so one command runs every live model
// eval; CI never compiles it, so CI never calls a provider. Run it by hand,
// with a key you are allowed to spend:
//
//	NLQ_EVAL_PROVIDER=gemini NLQ_EVAL_API_KEY=... NLQ_EVAL_MODEL=gemini-3.5-flash-lite \
//	  go test -tags nlqmodeleval ./ai -run TestPlannerLiveProvider -v -timeout 60m
//
// PLANNER_EVAL_MAX bounds how many phrasings are sent (default: all). It
// reports accuracy per route and overall, every miss with what the model
// chose, and fails below plannerLiveFloor. A reply outside the closed
// vocabulary counts as a miss AND is listed: the planner never acts on one.

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

// plannerLiveFloor is the minimum overall routing accuracy a provider must
// reach on the corpus (the owner's goal: understood however it is asked).
const plannerLiveFloor = 0.90

type livePlannerLLM struct{ provider, key, model string }

func (m livePlannerLLM) Complete(ctx context.Context, system string, msgs []LLMMessage) (string, string, error) {
	cm := make([]ChatMessage, 0, len(msgs))
	for _, x := range msgs {
		cm = append(cm, ChatMessage{Role: x.Role, Content: x.Content})
	}
	text, err := CallProvider(ctx, m.provider, m.key, m.model, system, cm)
	return text, m.provider, err
}

func TestPlannerLiveProvider(t *testing.T) {
	provider, key, model := os.Getenv("NLQ_EVAL_PROVIDER"), os.Getenv("NLQ_EVAL_API_KEY"), os.Getenv("NLQ_EVAL_MODEL")
	if provider == "" || key == "" {
		t.Skip("set NLQ_EVAL_PROVIDER and NLQ_EVAL_API_KEY to run the live planner eval")
	}
	sk, err := LoadSkills()
	if err != nil {
		t.Fatal(err)
	}
	c := loadParaphrases(t)
	type item struct{ q, route, module string }
	var items []item
	for route, qs := range c.Routes {
		for _, q := range qs {
			items = append(items, item{q, route, ""})
		}
	}
	for _, it := range c.ModuleItems {
		items = append(items, item{it.Q, PlanRouteModule, it.Module})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].q < items[j].q })
	if n, err := strconv.Atoi(os.Getenv("PLANNER_EVAL_MAX")); err == nil && n > 0 && n < len(items) {
		items = items[:n]
	}
	o := &Orchestrator{LLM: livePlannerLLM{provider, key, model}, Skills: sk, Scope: &ScopeFacts{TenantID: "t-eval"}}
	o.ModelBudgets = StageBudgets{Fast: 20 * time.Second}
	right, invalid := map[string]int{}, 0
	totals := map[string]int{}
	for _, it := range items {
		totals[it.route]++
		ch, ok, err := o.planRoute(context.Background(), Principal{Tenant: "t-eval"}, it.q, false)
		switch {
		case !ok && err != nil && !errors.Is(err, errPlannerInvalid):
			t.Fatalf("provider failed on %q: %v", it.q, err)
		case !ok:
			invalid++
			t.Logf("INVALID  %-14s %q", it.route, it.q)
		case ch.Route == it.route && (it.module == "" || ch.Module == it.module):
			right[it.route]++
		default:
			t.Logf("MISS     %-14s → %-14s %q", it.route, ch.Route, it.q)
		}
	}
	routes := make([]string, 0, len(totals))
	for r := range totals {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	sum := 0
	for _, r := range routes {
		sum += right[r]
		t.Logf("planner  %-18s %2d/%2d", r, right[r], totals[r])
	}
	acc := float64(sum) / float64(len(items))
	t.Logf("planner overall: %d/%d (%.1f%%), invalid replies %d — provider %s model %s", sum, len(items), 100*acc, invalid, provider, model)
	if acc < plannerLiveFloor {
		t.Fatalf("routing accuracy %.3f is below the floor %.2f", acc, plannerLiveFloor)
	}
}
