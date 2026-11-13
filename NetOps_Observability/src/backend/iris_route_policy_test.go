// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_route_policy_test.go — the Iris routing policy end to end through
// /api/ai/ask (ai/route_policy.go, owner 2026-11-12):
//
//   - a question the deterministic path covers is answered there and never
//     calls the model (the cost guard);
//   - a question it does not cover goes to the model, grounded in the
//     caller's data, with invented citations stripped;
//   - with no model, the built-in answer says the model did not answer;
//   - a multi-part question is answered part by part, or by the model when a
//     part is not covered;
//   - a problem in view (RCA workspace context) is the subject of every
//     question, never product help, at one model call — and another tenant's
//     problem id is the honest not-found answer with no evidence (§3a);
//   - the decision is logged and counted.
//
// No real provider is called: Gemini, ClickHouse and VictoriaMetrics are
// local fakes.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aiprovider"
	"netops/backend/internal/aiscore"
	"netops/backend/models"
)

// routeGemini is a Gemini endpoint that records each request body and answers
// every call with one text reply.
type routeGemini struct {
	mu     sync.Mutex
	bodies []string
	reply  string
}

func (g *routeGemini) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.bodies...)
}

func (g *routeGemini) reset() { g.mu.Lock(); g.bodies = nil; g.mu.Unlock() }

func startRouteGemini(t *testing.T, reply string) *routeGemini {
	t.Helper()
	g := &routeGemini{reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.bodies = append(g.bodies, string(b))
		text := g.reply
		g.mu.Unlock()
		out, _ := json.Marshal(map[string]any{
			"candidates":    []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}}, "finishReason": "STOP"}},
			"usageMetadata": map[string]any{"promptTokenCount": 10, "candidatesTokenCount": 5},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(ai.SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	return g
}

const routeProblemID = "4fdcb775-6e0c-4827-8c23-31467149ebff"

// routeStores fakes ClickHouse and VictoriaMetrics. ClickHouse is HOSTILE for
// the correlation object: it returns tenant A's problem to every caller, so
// anything another tenant gets back is the app layer's doing (§3a).
func routeStores(t *testing.T) {
	t.Helper()
	row := `{"correlation_id":"` + routeProblemID + `","tenant_id":"t-a","top_hypothesis":"sig.wan.flap",
		"top_confidence":0.62,"verdict_tier":"suspected","evidence_missing":"[]","affected":"[\"dev-a\"]",
		"hypotheses":"[]","signal_count":3,"node_count":2,"created_at":"2026-11-12T01:00:00Z"}`
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "corr_objects") {
			_, _ = w.Write([]byte(`{"data":[` + row + `]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
}

// routeFixture is the /api/ai/ask fixture with (or without) a platform model.
func routeFixture(t *testing.T, withModel bool) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	routeStores(t)
	s, a, b := nlqAPIFixture(t)
	clearAIEnv(t)
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil)
	if withModel {
		s.copilotCfg.Set(copilotConfig{Provider: "gemini", Key: platformKey})
	}
	if s.aiTenantCfg == nil {
		s.aiTenantCfg = newAITenantConfigStore(t.TempDir()+"/ai_tenant_config.json", nil)
	}
	s.aiBreaker = aiprovider.NewBreaker(aiprovider.Config{Threshold: 1000, Cooldown: time.Hour})
	s.aiProvCalls = aiprovider.NewMetrics(s.aiBreaker)
	s.aiScore = aiscore.NewMetrics(aiscore.Price{})
	return s, a, b
}

func askIrisCtx(t *testing.T, s *server, c jwtClaims, question string, uiContext map[string]string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"question": question, "context": uiContext})
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(string(body)))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIAsk(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ask %q: %d %s", question, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func routingOf(out map[string]any) (string, string) {
	r, _ := out["routing"].(map[string]any)
	p, _ := r["path"].(string)
	rs, _ := r["reason"].(string)
	return p, rs
}

func citationIDs(out map[string]any) []string {
	var ids []string
	cs, _ := out["citations"].([]any)
	for _, c := range cs {
		if m, ok := c.(map[string]any); ok {
			id, _ := m["id"].(string)
			ids = append(ids, id)
		}
	}
	return ids
}

// The question the deterministic path cannot cover. No method claims it.
const uncoveredQuestion = "how chatty is the frobnicator on edge-a"

func TestAnUncoveredQuestionIsAnsweredByTheModel(t *testing.T) {
	s, a, _ := routeFixture(t, true)
	g := startRouteGemini(t, "You are in tenant t-a [scope:caller], and nothing in the data names a frobnicator [problem:00000000-0000-4000-8000-000000000000].")
	out := askIris(t, s, a, uncoveredQuestion)
	if out["mode"] != string(ai.ModeModelAnswer) {
		t.Fatalf("an uncovered question must be answered by the model: %v", out)
	}
	if p, r := routingOf(out); p != ai.RoutePathModel || r != ai.RouteReasonMiss {
		t.Fatalf("routing = %s/%s", p, r)
	}
	text, _ := out["text"].(string)
	if strings.Contains(text, "00000000-0000-4000-8000-000000000000") {
		t.Fatalf("an invented citation must be stripped (§15 grounding): %q", text)
	}
	if ids := citationIDs(out); len(ids) != 1 || ids[0] != "scope:caller" {
		t.Fatalf("only the evidence the answer cites is a citation: %v", ids)
	}
	calls := g.calls()
	if len(calls) == 0 || len(calls) > 2 {
		t.Fatalf("one rephrase (fast) and one answer at most, got %d calls", len(calls))
	}
	for _, c := range calls {
		if strings.Contains(c, "Translate the QUESTION") {
			t.Fatal("the strong compile's repair loop must not run before the model answer (the 12.9 s miss)")
		}
		if strings.Contains(c, platformKey) {
			t.Fatal("the key must never be in a prompt")
		}
	}
	// The system prompt is the server's (LLM01) and the evidence is fenced.
	last := calls[len(calls)-1]
	if !strings.Contains(last, "evidence-grounded NOC assistant") || !strings.Contains(last, "EVIDENCE (cite ids)") {
		t.Fatalf("the model answer must carry the server-owned prompt and the evidence block: %.300s", last)
	}
	if strings.Contains(last, "t-b") || strings.Contains(last, "edge-b") {
		t.Fatal("LEAK: another tenant's data in tenant A's prompt")
	}
}

func TestWithoutAModelTheBuiltInAnswerSaysSo(t *testing.T) {
	s, a, _ := routeFixture(t, false)
	out := askIris(t, s, a, uncoveredQuestion)
	if out["mode"] != string(ai.ModeUnavailable) || out["intent"] != "capability" {
		t.Fatalf("no model: the built-in clarification: %v", out)
	}
	if p, r := routingOf(out); p != ai.RoutePathModelUnavailable || r != ai.RouteReasonMiss {
		t.Fatalf("routing = %s/%s", p, r)
	}
	if note, _ := out["provider_note"].(string); !strings.Contains(note, "No AI model is connected") {
		t.Fatalf("the answer must say no model answered, and why: %q", note)
	}
}

// The cost guard: a question the deterministic path covers never calls the
// model — including the two lab utterances of 2026-11-12, which the grammar
// now reads (verdict referents; "connected" no longer rewritten).
func TestACoveredQuestionNeverCallsTheModel(t *testing.T) {
	s, a, _ := routeFixture(t, true)
	g := startRouteGemini(t, "unused")
	for _, q := range []string{
		"which devices are down right now?",
		"Check RCA and identify the one which has confirmed",
		"list critical issues",
		"tell me which tenant are we in and how many devices are connected and how are they discovereD?",
	} {
		g.reset()
		out := askIris(t, s, a, q)
		if p, _ := routingOf(out); p != ai.RoutePathDeterministic {
			t.Errorf("%q: routing %v, want deterministic: %v", q, out["routing"], out["text"])
		}
		if n := len(g.calls()); n != 0 {
			t.Errorf("%q: a covered question called the model %d times", q, n)
		}
	}
}

func TestTheOwnersCompoundQuestionIsAnsweredPartByPart(t *testing.T) {
	s, a, _ := routeFixture(t, false)
	out := askIris(t, s, a, "tell me which tenant are we in and how many devices are connected and how are they discovereD?")
	if out["mode"] != string(ai.ModeDataQuery) || out["intent"] != ai.IntentMultiQuestion {
		t.Fatalf("every part is covered here: %v", out)
	}
	text, _ := out["text"].(string)
	for _, want := range []string{"You are in tenant t-a", "how many devices are connected", "Of the 1 device in your inventory: 1 by"} {
		if !strings.Contains(text, want) {
			t.Errorf("answer must contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "integration") || strings.Contains(text, "Nothing to report") {
		t.Fatalf("the integrations module must not answer it (the live regression): %s", text)
	}
	disc, _ := json.Marshal(out["disclaimers"])
	if !strings.Contains(string(disc), `I read \"connected\" as \"devices in your inventory\".`) {
		t.Fatalf("the reading of \"connected\" must be disclosed: %s", disc)
	}
	if strings.Contains(string(disc), "connector") {
		t.Fatalf("\"connected\" must never be read as \"connector\": %s", disc)
	}
}

func TestACompoundQuestionWithAnUncoveredPartGoesToTheModel(t *testing.T) {
	q := "which tenant are we in and how chatty is the frobnicator"
	s, a, _ := routeFixture(t, true)
	startRouteGemini(t, "You are in tenant t-a [scope:caller]; no data names a frobnicator.")
	out := askIris(t, s, a, q)
	if p, r := routingOf(out); out["mode"] != string(ai.ModeModelAnswer) || p != ai.RoutePathModel || r != ai.RouteReasonCompound {
		t.Fatalf("a part nothing deterministic covers sends the whole question to the model: %v", out)
	}

	s2, a2, _ := routeFixture(t, false)
	out = askIris(t, s2, a2, q)
	text, _ := out["text"].(string)
	if p, r := routingOf(out); p != ai.RoutePathModelUnavailable || r != ai.RouteReasonCompound {
		t.Fatalf("routing = %s/%s", p, r)
	}
	if !strings.Contains(text, "You are in tenant t-a") || !strings.Contains(text, "I could not answer “how chatty is the frobnicator”") {
		t.Fatalf("without a model the covered part is kept and the rest is named: %s", text)
	}
}

// RCA workspace (RCA_DOCUMENT_V2 §5): the problem in view is the subject.
var rcaContextQuestions = []string{
	"Explain this problem", "explain this", "what happened here", "why is this only suspected and what should I check?",
	"why only suspected", "what should I check", "who is affected", "what changed before this", "what am I looking at",
}

func TestAProblemInViewIsTheSubjectNeverProductHelp(t *testing.T) {
	s, a, _ := routeFixture(t, true)
	g := startRouteGemini(t, "This is a suspected WAN flap affecting edge-a [problem:"+routeProblemID+"].")
	ctx := map[string]string{"correlation_id": routeProblemID}
	for _, q := range rcaContextQuestions {
		g.reset()
		out := askIrisCtx(t, s, a, q, ctx)
		if out["mode"] == string(ai.ModeProductAnswer) || out["mode"] != string(ai.ModeProblemExplanation) {
			t.Errorf("%q with a problem in view: mode %v, want problem_explanation: %v", q, out["mode"], out["text"])
			continue
		}
		if p, r := routingOf(out); p != ai.RoutePathModel || r != ai.RouteReasonProblemContext {
			t.Errorf("%q: routing %s/%s", q, p, r)
		}
		// One model budget: the narration only — no tie-break, no rephrase,
		// no compile, no skill chain.
		if n := len(g.calls()); n != 1 {
			t.Errorf("%q: a contextual answer must make exactly one model call, made %d", q, n)
		}
	}
	// A question about the product's screens is still product help.
	if out := askIrisCtx(t, s, a, "what does this page show", ctx); out["mode"] == string(ai.ModeProblemExplanation) {
		t.Fatalf("an explicit UI question must not be read as the problem: %v", out)
	}
}

// §3a: another tenant's problem id in the context is the honest not-found
// answer — no evidence, no model call — even though the (hostile) store hands
// the row over.
func TestAnotherTenantsProblemInViewIsNotFound(t *testing.T) {
	s, _, b := routeFixture(t, true)
	g := startRouteGemini(t, "must not be called")
	out := askIrisCtx(t, s, b, "Explain this problem", map[string]string{"correlation_id": routeProblemID})
	text, _ := out["text"].(string)
	if !strings.Contains(text, "isn't available in your scope") {
		t.Fatalf("a foreign problem must read as not found: %v", out)
	}
	if ids := citationIDs(out); len(ids) != 0 {
		t.Fatalf("LEAK: evidence of another tenant's problem: %v", ids)
	}
	if out["problem"] != nil || len(g.calls()) != 0 {
		t.Fatalf("LEAK: another tenant's problem reached the answer or the model: %v (calls %d)", out["problem"], len(g.calls()))
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), "sig.wan.flap") || strings.Contains(string(b), "dev-a") {
		t.Fatalf("LEAK: tenant A's correlation intel in tenant B's answer: %s", b)
	}
}

func TestTheRoutingDecisionIsLoggedAndCounted(t *testing.T) {
	s, a, _ := routeFixture(t, false)
	logs := captureProviderLogs(t)
	askIris(t, s, a, uncoveredQuestion)
	askIris(t, s, a, "which devices are down right now?")
	if n := s.aiScore.RoutingCount(ai.RoutePathModelUnavailable, ai.RouteReasonMiss); n != 1 {
		t.Fatalf("model_unavailable/deterministic_miss counted %d, want 1", n)
	}
	if n := s.aiScore.RoutingCount(ai.RoutePathDeterministic, ai.RouteReasonCovered); n != 1 {
		t.Fatalf("deterministic/covered counted %d, want 1", n)
	}
	var found bool
	for _, l := range logs.find("ask") {
		if l["routing_path"] == ai.RoutePathModelUnavailable && l["routing_reason"] == ai.RouteReasonMiss {
			found = true
		}
	}
	if !found {
		t.Fatal("the miss must be visible in the api log with its routing path and reason")
	}
	logs.mustNotContain(t, uncoveredQuestion) // never the question text
}

// §3a for the new reads: the inventory facts (how devices were discovered)
// count the caller's own visible devices only, and the scope facts come from
// the token — an ActingTenant smuggled into a non-owner's claims changes
// neither.
func TestScopeAndInventoryFactsAreTheCallersOwn(t *testing.T) {
	s, a, b := routeFixture(t, false)
	if err := s.discovery.Upsert(models.Device{ID: "dev-b2", Name: "edge-b2", TenantID: "t-b", Source: "api:vmanage"}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	invA, _ := s.aiInventoryFacts(a)(ctx, ai.Principal{Tenant: "t-a"})
	invB, _ := s.aiInventoryFacts(b)(ctx, ai.Principal{Tenant: "t-b"})
	if invA.Total != 1 || invB.Total != 2 {
		t.Fatalf("own-only counts: A=%d B=%d (want 1, 2)", invA.Total, invB.Total)
	}
	for _, sc := range invA.BySource {
		if sc.Source == "api:vmanage" {
			t.Fatal("LEAK: tenant B's integration-sourced device counted for tenant A")
		}
	}
	smuggled := a
	smuggled.ActingTenant = "t-b"
	if inv, _ := s.aiInventoryFacts(smuggled)(ctx, ai.Principal{Tenant: "t-a"}); inv.Total != 1 {
		t.Fatalf("an ActingTenant on a non-owner must be ignored: %+v", inv)
	}
	if sf := s.aiScopeFacts(smuggled); sf.TenantID != "t-a" || sf.AllTenants || sf.Provider {
		t.Fatalf("scope facts must come from the token tenant: %+v", sf)
	}
	// The platform owner is told it is the All tenants view, or the Provider view.
	if sf := s.aiScopeFacts(aiPlatformOwn); !sf.AllTenants {
		t.Fatalf("platform owner: %+v", sf)
	}
	prov := aiPlatformOwn
	prov.ActingTenant = TenantGlobal
	if sf := s.aiScopeFacts(prov); !sf.Provider || sf.AllTenants {
		t.Fatalf("platform owner in the Provider view: %+v", sf)
	}
	out := askIris(t, s, b, "which tenant are we in and how were the devices discovered")
	text, _ := out["text"].(string)
	if !strings.Contains(text, "You are in tenant t-b") || !strings.Contains(text, "Of the 2 devices in your inventory") ||
		!strings.Contains(text, "the Cisco vManage integration") || strings.Contains(text, "t-a") {
		t.Fatalf("tenant B's own answer: %s", text)
	}
}

// The routing vocabularies are one list: aiscore repeats ai's (it does not
// import ai), so they are pinned equal here.
func TestRoutingVocabulariesAgree(t *testing.T) {
	if strings.Join(ai.RoutePaths, ",") != strings.Join(aiscore.RoutingPaths, ",") ||
		strings.Join(ai.RouteReasons, ",") != strings.Join(aiscore.RoutingReasons, ",") {
		t.Fatalf("ai %v %v ≠ aiscore %v %v", ai.RoutePaths, ai.RouteReasons, aiscore.RoutingPaths, aiscore.RoutingReasons)
	}
	// The planner's decision is ledgered as a plan step, not a tool run: the
	// ledger's mirror of its name must be the same string.
	if ai.PlannerTool != aidecision.RoutePlannerTool || ai.RouteTieBreakTool != aidecision.RouteTieBreakTool {
		t.Fatalf("router step names drifted: %q/%q vs %q/%q", ai.PlannerTool, ai.RouteTieBreakTool, aidecision.RoutePlannerTool, aidecision.RouteTieBreakTool)
	}
}

// Model-first is the AI add-on: licensed AND the models switch on. Neither
// alone turns it on (owner 2026-11-13; ai/planner.go).
func TestModelFirstNeedsTheLicensedAddOn(t *testing.T) {
	s := &server{}
	if s.aiModelFirst() {
		t.Fatal("no licence and no switch: the deterministic router decides")
	}
}
