// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_model_fallback_test.go — the NL query model fallback (tracker 337
// N-C5) end to end through the root wiring, §3a/§15:
//
//   - a question the grammar cannot parse is compiled by the caller's OWN
//     provider, marked source=model, and validated in the caller's scope;
//   - no provider, the kill switch, or a spent budget ⇒ no provider call and
//     the grammar's honest "not understood" (key-free behaviour unchanged);
//   - tenant B never gets tenant A's entity, neither by naming it nor by a
//     model that emits A's id — and A's names never reach B's prompt;
//   - the /api/ai/ask data arm discloses a model interpretation.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/nlquery/modelc"
)

// recordingProvider answers every provider call with one OpenAI-shaped
// completion carrying reply, and records each request body.
type recordingProvider struct {
	reply  string
	mu     sync.Mutex
	bodies []string
}

func (p *recordingProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.bodies = append(p.bodies, string(b))
	p.mu.Unlock()
	content, err := json.Marshal(p.reply)
	if err != nil {
		return nil, err
	}
	body := `{"choices":[{"message":{"content":` + string(content) + `}}],"usage":{"prompt_tokens":10,"completion_tokens":10}}`
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader([]byte(body))), Request: r}, nil
}

func (p *recordingProvider) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.bodies...)
}

func modelEnvelope(astJSON string) string { return `{"ast":` + astJSON + `,"unmatched_names":[]}` }

const cpuOnDevA = `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:dev-a"}],"time_range":{"kind":"relative","last":"1h"}}`

// The grammar leaves this Unparsed ("hot", "running"); a model can read it.
const hotCPUQuestion = "how hot has the cpu been running on edge-a"

// modelFallbackFixture is nlqAPIFixture with the AI config stores and a
// recording provider; tenants listed in keyed get their own (BYO) key.
func modelFallbackFixture(t *testing.T, reply string, keyed ...string) (*server, jwtClaims, jwtClaims, *recordingProvider) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	for _, k := range []string{"OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "COPILOT_API_KEY", "IRIS_NLQ_MODEL_FALLBACK"} {
		t.Setenv(k, "")
	}
	p := &recordingProvider{reply: reply}
	t.Cleanup(ai.SwapProviderHTTPForTest(&http.Client{Transport: p}))
	s, a, b := nlqAPIFixture(t)
	dir := t.TempDir()
	s.aiToolBudget = ai.NewDailyBudget()
	s.copilotCfg = newCopilotConfigStore(dir+"/copilot_config.json", nil)
	s.aiTenantCfg = newAITenantConfigStore(dir+"/ai_tenant_config.json", nil)
	for _, tenant := range keyed {
		if _, err := s.aiTenantCfg.SetTenantSettings(tenant, ai.TenantSettings{Provider: "openai", Model: "gpt-4o-mini", Key: "sk-test"}); err != nil {
			t.Fatal(err)
		}
	}
	return s, a, b, p
}

func compileQ(t *testing.T, s *server, c jwtClaims, question string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]string{"question": question})
	if err != nil {
		t.Fatal(err)
	}
	code, out := nlqAPI(t, s, c, "/api/ai/query/compile", string(body))
	if code != http.StatusOK {
		t.Fatalf("compile %q: %d %v", question, code, out)
	}
	return out
}

func TestModelFallbackCompilesWhatTheGrammarCannot(t *testing.T) {
	s, a, _, p := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	out := compileQ(t, s, a, hotCPUQuestion)
	if out["source"] != modelc.SourceModel || out["unparsed"] == true || !strings.Contains(nlqJSON(out["ast"]), "device:dev-a") {
		t.Fatalf("the model's validated query must come back marked source=model: %v", out)
	}
	if v, _ := out["validation"].(map[string]any); v["valid"] != true {
		t.Fatalf("the model's query must be validated: %v", out["validation"])
	}
	calls := p.calls()
	if len(calls) != 1 {
		t.Fatalf("one provider call expected, got %d", len(calls))
	}
	req := calls[0]
	if !strings.Contains(req, "CorrelixQueryAST") || !strings.Contains(req, "device:dev-a") {
		t.Fatal("the request must carry the server's system prompt and the caller's resolved device")
	}
	for _, leak := range []string{"dev-b", "edge-b", "t-b"} {
		if strings.Contains(req, leak) {
			t.Errorf("tenant A's prompt carries %q", leak)
		}
	}
	if s.aiToolBudget.UsedByTenant()["t-a"] != 20 {
		t.Fatalf("the call must be charged to tenant A's budget: %v", s.aiToolBudget.UsedByTenant())
	}
	// The grammar's own answers never reach the model.
	if out := compileQ(t, s, a, "show cpu on edge-a for the last hour"); out["source"] != nil || len(p.calls()) != 1 {
		t.Fatalf("a question the grammar parses must not call the model: %v (calls %d)", out, len(p.calls()))
	}
	if out := compileQ(t, s, a, "restart edge-a"); out["decline"] != "not_a_query" || len(p.calls()) != 1 {
		t.Fatalf("a declined question must not call the model: %v", out)
	}
}

func TestModelFallbackIsUnavailableWithoutAProvider(t *testing.T) {
	s, a, _, p := modelFallbackFixture(t, modelEnvelope(cpuOnDevA)) // no key anywhere
	if out := compileQ(t, s, a, hotCPUQuestion); out["unparsed"] != true || out["source"] != nil {
		t.Fatalf("no provider ⇒ the grammar's honest answer: %v", out)
	}
	s2, a2, _, p2 := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	t.Setenv("IRIS_NLQ_MODEL_FALLBACK", "false")
	if out := compileQ(t, s2, a2, hotCPUQuestion); out["unparsed"] != true {
		t.Fatalf("the kill switch must disable the fallback: %v", out)
	}
	if len(p.calls())+len(p2.calls()) != 0 {
		t.Fatal("no provider may be called")
	}
}

// LLM04: a tenant that has spent its daily budget gets no provider call.
func TestModelFallbackRespectsTheTenantBudget(t *testing.T) {
	t.Setenv("AI_TOOLS_DAILY_TOKENS", "100")
	s, a, _, p := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	s.aiToolBudget.Charge("t-a", 100)
	if out := compileQ(t, s, a, hotCPUQuestion); out["unparsed"] != true || out["source"] != nil {
		t.Fatalf("a spent budget ⇒ Unparsed: %v", out)
	}
	if n := len(p.calls()); n != 0 {
		t.Fatalf("a spent budget must refuse BEFORE the provider is called; calls=%d", n)
	}
}

// §3a: B naming A's device, or B's model emitting A's id, never compiles.
func TestModelFallbackNeverCrossesTenants(t *testing.T) {
	s, _, b, p := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-b")
	if out := compileQ(t, s, b, hotCPUQuestion); out["unparsed"] != true || out["ast"] != nil {
		t.Fatalf("tenant B must not compile tenant A's device: %v", out)
	}
	if n := len(p.calls()); n != 0 {
		t.Fatalf("a name B's resolver cannot find must not even reach the model; calls=%d", n)
	}
	out := compileQ(t, s, b, "how hot has the cpu been running lately")
	if out["unparsed"] != true || out["ast"] != nil || strings.Contains(nlqJSON(out), "dev-a") {
		t.Fatalf("a model-emitted foreign id must be refused: %v", out)
	}
	calls := p.calls()
	if len(calls) != 1+modelc.MaxRepairRounds {
		t.Fatalf("want the first try plus %d repairs, got %d calls", modelc.MaxRepairRounds, len(calls))
	}
	for _, c := range calls {
		if strings.Contains(c, "edge-a") {
			t.Fatal("tenant A's device name reached tenant B's prompt")
		}
	}
}

func TestTheDataArmDisclosesAModelInterpretation(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"],[2,"48"]]}]}}`)) // best-effort: a stub VictoriaMetrics reply
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, _, _ := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	out := askIris(t, s, a, hotCPUQuestion)
	if out["mode"] != "data_query" {
		t.Fatalf("the model-compiled query must answer on the data arm: %v", out)
	}
	if !strings.Contains(nlqJSON(out["disclaimers"]), "Interpreted by the AI model") {
		t.Fatalf("a model interpretation must be disclosed: %v", out["disclaimers"])
	}
	if !strings.Contains(nlqJSON(out["data"]), `"source":"model"`) {
		t.Fatalf("the payload must mark the query as model-compiled: %v", out["data"])
	}
}

// The compile_query tool interprets in the caller's scope and never runs.
func TestCompileQueryToolInterpretsInScope(t *testing.T) {
	var reads atomic.Int32
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		_, _ = w.Write([]byte(`{"data":{"result":[]}}`)) // best-effort: a stub VictoriaMetrics reply
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b, _ := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a", "t-b")
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil)
	fa := s.aiCompileQuery(r, a)
	if fa == nil {
		t.Fatal("an infrastructure reader must get compile_query")
	}
	in, err := fa(r.Context(), ai.Principal{Tenant: "t-a"}, hotCPUQuestion)
	if err != nil || in.Status != ai.QueryCompiled || in.Source != modelc.SourceModel || !strings.Contains(string(in.Query), "device:dev-a") {
		t.Fatalf("tenant A: %+v %v", in, err)
	}
	in, err = s.aiCompileQuery(r, b)(r.Context(), ai.Principal{Tenant: "t-b"}, "show cpu on edge-a for the last hour")
	if err != nil || in.Status == ai.QueryCompiled || strings.Contains(string(in.Query), "dev-a") {
		t.Fatalf("tenant B must not compile tenant A's device: %+v %v", in, err)
	}
	if n := reads.Load(); n != 0 {
		t.Fatalf("compile_query must never read data (%d reads)", n)
	}
	viewer := a
	viewer.Role = "no-such-role"
	if s.aiCompileQuery(r, viewer) != nil {
		t.Fatal("a caller without infrastructure:read must not get compile_query")
	}
}
