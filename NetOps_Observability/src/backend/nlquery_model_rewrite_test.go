// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_model_rewrite_test.go — the fast rephrase stage (hybrid NLU plan B1)
// end to end through the root wiring, §3a/§15:
//
//   - on a question the grammar cannot parse, the caller's OWN provider is
//     asked for one line; the grammar reads it in the caller's scope; the
//     answer is source=model_rewrite, discloses the rephrase, and costs ONE
//     call charged to the caller's budget;
//   - a refused rephrase falls through to the strong fallback (B3);
//   - IRIS_NLQ_REWRITE=false switches the stage off alone;
//   - tenant B never gets tenant A's entity through a rephrase, and A's names
//     never reach B's prompt;
//   - the query log attributes the query to the model with the rephrase
//     disclosure, and a colleague's rephrase is withheld from an admin.

import (
	"net/http"
	"strings"
	"testing"

	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/nlquery/modelc"
)

// hotCPURephrase is what a fast model would make of hotCPUQuestion: the
// question's own device, the grammar's words ("hot", "running" replaced).
const hotCPURephrase = "average cpu utilization on edge-a"

// rewriteFixture is modelFallbackFixture with the rephrase stage ON (the
// fallback tests switch it off to test B3 alone).
func rewriteFixture(t *testing.T, reply string, keyed ...string) (*server, jwtClaims, jwtClaims, *recordingProvider) {
	t.Helper()
	s, a, b, p := modelFallbackFixture(t, reply, keyed...)
	t.Setenv("IRIS_NLQ_REWRITE", "")
	return s, a, b, p
}

func TestModelRewriteAnswersBeforeTheStrongFallback(t *testing.T) {
	s, a, _, p := rewriteFixture(t, hotCPURephrase, "t-a")
	s.nlqQueryLog = irisquerylog.NewMemStore()
	s.nlqQueryLogMetrics = irisquerylog.NewMetrics()
	out := compileQ(t, s, a, hotCPUQuestion)
	if out["source"] != modelc.SourceRewrite || out["unparsed"] == true || !strings.Contains(nlqJSON(out["ast"]), "device:dev-a") {
		t.Fatalf("the grammar's reading of the rephrase must come back marked source=model_rewrite: %v", out)
	}
	if v, _ := out["validation"].(map[string]any); v["valid"] != true {
		t.Fatalf("the query must be validated: %v", out["validation"])
	}
	if r := nlqJSON(out["readings"]); !strings.Contains(r, `"kind":"rephrase"`) || !strings.Contains(r, hotCPURephrase) {
		t.Fatalf("the rephrase must be disclosed as a reading: %s", r)
	}
	calls := p.calls()
	if len(calls) != 1 {
		t.Fatalf("one provider call expected (no strong fallback after an accepted rephrase), got %d", len(calls))
	}
	if !strings.Contains(calls[0], "You rephrase ONE network-operations question") || !strings.Contains(calls[0], `\"edge-a\"`) {
		t.Fatalf("the request must carry the rephrase system prompt and the caller's name to keep: %s", calls[0])
	}
	for _, leak := range []string{"dev-b", "edge-b", "t-b", "CorrelixQueryAST"} {
		if strings.Contains(calls[0], leak) {
			t.Errorf("the rephrase request carries %q", leak)
		}
	}
	if got := s.aiToolBudget.UsedByTenant()["t-a"]; got != 20 {
		t.Fatalf("the call must be charged to tenant A's budget: %v", got)
	}
	// The query log keeps it as model-written, with the rephrase disclosure.
	id, _ := out["query_log_id"].(string)
	code, rec, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id)
	if code != http.StatusOK || rec["compiled_by"] != irisquerylog.CompiledByModel || rec["disclosure"] != nlqRewriteDisclosure {
		t.Fatalf("GET must attribute the query to the model and disclose the rephrase: %d %v", code, rec)
	}
	code, ex, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id+"/explain")
	if code != http.StatusOK || ex["source"] != modelc.SourceModel || ex["disclosure"] != nlqRewriteDisclosure {
		t.Fatalf("explain must disclose the rephrase: %d %v", code, ex)
	}
}

func TestModelRewriteRefusedFallsThroughToTheStrongFallback(t *testing.T) {
	// The provider answers every call with an AST envelope: as a rephrase it is
	// refused (not the grammar's words), as a structured answer it is accepted.
	s, a, _, p := rewriteFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	out := compileQ(t, s, a, hotCPUQuestion)
	if out["source"] != modelc.SourceModel {
		t.Fatalf("a refused rephrase must fall through to the strong fallback: %v", out)
	}
	calls := p.calls()
	if len(calls) != 2 || !strings.Contains(calls[0], "You rephrase ONE") || !strings.Contains(calls[1], "CorrelixQueryAST") {
		t.Fatalf("want the rephrase call then the fallback call, got %d", len(calls))
	}
}

func TestModelRewriteKillSwitchIsItsOwn(t *testing.T) {
	s, a, _, p := rewriteFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	t.Setenv("IRIS_NLQ_REWRITE", "false")
	if out := compileQ(t, s, a, hotCPUQuestion); out["source"] != modelc.SourceModel {
		t.Fatalf("with the stage off the fallback still answers: %v", out)
	}
	if calls := p.calls(); len(calls) != 1 || strings.Contains(calls[0], "You rephrase ONE") {
		t.Fatalf("IRIS_NLQ_REWRITE=false must skip the rephrase call: %d calls", len(calls))
	}
	t.Setenv("IRIS_NLQ_MODEL_FALLBACK", "false")
	if out := compileQ(t, s, a, hotCPUQuestion); out["unparsed"] != true || len(p.calls()) != 1 {
		t.Fatalf("the model kill switch covers both stages: %v (calls %d)", out, len(p.calls()))
	}
}

// §3a: B naming A's device never reaches B's model; a rephrase that names A's
// device never compiles for B; A's names never reach B's prompt.
func TestModelRewriteNeverCrossesTenants(t *testing.T) {
	s, _, b, p := rewriteFixture(t, hotCPURephrase, "t-b")
	if out := compileQ(t, s, b, hotCPUQuestion); out["unparsed"] != true || out["ast"] != nil {
		t.Fatalf("tenant B must not compile tenant A's device: %v", out)
	}
	if n := len(p.calls()); n != 0 {
		t.Fatalf("a name B's resolver cannot find must not reach the model; calls=%d", n)
	}
	// B asks without a name; the "model" answers with A's device.
	out := compileQ(t, s, b, "how hot has the cpu been running lately")
	if out["source"] == modelc.SourceRewrite || strings.Contains(nlqJSON(out), "dev-a") {
		t.Fatalf("a rephrase naming A's device must be refused for B: %v", out)
	}
	// The rephrase prompt is built from B's question and B's scope only. (The
	// fallback's repair turns echo the stub's own reply, which is why only the
	// first, server-built request is inspected.)
	calls := p.calls()
	if len(calls) == 0 || !strings.Contains(calls[0], "You rephrase ONE") {
		t.Fatalf("want the rephrase call first, got %d calls", len(calls))
	}
	if strings.Contains(calls[0], "edge-a") || strings.Contains(calls[0], "dev-a") {
		t.Fatal("tenant A's device reached tenant B's prompt")
	}
}

func TestWithholdColleagueTextDropsTheRephrase(t *testing.T) {
	shared := []irisquerylog.Reading{
		{From: "is cpu sluggish on edge-a", To: "average cpu on edge-a", Kind: lex.KindRephrase},
		{From: "shwo", To: "show", Kind: lex.KindTypo},
	}
	rec := irisquerylog.Record{Question: "is cpu sluggish on edge-a", Readings: shared}
	withholdColleagueText(&rec)
	if rec.Question != "" || len(rec.Readings) != 1 || rec.Readings[0].Kind != lex.KindTypo {
		t.Fatalf("a colleague's rephrase must be withheld: %+v", rec)
	}
	if shared[0].Kind != lex.KindRephrase || len(shared) != 2 {
		t.Fatal("withholding must not touch the store's own copy")
	}
}
