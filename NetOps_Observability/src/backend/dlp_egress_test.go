package backend

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/ai"
)

// dlp_egress_test.go — audit PIPE-MED-5: the outbound data-loss-prevention layer.
//
// The defect was not a missing filter, it was a filter DECLARED and never
// WIRED: ai.Orchestrator.Redactor existed, was applied at three prompt sites,
// and was nil at the only construction site — so redact() was the identity
// function in production while the agent loop rendered raw tenant rows straight
// into the conversation and shipped them to OpenAI/Gemini/Anthropic.
//
// These tests hold three lines:
//  1. the wiring is explicit at every construction site (structural guard);
//  2. a tool result carrying a credential never reaches the provider payload
//     (behavioural, end-to-end through the real encoder + the real egress);
//  3. the syslog tool's per-line redaction uses the shared dialect, so coverage
//     added in ai/redact.go reaches it too.

// ---- Guard 1: every construction site wires the redactor -------------------

// TestEveryOrchestratorConstructionWiresARedactor fails when an
// ai.Orchestrator composite literal omits Redactor.
//
// The nil-Redactor fallback in ai/redact.go already makes a forgotten field
// SAFE (it defaults to ai.Redact, never to identity — see
// TestOrchestratorCannotBeConstructedWithoutARedactor). This guard is the
// second half: it keeps the egress filter VISIBLE at the call site, so a
// reviewer reading newOrchestrator can see that outbound redaction is wired
// rather than having to know about a fallback three packages away. Silent
// defaults are how the original defect survived review.
func TestEveryOrchestratorConstructionWiresARedactor(t *testing.T) {
	fset := token.NewFileSet()
	found := 0
	for path, src := range dlpGoSources(t) {
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isOrchestratorType(lit.Type) {
				return true
			}
			found++
			for _, el := range lit.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Redactor" {
						return true
					}
				}
			}
			t.Errorf("%s:%d constructs an ai.Orchestrator without a Redactor. Everything the "+
				"orchestrator sends to an external LLM provider must pass the outbound DLP "+
				"filter (CLAUDE.md §15/LLM06) — set `Redactor: ai.Redact`.",
				path, fset.Position(lit.Pos()).Line)
			return true
		})
	}
	if found == 0 {
		t.Fatal("this guard found NO ai.Orchestrator construction site — it has stopped " +
			"testing anything (was the type renamed?). Fix the guard, do not delete it.")
	}
}

// isOrchestratorType matches `ai.Orchestrator{...}` and, inside package ai
// itself, `Orchestrator{...}`.
func isOrchestratorType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "ai" && t.Sel.Name == "Orchestrator"
	case *ast.Ident:
		return t.Name == "Orchestrator"
	}
	return false
}

// dlpGoSources reads the non-test, non-vendored Go sources of the backend
// module. Deliberately self-contained (rather than reusing the helper in
// architecture_guards_test.go) so this guard cannot be disabled as a side
// effect of an unrelated edit to another guard file.
func dlpGoSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend sources: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no Go sources found — the guard would pass vacuously")
	}
	return out
}

// ---- Guard 2: a tool result never carries a credential to the provider -----

// capturingTransport records the request body instead of performing the call,
// so the assertion is on the exact bytes that would have gone to the provider.
type capturingTransport struct{ body []byte }

func (c *capturingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		c.body, _ = io.ReadAll(r.Body)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    r,
	}, nil
}

// TestToolResultCredentialNeverReachesProviderPayload is the end-to-end proof
// for the defect the audit found: a tool returns a syslog row containing an
// SNMP community string and a client MAC, the agent loop renders it into the
// conversation, and the conversation is encoded and shipped to OpenAI. The
// assertion is made on the wire bytes, after the real encoder — not on an
// intermediate string — because that is where a leak would actually happen.
func TestToolResultCredentialNeverReachesProviderPayload(t *testing.T) {
	result := ai.ToolResult{
		Items: []ai.EvidenceItem{{
			CitationID: "log:1",
			Kind:       "log",
			Text:       "rtr1 CONFIG: snmp-server community S3cr3tR0 RW; admin password=hunter2; client a4:83:e7:1b:2c:3d assoc; user=jsmith@corp.example.com",
		}},
		Notes: []string{"bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln in upstream reply"},
	}
	rendered := ai.RenderToolReply(&result)

	// The rendered block is what re-enters the conversation.
	for _, secret := range []string{"S3cr3tR0", "hunter2", "a4:83:e7:1b:2c:3d", "jsmith@corp.example.com", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("renderToolReply leaked %q into the prompt block:\n%s", secret, rendered)
		}
	}
	// …and it must still be useful evidence.
	for _, keep := range []string{"log:1", "rtr1", "a4:83:e7"} {
		if !strings.Contains(rendered, keep) {
			t.Errorf("renderToolReply destroyed useful evidence %q:\n%s", keep, rendered)
		}
	}

	cap := &capturingTransport{}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()

	turns := []ai.AgentTurn{
		{Role: "user", Content: "what changed on rtr1?"},
		{Role: "assistant", Calls: []ai.ToolCall{{ID: "c1", Name: "search_logs", Args: []byte(`{"query":"rtr1"}`)}}},
		{Role: "user", Replies: []ai.ToolReply{{ID: "c1", Name: "search_logs", Content: rendered}}},
	}
	if _, _, err := ai.CallTools(context.Background(), ai.ProviderDo, "openai", "test-key", "gpt-4o-mini", "system", turns, nil); err != nil {
		t.Fatalf("ai.CallTools: %v", err)
	}
	payload := string(cap.body)
	if payload == "" {
		t.Fatal("no provider payload captured — the test proved nothing")
	}
	for _, secret := range []string{"S3cr3tR0", "hunter2", "a4:83:e7:1b:2c:3d", "jsmith@corp.example.com", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(payload, secret) {
			t.Errorf("PROVIDER PAYLOAD carries %q — a credential/identifier left the process (LLM06):\n%s", secret, payload)
		}
	}
}

// TestProviderPayloadSweepCatchesAnUnredactedAssembler proves the LAST-line
// backstop in providerDo independently of the loop: even if a future assembler
// forgets to redact, credential-shaped material cannot reach the wire. This is
// the difference between fixing today's leak and closing the class.
func TestProviderPayloadSweepCatchesAnUnredactedAssembler(t *testing.T) {
	cap := &capturingTransport{}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()

	// A raw, deliberately UNredacted body — as a careless new caller would build.
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"deploy with api_key=sk-live-AAAAAAAAAAAAAAAAAAAA and password: hunter2"}]}`)
	if _, err := ai.ProviderDo(context.Background(), "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatalf("providerDo: %v", err)
	}
	payload := string(cap.body)
	for _, secret := range []string{"sk-live-AAAAAAAAAAAAAAAAAAAA", "hunter2"} {
		if strings.Contains(payload, secret) {
			t.Errorf("the provider-payload sweep let %q through:\n%s", secret, payload)
		}
	}
	if !strings.Contains(payload, `"model":"m"`) {
		t.Errorf("the sweep corrupted the payload structure:\n%s", payload)
	}
}

// ---- Guard 3: one dialect, not three ---------------------------------------

// TestRedactAILogLineUsesTheSharedDialect — the syslog tool used to own the
// ONLY redaction on the whole egress path, via a private regex that knew about
// eight key names and nothing else. It must now inherit everything ai.Redact
// covers, so widening coverage means editing one file.
func TestRedactAILogLineUsesTheSharedDialect(t *testing.T) {
	line := "Jul 26 rtr1: snmp-server community S3cr3tR0 RO; client a4:83:e7:1b:2c:3d; user=jsmith"
	got := redactAILogLine(line)
	for _, secret := range []string{"S3cr3tR0", "a4:83:e7:1b:2c:3d", "jsmith"} {
		if strings.Contains(got, secret) {
			t.Errorf("redactAILogLine leaked %q (it must apply the shared ai.Redact dialect): %s", secret, got)
		}
	}
	if !strings.Contains(got, "rtr1") {
		t.Errorf("redactAILogLine destroyed the device name: %s", got)
	}
	// The per-line cap it still owns must survive.
	long := strings.Repeat("x", aiLogMaxLineCh+200)
	if capped := redactAILogLine(long); len([]rune(capped)) > aiLogMaxLineCh+3 {
		t.Errorf("redactAILogLine no longer caps line length: %d runes", len([]rune(capped)))
	}
}
