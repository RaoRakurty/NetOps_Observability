package ai

import (
	"encoding/json"
	"strings"
	"testing"
)

// copilot_tools_test.go — wire-format tests for the provider tool-calling
// adapters: neutral turns/specs encode to each provider's shape and each
// provider's response decodes back to neutral ToolCalls. Fixtures follow the
// documented formats (plan §2.3).

var wireSpecs = []ToolSpec{{
	Name: "get_problem", Description: "Fetch one problem.",
	InputSchema: json.RawMessage(`{"type":"object","properties":{"problem_id":{"type":"string"}},"required":["problem_id"]}`),
}}

var wireTurns = []AgentTurn{
	{Role: "user", Content: "what is wrong with edge-1?"},
	{Role: "assistant", Content: "checking", Calls: []ToolCall{{ID: "c1", Name: "get_problem", Args: json.RawMessage(`{"problem_id":"pa"}`)}}},
	{Role: "user", Replies: []ToolReply{{ID: "c1", Name: "get_problem", Content: "[problem:pa] BGP peer down"}}},
}

func TestBuildOpenAIToolsBody(t *testing.T) {
	b, err := buildOpenAIToolsBody("gpt-test", "sys", wireTurns, wireSpecs)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	msgs := body["messages"].([]any)
	// system + user + assistant(tool_calls) + one role:tool message
	if len(msgs) != 4 {
		t.Fatalf("want 4 messages, got %d: %s", len(msgs), b)
	}
	toolMsg := msgs[3].(map[string]any)
	if toolMsg["role"] != "tool" || toolMsg["tool_call_id"] != "c1" {
		t.Fatalf("tool reply message wrong: %v", toolMsg)
	}
	asst := msgs[2].(map[string]any)
	call := asst["tool_calls"].([]any)[0].(map[string]any)
	fn := call["function"].(map[string]any)
	// OpenAI arguments must be a JSON-ENCODED STRING.
	if _, ok := fn["arguments"].(string); !ok {
		t.Fatalf("openai arguments must be a string, got %T", fn["arguments"])
	}
	if body["tools"] == nil {
		t.Fatal("tools missing from body")
	}
}

func TestParseOpenAIToolsResp(t *testing.T) {
	rb := []byte(`{"choices":[{"message":{"content":null,"tool_calls":[
		{"id":"call_9","type":"function","function":{"name":"get_problem","arguments":"{\"problem_id\":\"pa\"}"}}]}}]}`)
	text, calls, err := parseOpenAIToolsResp(rb)
	if err != nil || text != "" || len(calls) != 1 {
		t.Fatalf("got %q %v %v", text, calls, err)
	}
	if calls[0].ID != "call_9" || calls[0].Name != "get_problem" || !strings.Contains(string(calls[0].Args), "pa") {
		t.Fatalf("call decoded wrong: %+v", calls[0])
	}
}

func TestBuildAnthropicToolsBody(t *testing.T) {
	b, err := buildAnthropicToolsBody("claude-test", "sys", wireTurns, wireSpecs)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body["system"] != "sys" {
		t.Fatal("anthropic system must be top-level")
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d", len(msgs))
	}
	// Assistant turn carries a tool_use block with a PARSED input object.
	blocks := msgs[1].(map[string]any)["content"].([]any)
	var sawToolUse bool
	for _, bl := range blocks {
		m := bl.(map[string]any)
		if m["type"] == "tool_use" {
			sawToolUse = true
			if _, ok := m["input"].(map[string]any); !ok {
				t.Fatalf("anthropic input must be an object, got %T", m["input"])
			}
		}
	}
	if !sawToolUse {
		t.Fatal("no tool_use block")
	}
	// Results ride in ONE user message of tool_result blocks.
	res := msgs[2].(map[string]any)
	if res["role"] != "user" {
		t.Fatal("tool results must be a user message")
	}
	rb0 := res["content"].([]any)[0].(map[string]any)
	if rb0["type"] != "tool_result" || rb0["tool_use_id"] != "c1" {
		t.Fatalf("tool_result block wrong: %v", rb0)
	}
}

func TestParseAnthropicToolsResp(t *testing.T) {
	rb := []byte(`{"stop_reason":"tool_use","content":[
		{"type":"text","text":"Let me check."},
		{"type":"tool_use","id":"tu_1","name":"get_problem","input":{"problem_id":"pa"}}]}`)
	text, calls, err := parseAnthropicToolsResp(rb)
	if err != nil || text != "Let me check." || len(calls) != 1 {
		t.Fatalf("got %q %v %v", text, calls, err)
	}
	if calls[0].ID != "tu_1" || !strings.Contains(string(calls[0].Args), "problem_id") {
		t.Fatalf("call decoded wrong: %+v", calls[0])
	}
}

func TestBuildAndParseGeminiTools(t *testing.T) {
	b, err := buildGeminiToolsBody("sys", wireTurns, wireSpecs)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	contents := body["contents"].([]any)
	if len(contents) != 3 {
		t.Fatalf("want 3 contents, got %d", len(contents))
	}
	// Results correlate by function NAME via functionResponse parts.
	parts := contents[2].(map[string]any)["parts"].([]any)
	fr := parts[0].(map[string]any)["functionResponse"].(map[string]any)
	if fr["name"] != "get_problem" {
		t.Fatalf("functionResponse name wrong: %v", fr)
	}
	if body["tools"].([]any)[0].(map[string]any)["functionDeclarations"] == nil {
		t.Fatal("functionDeclarations missing")
	}

	rb := []byte(`{"candidates":[{"content":{"parts":[
		{"functionCall":{"name":"get_problem","args":{"problem_id":"pa"}}}]}}]}`)
	text, calls, err := parseGeminiToolsResp(rb)
	if err != nil || text != "" || len(calls) != 1 || calls[0].Name != "get_problem" {
		t.Fatalf("got %q %v %v", text, calls, err)
	}
}
