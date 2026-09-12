// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// toolwire.go — per-provider tool-calling adapters (intelligence plan P2,
// §3.d). One neutral shape (ToolSpec / ToolCall / ToolReply + the
// AgentTurn conversation) is encoded to each provider's wire format and the
// response decoded back. Pure stdlib; encode/parse are separated from the HTTP
// call so they unit-test on fixtures. Tool-call turns are never streamed
// (deliberate simplification — providers stream partial JSON differently).

// AgentTurn is one provider-neutral conversation turn in the agent loop.
// Exactly one of the shapes is populated:
//   - user text:        Role="user", Content
//   - assistant text:   Role="assistant", Content (and/or Calls)
//   - assistant calls:  Role="assistant", Calls (Content may accompany)
//   - tool results:     Role="user", Replies (the results for the previous
//     assistant turn's Calls — Anthropic/Gemini carry them in a user message)
type AgentTurn struct {
	Role    string
	Content string
	Calls   []ToolCall
	Replies []ToolReply
}

// MaxOutputTokens caps every provider request body this package (and the
// integrator's non-tool paths) builds — the OWASP LLM04 bounded-output-cost
// control. One definition so no body can be built without it.
const MaxOutputTokens = 1024

// DoFunc is the transport the integrator supplies for provider round-trips —
// it owns timeout, retry and log-redaction policy (main's providerDo).
type DoFunc func(ctx context.Context, url string, headers map[string]string, body []byte, provider string) ([]byte, error)

// CallTools performs ONE model round-trip with tools attached and returns the
// assistant text and/or the tool calls it requested. specs may be nil/empty
// for the final "answer with what you have" call.
func CallTools(ctx context.Context, do DoFunc, name, key, model, system string, turns []AgentTurn, specs []ToolSpec) (string, []ToolCall, error) {
	switch name {
	case "openai":
		body, err := buildOpenAIToolsBody(model, system, turns, specs)
		if err != nil {
			return "", nil, err
		}
		rb, err := do(ctx, "https://api.openai.com/v1/chat/completions", map[string]string{"Authorization": "Bearer " + key}, body, "openai")
		if err != nil {
			return "", nil, err
		}
		return parseOpenAIToolsResp(rb)
	case "anthropic":
		body, err := buildAnthropicToolsBody(model, system, turns, specs)
		if err != nil {
			return "", nil, err
		}
		rb, err := do(ctx, "https://api.anthropic.com/v1/messages",
			map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}, body, "anthropic")
		if err != nil {
			return "", nil, err
		}
		return parseAnthropicToolsResp(rb)
	case "gemini":
		body, err := buildGeminiToolsBody(system, turns, specs)
		if err != nil {
			return "", nil, err
		}
		endpoint := "https://generativelanguage.googleapis.com/v1beta/models/" + url.PathEscape(model) + ":generateContent?key=" + url.QueryEscape(key)
		rb, err := do(ctx, endpoint, nil, body, "gemini")
		if err != nil {
			return "", nil, err
		}
		return parseGeminiToolsResp(rb)
	}
	return "", nil, fmt.Errorf("unknown provider %q", name)
}

// rawArgsOrEmpty normalizes a possibly-empty raw args payload to a JSON object.
func rawArgsOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" {
		return json.RawMessage(`{}`)
	}
	return raw
}

// ---- OpenAI (chat/completions function calling) -----------------------------

func buildOpenAIToolsBody(model, system string, turns []AgentTurn, specs []ToolSpec) ([]byte, error) {
	msgs := []map[string]any{{"role": "system", "content": system}}
	for _, t := range turns {
		switch {
		case len(t.Replies) > 0:
			// OpenAI wants one role:"tool" message per result, keyed by call id.
			for _, rep := range t.Replies {
				msgs = append(msgs, map[string]any{"role": "tool", "tool_call_id": rep.ID, "content": rep.Content})
			}
		case t.Role == "assistant" && len(t.Calls) > 0:
			calls := make([]map[string]any, 0, len(t.Calls))
			for _, c := range t.Calls {
				calls = append(calls, map[string]any{
					"id": c.ID, "type": "function",
					// OpenAI carries arguments as a JSON-ENCODED STRING (§2.3).
					"function": map[string]any{"name": c.Name, "arguments": string(rawArgsOrEmpty(c.Args))},
				})
			}
			m := map[string]any{"role": "assistant", "tool_calls": calls}
			if t.Content != "" {
				m["content"] = t.Content
			}
			msgs = append(msgs, m)
		default:
			msgs = append(msgs, map[string]any{"role": t.Role, "content": t.Content})
		}
	}
	body := map[string]any{"model": model, "messages": msgs, "max_tokens": MaxOutputTokens}
	if len(specs) > 0 {
		tools := make([]map[string]any, 0, len(specs))
		for _, sp := range specs {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{
				"name": sp.Name, "description": sp.Description, "parameters": sp.InputSchema,
			}})
		}
		body["tools"] = tools
	}
	return json.Marshal(body)
}

func parseOpenAIToolsResp(rb []byte) (string, []ToolCall, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", nil, err
	}
	if len(out.Choices) == 0 {
		return "", nil, fmt.Errorf("openai: empty response")
	}
	msg := out.Choices[0].Message
	calls := make([]ToolCall, 0, len(msg.ToolCalls))
	for i, c := range msg.ToolCalls {
		id := c.ID
		if id == "" {
			id = fmt.Sprintf("call-%d", i)
		}
		calls = append(calls, ToolCall{ID: id, Name: c.Function.Name, Args: rawArgsOrEmpty(json.RawMessage(c.Function.Arguments))})
	}
	return msg.Content, calls, nil
}

// ---- Anthropic (Messages tool use) ------------------------------------------

func buildAnthropicToolsBody(model, system string, turns []AgentTurn, specs []ToolSpec) ([]byte, error) {
	msgs := make([]map[string]any, 0, len(turns))
	for _, t := range turns {
		switch {
		case len(t.Replies) > 0:
			// All results for the previous assistant turn ride in ONE user message
			// of tool_result blocks (§2.3).
			blocks := make([]map[string]any, 0, len(t.Replies))
			for _, rep := range t.Replies {
				b := map[string]any{"type": "tool_result", "tool_use_id": rep.ID, "content": rep.Content}
				if rep.IsError {
					b["is_error"] = true
				}
				blocks = append(blocks, b)
			}
			msgs = append(msgs, map[string]any{"role": "user", "content": blocks})
		case t.Role == "assistant" && len(t.Calls) > 0:
			blocks := []map[string]any{}
			if t.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": t.Content})
			}
			for _, c := range t.Calls {
				// Anthropic carries input as a PARSED JSON OBJECT (§2.3).
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Name, "input": rawArgsOrEmpty(c.Args)})
			}
			msgs = append(msgs, map[string]any{"role": "assistant", "content": blocks})
		default:
			msgs = append(msgs, map[string]any{"role": t.Role, "content": t.Content})
		}
	}
	body := map[string]any{"model": model, "max_tokens": MaxOutputTokens, "system": system, "messages": msgs}
	if len(specs) > 0 {
		tools := make([]map[string]any, 0, len(specs))
		for _, sp := range specs {
			tools = append(tools, map[string]any{"name": sp.Name, "description": sp.Description, "input_schema": sp.InputSchema})
		}
		body["tools"] = tools
	}
	return json.Marshal(body)
}

func parseAnthropicToolsResp(rb []byte) (string, []ToolCall, error) {
	var out struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", nil, err
	}
	var sb strings.Builder
	var calls []ToolCall
	for i, c := range out.Content {
		switch c.Type {
		case "text":
			sb.WriteString(c.Text)
		case "tool_use":
			id := c.ID
			if id == "" {
				id = fmt.Sprintf("call-%d", i)
			}
			calls = append(calls, ToolCall{ID: id, Name: c.Name, Args: rawArgsOrEmpty(c.Input)})
		}
	}
	if sb.Len() == 0 && len(calls) == 0 {
		return "", nil, fmt.Errorf("anthropic: empty response")
	}
	return sb.String(), calls, nil
}

// ---- Gemini (generateContent function calling) --------------------------------

func buildGeminiToolsBody(system string, turns []AgentTurn, specs []ToolSpec) ([]byte, error) {
	contents := make([]map[string]any, 0, len(turns))
	for _, t := range turns {
		switch {
		case len(t.Replies) > 0:
			// Gemini correlates results by FUNCTION NAME, not call id.
			parts := make([]map[string]any, 0, len(t.Replies))
			for _, rep := range t.Replies {
				parts = append(parts, map[string]any{"functionResponse": map[string]any{
					"name": rep.Name, "response": map[string]any{"content": rep.Content, "is_error": rep.IsError},
				}})
			}
			contents = append(contents, map[string]any{"role": "user", "parts": parts})
		case t.Role == "assistant" && len(t.Calls) > 0:
			parts := []map[string]any{}
			if t.Content != "" {
				parts = append(parts, map[string]any{"text": t.Content})
			}
			for _, c := range t.Calls {
				var argsObj map[string]any
				if err := json.Unmarshal(rawArgsOrEmpty(c.Args), &argsObj); err != nil {
					argsObj = map[string]any{}
				}
				parts = append(parts, map[string]any{"functionCall": map[string]any{"name": c.Name, "args": argsObj}})
			}
			contents = append(contents, map[string]any{"role": "model", "parts": parts})
		default:
			role := "user"
			if t.Role == "assistant" {
				role = "model"
			}
			contents = append(contents, map[string]any{"role": role, "parts": []map[string]any{{"text": t.Content}}})
		}
	}
	body := map[string]any{
		"system_instruction": map[string]any{"parts": []map[string]any{{"text": system}}},
		"contents":           contents,
		"generationConfig":   map[string]any{"maxOutputTokens": MaxOutputTokens},
	}
	if len(specs) > 0 {
		decls := make([]map[string]any, 0, len(specs))
		for _, sp := range specs {
			decls = append(decls, map[string]any{"name": sp.Name, "description": sp.Description, "parameters": sp.InputSchema})
		}
		body["tools"] = []map[string]any{{"functionDeclarations": decls}}
	}
	return json.Marshal(body)
}

func parseGeminiToolsResp(rb []byte) (string, []ToolCall, error) {
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						Name string          `json:"name"`
						Args json.RawMessage `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", nil, err
	}
	if len(out.Candidates) == 0 {
		return "", nil, fmt.Errorf("gemini: empty response")
	}
	var sb strings.Builder
	var calls []ToolCall
	for i, p := range out.Candidates[0].Content.Parts {
		if p.FunctionCall != nil {
			calls = append(calls, ToolCall{
				// Gemini has no call ids; synthesize one (replies key on Name anyway).
				ID:   fmt.Sprintf("call-%d-%s", i, p.FunctionCall.Name),
				Name: p.FunctionCall.Name,
				Args: rawArgsOrEmpty(p.FunctionCall.Args),
			})
			continue
		}
		sb.WriteString(p.Text)
	}
	if sb.Len() == 0 && len(calls) == 0 {
		return "", nil, fmt.Errorf("gemini: empty response")
	}
	return sb.String(), calls, nil
}
