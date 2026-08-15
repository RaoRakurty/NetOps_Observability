package ai

// llm_transport.go — the copilot LLM transport + prompt hygiene (Phase-2
// W3.5, extracted from package main's copilot.go): the wire ChatMessage,
// server-side message sanitization (LLM01: the system prompt is
// server-controlled and a client system turn is rejected), the doc-ref
// anti-fabrication strip (LLM02-adjacent), the three raw provider clients
// (OpenAI / Gemini / Anthropic) behind ProviderDo (timeout, bounded reads,
// redacted logging), CallProvider dispatch and the default system prompt.
// Env resolution (provider chain / keys / models), the docs index, the agent
// loop and the handler stay in main.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"netops/backend/internal/applog"
)

const (
	MaxMessages   = 64      // conversation-length cap
	MaxInputChars = 200_000 // total message-content budget (~200 KB)
)

type ChatMessage struct {
	Role    string `json:"role"` // "user" | "assistant" | "system"
	Content string `json:"content"`
}

func SanitizeMessages(in []ChatMessage) ([]ChatMessage, error) {
	out := make([]ChatMessage, 0, len(in))
	total := 0
	for _, m := range in {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role != "user" && role != "assistant" {
			continue
		}
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		total += len(content)
		out = append(out, ChatMessage{Role: role, Content: content})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable messages")
	}
	if len(out) > MaxMessages {
		return nil, fmt.Errorf("too many messages (max %d)", MaxMessages)
	}
	if total > MaxInputChars {
		return nil, fmt.Errorf("conversation too large (max %d characters)", MaxInputChars)
	}
	return out, nil
}

// copilotSystemPrompt returns the server-controlled system prompt: the
// admin-configured override when set, otherwise the built-in default. The
// client never gets a say (OWASP LLM01).
type DocRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

// LatestUserMessage returns the newest user turn — the question retrieval runs on.
func LatestUserMessage(msgs []ChatMessage) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[i].Content
		}
	}
	return ""
}

// reDocRef matches only doc-namespace citations, e.g. [doc:send-data/syslog#step-1].
var reDocRef = regexp.MustCompile(`\s?\[(doc:[^\]]{1,200})\]`)

// StripFabricatedDocRefs removes bracketed [doc:…] citations the model invented
// (ids not among the actually-retrieved chunks). Scoped to the doc: namespace on
// purpose: free-form prose legitimately uses other bracketed text ("[RFC 5880:
// BFD]"), which must survive untouched.
func StripFabricatedDocRefs(text string, refs []DocRef) string {
	if !strings.Contains(text, "[doc:") {
		return text
	}
	valid := make(map[string]bool, len(refs))
	for _, r := range refs {
		valid[strings.ToLower(r.ID)] = true
	}
	return reDocRef.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.TrimSpace(m)
		inner = strings.ToLower(strings.Trim(inner, "[] "))
		if valid[inner] {
			return m
		}
		return ""
	})
}

// ---- provider chain ---------------------------------------------------------

// CallProvider dispatches one attempt to a named provider, returning the
// assistant text or an error. Pure (no s) — the chain in handleCopilot owns
// fallback/ordering.
func CallProvider(ctx context.Context, name, key, model, system string, msgs []ChatMessage) (string, error) {
	switch name {
	case "openai":
		return callOpenAI(ctx, key, model, system, msgs)
	case "gemini":
		return callGemini(ctx, key, model, system, msgs)
	case "anthropic":
		return callAnthropic(ctx, key, model, system, msgs)
	}
	return "", fmt.Errorf("unknown provider %q", name)
}

// copilotProviderChain returns the fallback order. Default ChatGPT→Gemini→
// Copilot(Claude); COPILOT_PROVIDER_CHAIN overrides; a legacy COPILOT_PROVIDER is
// promoted to the front of the default order.
func NormalizeProvider(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "openai", "chatgpt", "gpt":
		return "openai"
	case "gemini", "google":
		return "gemini"
	case "anthropic", "claude", "copilot":
		return "anthropic"
	}
	return ""
}

// providerKey resolves a provider's API key: its own env var, else the legacy
// COPILOT_API_KEY when this provider is the configured COPILOT_PROVIDER.
var providerHTTP = &http.Client{Timeout: 60 * time.Second}

// SwapProviderHTTPForTest replaces the provider HTTP client and returns a
// restore func — tests only (the DLP egress capture uses it).
func SwapProviderHTTPForTest(c *http.Client) (restore func()) {
	prev := providerHTTP
	providerHTTP = c
	return func() { providerHTTP = prev }
}

// ProviderDo performs one provider HTTP call and returns the 2xx body. On a
// non-2xx it logs the provider's error body server-side (SR-022 — never echoed
// to the client) and returns an error so the chain falls through. The URL is
// never logged (Gemini carries its key in the query string).
func ProviderDo(ctx context.Context, urlStr string, headers map[string]string, body []byte, provider string) ([]byte, error) {
	// LLM06 backstop — the LAST line before bytes leave the process. Every
	// assembler upstream (plain chat, the grounded prompts, the agent loop's
	// tool replies) is expected to have redacted already; this pass guarantees
	// that a NEW assembler added later cannot ship a credential just because its
	// author forgot. Credential tier only: identifiers are redacted upstream
	// where server-originated data is rendered, so an operator asking about the
	// MAC or username they typed still gets an answer about it.
	// Mask contains no quoting/escaping characters and the value patterns
	// stop at structural characters, so the JSON payload stays well-formed.
	body = []byte(RedactSecrets(string(body)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := providerHTTP.Do(req)
	if err != nil {
		applog.Error("copilot", "provider request failed", map[string]any{"provider": provider, "err": err.Error()})
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // best-effort: diagnostic snippet; a read error just leaves it empty
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := rb
		if len(snippet) > 512 {
			snippet = snippet[:512]
		}
		applog.Error("copilot", "provider returned error", map[string]any{"provider": provider, "status": resp.StatusCode, "body": string(snippet)})
		return nil, fmt.Errorf("%s: status %d", provider, resp.StatusCode)
	}
	return rb, nil
}

// ---- OpenAI (ChatGPT) -------------------------------------------------------

func callOpenAI(ctx context.Context, key, model, system string, msgs []ChatMessage) (string, error) {
	// The server-controlled system prompt goes in as a leading system-role
	// message; msgs are already sanitized to user/assistant.
	all := append([]ChatMessage{{Role: "system", Content: system}}, msgs...)
	body, _ := json.Marshal(map[string]any{"model": model, "messages": all, "max_tokens": MaxOutputTokens}) // discard: marshalling an in-memory value cannot fail
	rb, err := ProviderDo(ctx, "https://api.openai.com/v1/chat/completions", map[string]string{"Authorization": "Bearer " + key}, body, "openai")
	if err != nil {
		return "", err
	}
	return parseOpenAI(rb)
}

// parseOpenAI extracts the assistant text from an OpenAI chat-completions body.
func parseOpenAI(rb []byte) (string, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

// ---- Gemini (Google) --------------------------------------------------------

func callGemini(ctx context.Context, key, model, system string, msgs []ChatMessage) (string, error) {
	type gpart struct {
		Text string `json:"text"`
	}
	type gcontent struct {
		Role  string  `json:"role"`
		Parts []gpart `json:"parts"`
	}
	contents := make([]gcontent, 0, len(msgs))
	for _, m := range msgs {
		role := "user"
		if m.Role == "assistant" {
			role = "model" // Gemini's assistant role
		}
		contents = append(contents, gcontent{Role: role, Parts: []gpart{{Text: m.Content}}})
	}
	body, _ := json.Marshal(map[string]any{ // discard: marshalling an in-memory value cannot fail
		"system_instruction": map[string]any{"parts": []gpart{{Text: system}}},
		"contents":           contents,
		"generationConfig":   map[string]any{"maxOutputTokens": MaxOutputTokens},
	})
	// Gemini authenticates via the API key in the query string (over HTTPS). The
	// URL is never logged (ProviderDo logs provider/status/body only).
	endpoint := "https://generativelanguage.googleapis.com/v1beta/models/" + url.PathEscape(model) + ":generateContent?key=" + url.QueryEscape(key)
	rb, err := ProviderDo(ctx, endpoint, nil, body, "gemini")
	if err != nil {
		return "", err
	}
	return parseGemini(rb)
}

// parseGemini extracts the assistant text from a Gemini generateContent body.
func parseGemini(rb []byte) (string, error) {
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) == 0 {
		return "", fmt.Errorf("gemini: empty response")
	}
	var sb strings.Builder
	for _, p := range out.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	return sb.String(), nil
}

// ---- Anthropic (Copilot/Claude) ---------------------------------------------

func callAnthropic(ctx context.Context, key, model, system string, msgs []ChatMessage) (string, error) {
	// Anthropic Messages API: "system" is separate from messages.
	body, _ := json.Marshal(map[string]any{ // discard: marshalling an in-memory value cannot fail
		"model": model, "max_tokens": MaxOutputTokens, "system": system, "messages": msgs,
	})
	rb, err := ProviderDo(ctx, "https://api.anthropic.com/v1/messages",
		map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}, body, "anthropic")
	if err != nil {
		return "", err
	}
	return parseAnthropic(rb)
}

// parseAnthropic extracts the assistant text from an Anthropic Messages body.
func parseAnthropic(rb []byte) (string, error) {
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("anthropic: empty response")
	}
	return sb.String(), nil
}

func DefaultSystemPrompt() string {
	return strings.TrimSpace(`
You are the NetOps Observability copilot — a senior network reliability
engineer embedded inside a NOC dashboard. The user is a network
operator. They expect terse, accurate, action-oriented answers grounded
in the log/metric/flow context they paste into the conversation. Cite
the timestamps and devices from that context. If asked for SQL, return
ClickHouse-flavoured SQL. If asked for log queries, return OpenSearch
query_string syntax. If you don't have enough context, say so and tell
the operator exactly which signal to fetch next.
`)
}
