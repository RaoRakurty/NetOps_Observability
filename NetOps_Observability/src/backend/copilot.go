package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// appKnowledge is the authoritative, version-controlled brief about THIS product,
// compiled into the binary and injected into the server-owned system prompt so
// the assistant is grounded in the application (architecture, config,
// troubleshooting) rather than guessing. Editing the .md updates the assistant.
//
//go:embed copilot_knowledge.md
var appKnowledge string

// copilot.go — AI Copilot endpoint.
//
// The frontend Correlix AI tab posts a chat history to /api/copilot/chat.
// We forward to the configured LLM provider and stream the response back.
// Provider credentials are read from env at request time so rotating
// COPILOT_API_KEY doesn't require a restart.
//
// Trust boundary (OWASP LLM Top 10 — see CLAUDE.md §15):
//   - The endpoint is authenticated + audited (withAuth/withAudit in main.go).
//   - The system prompt is SERVER-controlled; a client-supplied "system" field
//     or "system"-role message is ignored (LLM01: no client jailbreak).
//   - The conversation is bounded (body size, message count, total chars) and
//     output tokens are capped (LLM04: no unbounded provider cost / DoS).
//   - The service does NOT auto-pull log/metric context; the UI adds any
//     context to the message list, so a misbehaving model can't reach into
//     arbitrary indices on its own.
//   - Responses are rendered as escaped text by the SPA (LLM02: no output-as-HTML).

type copilotMessage struct {
	Role    string `json:"role"` // "user" | "assistant" | "system"
	Content string `json:"content"`
}

type copilotRequest struct {
	Messages []copilotMessage `json:"messages"`
	// System is accepted for backward compatibility but IGNORED: the system
	// prompt is server-controlled (OWASP LLM01 — a client must not be able to
	// override the model's instructions / jailbreak it). See handleCopilot.
	System string `json:"system,omitempty"`
}

// Input guardrails for the copilot proxy (OWASP LLM01/LLM04): the system prompt
// is server-owned and the conversation is bounded so a client can't run up
// unbounded provider cost or smuggle in a rogue system role.
const (
	maxCopilotBodyBytes    = 256 << 10 // 256 KiB request cap
	maxCopilotMessages     = 64        // conversation-length cap
	maxCopilotInputChars   = 200_000   // total message-content budget (~200 KB)
	maxCopilotOutputTokens = 1024      // bounded output cost
)

// sanitizeCopilotMessages enforces the input guardrails: only user/assistant
// turns survive (client-supplied "system" or unknown roles are dropped, since
// the system prompt is server-controlled), empties are skipped, and an
// oversized conversation is rejected rather than silently truncated.
func sanitizeCopilotMessages(in []copilotMessage) ([]copilotMessage, error) {
	out := make([]copilotMessage, 0, len(in))
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
		out = append(out, copilotMessage{Role: role, Content: content})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable messages")
	}
	if len(out) > maxCopilotMessages {
		return nil, fmt.Errorf("too many messages (max %d)", maxCopilotMessages)
	}
	if total > maxCopilotInputChars {
		return nil, fmt.Errorf("conversation too large (max %d characters)", maxCopilotInputChars)
	}
	return out, nil
}

// copilotSystemPrompt returns the server-controlled system prompt: the
// admin-configured override when set, otherwise the built-in default. The
// client never gets a say (OWASP LLM01).
func (s *server) copilotSystemPrompt() string {
	persona := defaultSystemPrompt()
	if s.copilotCfg != nil {
		if sys := strings.TrimSpace(s.copilotCfg.get().System); sys != "" {
			persona = sys
		}
	}
	// Always ground the assistant in the embedded application knowledge, whether
	// the persona is the default or an admin override.
	if k := strings.TrimSpace(appKnowledge); k != "" {
		return persona + "\n\n" + k
	}
	return persona
}

func (s *server) handleCopilot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if os.Getenv("FEATURE_COPILOT") != "true" {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("copilot disabled — set FEATURE_COPILOT=true"))
		return
	}

	// SR-021: per-principal rate limit. Each chat turn is a paid provider call, so
	// an authenticated user spamming /api/copilot/chat is a provider-cost DoS.
	// Keyed by tenant|user (authenticated identity, not a spoofable IP);
	// COPILOT_RATE_PER_MIN tunes the budget (default 20/min, ≤0 disables).
	claims, _ := userFrom(r.Context())
	if !s.copilotLimiter.allowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("copilot rate limit exceeded — slow down"))
		return
	}

	// Bound the request body before decoding (LLM04: no unbounded input).
	r.Body = http.MaxBytesReader(w, r.Body, maxCopilotBodyBytes)
	var req copilotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	msgs, err := sanitizeCopilotMessages(req.Messages)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Server-controlled system prompt — req.System is intentionally ignored.
	system := s.copilotSystemPrompt()

	// Provider fallback chain: ChatGPT (OpenAI) → Gemini → Copilot (Anthropic).
	// Each provider that has a key is tried in order; on error (no key is skipped,
	// a provider error/non-2xx falls through) the next is attempted; the first
	// success wins. Order configurable via COPILOT_PROVIDER_CHAIN.
	// The UI-stored (encrypted) key + model apply to the configured provider, used
	// as the fallback when no per-provider env key is set — so the platform owner
	// can enable the assistant by pasting a key in settings (no .env edit).
	storedKey := s.copilotCfg.apiKey()
	cfgProvider := s.copilotCfg.get().Provider
	cfgModel := s.copilotCfg.get().Model

	attempted := false
	for _, name := range copilotProviderChain() {
		key := providerKey(name)
		if key == "" && storedKey != "" && name == cfgProvider {
			key = storedKey
		}
		if key == "" {
			continue // provider not configured — skip silently
		}
		model := providerModel(name)
		if name == cfgProvider && cfgModel != "" {
			model = cfgModel
		}
		attempted = true
		text, err := callProvider(r.Context(), name, key, model, system, msgs)
		if err == nil && strings.TrimSpace(text) != "" {
			writeJSON(w, http.StatusOK, map[string]string{"provider": name, "text": text})
			return
		}
		// SR-022: the provider's raw error body is logged server-side by
		// providerDo, never echoed to the client. Fall through to the next.
		logWarn("copilot", "provider attempt failed, falling through", map[string]any{"provider": name})
	}
	if !attempted {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Correlix AI isn't connected to an AI provider yet — open the assistant settings (gear icon) and add an API key"))
		return
	}
	writeError(w, http.StatusBadGateway, fmt.Errorf("Correlix AI couldn't reach the AI provider — please try again; if it persists, check the API key in settings"))
}

// ---- provider chain ---------------------------------------------------------

// callProvider dispatches one attempt to a named provider, returning the
// assistant text or an error. Pure (no s) — the chain in handleCopilot owns
// fallback/ordering.
func callProvider(ctx context.Context, name, key, model, system string, msgs []copilotMessage) (string, error) {
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
func copilotProviderChain() []string {
	if raw := strings.TrimSpace(os.Getenv("COPILOT_PROVIDER_CHAIN")); raw != "" {
		var out []string
		for _, t := range strings.Split(raw, ",") {
			if p := normalizeProvider(t); p != "" && !containsStr(out, p) {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	order := []string{"openai", "gemini", "anthropic"}
	if p := normalizeProvider(os.Getenv("COPILOT_PROVIDER")); p != "" && order[0] != p {
		out := []string{p}
		for _, o := range order {
			if o != p {
				out = append(out, o)
			}
		}
		return out
	}
	return order
}

func normalizeProvider(s string) string {
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

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// providerKey resolves a provider's API key: its own env var, else the legacy
// COPILOT_API_KEY when this provider is the configured COPILOT_PROVIDER.
func providerKey(name string) string {
	switch name {
	case "openai":
		if k := os.Getenv("OPENAI_API_KEY"); k != "" {
			return k
		}
	case "gemini":
		if k := os.Getenv("GEMINI_API_KEY"); k != "" {
			return k
		}
		if k := os.Getenv("GOOGLE_API_KEY"); k != "" {
			return k
		}
	case "anthropic":
		if k := os.Getenv("ANTHROPIC_API_KEY"); k != "" {
			return k
		}
	}
	if name == normalizeProvider(envOr("COPILOT_PROVIDER", "openai")) {
		return os.Getenv("COPILOT_API_KEY")
	}
	return ""
}

// providerModel resolves the model: per-provider override, else legacy
// COPILOT_MODEL for the configured provider, else a sensible default.
func providerModel(name string) string {
	envVar := map[string]string{"openai": "OPENAI_MODEL", "gemini": "GEMINI_MODEL", "anthropic": "ANTHROPIC_MODEL"}[name]
	if m := os.Getenv(envVar); m != "" {
		return m
	}
	if name == normalizeProvider(envOr("COPILOT_PROVIDER", "openai")) {
		if m := os.Getenv("COPILOT_MODEL"); m != "" {
			return m
		}
	}
	switch name {
	case "openai":
		return "gpt-4o-mini"
	case "gemini":
		return "gemini-1.5-flash"
	case "anthropic":
		return "claude-sonnet-4-5"
	}
	return ""
}

var copilotHTTP = &http.Client{Timeout: 60 * time.Second}

// providerDo performs one provider HTTP call and returns the 2xx body. On a
// non-2xx it logs the provider's error body server-side (SR-022 — never echoed
// to the client) and returns an error so the chain falls through. The URL is
// never logged (Gemini carries its key in the query string).
func providerDo(ctx context.Context, urlStr string, headers map[string]string, body []byte, provider string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := copilotHTTP.Do(req)
	if err != nil {
		logError("copilot", "provider request failed", map[string]any{"provider": provider, "err": err.Error()})
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := rb
		if len(snippet) > 512 {
			snippet = snippet[:512]
		}
		logError("copilot", "provider returned error", map[string]any{"provider": provider, "status": resp.StatusCode, "body": string(snippet)})
		return nil, fmt.Errorf("%s: status %d", provider, resp.StatusCode)
	}
	return rb, nil
}

// ---- OpenAI (ChatGPT) -------------------------------------------------------

func callOpenAI(ctx context.Context, key, model, system string, msgs []copilotMessage) (string, error) {
	// The server-controlled system prompt goes in as a leading system-role
	// message; msgs are already sanitized to user/assistant.
	all := append([]copilotMessage{{Role: "system", Content: system}}, msgs...)
	body, _ := json.Marshal(map[string]any{"model": model, "messages": all, "max_tokens": maxCopilotOutputTokens})
	rb, err := providerDo(ctx, "https://api.openai.com/v1/chat/completions", map[string]string{"Authorization": "Bearer " + key}, body, "openai")
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

func callGemini(ctx context.Context, key, model, system string, msgs []copilotMessage) (string, error) {
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
	body, _ := json.Marshal(map[string]any{
		"system_instruction": map[string]any{"parts": []gpart{{Text: system}}},
		"contents":           contents,
		"generationConfig":   map[string]any{"maxOutputTokens": maxCopilotOutputTokens},
	})
	// Gemini authenticates via the API key in the query string (over HTTPS). The
	// URL is never logged (providerDo logs provider/status/body only).
	endpoint := "https://generativelanguage.googleapis.com/v1beta/models/" + url.PathEscape(model) + ":generateContent?key=" + url.QueryEscape(key)
	rb, err := providerDo(ctx, endpoint, nil, body, "gemini")
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

func callAnthropic(ctx context.Context, key, model, system string, msgs []copilotMessage) (string, error) {
	// Anthropic Messages API: "system" is separate from messages.
	body, _ := json.Marshal(map[string]any{
		"model": model, "max_tokens": maxCopilotOutputTokens, "system": system, "messages": msgs,
	})
	rb, err := providerDo(ctx, "https://api.anthropic.com/v1/messages",
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

func defaultSystemPrompt() string {
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
