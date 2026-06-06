package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// copilot.go — AI Copilot endpoint.
//
// The frontend Copilot tab posts a chat history to /api/copilot/chat.
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
	Role    string `json:"role"`    // "user" | "assistant" | "system"
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
	if s.copilotCfg != nil {
		if sys := strings.TrimSpace(s.copilotCfg.get().System); sys != "" {
			return sys
		}
	}
	return defaultSystemPrompt()
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
	apiKey := os.Getenv("COPILOT_API_KEY")
	if apiKey == "" {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("COPILOT_API_KEY not set"))
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

	// Default provider is OpenAI/ChatGPT (the in-product assistant is branded
	// "ChatGPT"); Anthropic stays selectable via COPILOT_PROVIDER=anthropic. The
	// default model tracks the chosen provider unless COPILOT_MODEL overrides.
	provider := strings.ToLower(envOr("COPILOT_PROVIDER", "openai"))
	model := os.Getenv("COPILOT_MODEL")
	if model == "" {
		if provider == "anthropic" {
			model = "claude-sonnet-4-5"
		} else {
			model = "gpt-4o-mini"
		}
	}

	switch provider {
	case "anthropic":
		s.callAnthropic(w, r, apiKey, model, system, msgs)
	case "openai":
		s.callOpenAI(w, r, apiKey, model, system, msgs)
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown COPILOT_PROVIDER %q", provider))
	}
}

// ---- Anthropic --------------------------------------------------------------

func (s *server) callAnthropic(w http.ResponseWriter, r *http.Request, apiKey, model, system string, msgs []copilotMessage) {
	// Anthropic Messages API: https://docs.anthropic.com/en/api/messages
	// The "system" field is separate from messages; msgs are already sanitized
	// to user/assistant only.
	body := map[string]any{
		"model":      model,
		"max_tokens": maxCopilotOutputTokens,
		"system":     system,
		"messages":   msgs,
	}
	buf, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		"https://api.anthropic.com/v1/messages",
		bytes.NewReader(buf),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logError("copilot", "anthropic request failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ---- OpenAI -----------------------------------------------------------------

func (s *server) callOpenAI(w http.ResponseWriter, r *http.Request, apiKey, model, system string, msgs []copilotMessage) {
	// OpenAI chat completions. The server-controlled system prompt goes in as a
	// leading system-role message; msgs are already sanitized to user/assistant.
	all := append([]copilotMessage{{Role: "system", Content: system}}, msgs...)
	body := map[string]any{
		"model":      model,
		"messages":   all,
		"max_tokens": maxCopilotOutputTokens,
	}
	buf, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(
		r.Context(),
		http.MethodPost,
		"https://api.openai.com/v1/chat/completions",
		bytes.NewReader(buf),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logError("copilot", "openai request failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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
