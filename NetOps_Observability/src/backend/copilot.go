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
// We forward to the configured LLM provider (Anthropic by default) and
// stream the response back. Provider credentials are read from env at
// request time so rotating COPILOT_API_KEY doesn't require a restart.
//
// The copilot service is intentionally minimal — it does NOT pull
// log/metric context automatically. The UI is responsible for adding
// any contextual snippets to the message list before posting, which
// keeps the trust boundary clean: a misbehaving model can't reach into
// arbitrary indices on its own.

type copilotMessage struct {
	Role    string `json:"role"`    // "user" | "assistant" | "system"
	Content string `json:"content"`
}

type copilotRequest struct {
	Messages []copilotMessage `json:"messages"`
	System   string           `json:"system,omitempty"`
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

	var req copilotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no messages"))
		return
	}

	provider := strings.ToLower(envOr("COPILOT_PROVIDER", "anthropic"))
	model := envOr("COPILOT_MODEL", "claude-sonnet-4-5")

	switch provider {
	case "anthropic":
		s.callAnthropic(w, apiKey, model, req)
	case "openai":
		s.callOpenAI(w, apiKey, model, req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown COPILOT_PROVIDER %q", provider))
	}
}

// ---- Anthropic --------------------------------------------------------------

func (s *server) callAnthropic(w http.ResponseWriter, apiKey, model string, req copilotRequest) {
	// Anthropic Messages API: https://docs.anthropic.com/en/api/messages
	// The "system" field is separate from messages.
	system := req.System
	if system == "" {
		system = defaultSystemPrompt()
	}
	// Strip any system messages from the history (Anthropic API rejects them).
	msgs := make([]copilotMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			if system == defaultSystemPrompt() {
				system = m.Content
			}
			continue
		}
		msgs = append(msgs, m)
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"system":     system,
		"messages":   msgs,
	}
	buf, _ := json.Marshal(body)

	httpReq, err := http.NewRequest(
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

func (s *server) callOpenAI(w http.ResponseWriter, apiKey, model string, req copilotRequest) {
	// OpenAI chat completions. We pass the message list through;
	// the system prompt (if any) goes in as a system-role message.
	msgs := req.Messages
	if req.System != "" {
		msgs = append([]copilotMessage{{Role: "system", Content: req.System}}, msgs...)
	}
	body := map[string]any{
		"model":    model,
		"messages": msgs,
	}
	buf, _ := json.Marshal(body)

	httpReq, err := http.NewRequest(
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
