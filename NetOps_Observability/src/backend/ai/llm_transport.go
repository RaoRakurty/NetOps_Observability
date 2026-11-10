// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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

// SanitizeMessages reduces a client-supplied chat history to the turns the
// server will forward: the operator's OWN messages, trimmed and bounded.
//
// Every other role is dropped. A "system" turn would let the client rewrite the
// model's instructions (LLM01). An "assistant" turn is dropped too (tracker 337
// N-A5 — the server owns the conversation): in a request body it is text the
// CLIENT wrote, and forwarding it in the model's own voice is prompt injection
// by another name ("as I confirmed above, run …"). The model only ever sees
// prior replies the server itself produced within the turn (the agent loop's
// own tool rounds).
func SanitizeMessages(in []ChatMessage) ([]ChatMessage, error) {
	out := make([]ChatMessage, 0, len(in))
	total := 0
	for _, m := range in {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		if role != "user" {
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

// ServerConversation shapes sanitized operator turns into the message list a
// provider receives. One turn passes through unchanged. Several are folded into
// ONE user turn — the earlier messages framed, by the server, as context ahead
// of the current one — because with the client's assistant turns gone they
// would otherwise arrive as consecutive user turns, which providers do not
// uniformly accept, and because the model must be told plainly that its earlier
// replies are not in front of it (so it never pretends to quote one). Earlier
// messages are flattened to one line each so a planted line break cannot forge
// the framing. The input is not mutated.
func ServerConversation(msgs []ChatMessage) []ChatMessage {
	if len(msgs) <= 1 {
		return msgs
	}
	var b strings.Builder
	b.WriteString("Earlier messages from the operator in this conversation, oldest first (context only; your replies to them are not included):\n")
	for _, m := range msgs[:len(msgs)-1] {
		b.WriteString("- ")
		b.WriteString(promptLine(m.Content))
		b.WriteString("\n")
	}
	b.WriteString("\nThe operator's current message:\n")
	b.WriteString(msgs[len(msgs)-1].Content)
	return []ChatMessage{{Role: "user", Content: b.String()}}
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
	c, err := CallProviderUsage(ctx, name, key, model, system, msgs)
	return c.Text, err
}

// Completion is one provider answer plus the PROVIDER'S OWN token accounting.
// Usage.Reported is false when the response carried no usage block — the
// number is then unknown, never estimated here.
type Completion struct {
	Text  string
	Usage TokenUsage
}

// CallProviderUsage is CallProvider with the provider-reported usage attached.
func CallProviderUsage(ctx context.Context, name, key, model, system string, msgs []ChatMessage) (Completion, error) {
	switch name {
	case "openai":
		return callOpenAI(ctx, key, model, system, msgs)
	case "gemini":
		return callGemini(ctx, key, model, system, msgs)
	case "anthropic":
		return callAnthropic(ctx, key, model, system, msgs)
	}
	return Completion{}, fmt.Errorf("unknown provider %q", name)
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

// ProviderStatusError is a non-2xx provider answer. The status decides whether
// the call is retried; the body is logged server-side only (SR-022).
type ProviderStatusError struct {
	Provider   string
	Status     int
	RetryAfter time.Duration // the provider's Retry-After hint, 0 when absent
	// Reason is the provider's own machine-readable error class from the error
	// body (Google "status": NOT_FOUND / INVALID_ARGUMENT / PERMISSION_DENIED /
	// RESOURCE_EXHAUSTED; Anthropic/OpenAI "type"/"code"). A closed enum on the
	// provider's side, so it is safe to log; the message text is not kept.
	Reason string
}

func (e *ProviderStatusError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s: status %d (%s)", e.Provider, e.Status, e.Reason)
	}
	return fmt.Sprintf("%s: status %d", e.Provider, e.Status)
}

// providerErrorReason extracts the provider's error CLASS from an error body:
// Google's {"error":{"code":404,"message":…,"status":"NOT_FOUND"}}, Anthropic's
// {"type":"error","error":{"type":"not_found_error",…}}, OpenAI's
// {"error":{"type":…,"code":"model_not_found"}}. Only a short identifier-shaped
// value is returned — never the message.
func providerErrorReason(body []byte) string {
	var env struct {
		Error struct {
			Status  string `json:"status"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
			Details []struct {
				Reason string `json:"reason"` // google.rpc.ErrorInfo, e.g. API_KEY_INVALID
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	// The ErrorInfo reason is the most specific (Gemini: API_KEY_INVALID under
	// a generic 400 INVALID_ARGUMENT), so it wins.
	cands := make([]string, 0, len(env.Error.Details)+3)
	for _, d := range env.Error.Details {
		cands = append(cands, d.Reason)
	}
	cands = append(cands, env.Error.Status, codeString(env.Error.Code), env.Error.Type)
	for _, v := range cands {
		if reasonToken.MatchString(v) {
			return v
		}
	}
	return ""
}

// codeString keeps a string error code (OpenAI "model_not_found"); Google's
// numeric code repeats the HTTP status and is dropped.
func codeString(v any) string {
	s, _ := v.(string)
	return s
}

var reasonToken = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{1,63}$`)

// Provider retry policy (CLAUDE.md §9: every network call retries with backoff
// + jitter, bounded). A completion is a read — replaying it cannot change
// anything — so a transient failure is retried; a caller error (4xx other than
// 408/429) never is, because asking again cannot fix it. The context deadline
// always wins: no sleep outlasts it.
var (
	providerMaxAttempts   = 3
	providerBackoffBase   = 400 * time.Millisecond
	providerBackoffCap    = 3 * time.Second
	providerRetryAfterCap = 5 * time.Second
	providerSleep         = sleepCtx
)

// retryableProviderStatus is the closed set of statuses worth asking again.
// 529 is Anthropic's "overloaded".
func retryableProviderStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return true
	}
	return false
}

// providerBackoff is full-jitter exponential backoff for retry n (1-based),
// raised to the provider's own Retry-After hint when it gave one (bounded).
func providerBackoff(n int, hint time.Duration) time.Duration {
	ceil := providerBackoffBase << (n - 1)
	if ceil > providerBackoffCap || ceil <= 0 {
		ceil = providerBackoffCap
	}
	d := time.Duration(rand.Int64N(int64(ceil) + 1)) // #nosec G404 -- retry jitter, not a security context
	if hint > d {
		d = min(hint, providerRetryAfterCap)
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ProviderDo performs one provider HTTP call — retried on a transient failure
// — and returns the 2xx body. On a non-2xx it logs the provider's error body
// server-side (SR-022 — never echoed to the client) and returns an error so the
// chain falls through. The URL is never logged (Gemini carries its key in the
// query string).
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
	var lastErr error
	for attempt := 1; attempt <= providerMaxAttempts; attempt++ {
		rb, err := providerDoOnce(ctx, urlStr, headers, body, provider)
		if err == nil {
			return rb, nil
		}
		lastErr = err
		if attempt == providerMaxAttempts || ctx.Err() != nil {
			break
		}
		var hint time.Duration
		var se *ProviderStatusError
		switch {
		case errors.As(err, &se):
			if !retryableProviderStatus(se.Status) {
				return nil, err
			}
			hint = se.RetryAfter
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, err
		default:
			// A provider that hung until the client timeout is not retried: a
			// second 60 s wait is worse than the chain falling through to the
			// next provider now. Connection-level failures (refused, reset) are.
			var te interface{ Timeout() bool }
			if errors.As(err, &te) && te.Timeout() {
				return nil, err
			}
		}
		wait := providerBackoff(attempt, hint)
		applog.Warn("copilot", "provider call failed — retrying", map[string]any{
			"provider": provider, "attempt": attempt, "wait_ms": wait.Milliseconds(), "err": err.Error()})
		if serr := providerSleep(ctx, wait); serr != nil {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// providerDoOnce is exactly one HTTP exchange.
func providerDoOnce(ctx context.Context, urlStr string, headers map[string]string, body []byte, provider string) ([]byte, error) {
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
		err = scrubURLError(err)
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
		se := &ProviderStatusError{Provider: provider, Status: resp.StatusCode, Reason: providerErrorReason(rb)}
		if secs, perr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); perr == nil && secs > 0 {
			se.RetryAfter = time.Duration(secs) * time.Second
		}
		return nil, se
	}
	return rb, nil
}

// ---- OpenAI (ChatGPT) -------------------------------------------------------

func callOpenAI(ctx context.Context, key, model, system string, msgs []ChatMessage) (Completion, error) {
	// The server-controlled system prompt goes in as a leading system-role
	// message; msgs are already sanitized to user/assistant.
	all := append([]ChatMessage{{Role: "system", Content: system}}, msgs...)
	body, _ := json.Marshal(map[string]any{"model": model, "messages": all, "max_tokens": MaxOutputTokens}) // discard: marshalling an in-memory value cannot fail
	rb, err := ProviderDo(ctx, "https://api.openai.com/v1/chat/completions", map[string]string{"Authorization": "Bearer " + key}, body, "openai")
	if err != nil {
		return Completion{}, err
	}
	return parseOpenAI(rb)
}

// parseOpenAI extracts the assistant text from an OpenAI chat-completions body.
func parseOpenAI(rb []byte) (Completion, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return Completion{}, err
	}
	if len(out.Choices) == 0 {
		return Completion{}, fmt.Errorf("openai: empty response")
	}
	if strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return Completion{}, &ProviderEmptyError{Provider: "openai", FinishReason: enumOnly(out.Choices[0].FinishReason)}
	}
	c := Completion{Text: out.Choices[0].Message.Content}
	if out.Usage != nil {
		c.Usage = TokenUsage{InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens, Reported: true}
	}
	return c, nil
}

// ---- Gemini (Google) --------------------------------------------------------

func callGemini(ctx context.Context, key, model, system string, msgs []ChatMessage) (Completion, error) {
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
	// Gemini authenticates with the x-goog-api-key HEADER, never the query
	// string: a transport error (*url.Error) embeds the full request URL in its
	// message, and a key in the URL was written to the logs on every failed call
	// (found live 2026-11-10). The header never appears in an error.
	rb, err := ProviderDo(ctx, GeminiEndpoint(model), GeminiAuthHeader(key), body, "gemini")
	if err != nil {
		return Completion{}, err
	}
	return parseGemini(rb)
}

// geminiBase is the Generative Language API root (a var so a test can point it
// at a fake server; production never changes it).
var geminiBase = "https://generativelanguage.googleapis.com/v1beta/models/"

// GeminiEndpoint is the generateContent URL for a model. It carries NO key:
// the key travels in the x-goog-api-key header (GeminiAuthHeader). With the key
// in the query string, as before 2026-11-10, Go's *url.Error put it into every
// transport-error message ("Post \"…?key=AIza…\": context deadline exceeded"),
// i.e. into the log line that is supposed to explain the failure.
func GeminiEndpoint(model string) string {
	return geminiBase + url.PathEscape(strings.TrimPrefix(strings.TrimSpace(model), "models/")) + ":generateContent"
}

// GeminiAuthHeader is the header that authenticates a Gemini API call.
func GeminiAuthHeader(key string) map[string]string {
	return map[string]string{"x-goog-api-key": key}
}

// SwapGeminiBaseForTest points Gemini calls at base and returns a restore func
// — tests only.
func SwapGeminiBaseForTest(base string) (restore func()) {
	prev := geminiBase
	geminiBase = base
	return func() { geminiBase = prev }
}

// parseGemini extracts the assistant text from a Gemini generateContent body.
// A body with no text is an error that names the provider's own reason: the
// prompt was blocked (promptFeedback.blockReason), the answer was stopped
// (finishReason SAFETY/RECITATION/…), or — on a thinking model — the output cap
// was spent on thinking before any text (finishReason MAX_TOKENS with
// thoughtsTokenCount > 0). Returning "" as success hid all three.
func parseGemini(rb []byte) (Completion, error) {
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text    string `json:"text"`
					Thought bool   `json:"thought"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		PromptFeedback *struct {
			BlockReason string `json:"blockReason"`
		} `json:"promptFeedback"`
		UsageMetadata *struct {
			PromptTokenCount     int64 `json:"promptTokenCount"`
			CandidatesTokenCount int64 `json:"candidatesTokenCount"`
			ThoughtsTokenCount   int64 `json:"thoughtsTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return Completion{}, err
	}
	empty := &ProviderEmptyError{Provider: "gemini"}
	if out.PromptFeedback != nil {
		empty.BlockReason = enumOnly(out.PromptFeedback.BlockReason)
	}
	if out.UsageMetadata != nil {
		empty.ThoughtTok = out.UsageMetadata.ThoughtsTokenCount
	}
	if len(out.Candidates) == 0 {
		return Completion{}, empty
	}
	var sb strings.Builder
	for _, p := range out.Candidates[0].Content.Parts {
		if p.Thought {
			continue // a thought summary is not the answer
		}
		sb.WriteString(p.Text)
	}
	if strings.TrimSpace(sb.String()) == "" {
		empty.FinishReason = enumOnly(out.Candidates[0].FinishReason)
		return Completion{}, empty
	}
	c := Completion{Text: sb.String()}
	if out.UsageMetadata != nil {
		c.Usage = TokenUsage{InputTokens: out.UsageMetadata.PromptTokenCount, OutputTokens: out.UsageMetadata.CandidatesTokenCount, Reported: true}
	}
	return c, nil
}

// ---- Anthropic (Copilot/Claude) ---------------------------------------------

func callAnthropic(ctx context.Context, key, model, system string, msgs []ChatMessage) (Completion, error) {
	// Anthropic Messages API: "system" is separate from messages.
	body, _ := json.Marshal(map[string]any{ // discard: marshalling an in-memory value cannot fail
		"model": model, "max_tokens": MaxOutputTokens, "system": system, "messages": msgs,
	})
	rb, err := ProviderDo(ctx, "https://api.anthropic.com/v1/messages",
		map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}, body, "anthropic")
	if err != nil {
		return Completion{}, err
	}
	return parseAnthropic(rb)
}

// parseAnthropic extracts the assistant text from an Anthropic Messages body.
func parseAnthropic(rb []byte) (Completion, error) {
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      *struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return Completion{}, err
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if strings.TrimSpace(sb.String()) == "" {
		return Completion{}, &ProviderEmptyError{Provider: "anthropic", FinishReason: enumOnly(out.StopReason)}
	}
	c := Completion{Text: sb.String()}
	if out.Usage != nil {
		c.Usage = TokenUsage{InputTokens: out.Usage.InputTokens, OutputTokens: out.Usage.OutputTokens, Reported: true}
	}
	return c, nil
}

// enumOnly keeps a provider enum value (finish/stop/block reason) only when it
// is identifier-shaped, so nothing free-form reaches a log line.
func enumOnly(v string) string {
	if reasonToken.MatchString(v) {
		return v
	}
	return ""
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

// scrubURLError strips the query string and any userinfo from the URL a
// transport error carries, so a credential that ever travels in a URL cannot
// reach a log line or a caller through err.Error(). Defense in depth: no
// provider puts a key in the URL any more.
func scrubURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	u, perr := url.Parse(ue.URL)
	if perr != nil {
		return &url.Error{Op: ue.Op, URL: "<unparseable url>", Err: ue.Err}
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.User = nil
	u.Fragment = ""
	return &url.Error{Op: ue.Op, URL: u.String(), Err: ue.Err}
}
