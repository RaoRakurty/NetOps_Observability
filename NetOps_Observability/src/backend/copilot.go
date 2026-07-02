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
	"regexp"
	"strings"
	"time"

	"netops/backend/ai"
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
	// Per-tenant entitlement (§3a): the assistant is a per-tenant feature, not a
	// platform-global one. Cross-tenant principals are never gated here.
	if !s.aiAssistantAllowed(claims) {
		writeError(w, http.StatusForbidden, errAITenantDisabled)
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

	// Docs-portal grounding (intelligence plan P1): retrieve the sections most
	// relevant to the operator's LATEST question and append them as a labeled
	// reference DATA block (LLM01: retrieved content is quoted material, never
	// instructions). Retrieval is server-side and deterministic; the retrieved
	// pages ride back to the UI as clickable "From the docs" links either way.
	docRefs := []copilotDocRef{}
	if q := latestUserMessage(msgs); q != "" {
		hits := aiDocsIndex.Search(q, 3)
		if block := ai.PromptBlock(hits, 2000, 7000); block != "" {
			system += "\n\n" + block
		}
		for _, h := range hits {
			if h.Chunk.Href != "" {
				docRefs = append(docRefs, copilotDocRef{ID: h.Chunk.ID, Label: h.Chunk.Breadcrumb, Href: h.Chunk.Href})
			}
		}
	}

	// Agent loop (intelligence plan P2): when FEATURE_AI_TOOLS is on and this
	// caller is in the rollout, let the model investigate with governed read-only
	// tools before answering. Falls back to plain chat when the loop can't start
	// (no budget, provider refuses) — but a turn that already executed lookups
	// fails cleanly rather than silently restarting as an unGrounded chat.
	if s.agentLoopEligible(claims) {
		if handled := s.tryAgentLoop(w, r, claims, msgs, system, docRefs); handled {
			return
		}
	}

	// Provider fallback chain, resolved PER PRINCIPAL (ai_tenant_config.go): a
	// tenant's own BYO key wins outright; a strict tenant (no_platform_key) gets
	// nothing rather than riding the platform key; otherwise the platform chain
	// applies (per-provider env keys, then the UI-stored platform key), order
	// configurable via COPILOT_PROVIDER_CHAIN. Each candidate is tried in order;
	// on provider error the next is attempted; the first success wins.
	attempted := false
	for _, cand := range s.providerCandidates(claims) {
		name := cand.name
		attempted = true
		text, err := callProvider(r.Context(), name, cand.key, cand.model, system, msgs)
		if err == nil && strings.TrimSpace(text) != "" {
			// Strip any doc citation the model INVENTED (an id not among the
			// retrieved chunks) — same fake-authority guardrail as the grounded
			// engine, scoped to doc: ids so ordinary bracketed prose survives.
			text = stripFabricatedDocRefs(text, docRefs)
			writeJSON(w, http.StatusOK, map[string]any{"provider": name, "text": text, "doc_refs": docRefs})
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

// firstConfiguredProvider resolves the first provider candidate for this
// principal (tenant BYO key first, then the platform chain) — the agent loop
// uses exactly one provider per turn (no cross-provider loop resumption, plan
// §3.d).
func (s *server) firstConfiguredProvider(claims jwtClaims) (name, key, model string) {
	if cands := s.providerCandidates(claims); len(cands) > 0 {
		return cands[0].name, cands[0].key, cands[0].model
	}
	return "", "", ""
}

// tryAgentLoop attempts the tool-driven investigation for this turn. Returns
// true when it wrote the response (success OR a mid-loop failure that must not
// silently restart as plain chat); false → caller falls through to plain chat.
func (s *server) tryAgentLoop(w http.ResponseWriter, r *http.Request, claims jwtClaims, msgs []copilotMessage, system string, docRefs []copilotDocRef) bool {
	name, key, model := s.firstConfiguredProvider(claims)
	if key == "" {
		return false // no provider — plain path renders the "add a key" message
	}
	tenant, _ := principalTenant(claims)
	if !s.aiToolBudget.allow(tenant) {
		logWarn("ai", "agent loop skipped — daily token budget exhausted", map[string]any{"tenant": claims.Tenant})
		return false // fail closed to chat-without-tools (plan §4.5), disclosed via provider note
	}
	p := s.aiPrincipal(claims)
	ds := aiDataSource{srv: s, ctx: r.Context(), scope: chTenantScope(r), claims: claims}
	reg := ai.Tools(ds)
	reg.AddDocsSearch(aiDocsIndex)
	pol := ai.NewPolicyEngine(ai.PolicyConfig{}, envFlagLookup) // safe default: read-only
	specs := ai.Manifest(reg, pol, p)
	if len(specs) == 0 {
		return false // caller can run nothing — plain chat is strictly better
	}
	// Server-owned investigation playbook + current-time anchor (models cannot
	// resolve "last night" without knowing now).
	system += "\n\n" + agentDoctrine(time.Now().UTC())
	call := func(ctx context.Context, sys string, turns []agentTurn, sp []ai.ToolSpec) (string, []ai.ToolCall, error) {
		return callProviderTools(ctx, name, key, model, sys, turns, sp)
	}
	preIDs := make([]string, 0, len(docRefs))
	for _, dr := range docRefs {
		preIDs = append(preIDs, dr.ID)
	}
	res, err := s.runAgentLoop(r.Context(), claims, p, reg, pol, specs, system, msgs, preIDs, call)
	if err != nil {
		logWarn("ai", "agent loop failed", map[string]any{"provider": name, "calls": res.Calls, "err": err.Error()})
		if res.Calls == 0 {
			return false // nothing executed — plain chat retry is safe
		}
		// Lookups already ran; disclose the failure instead of silently
		// re-answering without them (plan §3.d: fail the turn cleanly).
		writeError(w, http.StatusBadGateway, fmt.Errorf("Correlix AI couldn't finish the investigation — please try again"))
		return true
	}
	// Doc-kind citations from search_docs join the "From the docs" chips (and
	// the [doc:…] strip set); everything else stays an evidence citation.
	docSet := make(map[string]bool, len(docRefs))
	for _, dr := range docRefs {
		docSet[strings.ToLower(dr.ID)] = true
	}
	evCites := make([]ai.Citation, 0, len(res.Citations))
	for _, c := range res.Citations {
		if c.Kind != "doc" {
			evCites = append(evCites, c)
			continue
		}
		if docSet[strings.ToLower(c.ID)] {
			continue
		}
		if ref, ok := docRefForChunkID(c.ID); ok {
			docRefs = append(docRefs, ref)
			docSet[strings.ToLower(c.ID)] = true
		}
	}
	text := stripFabricatedDocRefs(res.Text, docRefs)
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": name, "text": text, "doc_refs": docRefs,
		"lookups": res.Lookups, "investigated": len(res.Lookups),
		"citations": evCites, "truncated": res.Truncated,
	})
	return true
}

// docRefForChunkID resolves a doc citation id back to its chunk so the UI chip
// carries the clean breadcrumb + Help-drawer link (small embedded corpus — a
// linear scan per doc citation is fine).
func docRefForChunkID(id string) (copilotDocRef, bool) {
	for _, c := range aiDocsIndex.All() {
		if strings.EqualFold(c.ID, id) {
			return copilotDocRef{ID: c.ID, Label: c.Breadcrumb, Href: c.Href}, true
		}
	}
	return copilotDocRef{}, false
}

// copilotDocRef is one retrieved documentation section returned alongside the
// answer, so the UI can render "From the docs" links that open the Help drawer.
type copilotDocRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

// latestUserMessage returns the newest user turn — the question retrieval runs on.
func latestUserMessage(msgs []copilotMessage) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[i].Content
		}
	}
	return ""
}

// reCopilotDocRef matches only doc-namespace citations, e.g. [doc:send-data/syslog#step-1].
var reCopilotDocRef = regexp.MustCompile(`\s?\[(doc:[^\]]{1,200})\]`)

// stripFabricatedDocRefs removes bracketed [doc:…] citations the model invented
// (ids not among the actually-retrieved chunks). Scoped to the doc: namespace on
// purpose: free-form prose legitimately uses other bracketed text ("[RFC 5880:
// BFD]"), which must survive untouched.
func stripFabricatedDocRefs(text string, refs []copilotDocRef) string {
	if !strings.Contains(text, "[doc:") {
		return text
	}
	valid := make(map[string]bool, len(refs))
	for _, r := range refs {
		valid[strings.ToLower(r.ID)] = true
	}
	return reCopilotDocRef.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.TrimSpace(m)
		inner = strings.ToLower(strings.Trim(inner, "[] "))
		if valid[inner] {
			return m
		}
		return ""
	})
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
		// Evergreen alias — Google retires dated 1.x/2.x ids (gemini-1.5-flash now 404s).
		return "gemini-flash-latest"
	case "anthropic":
		return "claude-sonnet-4-6"
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
