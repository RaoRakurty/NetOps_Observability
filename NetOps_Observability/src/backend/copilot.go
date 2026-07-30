package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
// The frontend Iris AI tab posts a chat history to /api/copilot/chat.
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

// copilotBodyCap caps the request body (LLM04: bound the request).
const copilotBodyCap = 256 << 10

type copilotRequest struct {
	Messages []copilotMessage `json:"messages"`
	// System is accepted for backward compatibility but IGNORED: the system
	// prompt is server-controlled (OWASP LLM01 — a client must not be able to
	// override the model's instructions / jailbreak it). See handleCopilot.
	System string `json:"system,omitempty"`
}

// The message sanitizer, doc-ref hygiene, provider transport and default
// system prompt moved to ai/llm_transport.go (Phase-2 W3.5). Aliases below;
// env resolution (chain/keys/models) and the docs index stay here.
type (
	copilotMessage = ai.ChatMessage
	copilotDocRef  = ai.DocRef
)

func (s *server) copilotSystemPrompt() string {
	persona := ai.DefaultSystemPrompt()
	if s.copilotCfg != nil {
		if sys := strings.TrimSpace(s.copilotCfg.Get().System); sys != "" {
			persona = sys
		}
	}
	// The brevity contract rides EVERY persona (default or override): operators
	// live in a console, and style instructions ("too verbose", "briefly") are
	// commands, not commentary — live incident 2026-07-02.
	persona += "\n\nBREVITY: be concise by default — at most ~6 short sentences unless the operator asks for detail. ALWAYS obey style instructions immediately: \"too verbose\"/\"briefly\"/\"shorter\" means compress your PREVIOUS answer to 2-3 sentences keeping the counts, the top item and the next action. Never respond to a style instruction with a menu of capabilities."
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
	if !s.copilotLimiter.AllowN(claims.Tenant+"|"+claims.Sub, envInt("COPILOT_RATE_PER_MIN", 20)) {
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
	r.Body = http.MaxBytesReader(w, r.Body, copilotBodyCap)
	var req copilotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	msgs, err := ai.SanitizeMessages(req.Messages)
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
	if q := ai.LatestUserMessage(msgs); q != "" {
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
		text, err := ai.CallProvider(r.Context(), name, cand.key, cand.model, system, msgs)
		if err == nil && strings.TrimSpace(text) != "" {
			// Strip any doc citation the model INVENTED (an id not among the
			// retrieved chunks) — same fake-authority guardrail as the grounded
			// engine, scoped to doc: ids so ordinary bracketed prose survives.
			text = ai.StripFabricatedDocRefs(text, docRefs)
			writeJSON(w, http.StatusOK, map[string]any{"provider": name, "text": text, "doc_refs": docRefs})
			return
		}
		// SR-022: the provider's raw error body is logged server-side by
		// providerDo, never echoed to the client. Fall through to the next.
		logWarn("copilot", "provider attempt failed, falling through", map[string]any{"provider": name})
	}
	// Provider-down fallback (owner decision 2026-07-02): the grounded engine
	// answers when no LLM can — evidence-only, tenant-scoped, key-free — with a
	// disclosure the UI renders as a slim banner. The assistant degrades, never
	// dead-ends. (No key configured at all still explains how to add one.)
	if attempted {
		if q := ai.LatestUserMessage(msgs); q != "" {
			if ans, err := s.newOrchestrator(r, claims).Ask(r.Context(), s.aiPrincipal(claims), q, nil); err == nil {
				logInfo("copilot", "provider unavailable — engine fallback answered", map[string]any{"tenant": claims.Tenant})
				writeJSON(w, http.StatusOK, map[string]any{
					"provider": "engine", "text": ans.Text, "grounded": ans, "doc_refs": docRefs,
					"fallback": "provider_unavailable",
				})
				return
			}
		}
		writeError(w, http.StatusBadGateway, fmt.Errorf("Iris AI couldn't reach the AI provider — please try again; if it persists, check the API key in settings"))
		return
	}
	writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Iris AI isn't connected to an AI provider yet — open the assistant settings (gear icon) and add an API key"))
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
	if !s.aiToolBudget.Allow(tenant, s.dailyTokensFor(tenant)) {
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
	system += "\n\n" + ai.AgentDoctrine(time.Now().UTC())
	call := func(ctx context.Context, sys string, turns []ai.AgentTurn, sp []ai.ToolSpec) (string, []ai.ToolCall, error) {
		return ai.CallTools(ctx, ai.ProviderDo, name, key, model, sys, turns, sp)
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
		writeError(w, http.StatusBadGateway, fmt.Errorf("Iris AI couldn't finish the investigation — please try again"))
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
	text := ai.StripFabricatedDocRefs(res.Text, docRefs)
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
func slicesContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func copilotProviderChain() []string {
	if raw := strings.TrimSpace(os.Getenv("COPILOT_PROVIDER_CHAIN")); raw != "" {
		var out []string
		for _, t := range strings.Split(raw, ",") {
			if p := ai.NormalizeProvider(t); p != "" && !slicesContains(out, p) {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	order := []string{"openai", "gemini", "anthropic"}
	if p := ai.NormalizeProvider(os.Getenv("COPILOT_PROVIDER")); p != "" && order[0] != p {
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
	if name == ai.NormalizeProvider(envOr("COPILOT_PROVIDER", "openai")) {
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
	if name == ai.NormalizeProvider(envOr("COPILOT_PROVIDER", "openai")) {
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
