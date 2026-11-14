// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/entitlement"
)

// ---- the AI add-on gate (owner 2026-11-12/13) ----------------------------------
//
// Model-backed Iris is the `iris_model` licence add-on (Enterprise includes it)
// AND the platform administrator's console-only "Iris AI models" switch
// (Features page). Both are platform-level; the tenant's own assistant switch
// is the third input (aientitlement.Model). The gate sits at the ONE place a
// provider candidate is produced — providerCandidatesForTier — so every model
// call, platform key or tenant BYO key, request or background, passes it.

// aiModelLicensed: the licence in force grants the AI add-on. Nil-safe: no
// licence service reads as Community, which does not include it.
func (s *server) aiModelLicensed() bool {
	return entitlement.Entitled(s.entitlements, entitlement.FeatureIrisModel)
}

// aiModelsSwitchOn / aiInvestigationsSwitchOn: the console-only switches. A
// nil registry reads off, and the registry itself reads off while the licence
// requirement is unmet.
func (s *server) aiModelsSwitchOn() bool { return s.features.Enabled(aientitlement.SwitchModels) }
func (s *server) aiInvestigationsSwitchOn() bool {
	return s.features.Enabled(aientitlement.SwitchInvestigations)
}

// The model planner's exact-match cache bounds (ai/planner.go): route ids
// only, so a few thousand entries cost well under a megabyte.
const (
	aiPlanCacheSize = 4096
	aiPlanCacheTTL  = 6 * time.Hour
	// The per-scope Iris vocabulary cache: one entry per tenant scope, rebuilt
	// on an inventory change or after the TTL (circuits, applications).
	aiGlossaryCacheSize = 1024
	aiGlossaryTTL       = 5 * time.Minute
)

// aiModelFirst: Iris routes the caller's questions through the model planner
// — exactly when the add-on gate would let a fast-tier call out for this
// caller: licensed, the "Iris AI models" switch on, the tenant's assistant on,
// and a provider key (the platform's or the workspace's own) configured. Asked
// of the one chokepoint, so model-first and the provider gate cannot disagree;
// with no model connected the deterministic router decides, as before.
func (s *server) aiModelFirst(claims jwtClaims) bool {
	return len(s.providerCandidatesForTier(claims, ai.TierFast)) > 0
}

// aiInvestigationsPlatformOn is the platform half of the investigation gate
// (what FEATURE_AI_TOOLS used to answer): licensed, models on, investigations on.
func (s *server) aiInvestigationsPlatformOn() bool {
	return s.aiModelLicensed() && s.aiModelsSwitchOn() && s.aiInvestigationsSwitchOn()
}

// writeAIAddOnRefusal answers a connection test on an install without the AI
// add-on: 402 with the licence refusal body, and false. A test is licensed
// alone — not switched — so an administrator can prove the key works before
// turning the switch on (a test sends a fixed prompt and no customer data).
func (s *server) writeAIAddOnRefusal(w http.ResponseWriter) bool {
	if err := entitlement.Require(s.entitlements, entitlement.FeatureIrisModel); err != nil {
		entitlement.WriteRefusal(w, err)
		return false
	}
	return true
}

// aiModelsView is the platform's model state for the SPA's banners: one
// state token (unlicensed | off | on) plus the three facts behind it. It is
// platform-level, identical for every caller, and carries no tenant data.
func (s *server) aiModelsView() map[string]any {
	licensed, models, investigations := s.aiModelLicensed(), s.aiModelsSwitchOn(), s.aiInvestigationsSwitchOn()
	state := "on"
	switch {
	case !licensed:
		state = "unlicensed"
	case !models:
		state = "off"
	}
	return map[string]any{
		"state": state, "licensed": licensed,
		"models_on": licensed && models, "investigations_on": licensed && models && investigations,
	}
}

// ai_tenant_config.go — per-tenant Iris AI configuration (intelligence plan
// P4a: "AI is per-tenant", CLAUDE.md §3a).
//
// Two concerns live here, both keyed by tenant in the store itself (no
// unscoped view exists for tenant callers):
//
//  1. ENTITLEMENT — whether a tenant's users may use the assistant at all, and
//     whether the bounded agent loop ("AI Investigations") is enabled for them.
//     Platform-owner controlled (requirePlatformAdmin): which tenants get AI is
//     platform packaging, not tenant self-service. Defaults: assistant ON,
//     investigations OFF (staged rollout preserved).
//  2. BYO PROVIDER KEY — a tenant admin may supply their own provider API key
//     so their AI traffic runs under their own provider agreement (LLM06).
//     Sealed at rest under the TENANT DEK (same Vault pattern as SNMP creds),
//     write-only, never returned to any client. A tenant key always wins over
//     the platform key; `no_platform_key` additionally forbids the platform-key
//     fallback for strict data-processing tenants (their AI goes dark instead
//     of riding the operator's provider account).
//
// Cross-tenant principals (the platform owner) are never gated here — they use
// the platform chain in copilot.go as before.

// The tenant AI config store moved to ai/tenant_config.go (Phase-2 W3.7).
type (
	aiTenantConfig      = ai.TenantConfig
	aiTenantConfigStore = ai.TenantConfigStore
)

func newAITenantConfigStore(path string, v ai.SecretSealer) *aiTenantConfigStore {
	return ai.NewTenantConfigStore(path, v)
}

func (s *server) maxCallsFor(tenant string) int {
	n := s.aiTenantCfg.Get(tenant).MaxCalls
	if n <= 0 {
		n = envInt("AI_TOOLS_MAX_CALLS", 4)
	}
	if n < 1 {
		n = 1
	} else if n > 8 {
		n = 8
	}
	return n
}

// dailyTokensFor resolves the tokens/day budget for a tenant: its override when
// set, else the platform default (AI_TOOLS_DAILY_TOKENS; <=0 disables metering).
func (s *server) dailyTokensFor(tenant string) int {
	if n := s.aiTenantCfg.Get(tenant).DailyTokens; n > 0 {
		return n
	}
	return aiToolsDailyTokens()
}

// ---- gates (used by copilot.go / ai_handlers.go / copilot_agent.go) ----------

// The per-tenant assistant / investigation switches are consulted through the
// atomic AI entitlements (below, tracker 337 N-A7), which AND them
// with the licence tier's mapping and the deployment flags.

var errAITenantDisabled = errors.New("Iris AI isn't enabled for this account — contact your administrator")

// providerCandidate is one resolved (provider, key, model) the assistant may
// call for a given principal, in fallback order.
type providerCandidate struct {
	name, key, model string
	source           string // "tenant" | "platform"
	// fallback marks the provider's recommended model standing in after the
	// configured one (withModelFallback): same provider, same key.
	fallback bool
}

// withModelFallback puts, right after each candidate, the same provider and
// key with its fallback model (ai.FallbackModel) — so an overloaded, retired
// or hanging model is followed by one that model's provider still serves,
// before the chain moves to the next provider. It adds no provider, no key
// and no reordering, so every BYO rule of providerCandidatesForTier holds: a
// tenant with its own key still only ever reaches its own provider and pays
// for its own calls. At most one fallback per candidate (the call budget is
// the stage's, so a fallback never extends a request; it only uses the time a
// fast failure — a 503, a 404 — left over).
func withModelFallback(cands []providerCandidate) []providerCandidate {
	out := make([]providerCandidate, 0, 2*len(cands))
	for _, c := range cands {
		out = append(out, c)
		if fb := ai.FallbackModel(c.name, c.model); fb != "" {
			out = append(out, providerCandidate{name: c.name, key: c.key, model: fb, source: c.source, fallback: true})
		}
	}
	return out
}

// providerCandidates resolves the provider fallback chain FOR A PRINCIPAL with
// NO routed tier — the free-form assistant proxy (copilot.go), which is not an
// answer mode. It is the pre-router behaviour, preserved exactly.
func (s *server) providerCandidates(claims jwtClaims) []providerCandidate {
	return s.providerCandidatesForTier(claims, "")
}

// providerCandidatesForTier resolves the provider fallback chain FOR A PRINCIPAL
// AND A MODEL TIER (§3a: every data-touching surface scopes by the caller;
// §10: the router picks the tier, this picks the model). Rules, unchanged:
//   - a tenant's own BYO key wins outright — their traffic never rides the
//     platform account when they brought a key;
//   - a strict tenant (no_platform_key) with no key of its own gets NOTHING —
//     fail closed to key-free mode rather than leak onto the platform key;
//   - otherwise (and always for cross-tenant principals) the platform chain
//     applies: per-provider env keys, then the UI-stored platform key.
//
// The TIER only ever chooses which of one configuration's model names is used.
// It cannot change the provider, cannot change the key, cannot add a provider
// and cannot reorder the chain (the one model fallback per candidate,
// withModelFallback, is the same provider and key) — so none of the BYO rules above can be reached
// through it. A tier with no model configured resolves to the provider's
// recommended model for that tier (ai.TierModels.ForProvider, owner decision
// 2026-11-12), never to the single default again.
func (s *server) providerCandidatesForTier(claims jwtClaims, tier ai.ModelTier) []providerCandidate {
	// THE AI ADD-ON GATE. No candidate — so no provider call, BYO or platform
	// — unless the licence carries the add-on, the platform switch is on and
	// the caller's tenant has the assistant on. An empty chain is what every
	// caller already handles as "no model": the grounded, evidence-only path.
	if !s.aiEntitled(claims, aientitlement.Model) {
		return nil
	}
	tenant, cross := principalTenant(claims)
	if !cross {
		if name, key, model, ok := s.aiTenantCfg.BYOProvider(tenant, tier, providerModel); ok {
			return withModelFallback([]providerCandidate{{name: name, key: key, model: model, source: "tenant"}})
		}
		if s.aiTenantCfg.NoPlatformKey(tenant) {
			return nil
		}
	}
	if s.copilotCfg == nil {
		return nil // no platform configuration wired: nothing to call
	}
	storedKey := s.copilotCfg.APIKey()
	cfg := s.copilotCfg.Get()
	var out []providerCandidate
	for _, name := range copilotProviderChain() {
		key := providerKey(name)
		if key == "" && storedKey != "" && name == cfg.Provider {
			key = storedKey
		}
		if key == "" {
			continue
		}
		// A per-tier (or single) model override applies only to the provider it
		// was configured FOR: a model name is provider-specific, and riding the
		// anthropic model into the openai fallback produces exactly the baffling
		// failure the provider-switch key rule already exists to prevent. A
		// blank tier is that provider's recommended tier model, never the
		// single default again (ai.TierModels.ForProvider, owner 2026-11-12).
		models := ai.TierModels{}
		if name == cfg.Provider {
			models = cfg.Models()
		}
		if strings.TrimSpace(models.Default) == "" {
			models.Default = providerModel(name) // env override, else the code default
		}
		model := models.ForProvider(tier, name)
		out = append(out, providerCandidate{name: name, key: key, model: model, source: "platform"})
	}
	return withModelFallback(out)
}

// ---- HTTP handlers ------------------------------------------------------------

// handleAITenantConfig: GET/PUT /api/ai/tenant-config — the CALLER'S OWN
// tenant's AI settings (tenant-admin gated). The tenant is always derived from
// the principal, never from the request (§3a.2). Entitlement fields are
// read-only here; the BYO key is write-only.
func (s *server) handleAITenantConfig(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	if cross {
		// The platform owner has no "own tenant" here — platform settings live in
		// /api/copilot/config, entitlement in /api/ai/tenants.
		writeError(w, http.StatusBadRequest, errors.New("platform owners configure the assistant in platform settings"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.aiTenantConfigView(tenant))
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		var req struct {
			Provider      string `json:"provider"`
			Model         string `json:"model"`
			ModelFast     string `json:"model_fast"`
			ModelStrong   string `json:"model_strong"`
			Key           string `json:"key"`
			NoPlatformKey bool   `json:"no_platform_key"`
			ClearKey      bool   `json:"clear_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if p := strings.TrimSpace(req.Provider); p != "" && ai.NormalizeProvider(p) == "" {
			writeError(w, http.StatusBadRequest, errors.New("unknown provider — use anthropic, openai or gemini"))
			return
		}
		if _, err := s.aiTenantCfg.SetTenantSettings(tenant, ai.TenantSettings{
			Provider: req.Provider, Model: req.Model,
			ModelFast: req.ModelFast, ModelStrong: req.ModelStrong,
			Key: req.Key, NoPlatformKey: req.NoPlatformKey, ClearKey: req.ClearKey,
		}); err != nil {
			// Audit the REFUSAL too. A write that failed and was never recorded
			// is indistinguishable from one that never happened.
			s.audit.Record(AuditEvent{
				Actor: claims.Sub, Tenant: tenant, Method: r.Method, Path: r.URL.Path,
				Status: http.StatusInternalServerError, Decision: "deny", Remote: auditClientIP(r),
				Detail: map[string]any{"action": "ai_tenant_settings", "error": "persist failed"},
			})
			writeError(w, http.StatusInternalServerError, errors.New("settings were not saved"))
			return
		}
		s.audit.Record(AuditEvent{
			Actor: claims.Sub, Tenant: tenant, Method: r.Method, Path: r.URL.Path,
			Status: http.StatusOK, Decision: "allow", Remote: auditClientIP(r),
			Detail: map[string]any{"action": "ai_tenant_settings", "key_changed": req.Key != "" || req.ClearKey},
		})
		writeJSON(w, http.StatusOK, s.aiTenantConfigView(tenant))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// aiTenantConfigView is the redacted own-tenant response: never the key, plus
// the read-only entitlement flags and whether a platform fallback even exists
// (so the UI can say "using the platform AI service" honestly).
func (s *server) aiTenantConfigView(tenant string) map[string]any {
	c := s.aiTenantCfg.Get(tenant)
	return map[string]any{
		"provider": c.Provider,
		"model":    c.Model,
		// §10 model-router overrides. Blank means "this tier uses model", which
		// is what the UI must render — not the resolved value, or an operator
		// could not tell a deliberate split from an inherited default.
		"model_fast":             c.ModelFast,
		"model_strong":           c.ModelStrong,
		"key_present":            c.Key != "",
		"no_platform_key":        c.NoPlatformKey,
		"assistant_enabled":      !c.AssistantOff,
		"investigations_enabled": c.AgentTools && s.aiInvestigationsPlatformOn(),
		"platform_key_available": s.copilotKeyPresent(),
		"providers":              []string{"gemini", "anthropic", "openai"},
		"model_suggestions":      ai.ModelSuggestions(),
		"recommended":            ai.RecommendedModels(),
		// D4: this workspace's own budget today (the banner says when spent).
		"budget": s.aiBudgetView(tenant),
	}
}

// handleAITenantConfigTest: POST /api/ai/tenant-config/test — a tenant admin
// tests THEIR OWN workspace's provider key (C3, §3a). The tenant comes from the
// principal only. A blank key tests the workspace's stored BYO key; the
// platform key is never tested here (a tenant must not be able to probe, and
// so learn about, the operator's provider account). The key is used for this
// one call only: never persisted, never logged, never echoed.
func (s *server) handleAITenantConfigTest(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, cross := principalTenant(claims)
	if cross {
		writeError(w, http.StatusBadRequest, errors.New("platform owners test the assistant in platform settings"))
		return
	}
	req, err := decodeProviderTest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// A workspace's own key is model-backed Iris too (owner 2026-11-13).
	if !s.writeAIAddOnRefusal(w) {
		return
	}
	tc := s.aiTenantCfg.Get(tenant)
	name, key := req.provider, req.key
	if key == "" {
		// The workspace's own stored key, for the provider it was stored for.
		bname, bkey, _, has := s.aiTenantCfg.BYOProvider(tenant, ai.TierFast, providerModel)
		if !has || (name != "" && name != bname) {
			writeError(w, http.StatusBadRequest, errors.New("this workspace has no API key of its own to test — paste one first"))
			return
		}
		name, key = bname, bkey
	}
	if name == "" {
		name = ai.NormalizeProvider(tc.Provider)
		if name == "" {
			name = "gemini"
		}
	}
	model := ai.ProbeModel(name, req.model, tc.Models(), ai.NormalizeProvider(tc.Provider))
	writeJSON(w, http.StatusOK, s.providerTest(r, claims, name, key, model, req.tierModels(name, tc.Models(), ai.NormalizeProvider(tc.Provider))))
}

// handleAITenants: GET /api/ai/tenants (list entitlements) and
// PUT /api/ai/tenants/{id} (set one tenant's entitlement) — platform owner
// only. This is platform packaging, deliberately NOT tenant-admin writable
// (§3a.3: a tenant admin holds administration:admin, so a scope-blind gate
// here would let tenants grant themselves the agent loop).
func (s *server) handleAITenants(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		type row struct {
			TenantID       string `json:"tenant_id"`
			Name           string `json:"name"`
			Assistant      bool   `json:"assistant_enabled"`
			Investigations bool   `json:"investigations_enabled"`
			MCP            bool   `json:"mcp_enabled"` // read-only MCP gateway opt-in (N-I5)
			KeyPresent     bool   `json:"key_present"` // tenant brought their own key
			NoPlatformKey  bool   `json:"no_platform_key"`
			MaxCalls       int    `json:"max_calls"`    // 0 = platform default
			DailyTokens    int    `json:"daily_tokens"` // 0 = platform default
		}
		var rows []row
		for _, t := range s.tenants.List() {
			if t.ID == TenantGlobal {
				continue // the platform's own tenant uses platform settings
			}
			c := s.aiTenantCfg.Get(t.ID)
			rows = append(rows, row{
				TenantID: t.ID, Name: t.Name,
				Assistant:      !c.AssistantOff,
				Investigations: c.AgentTools,
				MCP:            c.MCP,
				KeyPresent:     c.Key != "",
				NoPlatformKey:  c.NoPlatformKey,
				MaxCalls:       c.MaxCalls,
				DailyTokens:    c.DailyTokens,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants": rows,
			// Investigations also need the platform half: the AI add-on and both
			// console switches (Features page). Kept under its historical key.
			"tools_feature": s.aiInvestigationsPlatformOn(),
			// The platform half of MCP (N-I5): the console-only IRIS_MCP switch.
			"mcp_feature": s.features != nil && s.features.Enabled(aientitlement.SwitchMCP),
			"models":      s.aiModelsView(),
			"defaults": map[string]int{ // platform defaults, for UI placeholders
				"max_calls":    envInt("AI_TOOLS_MAX_CALLS", 4),
				"daily_tokens": aiToolsDailyTokens(),
			},
		})
	case http.MethodPut:
		id := strings.TrimPrefix(r.URL.Path, "/api/ai/tenants/")
		if id == "" || strings.Contains(id, "/") {
			writeError(w, http.StatusBadRequest, errors.New("tenant id required"))
			return
		}
		t, found := s.tenants.Get(id)
		if !found || t.ID == TenantGlobal {
			writeError(w, http.StatusNotFound, errors.New("tenant not found"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
		var req struct {
			Assistant      bool `json:"assistant_enabled"`
			Investigations bool `json:"investigations_enabled"`
			// MCP is optional so a client that predates N-I5 never switches it
			// off by omission: absent → the stored value is kept.
			MCP         *bool `json:"mcp_enabled,omitempty"`
			MaxCalls    int   `json:"max_calls"`    // 0 = platform default
			DailyTokens int   `json:"daily_tokens"` // 0 = platform default
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		c, err := s.aiTenantCfg.SetEntitlement(t.ID, !req.Assistant, req.Investigations, req.MaxCalls, req.DailyTokens)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("entitlement was not saved"))
			return
		}
		if req.MCP != nil && *req.MCP != c.MCP {
			if c, err = s.aiTenantCfg.SetMCP(t.ID, *req.MCP); err != nil {
				writeError(w, http.StatusInternalServerError, errors.New("MCP setting was not saved"))
				return
			}
			if s.audit != nil {
				s.audit.Record(AuditEvent{Time: time.Now().UTC(), Actor: claims.Sub, Tenant: t.ID, Cross: true,
					Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
					Detail: map[string]any{"action": "ai.mcp.workspace", "enabled": c.MCP}})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":              t.ID,
			"assistant_enabled":      !c.AssistantOff,
			"investigations_enabled": c.AgentTools,
			"mcp_enabled":            c.MCP,
			"max_calls":              c.MaxCalls,
			"daily_tokens":           c.DailyTokens,
		})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// aiTenantConfigPath resolves the store's kv key (env-overridable like every
// other config store).
func aiTenantConfigPath() string {
	return envOr("AI_TENANT_CONFIG_FILE", "/data/ai_tenant_config.json")
}

// ---- atomic AI entitlements (tracker 337 N-A7) -------------------------------

// The server side of the atomic AI entitlements
// (tracker 337 N-A7). Every AI route asks requireAIEntitlement for the one
// capability it exercises; the frontend receives aiEntitlementsFor via
// GET /api/features to hide what the caller cannot use. Hidden is cosmetic —
// these server-side gates are the control, and they are default-closed: an
// unparseable mapping, an unknown tier, a nil policy or a tenant with no
// switch source grants nothing.
//
// The licence tier only ever reaches this file as an opaque key into the
// shipped mapping (internal/aientitlement/tiers.json). Nothing here compares
// it to a tier name.

// aiDefaultPolicy is the shipped tier → entitlement mapping, parsed once. Like
// aiSkills it is embedded, immutable content; a parse failure is content drift
// identical on every deployment, logged LOUDLY, and the process then runs with
// a nil policy — no AI capability is granted, rather than all of them.
var aiDefaultPolicy = loadAIEntitlementPolicy()

func loadAIEntitlementPolicy() *aientitlement.Policy {
	p, err := aientitlement.Default()
	if err != nil {
		log.Printf("FATAL-GRADE CONFIG ERROR: the AI entitlement mapping failed to load — every AI capability is REFUSED for this process: %v", err)
		return nil
	}
	return p
}

// aiPolicy is the mapping in force: the injected one when set (tests), else
// the shipped default.
func (s *server) aiPolicy() *aientitlement.Policy {
	if s.aiEntitlementPolicy != nil {
		return s.aiEntitlementPolicy
	}
	return aiDefaultPolicy
}

// aiEntitlementInputs gathers the three inputs for one principal: the licence
// tier in force (Community when no licence service is wired — the entitlement
// package's own fail-closed default), the process flags, and the caller's
// tenant switches.
func (s *server) aiEntitlementInputs(claims jwtClaims) aientitlement.Inputs {
	tenant, cross := principalTenant(claims)
	return aientitlement.Inputs{
		Tier:   string(s.entitlements.Tier()), // nil-safe: a nil *licence.Service reads as Community
		Env:    os.Getenv,
		Tenant: tenant,
		Cross:  cross,
		// The store's own defaults apply when it holds no row for the tenant
		// (assistant on, investigations off — the platform owner's staged-
		// rollout policy, unchanged by N-A7). Its methods are nil-safe and
		// answer those same defaults, exactly as the pre-N-A7 gates did.
		Switches: s.aiTenantCfg,
		// The AI add-on (owner 2026-11-12/13): the licence and the console
		// switches. All three read false when unwired — fail closed.
		ModelLicensed:    s.aiModelLicensed(),
		ModelsOn:         s.aiModelsSwitchOn(),
		InvestigationsOn: s.aiInvestigationsSwitchOn(),
	}
}

// aiDecide answers one entitlement for one principal.
func (s *server) aiDecide(claims jwtClaims, e aientitlement.Entitlement) aientitlement.Decision {
	return aientitlement.Decide(s.aiPolicy(), e, s.aiEntitlementInputs(claims))
}

// aiEntitled is the boolean form, for paths that degrade rather than refuse
// (the investigation loop inside a chat turn, the data arm of an ask).
func (s *server) aiEntitled(claims jwtClaims, e aientitlement.Entitlement) bool {
	return s.aiDecide(claims, e).Granted
}

// aiEntitlementsFor is the caller's granted set, for the frontend.
func (s *server) aiEntitlementsFor(claims jwtClaims) []aientitlement.Entitlement {
	return aientitlement.Resolve(s.aiPolicy(), s.aiEntitlementInputs(claims))
}

// requireAIEntitlement is the route gate. It writes the refusal and returns
// false when the caller lacks e. Statuses keep their pre-N-A7 meaning so
// existing clients read them the same way:
//
//	503 — a deployment flag is off (the feature is switched off here)
//	403 — the licence tier's mapping does not include it, or the caller's
//	      tenant is not switched on (errAITenantDisabled, unchanged text)
//
// The body carries the entitlement and a stable reason token so the SPA can
// say WHICH capability is missing without parsing prose.
func (s *server) requireAIEntitlement(w http.ResponseWriter, claims jwtClaims, e aientitlement.Entitlement) bool {
	d := s.aiDecide(claims, e)
	if d.Granted {
		return true
	}
	status, msg := http.StatusForbidden, "this installation's license does not include "+aientitlement.Label(e)
	switch d.Reason {
	case aientitlement.ReasonDisabled:
		status = http.StatusServiceUnavailable
		msg = "Iris AI is disabled — set FEATURE_AI=true"
	case aientitlement.ReasonNotLicensed:
		// 402, as every licence refusal: the fix is the licence.
		status = http.StatusPaymentRequired
		msg = aientitlement.Label(e) + " need the Iris AI add-on on this installation's license (Enterprise includes it)"
	case aientitlement.ReasonSwitchedOff:
		status = http.StatusServiceUnavailable
		msg = aientitlement.Label(e) + " are turned off — a platform administrator can turn them on under Administration → Features"
	case aientitlement.ReasonTenantOff:
		msg = errAITenantDisabled.Error()
	case aientitlement.ReasonUnknown:
		msg = "unknown AI capability"
	}
	writeJSON(w, status, map[string]string{"error": msg, "entitlement": string(e), "reason": string(d.Reason)})
	return false
}
