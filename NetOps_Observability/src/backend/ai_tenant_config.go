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

	"netops/backend/ai"
	"netops/backend/internal/aientitlement"
)

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
// It cannot change the provider, cannot change the key, cannot add a candidate
// and cannot reorder the chain — so none of the BYO rules above can be reached
// through it. With no per-tier model configured (every deployment until an
// operator sets one) every tier resolves to the same single model the chain
// resolved before, which is why this change is invisible to an existing install.
func (s *server) providerCandidatesForTier(claims jwtClaims, tier ai.ModelTier) []providerCandidate {
	tenant, cross := principalTenant(claims)
	if !cross {
		if name, key, model, ok := s.aiTenantCfg.BYOProvider(tenant, tier, providerModel); ok {
			return []providerCandidate{{name: name, key: key, model: model, source: "tenant"}}
		}
		if s.aiTenantCfg.NoPlatformKey(tenant) {
			return nil
		}
	}
	storedKey := s.copilotCfg.APIKey()
	cfg := s.copilotCfg.Get()
	tiered := cfg.Models().For(tier)
	var out []providerCandidate
	for _, name := range copilotProviderChain() {
		key := providerKey(name)
		if key == "" && storedKey != "" && name == cfg.Provider {
			key = storedKey
		}
		if key == "" {
			continue
		}
		model := providerModel(name)
		// A per-tier (or single) model override applies only to the provider it
		// was configured FOR: a model name is provider-specific, and riding the
		// anthropic model into the openai fallback produces exactly the baffling
		// failure the provider-switch key rule already exists to prevent.
		if name == cfg.Provider && tiered != "" {
			model = tiered
		}
		out = append(out, providerCandidate{name: name, key: key, model: model, source: "platform"})
	}
	return out
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
		"investigations_enabled": c.AgentTools && featureAIToolsEnabled(),
		"platform_key_available": s.copilotKeyPresent(),
		"providers":              []string{"anthropic", "openai", "gemini"},
		"model_suggestions": map[string][]string{
			"anthropic": {"claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"},
			"openai":    {"gpt-4o", "gpt-4o-mini", "gpt-4.1"},
			"gemini":    {"gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest"},
		},
	}
}

// handleAITenants: GET /api/ai/tenants (list entitlements) and
// PUT /api/ai/tenants/{id} (set one tenant's entitlement) — platform owner
// only. This is platform packaging, deliberately NOT tenant-admin writable
// (§3a.3: a tenant admin holds administration:admin, so a scope-blind gate
// here would let tenants grant themselves the agent loop).
func (s *server) handleAITenants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		type row struct {
			TenantID       string `json:"tenant_id"`
			Name           string `json:"name"`
			Assistant      bool   `json:"assistant_enabled"`
			Investigations bool   `json:"investigations_enabled"`
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
				KeyPresent:     c.Key != "",
				NoPlatformKey:  c.NoPlatformKey,
				MaxCalls:       c.MaxCalls,
				DailyTokens:    c.DailyTokens,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants":       rows,
			"tools_feature": featureAIToolsEnabled(), // investigations need FEATURE_AI_TOOLS too
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
			MaxCalls       int  `json:"max_calls"`    // 0 = platform default
			DailyTokens    int  `json:"daily_tokens"` // 0 = platform default
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
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":              t.ID,
			"assistant_enabled":      !c.AssistantOff,
			"investigations_enabled": c.AgentTools,
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
	status, msg := http.StatusForbidden, "this installation's licence does not include "+aientitlement.Label(e)
	switch d.Reason {
	case aientitlement.ReasonDisabled:
		status = http.StatusServiceUnavailable
		msg = "Iris AI is disabled — set FEATURE_AI=true"
		if e == aientitlement.Investigate {
			msg = "AI investigations are disabled — set FEATURE_AI_TOOLS=true"
		}
	case aientitlement.ReasonTenantOff:
		msg = errAITenantDisabled.Error()
	case aientitlement.ReasonUnknown:
		msg = "unknown AI capability"
	}
	writeJSON(w, status, map[string]string{"error": msg, "entitlement": string(e), "reason": string(d.Reason)})
	return false
}
