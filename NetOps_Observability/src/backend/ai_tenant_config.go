// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"netops/backend/ai"
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

// aiAssistantAllowed: cross-tenant principals always may use the assistant;
// tenant users only when their tenant's entitlement says so.
func (s *server) aiAssistantAllowed(claims jwtClaims) bool {
	tenant, cross := principalTenant(claims)
	if cross {
		return true
	}
	return s.aiTenantCfg.AssistantEnabled(tenant)
}

var errAITenantDisabled = errors.New("Iris AI isn't enabled for this account — contact your administrator")

// providerCandidate is one resolved (provider, key, model) the assistant may
// call for a given principal, in fallback order.
type providerCandidate struct {
	name, key, model string
	source           string // "tenant" | "platform"
}

// providerCandidates resolves the provider fallback chain FOR A PRINCIPAL
// (§3a: every data-touching surface scopes by the caller). Rules:
//   - a tenant's own BYO key wins outright — their traffic never rides the
//     platform account when they brought a key;
//   - a strict tenant (no_platform_key) with no key of its own gets NOTHING —
//     fail closed to key-free mode rather than leak onto the platform key;
//   - otherwise (and always for cross-tenant principals) the platform chain
//     applies: per-provider env keys, then the UI-stored platform key.
func (s *server) providerCandidates(claims jwtClaims) []providerCandidate {
	tenant, cross := principalTenant(claims)
	if !cross {
		if name, key, model, ok := s.aiTenantCfg.BYOProvider(tenant, providerModel); ok {
			return []providerCandidate{{name: name, key: key, model: model, source: "tenant"}}
		}
		if s.aiTenantCfg.NoPlatformKey(tenant) {
			return nil
		}
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
		model := providerModel(name)
		if name == cfg.Provider && cfg.Model != "" {
			model = cfg.Model
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
		if _, err := s.aiTenantCfg.SetTenantSettings(tenant, req.Provider, req.Model, req.Key, req.NoPlatformKey, req.ClearKey); err != nil {
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
		"provider":               c.Provider,
		"model":                  c.Model,
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
