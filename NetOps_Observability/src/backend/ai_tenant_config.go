package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
)

// ai_tenant_config.go — per-tenant Correlix AI configuration (intelligence plan
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

const aiFieldProviderKey = "ai_provider_key"

// aiTenantConfig is one tenant's AI settings. The zero value IS the default
// posture: assistant on, investigations off, platform-key fallback allowed.
type aiTenantConfig struct {
	TenantID      string `json:"tenant_id"`
	AssistantOff  bool   `json:"assistant_off,omitempty"`   // entitlement: true → assistant disabled for this tenant
	AgentTools    bool   `json:"agent_tools,omitempty"`     // entitlement: true → bounded agent loop enabled
	Provider      string `json:"provider,omitempty"`        // BYO: "anthropic" | "openai" | "gemini" ("" → unset)
	Model         string `json:"model,omitempty"`           // BYO model override ("" → provider default)
	Key           string `json:"key,omitempty"`             // BYO provider key — sealed under the tenant DEK, never sent to clients
	NoPlatformKey bool   `json:"no_platform_key,omitempty"` // true → never fall back to the platform key
}

type aiTenantConfigStore struct {
	mu    sync.RWMutex
	cfgs  map[string]aiTenantConfig // in-memory, key decrypted
	path  string
	vault *Vault
}

func newAITenantConfigStore(path string, v *Vault) *aiTenantConfigStore {
	s := &aiTenantConfigStore{cfgs: map[string]aiTenantConfig{}, path: path, vault: v}
	s.load()
	return s
}

func (s *aiTenantConfigStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var m map[string]aiTenantConfig
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for id, c := range m {
		c.TenantID = id
		// Decrypt the BYO key under this tenant's DEK (no-op on a dormant Vault).
		if key, err := s.vault.Decrypt(id, aiFieldProviderKey, c.Key); err == nil {
			c.Key = key
		}
		m[id] = c
	}
	s.cfgs = m
}

// saveLocked persists the map with every BYO key sealed under its own tenant's
// DEK. Caller holds s.mu. A blank path means in-memory only (tests).
func (s *aiTenantConfigStore) saveLocked() {
	if s.path == "" {
		return
	}
	sealed := make(map[string]aiTenantConfig, len(s.cfgs))
	for id, c := range s.cfgs {
		if c.Key != "" {
			enc, err := s.vault.Encrypt(id, aiFieldProviderKey, c.Key)
			if err != nil {
				logWarn("ai", "seal tenant provider key failed — record not persisted", map[string]any{"tenant": id})
				continue
			}
			c.Key = enc
		}
		sealed[id] = c
	}
	if b, err := json.MarshalIndent(sealed, "", "  "); err == nil {
		_ = kvSave(s.path, b)
	}
}

// get returns the tenant's record; an unconfigured tenant gets the default
// posture (zero value). Nil-safe on purpose: every read gate funnels through
// here, so a server built without the store behaves as "all defaults" instead
// of panicking (defense-in-depth — the default posture is also the safe one:
// assistant on, agent loop OFF, no BYO key).
func (s *aiTenantConfigStore) get(tenant string) aiTenantConfig {
	if s == nil {
		return aiTenantConfig{TenantID: tenant}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	return c
}

// assistantEnabled: may this tenant's users talk to Correlix AI at all?
func (s *aiTenantConfigStore) assistantEnabled(tenant string) bool {
	return !s.get(tenant).AssistantOff
}

// agentToolsEnabled: is the bounded agent loop entitled for this tenant?
func (s *aiTenantConfigStore) agentToolsEnabled(tenant string) bool {
	return s.get(tenant).AgentTools
}

// byoProvider returns the tenant's own provider configuration when a key is
// stored. The returned key is the decrypted secret — server-side use only.
func (s *aiTenantConfigStore) byoProvider(tenant string) (name, key, model string, ok bool) {
	c := s.get(tenant)
	if c.Key == "" {
		return "", "", "", false
	}
	name = normalizeProvider(c.Provider)
	if name == "" {
		name = "anthropic"
	}
	model = c.Model
	if model == "" {
		model = providerModel(name)
	}
	return name, c.Key, model, true
}

func (s *aiTenantConfigStore) noPlatformKey(tenant string) bool {
	return s.get(tenant).NoPlatformKey
}

// setTenantSettings updates the fields a TENANT ADMIN may change: provider,
// model, BYO key, and the platform-key opt-out. Entitlement fields are not
// reachable from here (§3a.2: never trust the request for authority). A blank
// key preserves the stored one (the GET form is redacted and must not wipe the
// secret on save); clearKey removes it explicitly.
func (s *aiTenantConfigStore) setTenantSettings(tenant, provider, model, key string, noPlatformKey, clearKey bool) aiTenantConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	c.Provider = normalizeProvider(provider)
	c.Model = strings.TrimSpace(model)
	c.NoPlatformKey = noPlatformKey
	switch {
	case clearKey:
		c.Key = ""
	case strings.TrimSpace(key) != "":
		c.Key = strings.TrimSpace(key)
	}
	s.cfgs[tenant] = c
	s.saveLocked()
	return c
}

// setEntitlement updates the PLATFORM-OWNER fields: assistant availability and
// the agent-loop grant.
func (s *aiTenantConfigStore) setEntitlement(tenant string, assistantOff, agentTools bool) aiTenantConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	c.AssistantOff = assistantOff
	c.AgentTools = agentTools
	s.cfgs[tenant] = c
	s.saveLocked()
	return c
}

// ---- gates (used by copilot.go / ai_handlers.go / copilot_agent.go) ----------

// aiAssistantAllowed: cross-tenant principals always may use the assistant;
// tenant users only when their tenant's entitlement says so.
func (s *server) aiAssistantAllowed(claims jwtClaims) bool {
	tenant, cross := principalTenant(claims)
	if cross {
		return true
	}
	return s.aiTenantCfg.assistantEnabled(tenant)
}

var errAITenantDisabled = errors.New("Correlix AI isn't enabled for this account — contact your administrator")

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
		if name, key, model, ok := s.aiTenantCfg.byoProvider(tenant); ok {
			return []providerCandidate{{name: name, key: key, model: model, source: "tenant"}}
		}
		if s.aiTenantCfg.noPlatformKey(tenant) {
			return nil
		}
	}
	storedKey := s.copilotCfg.apiKey()
	cfg := s.copilotCfg.get()
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
		if p := strings.TrimSpace(req.Provider); p != "" && normalizeProvider(p) == "" {
			writeError(w, http.StatusBadRequest, errors.New("unknown provider — use anthropic, openai or gemini"))
			return
		}
		s.aiTenantCfg.setTenantSettings(tenant, req.Provider, req.Model, req.Key, req.NoPlatformKey, req.ClearKey)
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
	c := s.aiTenantCfg.get(tenant)
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
		}
		var rows []row
		for _, t := range s.tenants.List() {
			if t.ID == TenantGlobal {
				continue // the platform's own tenant uses platform settings
			}
			c := s.aiTenantCfg.get(t.ID)
			rows = append(rows, row{
				TenantID: t.ID, Name: t.Name,
				Assistant:      !c.AssistantOff,
				Investigations: c.AgentTools,
				KeyPresent:     c.Key != "",
				NoPlatformKey:  c.NoPlatformKey,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants":       rows,
			"tools_feature": featureAIToolsEnabled(), // investigations need FEATURE_AI_TOOLS too
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
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		c := s.aiTenantCfg.setEntitlement(t.ID, !req.Assistant, req.Investigations)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":              t.ID,
			"assistant_enabled":      !c.AssistantOff,
			"investigations_enabled": c.AgentTools,
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
