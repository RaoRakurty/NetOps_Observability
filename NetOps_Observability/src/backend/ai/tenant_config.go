// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// tenant_config.go — the per-tenant AI entitlement + BYO provider-key store
// (Phase-2 W3.7, extracted from package main): vault-sealed key custody via
// the injected SecretSealer, the F-64 all-or-nothing three-state load with
// restore-on-failed-persist, entitlement clamps and the BYO resolution facts.
// The provider-candidate fallback CHAIN, entitlement env defaults, handlers
// and views stay in main (welded to the platform copilot config).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// normTenantAI mirrors main's tenant normalization (duplicated).
func normTenantAI(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

const FieldProviderKey = "ai_provider_key"

// TenantConfig is one tenant's AI settings. The zero value IS the default
// posture: assistant on, investigations off, platform-key fallback allowed.
type TenantConfig struct {
	TenantID      string `json:"tenant_id"`
	AssistantOff  bool   `json:"assistant_off,omitempty"`   // entitlement: true → assistant disabled for this tenant
	AgentTools    bool   `json:"agent_tools,omitempty"`     // entitlement: true → bounded agent loop enabled
	MaxCalls      int    `json:"max_calls,omitempty"`       // guardrail override: lookups per question (0 → platform default, clamp 1-8)
	DailyTokens   int    `json:"daily_tokens,omitempty"`    // guardrail override: tokens/day (0 → platform default)
	Provider      string `json:"provider,omitempty"`        // BYO: "anthropic" | "openai" | "gemini" ("" → unset)
	Model         string `json:"model,omitempty"`           // BYO model override ("" → provider default)
	Key           string `json:"key,omitempty"`             // BYO provider key — sealed under the tenant DEK, never sent to clients
	NoPlatformKey bool   `json:"no_platform_key,omitempty"` // true → never fall back to the platform key
}

// SecretSealer is the narrow slice of the Vault this store actually depends on
// (§5: depend on an interface, not the concrete dependency). *Vault satisfies
// it. Taking an interface here is also what makes the SEAL-FAILURE path
// testable — see settings_persist_failure_test.go. Before this, a seal failure
// could only be reached with a live custody provider, so the branch that
// destroyed another tenant's data (F-64) had no test and never got one.
type SecretSealer interface {
	Encrypt(tenant, fieldID, plaintext string) (string, error)
	Decrypt(tenant, fieldID, stored string) (string, error)
}

type TenantConfigStore struct {
	mu    sync.RWMutex
	cfgs  map[string]TenantConfig // in-memory, key decrypted
	path  string
	vault SecretSealer
	// loadErr is set when the stored map could not be read/decoded, or when a
	// stored provider key could not be unsealed. The in-memory map is then NOT
	// the stored state, so writes are refused (same all-or-nothing doctrine as
	// saveLocked's F-64 fix) instead of flushing a lossy copy over the file.
	loadErr error
}

// seal/unseal centralize the nil-sealer case: a store built without custody
// passes values through, exactly as a dormant *Vault does.
func (s *TenantConfigStore) seal(tenant, field, v string) (string, error) {
	if s.vault == nil {
		return v, nil
	}
	return s.vault.Encrypt(tenant, field, v)
}

func (s *TenantConfigStore) unseal(tenant, field, v string) (string, error) {
	if s.vault == nil {
		return v, nil
	}
	return s.vault.Decrypt(tenant, field, v)
}

func NewTenantConfigStore(path string, v SecretSealer) *TenantConfigStore {
	s := &TenantConfigStore{cfgs: map[string]TenantConfig{}, path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		applog.Error("ai.config", "per-tenant AI config unreadable — every tenant reads as DEFAULT and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	return s
}

// load reads the stored per-tenant config. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — no tenant configured yet) / loaded.
func (s *TenantConfigStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = nothing configured yet
	}
	if err != nil {
		return fmt.Errorf("read AI tenant config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing configured yet
	}
	var m map[string]TenantConfig
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode AI tenant config: %w", err)
	}
	unsealFailed := 0
	for id, c := range m {
		c.TenantID = id
		// Decrypt the BYO key under this tenant's DEK (no-op on a dormant Vault).
		// A failure used to leave the SEALED bytes in place as the live provider
		// key: every request to the model then failed authentication and read as
		// "the provider rejected us" rather than "we never opened the envelope".
		key, uerr := s.unseal(id, FieldProviderKey, c.Key)
		if uerr != nil {
			c.Key = "" // never use ciphertext as a credential
			unsealFailed++
			applog.Error("ai.config", "unseal tenant provider key failed — the tenant reads as having no BYO key", map[string]any{"tenant": id})
		} else {
			c.Key = key
		}
		m[id] = c
	}
	s.cfgs = m
	if unsealFailed > 0 {
		// Entitlements stay usable; the map is lossy, so it must never be flushed
		// back over the file (that would DELETE the sealed keys, F-64 all over).
		return fmt.Errorf("could not unseal the stored provider key for %d tenant(s)", unsealFailed)
	}
	return nil
}

// saveLocked persists the map with every BYO key sealed under its own tenant's
// DEK. Caller holds s.mu. A blank path means in-memory only (tests).
//
// F-64 (Critical, cross-tenant data destruction): this used to `continue` past
// a tenant whose Encrypt failed and then write the map WITHOUT it, discarding
// the kvSave error too. Because the file is rewritten whole, tenant B's save
// silently DELETED tenant A's stored provider key from disk — and both callers
// got 200. A per-record failure may never be resolved by dropping the record:
// this whole-file store is all-or-nothing, so one unsealable key fails the
// entire write and the caller is told. The on-disk copy stays intact and
// correct, which is the outcome that matters.
func (s *TenantConfigStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	// The in-memory map is not the stored state when the load failed: flushing it
	// would erase the tenants (and sealed keys) that are still on disk.
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the AI tenant config: its stored contents were not fully read: %w", s.loadErr)
	}
	sealed := make(map[string]TenantConfig, len(s.cfgs))
	for id, c := range s.cfgs {
		if c.Key != "" {
			enc, err := s.seal(id, FieldProviderKey, c.Key)
			if err != nil {
				// Name the tenant in the log, never in the returned error: the
				// caller is a different tenant and must not learn that another
				// tenant exists, let alone which one.
				applog.Error("ai", "seal tenant provider key failed — refusing to persist a partial map", map[string]any{"tenant": id, "err": err.Error()})
				return errors.New("could not seal a stored provider key; nothing was saved")
			}
			c.Key = enc
		}
		sealed[id] = c
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ai tenant config: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		return fmt.Errorf("persist ai tenant config: %w", err)
	}
	return nil
}

// get returns the tenant's record; an unconfigured tenant gets the default
// posture (zero value). Nil-safe on purpose: every read gate funnels through
// here, so a server built without the store behaves as "all defaults" instead
// of panicking (defense-in-depth — the default posture is also the safe one:
// assistant on, agent loop OFF, no BYO key).
// SeedForTest stores one tenant's config and persists — tests only.
func (s *TenantConfigStore) SeedForTest(tenantID string, cfg TenantConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfgs[normTenantAI(tenantID)] = cfg
	return s.saveLocked()
}

func (s *TenantConfigStore) Get(tenant string) TenantConfig {
	if s == nil {
		return TenantConfig{TenantID: tenant}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	return c
}

// assistantEnabled: may this tenant's users talk to Iris AI at all?
func (s *TenantConfigStore) AssistantEnabled(tenant string) bool {
	return !s.Get(tenant).AssistantOff
}

// agentToolsEnabled: is the bounded agent loop entitled for this tenant?
func (s *TenantConfigStore) AgentToolsEnabled(tenant string) bool {
	return s.Get(tenant).AgentTools
}

// byoProvider returns the tenant's own provider configuration when a key is
// stored. The returned key is the decrypted secret — server-side use only.
func (s *TenantConfigStore) BYOProvider(tenant string, defaultModel func(string) string) (name, key, model string, ok bool) {
	c := s.Get(tenant)
	if c.Key == "" {
		return "", "", "", false
	}
	name = NormalizeProvider(c.Provider)
	if name == "" {
		name = "anthropic"
	}
	model = c.Model
	if model == "" && defaultModel != nil {
		model = defaultModel(name)
	}
	return name, c.Key, model, true
}

func (s *TenantConfigStore) NoPlatformKey(tenant string) bool {
	return s.Get(tenant).NoPlatformKey
}

// setTenantSettings updates the fields a TENANT ADMIN may change: provider,
// model, BYO key, and the platform-key opt-out. Entitlement fields are not
// reachable from here (§3a.2: never trust the request for authority). A blank
// key preserves the stored one (the GET form is redacted and must not wipe the
// secret on save); clearKey removes it explicitly.
func (s *TenantConfigStore) SetTenantSettings(tenant, provider, model, key string, noPlatformKey, clearKey bool) (TenantConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.Provider = NormalizeProvider(provider)
	c.Model = strings.TrimSpace(model)
	c.NoPlatformKey = noPlatformKey
	switch {
	case clearKey:
		c.Key = ""
	case strings.TrimSpace(key) != "":
		c.Key = strings.TrimSpace(key)
	}
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return prev, err
	}
	return c, nil
}

// restoreLocked rolls the in-memory map back after a failed persist so RAM and
// disk cannot disagree. Without it a rejected write still changes behaviour
// until the next restart — the same "looks applied, isn't" shape the failed
// save was reported for. Caller holds s.mu.
func (s *TenantConfigStore) restoreLocked(tenant string, prev TenantConfig, had bool) {
	if had {
		s.cfgs[tenant] = prev
		return
	}
	delete(s.cfgs, tenant)
}

// setEntitlement updates the PLATFORM-OWNER fields: assistant availability, the
// agent-loop grant, and the per-tenant spend guardrails (0 = platform default).
func (s *TenantConfigStore) SetEntitlement(tenant string, assistantOff, agentTools bool, maxCalls, dailyTokens int) (TenantConfig, error) {
	if maxCalls < 0 {
		maxCalls = 0
	} else if maxCalls > 8 {
		maxCalls = 8 // same hard ceiling the loop clamps to
	}
	if dailyTokens < 0 {
		dailyTokens = 0
	} else if dailyTokens > 5_000_000 {
		dailyTokens = 5_000_000 // sanity ceiling — a tenant is not the whole platform
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.AssistantOff = assistantOff
	c.AgentTools = agentTools
	c.MaxCalls = maxCalls
	c.DailyTokens = dailyTokens
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return prev, err
	}
	return c, nil
}

// maxCallsFor resolves the per-question lookup cap for a tenant: its override
// when set, else the platform default (AI_TOOLS_MAX_CALLS), clamped 1-8.
