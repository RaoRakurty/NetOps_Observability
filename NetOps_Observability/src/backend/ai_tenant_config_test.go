// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netops/backend/internal/ratelimit"

	"netops/backend/ai"
)

// ai_tenant_config_test.go — per-tenant Iris AI settings (P4a): store
// semantics, per-principal provider resolution, HTTP isolation (§3a.5), and
// the entitlement gates. The invariants under test:
//
//   - tenant A's BYO key is NEVER used for tenant B (or anyone else);
//   - a tenant admin cannot grant itself the agent loop (entitlement is
//     platform packaging);
//   - a strict tenant (no_platform_key) fails CLOSED to key-free mode;
//   - the key is write-only: no response ever carries it;
//   - the key is sealed at rest under the OWNER tenant's DEK.

func aiCfgTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := newTenantStore(dir + "/tenants.json")
	if err != nil {
		t.Fatal(err)
	}
	au, err := newAuditStore(dir + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		roles:          rs,
		tenants:        ts,
		audit:          au,
		copilotLimiter: ratelimit.New(),
		aiToolBudget:   ai.NewDailyBudget(),
		copilotCfg:     newCopilotConfigStore(dir+"/copilot_config.json", nil),
		aiTenantCfg:    newAITenantConfigStore(dir+"/ai_tenant_config.json", nil),
	}
}

func claimsCtx(r *http.Request, c jwtClaims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

var (
	aiTenantAdminA = jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	aiTenantAdminB = jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	aiTenantUserA  = jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}
	aiPlatformOwn  = jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}
)

// ---- store semantics -----------------------------------------------------------

func TestAITenantConfigStoreDefaults(t *testing.T) {
	st := newAITenantConfigStore("", nil)
	// Default posture: assistant on, investigations off, platform fallback allowed.
	if !st.AssistantEnabled("t-x") {
		t.Fatal("assistant must default ON")
	}
	if st.AgentToolsEnabled("t-x") {
		t.Fatal("agent tools must default OFF")
	}
	if st.NoPlatformKey("t-x") {
		t.Fatal("platform fallback must default allowed")
	}
	if _, _, _, ok := st.BYOProvider("t-x", providerModel); ok {
		t.Fatal("no BYO provider without a key")
	}
	// Nil-store defense-in-depth: same defaults, no panic.
	var nilStore *aiTenantConfigStore
	if !nilStore.AssistantEnabled("t-x") || nilStore.AgentToolsEnabled("t-x") {
		t.Fatal("nil store must behave as defaults")
	}
}

func TestAITenantConfigStoreKeyLifecycle(t *testing.T) {
	st := newAITenantConfigStore("", nil)
	_, _ = st.SetTenantSettings("t-a", "anthropic", "claude-sonnet-4-6", "sk-ant-secret", false, false)
	name, key, model, ok := st.BYOProvider("t-a", providerModel)
	if !ok || name != "anthropic" || key != "sk-ant-secret" || model != "claude-sonnet-4-6" {
		t.Fatalf("BYO provider wrong: %s %s %s %v", name, key, model, ok)
	}
	// A blank key on save preserves the stored one (the GET form is redacted and
	// must not wipe the secret).
	_, _ = st.SetTenantSettings("t-a", "anthropic", "claude-opus-4-8", "", false, false)
	if _, key, model, _ := st.BYOProvider("t-a", providerModel); key != "sk-ant-secret" || model != "claude-opus-4-8" {
		t.Fatalf("blank key must preserve stored secret, got %q model %q", key, model)
	}
	// clear_key removes it explicitly.
	_, _ = st.SetTenantSettings("t-a", "", "", "", false, true)
	if _, _, _, ok := st.BYOProvider("t-a", providerModel); ok {
		t.Fatal("clear_key must remove the BYO key")
	}
	// Entitlement writes never disturb tenant settings and vice versa.
	_, _ = st.SetTenantSettings("t-a", "openai", "", "sk-oai", true, false)
	_, _ = st.SetEntitlement("t-a", true, true, 0, 0)
	c := st.Get("t-a")
	if c.Key != "sk-oai" || !c.NoPlatformKey || !c.AssistantOff || !c.AgentTools {
		t.Fatalf("entitlement and tenant settings must compose: %+v", c)
	}
}

// TestAITenantKeySealedAtRest: the persisted file carries the key encrypted
// under the OWNER tenant's DEK — and decrypting it as another tenant fails
// (AAD binds tenant|field), which is the cryptographic half of "tenant A's key
// can never serve tenant B".
func TestAITenantKeySealedAtRest(t *testing.T) {
	v := newTestVault(t)
	path := t.TempDir() + "/ai_tenant_config.json"
	st := newAITenantConfigStore(path, v)
	_, _ = st.SetTenantSettings("t-a", "anthropic", "", "sk-ant-supersecret", false, false)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sk-ant-supersecret") {
		t.Fatal("BYO key must not be plaintext at rest")
	}
	var onDisk map[string]aiTenantConfig
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	sealed := onDisk["t-a"].Key
	if !strings.HasPrefix(sealed, "v1:") {
		t.Fatalf("key must be vault-sealed, got %q", sealed)
	}
	if _, err := v.Decrypt("t-b", ai.FieldProviderKey, sealed); err == nil {
		t.Fatal("another tenant's DEK must not decrypt the key")
	}
	// Reload (fresh store, same vault) round-trips the decrypted key.
	st2 := newAITenantConfigStore(path, v)
	if _, key, _, ok := st2.BYOProvider("t-a", providerModel); !ok || key != "sk-ant-supersecret" {
		t.Fatalf("reload must recover the key, got %q ok=%v", key, ok)
	}
}

// ---- per-principal provider resolution ------------------------------------------

func TestProviderCandidatesPerTenant(t *testing.T) {
	s := aiCfgTestServer(t)
	t.Setenv("OPENAI_API_KEY", "sk-platform-env")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("COPILOT_API_KEY", "")

	// No tenant config → the platform chain applies.
	cands := s.providerCandidates(jwtClaims{Role: "viewer", Tenant: "t-a"})
	if len(cands) != 1 || cands[0].source != "platform" || cands[0].key != "sk-platform-env" {
		t.Fatalf("default tenant must ride the platform chain: %+v", cands)
	}

	// Tenant A brings its own key: it wins OUTRIGHT (single candidate) — and
	// tenant B still resolves to the platform chain, never A's key.
	_, _ = s.aiTenantCfg.SetTenantSettings("t-a", "anthropic", "claude-sonnet-4-6", "sk-tenant-a", false, false)
	cands = s.providerCandidates(jwtClaims{Role: "viewer", Tenant: "t-a"})
	if len(cands) != 1 || cands[0].source != "tenant" || cands[0].key != "sk-tenant-a" || cands[0].name != "anthropic" {
		t.Fatalf("tenant BYO key must win outright: %+v", cands)
	}
	for _, c := range s.providerCandidates(jwtClaims{Role: "viewer", Tenant: "t-b"}) {
		if c.key == "sk-tenant-a" {
			t.Fatal("CROSS-TENANT LEAK: tenant A's key resolved for tenant B")
		}
	}

	// Strict tenant: no key of its own + no_platform_key → NOTHING (fail closed).
	_, _ = s.aiTenantCfg.SetTenantSettings("t-b", "", "", "", true, false)
	if cands := s.providerCandidates(jwtClaims{Role: "viewer", Tenant: "t-b"}); cands != nil {
		t.Fatalf("strict tenant without a key must get no provider: %+v", cands)
	}

	// The platform owner is never affected by tenant records.
	cands = s.providerCandidates(aiPlatformOwn)
	if len(cands) != 1 || cands[0].source != "platform" {
		t.Fatalf("cross principal must use the platform chain: %+v", cands)
	}
	for _, c := range cands {
		if c.key == "sk-tenant-a" {
			t.Fatal("tenant BYO key must never serve the platform principal")
		}
	}
}

// ---- HTTP isolation (§3a.5) -----------------------------------------------------

func TestAITenantConfigHandlerIsolation(t *testing.T) {
	s := aiCfgTestServer(t)

	put := func(c jwtClaims, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/ai/tenant-config", strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAITenantConfig(w, claimsCtx(r, c))
		return w
	}
	get := func(c jwtClaims) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodGet, "/api/ai/tenant-config", nil)
		w := httptest.NewRecorder()
		s.handleAITenantConfig(w, claimsCtx(r, c))
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}

	// Tenant A's admin stores a key — trying to smuggle entitlement fields in the
	// same payload (§3a.2: authority never comes from the request body).
	w := put(aiTenantAdminA, `{"provider":"anthropic","key":"sk-a-secret","agent_tools":true,"assistant_off":false,"investigations_enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("tenant admin PUT: %d %s", w.Code, w.Body.String())
	}
	if s.aiTenantCfg.AgentToolsEnabled("t-a") {
		t.Fatal("PRIVILEGE LEAK: tenant admin self-granted the agent loop")
	}
	if !strings.Contains(w.Body.String(), `"key_present":true`) || strings.Contains(w.Body.String(), "sk-a-secret") {
		t.Fatalf("key must be write-only: %s", w.Body.String())
	}

	// Tenant B sees ITS OWN (empty) record — never A's.
	code, m := get(aiTenantAdminB)
	if code != http.StatusOK || m["key_present"] != false {
		t.Fatalf("tenant B must see its own empty record: %d %v", code, m)
	}
	// And B's writes don't touch A.
	put(aiTenantAdminB, `{"provider":"openai","key":"sk-b","no_platform_key":true}`)
	if _, key, _, _ := s.aiTenantCfg.BYOProvider("t-a", providerModel); key != "sk-a-secret" {
		t.Fatal("tenant B's write must not affect tenant A")
	}

	// Non-admin tenant user → 403; platform owner → this isn't their surface.
	if w := put(aiTenantUserA, `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("viewer must be refused: %d", w.Code)
	}
	if code, _ := get(aiPlatformOwn); code != http.StatusBadRequest {
		t.Fatalf("platform owner has no own-tenant config here: %d", code)
	}
}

func TestAITenantsEntitlementHandler(t *testing.T) {
	s := aiCfgTestServer(t)
	created, err := s.tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	acme := created.ID

	do := func(c jwtClaims, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		w := httptest.NewRecorder()
		s.handleAITenants(w, claimsCtx(r, c))
		return w
	}

	// A tenant admin must NOT reach entitlement — read or write (§3a.3).
	if w := do(aiTenantAdminA, http.MethodGet, "/api/ai/tenants", ""); w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin must not list entitlements: %d", w.Code)
	}
	if w := do(aiTenantAdminA, http.MethodPut, "/api/ai/tenants/"+acme, `{"assistant_enabled":true,"investigations_enabled":true}`); w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin must not set entitlements: %d", w.Code)
	}

	// Platform owner grants investigations to acme.
	w := do(aiPlatformOwn, http.MethodPut, "/api/ai/tenants/"+acme, `{"assistant_enabled":true,"investigations_enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("platform PUT: %d %s", w.Code, w.Body.String())
	}
	if !s.aiTenantCfg.AgentToolsEnabled(acme) {
		t.Fatal("entitlement not applied")
	}
	if w := do(aiPlatformOwn, http.MethodGet, "/api/ai/tenants", ""); !strings.Contains(w.Body.String(), acme) {
		t.Fatalf("list must include the tenant: %s", w.Body.String())
	}
	// Unknown / global targets → not found.
	if w := do(aiPlatformOwn, http.MethodPut, "/api/ai/tenants/nope", `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant must 404: %d", w.Code)
	}
	if w := do(aiPlatformOwn, http.MethodPut, "/api/ai/tenants/"+TenantGlobal, `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("global tenant must 404: %d", w.Code)
	}
}

// ---- entitlement gates on the answer surfaces ------------------------------------

func TestAssistantEntitlementGate(t *testing.T) {
	s := aiCfgTestServer(t)
	t.Setenv("FEATURE_AI", "true")

	ask := func(c jwtClaims) int {
		r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(`{"question":"/help"}`))
		w := httptest.NewRecorder()
		s.handleAIAsk(w, claimsCtx(r, c))
		return w.Code
	}

	if code := ask(aiTenantUserA); code != http.StatusOK {
		t.Fatalf("entitled-by-default tenant must reach the assistant: %d", code)
	}
	_, _ = s.aiTenantCfg.SetEntitlement("t-a", true, false, 0, 0) // assistant OFF for t-a
	if code := ask(aiTenantUserA); code != http.StatusForbidden {
		t.Fatalf("disabled tenant must be refused: %d", code)
	}
	if code := ask(aiTenantAdminB); code != http.StatusOK {
		t.Fatal("disabling one tenant must not affect another")
	}
	if code := ask(aiPlatformOwn); code != http.StatusOK {
		t.Fatal("the platform owner is never gated by tenant entitlement")
	}
}
