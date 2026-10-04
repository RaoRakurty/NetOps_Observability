// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_entitlements_test.go — the atomic AI entitlements on the wire (tracker
// 337 N-A7).
//
// Pinned:
//   - the GUARD: every AI route registered in main.go (the /api/ai/ and
//     /api/copilot/ families, plus any route whose handler is an AI handler
//     wherever it is mounted) is classified here, either with the entitlement
//     it gates on or as an admin-plane route with the reason it is not;
//   - every entitlement-gated route REFUSES a caller whose tier mapping lacks
//     its entitlement, and ADMITS the same caller once the mapping grants it —
//     driven through the real router, so a registration that points at an
//     ungated handler fails here;
//   - the refusal statuses keep their pre-N-A7 meaning (503 flag off, 403
//     tenant off), plus 403 not_in_tier;
//   - the investigation loop and the ask's data arm degrade (never refuse)
//     without ai.investigate / ai.nlquery;
//   - GET /api/features exposes the CALLER's set, scoped to their own tenant.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/aientitlement"
	"netops/backend/internal/irisconvo"
	"netops/backend/internal/irisquerylog"
)

// adminPlane is the marker for AI CONFIGURATION routes. They configure the
// assistant rather than use it, and are gated by administration, not by a
// usage entitlement: gating them on one would make it impossible to switch AI
// on for a tenant (or to install a provider key) while it is off — the
// operator would be locked out of the very switch the entitlement reads.
const adminPlane = aientitlement.Entitlement("admin-plane")

// aiRouteEntitlements is THE classification of every AI route.
var aiRouteEntitlements = map[string]aientitlement.Entitlement{
	"/api/ai/ask":                  aientitlement.Chat,
	"/api/copilot/chat":            aientitlement.Chat, // + ai.investigate for the agent loop inside the turn
	"/api/ai/modules":              aientitlement.Chat,
	"/api/ai/commands":             aientitlement.Chat,
	"/api/ai/commands/suggestions": aientitlement.Chat,
	"/api/ai/feedback":             aientitlement.Chat,
	"/api/ai/aliases":              aientitlement.NLQuery,
	"/api/ai/entities/resolve":     aientitlement.NLQuery,
	"/api/ai/query/compile":        aientitlement.NLQuery,
	"/api/ai/query/execute":        aientitlement.NLQuery,
	"/api/ai/conversations":        aientitlement.NLQuery,
	"/api/ai/conversations/":       aientitlement.NLQuery,
	"/api/ai/queries":              aientitlement.NLQuery,
	"/api/ai/queries/":             aientitlement.NLQuery,

	"/api/ai/tenant-config": adminPlane, // requireAdmin: the tenant's own BYO provider key
	"/api/ai/tenants":       adminPlane, // requirePlatformAdmin: per-tenant AI switches
	"/api/ai/tenants/":      adminPlane, // requirePlatformAdmin
	"/api/copilot/config":   adminPlane, // requirePlatformAdmin: provider + platform key
}

// aiHandlerName matches a handler that implements an AI surface, wherever its
// route is mounted — so an AI handler registered under some other prefix is
// still caught by the guard.
var aiHandlerName = regexp.MustCompile(`^handle(AI|Copilot|Iris)`)

// registeredAIRoutes parses main.go for AI routes.
func registeredAIRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(/api/[^"]+)",\s*(?:s\.(\w+))?`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		path, handler := m[1], m[2]
		if strings.HasPrefix(path, "/api/ai/") || strings.HasPrefix(path, "/api/copilot/") || aiHandlerName.MatchString(handler) {
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryAIRouteIsEntitlementGated is the guard: no AI route ships
// unclassified, no classification outlives its route, and no route claims an
// entitlement that is defined-but-unbacked.
func TestEveryAIRouteIsEntitlementGated(t *testing.T) {
	routes := registeredAIRoutes(t)
	if len(routes) < len(aiRouteEntitlements) {
		t.Fatalf("parsed only %d AI routes from main.go — the guard would prove nothing", len(routes))
	}
	live := map[string]bool{}
	for _, r := range routes {
		live[r] = true
		e, ok := aiRouteEntitlements[r]
		if !ok {
			t.Errorf("UNGATED AI ROUTE %q — gate its handler with requireAIEntitlement on the right "+
				"entitlement (internal/aientitlement) and classify it in aiRouteEntitlements, with a probe in aiRouteProbes", r)
			continue
		}
		if e == adminPlane {
			continue
		}
		if !aientitlement.Valid(e) {
			t.Errorf("%q claims unknown entitlement %q", r, e)
		}
		if !aientitlement.Backed(e) {
			t.Errorf("%q gates on %q, which is defined but not backed — flip Backed() in the same change", r, e)
		}
	}
	for r := range aiRouteEntitlements {
		if !live[r] {
			t.Errorf("STALE classification %q — no longer registered in main.go", r)
		}
	}
	// Every gated route has at least one probe in the refusal test below.
	probed := map[string]bool{}
	for _, p := range aiRouteProbes {
		probed[p.route] = true
		if aiRouteEntitlements[p.route] != p.want {
			t.Errorf("probe %s %s expects %q but the route is classified %q", p.method, p.path, p.want, aiRouteEntitlements[p.route])
		}
	}
	for r, e := range aiRouteEntitlements {
		if e != adminPlane && !probed[r] {
			t.Errorf("gated AI route %q has no refusal probe in aiRouteProbes", r)
		}
	}
	for _, p := range adminPlaneProbes {
		probed[p.route] = true
	}
	for r, e := range aiRouteEntitlements {
		if e == adminPlane && !probed[r] {
			t.Errorf("admin-plane AI route %q has no admin-gate probe in adminPlaneProbes", r)
		}
	}
}

type aiProbe struct {
	route        string // the registered pattern
	method, path string
	body         string
	want         aientitlement.Entitlement
}

const probeID = "0b0a0c0d-1e1f-4a2b-8c3d-4e5f6a7b8c9d"

var aiRouteProbes = []aiProbe{
	{"/api/ai/ask", http.MethodPost, "/api/ai/ask", `{"question":"how do I add a device"}`, aientitlement.Chat},
	{"/api/copilot/chat", http.MethodPost, "/api/copilot/chat", `{"messages":[{"role":"user","content":"hello"}]}`, aientitlement.Chat},
	{"/api/ai/modules", http.MethodGet, "/api/ai/modules", "", aientitlement.Chat},
	{"/api/ai/commands", http.MethodGet, "/api/ai/commands", "", aientitlement.Chat},
	{"/api/ai/commands/suggestions", http.MethodGet, "/api/ai/commands/suggestions?q=sh", "", aientitlement.Chat},
	{"/api/ai/feedback", http.MethodPost, "/api/ai/feedback", `{"rating":"up"}`, aientitlement.Chat},
	{"/api/ai/feedback", http.MethodGet, "/api/ai/feedback", "", aientitlement.Chat},
	{"/api/ai/aliases", http.MethodGet, "/api/ai/aliases", "", aientitlement.NLQuery},
	{"/api/ai/aliases", http.MethodPut, "/api/ai/aliases", `{"entity_type":"device","entity_id":"device:dev-a","alias":"core one"}`, aientitlement.NLQuery},
	{"/api/ai/aliases", http.MethodDelete, "/api/ai/aliases?entity_type=device&alias=core+one", "", aientitlement.NLQuery},
	{"/api/ai/entities/resolve", http.MethodPost, "/api/ai/entities/resolve", `{"text":"edge-a"}`, aientitlement.NLQuery},
	{"/api/ai/query/compile", http.MethodPost, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`, aientitlement.NLQuery},
	{"/api/ai/query/execute", http.MethodPost, "/api/ai/query/execute", `{"ast":{}}`, aientitlement.NLQuery},
	{"/api/ai/conversations", http.MethodPost, "/api/ai/conversations", "", aientitlement.NLQuery},
	{"/api/ai/conversations/", http.MethodGet, "/api/ai/conversations/" + probeID, "", aientitlement.NLQuery},
	{"/api/ai/conversations/", http.MethodPost, "/api/ai/conversations/" + probeID + "/messages", `{"question":"cpu on edge-a"}`, aientitlement.NLQuery},
	{"/api/ai/queries", http.MethodGet, "/api/ai/queries", "", aientitlement.NLQuery},
	{"/api/ai/queries/", http.MethodPost, "/api/ai/queries/" + probeID + "/corrections", `{"kind":"wrong_entity"}`, aientitlement.NLQuery},
}

// policyWithout is a mapping for the tier in force that grants everything
// except the named entitlements.
func policyWithout(t *testing.T, s *server, missing ...aientitlement.Entitlement) *aientitlement.Policy {
	t.Helper()
	skip := map[aientitlement.Entitlement]bool{}
	for _, m := range missing {
		skip[m] = true
	}
	var grants []string
	for _, e := range aientitlement.All() {
		if !skip[e] {
			grants = append(grants, string(e))
		}
	}
	doc, err := json.Marshal(map[string]any{"tiers": map[string][]string{string(s.entitlements.Tier()): grants}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := aientitlement.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// aiEntFixture is a server with every AI store wired, so a probe that clears
// the entitlement gate reaches the handler body rather than a 503 for a
// missing store, and two admin principals in two tenants.
func aiEntFixture(t *testing.T) (*server, http.Handler, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := aliasFixture(t)
	a.Role, b.Role = "admin", "admin"
	s.nlqConvos = irisconvo.NewMemStore()
	s.nlqQueryLog = irisquerylog.NewMemStore()
	s.aiTenantCfg = newAITenantConfigStore(t.TempDir()+"/ai_tenant_config.json", nil)
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil) // no key: no provider is ever called
	mux := http.NewServeMux()
	s.routes(mux)
	return s, mux, a, b
}

func serveAs(h http.Handler, c jwtClaims, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// entitlementRefusal returns the entitlement a response refused for ("" when
// it is not an entitlement refusal).
func entitlementRefusal(w *httptest.ResponseRecorder) (aientitlement.Entitlement, string) {
	var body struct {
		Entitlement string `json:"entitlement"`
		Reason      string `json:"reason"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body) // non-JSON bodies are simply "not a refusal"
	return aientitlement.Entitlement(body.Entitlement), body.Reason
}

func TestAIRoutesRefuseWithoutTheirEntitlementAndAdmitWithIt(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("FEATURE_COPILOT", "true") // the provider-proxy switch on top of ai.chat
	t.Setenv("COPILOT_RATE_PER_MIN", "0")
	// One fixture for every probe: each probe sets the policy it needs before
	// each request, so nothing a previous probe did changes its gate decision.
	// (A fixture per probe cost ~0.35 s each, ~10x that under -race, against a
	// root-package -race budget that is already near its 40 m ceiling.)
	s, h, a, _ := aiEntFixture(t)
	for _, p := range aiRouteProbes {
		p := p
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			s.aiEntitlementPolicy = policyWithout(t, s, p.want)
			w := serveAs(h, a, p.method, p.path, p.body)
			got, reason := entitlementRefusal(w)
			if w.Code != http.StatusForbidden || got != p.want || reason != string(aientitlement.ReasonNotInTier) {
				t.Fatalf("without %s: got %d entitlement=%q reason=%q (%s) — want 403 refusing %s", p.want, w.Code, got, reason, w.Body.String(), p.want)
			}

			// Every OTHER entitlement withheld, this one granted: the route must
			// admit — proving it gates on exactly its own entitlement and not on
			// a neighbour's.
			var others []aientitlement.Entitlement
			for _, e := range aientitlement.All() {
				if e != p.want {
					others = append(others, e)
				}
			}
			s.aiEntitlementPolicy = policyWithout(t, s, others...)
			w = serveAs(h, a, p.method, p.path, p.body)
			if got, _ := entitlementRefusal(w); got != "" {
				t.Fatalf("with %s granted the route still refused for %q: %d %s", p.want, got, w.Code, w.Body.String())
			}
			// Past the gate the handler answers on its own terms (copilot with no
			// provider key is a 503 "not connected", a probe id is a 404, ...);
			// what it must never be is a 403 — the only 403 these probes could
			// earn is an entitlement or tenant refusal.
			if w.Code == http.StatusForbidden {
				t.Fatalf("with %s granted: %d %s", p.want, w.Code, w.Body.String())
			}
		})
	}
}

// adminPlaneProbes prove the configuration routes are not ungated: a tenant
// operator (no administration:admin) is refused by the admin gate.
var adminPlaneProbes = []aiProbe{
	{"/api/ai/tenant-config", http.MethodGet, "/api/ai/tenant-config", "", adminPlane},
	{"/api/ai/tenants", http.MethodGet, "/api/ai/tenants", "", adminPlane},
	{"/api/ai/tenants/", http.MethodPut, "/api/ai/tenants/t-a", `{"assistant_enabled":true}`, adminPlane},
	{"/api/copilot/config", http.MethodGet, "/api/copilot/config", "", adminPlane},
}

func TestAIAdminPlaneRoutesRefuseNonAdmins(t *testing.T) {
	_, h, a, _ := aiEntFixture(t)
	op := a
	op.Role = "operator"
	tenantAdmin := a // admin of ONE tenant: not the platform owner
	for _, p := range adminPlaneProbes {
		if w := serveAs(h, op, p.method, p.path, p.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as a tenant operator: %d — want 403", p.method, p.path, w.Code)
		}
		if p.route == "/api/ai/tenant-config" {
			continue // a tenant admin legitimately configures their OWN tenant's key
		}
		if w := serveAs(h, tenantAdmin, p.method, p.path, p.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as a tenant admin: %d — want 403 (platform-global, §3a rule 3)", p.method, p.path, w.Code)
		}
	}
}

// TestAIRefusalStatusesKeepTheirMeaning: flag off is 503, tenant off is 403
// with the unchanged message, tier lacks it is 403 not_in_tier — and the
// deployment switch is named first when several are off.
func TestAIRefusalStatusesKeepTheirMeaning(t *testing.T) {
	s, h, a, b := aiEntFixture(t)
	ask := func(c jwtClaims) *httptest.ResponseRecorder {
		return serveAs(h, c, http.MethodPost, "/api/ai/query/compile", `{"question":"show cpu on edge-a"}`)
	}

	t.Setenv("FEATURE_AI", "false")
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.NLQuery)
	if w := ask(a); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Iris off must be 503 whatever the tier says: %d %s", w.Code, w.Body.String())
	}

	t.Setenv("FEATURE_AI", "true")
	s.aiEntitlementPolicy = nil // the shipped mapping
	if _, err := s.aiTenantCfg.SetEntitlement(a.Tenant, true /* assistantOff */, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	w := ask(a)
	if got, reason := entitlementRefusal(w); w.Code != http.StatusForbidden || got != aientitlement.NLQuery || reason != string(aientitlement.ReasonTenantOff) ||
		!strings.Contains(w.Body.String(), "isn't enabled for this account") {
		t.Fatalf("tenant A switched off: %d %s", w.Code, w.Body.String())
	}
	// Tenant A's switch must not reach tenant B.
	if w := ask(b); w.Code != http.StatusOK {
		t.Fatalf("tenant B is untouched by tenant A's switch: %d %s", w.Code, w.Body.String())
	}
	// The platform owner is not tenant-gated.
	owner := jwtClaims{Sub: "root", Tenant: TenantGlobal, Role: "admin"}
	if got, _ := entitlementRefusal(ask(owner)); got != "" {
		t.Fatalf("a cross-tenant principal must not be tenant-gated, refused for %q", got)
	}
}

// TestDegradingPathsFollowTheirEntitlement: the agent loop inside a chat turn
// and the data arm of an ask are capabilities of their own. Without them the
// turn degrades — it is not refused.
func TestDegradingPathsFollowTheirEntitlement(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("FEATURE_AI_TOOLS", "true")
	s, _, a, _ := aiEntFixture(t)
	owner := jwtClaims{Sub: "root", Tenant: TenantGlobal, Role: "admin"}

	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.Investigate)
	if s.agentLoopEligible(owner) {
		t.Fatal("no ai.investigate in the tier: no investigation loop, even for the platform owner")
	}
	s.aiEntitlementPolicy = policyWithout(t, s)
	if !s.agentLoopEligible(owner) {
		t.Fatal("ai.investigate granted: the platform owner runs the loop")
	}

	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil)
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.NLQuery)
	if s.aiNLQuery(r, a) != nil || s.aiCompileQuery(r, a) != nil {
		t.Fatal("no ai.nlquery: the ask's data arm and the compile_query tool must not exist")
	}
	s.aiEntitlementPolicy = policyWithout(t, s)
	if s.aiNLQuery(r, a) == nil || s.aiCompileQuery(r, a) == nil {
		t.Fatal("ai.nlquery granted: the data arm and the tool are available")
	}
}

// TestFeaturesExposeTheCallersOwnEntitlements: the SPA's view is the caller's
// own set — tenant A switched off does not change what tenant B sees, and the
// set follows the tier mapping.
func TestFeaturesExposeTheCallersOwnEntitlements(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("FEATURE_AI_TOOLS", "")
	s, h, a, b := aiEntFixture(t)
	read := func(c jwtClaims) []string {
		t.Helper()
		w := serveAs(h, c, http.MethodGet, "/api/features", "")
		if w.Code != http.StatusOK {
			t.Fatalf("/api/features: %d %s", w.Code, w.Body.String())
		}
		var out struct {
			AI []string `json:"ai_entitlements"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.AI == nil {
			t.Fatal("ai_entitlements must always be a list, never absent or null")
		}
		return out.AI
	}
	has := func(set []string, e aientitlement.Entitlement) bool {
		for _, x := range set {
			if x == string(e) {
				return true
			}
		}
		return false
	}

	if got := read(a); !has(got, aientitlement.Chat) || !has(got, aientitlement.NLQuery) || has(got, aientitlement.Investigate) {
		t.Fatalf("defaults: chat + nlquery, no investigate without FEATURE_AI_TOOLS: %v", got)
	}
	if _, err := s.aiTenantCfg.SetEntitlement(a.Tenant, true /* assistantOff */, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := read(a); has(got, aientitlement.Chat) || has(got, aientitlement.NLQuery) {
		t.Fatalf("tenant A switched off must see no assistant: %v", got)
	}
	if got := read(b); !has(got, aientitlement.Chat) {
		t.Fatalf("tenant B must not inherit tenant A's switch: %v", got)
	}
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.Chat)
	if got := read(b); has(got, aientitlement.Chat) || !has(got, aientitlement.NLQuery) {
		t.Fatalf("the set must follow the tier mapping: %v", got)
	}
}

// TestAIEntitlementIsolationAcrossTenants is the §3a cross-tenant proof for the
// entitlement gate on the assistant routes: tenant A switched off is refused on
// /api/ai/modules and /api/copilot/chat, tenant B (switched on) is admitted,
// and A naming B via ?as_tenant= does not borrow B's entitlement — the tenant
// the gate reads comes from the token, never the request.
func TestAIEntitlementIsolationAcrossTenants(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("FEATURE_COPILOT", "true")
	t.Setenv("COPILOT_RATE_PER_MIN", "0")
	s, h, a, b := aiEntFixture(t)
	if _, err := s.aiTenantCfg.SetEntitlement(a.Tenant, true /* assistantOff */, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	probes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/ai/modules", ""},
		{http.MethodPost, "/api/copilot/chat", `{"messages":[{"role":"user","content":"hello"}]}`},
	}
	for _, p := range probes {
		for _, target := range []string{p.path, p.path + "?as_tenant=" + b.Tenant} {
			w := serveAs(h, a, p.method, target, p.body)
			if got, reason := entitlementRefusal(w); w.Code != http.StatusForbidden || got != aientitlement.Chat ||
				reason != string(aientitlement.ReasonTenantOff) {
				t.Errorf("tenant A (off) %s %s: %d %s — want 403 tenant_off; as_tenant must not borrow tenant B's entitlement",
					p.method, target, w.Code, w.Body.String())
			}
		}
		w := serveAs(h, b, p.method, p.path, p.body)
		if got, _ := entitlementRefusal(w); got != "" || w.Code == http.StatusForbidden || w.Code == http.StatusNotFound {
			t.Errorf("tenant B (on) %s %s: %d %s — tenant A's switch must not reach tenant B", p.method, p.path, w.Code, w.Body.String())
		}
	}
}

// TestAskDoesNotReachConversationsWithoutNLQuery: Iris conversations belong to
// ai.nlquery. A caller with ai.chat but not ai.nlquery who names a conversation
// on /api/ai/ask gets a plain answer — the conversation is not appended to and
// no conversation_id comes back — and once ai.nlquery is granted the same ask
// is recorded in it.
func TestAskDoesNotReachConversationsWithoutNLQuery(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("COPILOT_RATE_PER_MIN", "0")
	s, h, a, _ := aiEntFixture(t)
	tenant, _ := principalTenant(a)
	c, err := s.nlqConvos.Create(context.Background(), tenant, a.Sub)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"question":"how do I add a device","conversation_id":"` + c.ID + `"}`
	turns := func() int {
		t.Helper()
		got, err := s.nlqConvos.Get(context.Background(), tenant, a.Sub, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return len(got.Turns)
	}

	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.NLQuery)
	w := serveAs(h, a, http.MethodPost, "/api/ai/ask", body)
	if w.Code != http.StatusOK {
		t.Fatalf("chat without nlquery: the ask itself must answer: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), c.ID) || turns() != 0 {
		t.Fatalf("chat without nlquery reached the conversation: %s (turns=%d)", w.Body.String(), turns())
	}

	s.aiEntitlementPolicy = policyWithout(t, s)
	if w := serveAs(h, a, http.MethodPost, "/api/ai/ask", body); w.Code != http.StatusOK || turns() != 1 {
		t.Fatalf("with nlquery the ask is recorded in the conversation: %d %s (turns=%d)", w.Code, w.Body.String(), turns())
	}
}
