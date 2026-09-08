// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// elevation_test.go — ELEVATION IDENTITY PROVIDERS end to end (2026-09-07).
//
// The customer pattern the owner brought back: a second, separately governed
// IdP that hands out just-in-time access without ever being able to hand out an
// identity. Everything here drives the REAL SSO code flow — a real JWKS, a real
// token endpoint, the real /api/auth/sso/login → /api/auth/sso/callback pair
// through the real middleware — because the three refusals that make the
// pattern safe (no account, no tenant move, no standing-role change) are
// properties of that path, not of a helper.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/jwks"
	"netops/backend/internal/oidc"
	"netops/backend/internal/ssoidp"
	"netops/backend/models"
)

const elevKID = "elev-kid"

// elevHarness is a full server plus a fake IdP that speaks both halves of the
// code flow (JWKS + token endpoint) and two provider buttons: a STANDING one
// and an ELEVATION one.
type elevHarness struct {
	srv    *httptest.Server
	s      *server
	key    *rsa.PrivateKey
	p      *oidcProvider
	claims map[string]any // what the next token exchange will assert
}

func newElevHarness(t *testing.T) *elevHarness {
	t.Helper()
	srv, s := newTestServerState(t)
	s.ssoTxns = newSSOTxnStore()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	h := &elevHarness{srv: srv, s: s, key: key}

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": elevKID, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(jwksSrv.Close)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": h.sign(t, h.claims)})
	}))
	t.Cleanup(tokenSrv.Close)

	// Two doors. "corp" is the everyday one; "elev" is the JIT one. The 4th CSV
	// segment is what marks it.
	p := oidc.NewProviderFromConfig(oidcConfig{
		Enabled: true, Issuer: "https://idp.example.test/realms/netops", ClientID: "netops-api",
		DefaultRole: RoleReadOnly, DefaultTenant: TenantGlobal,
		Providers:    "corp:Corp SSO:oidc,elev:Break Glass IdP:oidc:elevation",
		PostLoginURL: "/",
	}, 10*time.Minute)
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: tokenSrv.URL,
		JWKSURI:       jwksSrv.URL,
	})
	s.oidc.Store(p)
	h.p = p

	// The stored record carrying the elevation POLICY (claim names + ceiling).
	s.ssoIdPCfg = ssoidp.NewStore(t.TempDir()+"/sso_idp.json", ssoidp.Deps{
		RoleValid:          func(string) bool { return true },
		AllowPlatformOwner: func() bool { return false },
		Errorf:             func(string, string, map[string]any) {},
	})
	if _, err := s.ssoIdPCfg.Set(ssoIdPConfig{
		Alias: "elev", DisplayName: "Break Glass IdP", Protocol: "oidc", Enabled: true,
		DiscoveryURL: "https://idp.example.test/.well-known/openid-configuration", ClientID: "x",
		Kind: ssoidp.KindElevation,
		Elevation: ssoidp.Elevation{
			TTLClaim: "access_expires_at", MaxMinutes: 30,
			ReasonClaim: "change_ticket", ScopeClaim: "target_device",
		},
	}); err != nil {
		t.Fatalf("seed elevation idp: %v", err)
	}
	return h
}

func (h *elevHarness) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(j)
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT", "kid": elevKID}) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ssoRoundTrip drives the real flow for one provider alias and returns the
// callback's redirect fragment as parsed values. extra is merged into the ID
// token's claims, so a test says only what it is actually about.
func (h *elevHarness) ssoRoundTrip(t *testing.T, alias, subject string, extra map[string]any) url.Values {
	t.Helper()
	// 1. /sso/login — the server mints state + nonce and records the alias.
	loginReq := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/login?idp="+url.QueryEscape(alias), nil)
	loginRec := httptest.NewRecorder()
	h.s.handleSSOLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("sso login: status %d, want 302 (%s)", loginRec.Code, loginRec.Body.String())
	}
	authURL, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state, nonce := authURL.Query().Get("state"), authURL.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize url carried no state/nonce: %s", authURL)
	}

	// 2. the IdP mints an ID token for this transaction.
	claims := map[string]any{
		"iss": h.p.Issuer(), "aud": h.p.ClientID(), "sub": subject, "preferred_username": subject,
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	}
	for k, v := range extra {
		claims[k] = v
	}
	h.claims = claims

	// 3. /sso/callback with the state cookie the login set.
	cbReq := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/callback?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range loginRec.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbRec := httptest.NewRecorder()
	h.s.handleSSOCallback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("sso callback: status %d, want 302 (%s)", cbRec.Code, cbRec.Body.String())
	}
	loc := cbRec.Header().Get("Location")
	frag := loc
	if i := strings.IndexByte(loc, '#'); i >= 0 {
		frag = loc[i+1:]
	}
	vals, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatalf("parse callback fragment: %v", err)
	}
	return vals
}

// seedFederatedUser creates the standing account an elevation login needs to
// find. It is created through UpsertFederated, exactly as a standing SSO login
// would create it.
func (h *elevHarness) seedFederatedUser(t *testing.T, name, role, tenant string) User {
	t.Helper()
	u, err := h.s.users.UpsertFederated(name, name+"@example.test", name, role, "oidc", tenant)
	if err != nil {
		t.Fatalf("seed federated user: %v", err)
	}
	h.s.logBindingSync(u, "oidc")
	return u
}

// elevationOf returns the principal's live elevation binding.
func (h *elevHarness) elevationOf(t *testing.T, user string) (RoleBinding, bool) {
	t.Helper()
	return h.s.activeElevation(httptest.NewRequest(http.MethodGet, "http://x/api/x", nil), user, "")
}

// ── 1. it never creates an account ──────────────────────────────────────────

func TestElevationLoginRefusesAnUnknownAccount(t *testing.T) {
	h := newElevHarness(t)
	frag := h.ssoRoundTrip(t, "elev", "nobody", nil)
	if frag.Get("token") != "" {
		t.Fatal("an elevation login signed in an account that does not exist")
	}
	if msg := frag.Get("sso_error"); !strings.Contains(msg, "standing provider") {
		t.Errorf("refusal %q does not point at the standing provider", msg)
	}
	if _, ok := h.s.users.Get("nobody"); ok {
		t.Fatal("an elevation login PROVISIONED an account; it must never create one")
	}
}

// ── 2. it mints the grant, bounded both ways ────────────────────────────────

func TestElevationLoginMintsATimeBoundBinding(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "opsuser", RoleReadOnly, TenantGlobal)

	t.Run("a shorter claim wins over the provider maximum", func(t *testing.T) {
		frag := h.ssoRoundTrip(t, "elev", "opsuser", map[string]any{
			"access_expires_at": time.Now().Add(5 * time.Minute).Unix(),
			"change_ticket":     "CHG-4471",
		})
		if frag.Get("token") == "" {
			t.Fatalf("elevation login failed: %s", frag.Get("sso_error"))
		}
		if frag.Get("elevated") != "1" {
			t.Error("the callback fragment does not mark the session as elevated")
		}
		b, ok := h.elevationOf(t, "opsuser")
		if !ok {
			t.Fatal("no elevation binding was created")
		}
		if b.ExpiresAt == nil {
			t.Fatal("the elevation binding is PERMANENT; it must expire")
		}
		if left := time.Until(*b.ExpiresAt); left > 6*time.Minute || left <= 0 {
			t.Errorf("expiry %v away — the 5-minute claim must beat the 30-minute ceiling", left)
		}
		if b.Reason != "CHG-4471" {
			t.Errorf("reason %q, want the change ticket from the claim", b.Reason)
		}
		if b.GrantedBy != "elev" {
			t.Errorf("granted_by %q, want the provider alias", b.GrantedBy)
		}
		if !b.IsElevation() {
			t.Error("the binding does not carry the elevation condition")
		}
	})

	t.Run("the provider maximum caps a longer claim", func(t *testing.T) {
		h.ssoRoundTrip(t, "elev", "opsuser", map[string]any{
			"access_expires_at": time.Now().Add(6 * time.Hour).Unix(),
		})
		b, ok := h.elevationOf(t, "opsuser")
		if !ok {
			t.Fatal("no elevation binding")
		}
		if left := time.Until(*b.ExpiresAt); left > 31*time.Minute {
			t.Errorf("expiry %v away — a 6-hour claim must be capped at the 30-minute ceiling", left)
		}
		if b.Reason != "elevation login" {
			t.Errorf("reason %q, want the default when the token names none", b.Reason)
		}
	})

	t.Run("an already-expired claim is refused rather than granted", func(t *testing.T) {
		frag := h.ssoRoundTrip(t, "elev", "opsuser", map[string]any{
			"access_expires_at": time.Now().Add(-time.Minute).Unix(),
		})
		if frag.Get("token") != "" {
			t.Error("a grant that is already over was still issued")
		}
	})
}

// ── 3. it never moves a tenant or changes a standing role ───────────────────

func TestElevationLoginNeverChangesTenantOrStandingRole(t *testing.T) {
	h := newElevHarness(t)
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, h.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenant := idOf(t, b)
	before := h.seedFederatedUser(t, "acmeuser", RoleReadOnly, tenant)

	// The token asserts an ADMIN realm role and a different tenant's name. Neither
	// may touch the stored account.
	h.ssoRoundTrip(t, "elev", "acmeuser", map[string]any{
		"realm_access": map[string]any{"roles": []string{"netops-admin"}},
		"tenant_id":    TenantGlobal,
	})
	after, ok := h.s.users.Get("acmeuser")
	if !ok {
		t.Fatal("the account vanished")
	}
	if after.TenantID != before.TenantID {
		t.Errorf("tenant moved %q → %q; a claim may NEVER move a tenant", before.TenantID, after.TenantID)
	}
	if after.Role != before.Role {
		t.Errorf("standing role changed %q → %q; an elevation provider may never rewrite it", before.Role, after.Role)
	}
	grant, held := h.elevationOf(t, "acmeuser")
	if !held {
		t.Fatal("no elevation binding")
	}
	if grant.RoleID == before.Role {
		t.Errorf("the grant carries the standing role %q; the elevated role should come from the provider mapping", grant.RoleID)
	}
	if grant.ScopeID != scopeTenant(tenant) {
		t.Errorf("grant scope %q, want the ACCOUNT's tenant scope %q", grant.ScopeID, scopeTenant(tenant))
	}
}

// ── 4. re-login refreshes, never stacks ─────────────────────────────────────

func TestElevationLoginDoesNotStack(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "stacker", RoleReadOnly, TenantGlobal)
	// Two logins mapping to DIFFERENT roles: the deterministic binding id differs,
	// so an overwrite-by-id would leave two live grants behind.
	h.ssoRoundTrip(t, "elev", "stacker", map[string]any{
		"realm_access": map[string]any{"roles": []string{"netops-operator"}},
	})
	h.ssoRoundTrip(t, "elev", "stacker", nil)
	live := 0
	for _, b := range h.s.bindings.ListByPrincipal("stacker") {
		if b.IsElevation() {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("%d live elevation bindings after two logins; a re-login must REFRESH, never stack", live)
	}
}

// ── 5. expiry stops it on the next request; revoke stops it immediately ─────

func TestElevationExpiryIsEnforcedOnTheNextRequest(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "expiring", RoleReadOnly, TenantGlobal)
	h.ssoRoundTrip(t, "elev", "expiring", nil)
	b, ok := h.elevationOf(t, "expiring")
	if !ok {
		t.Fatal("no elevation binding")
	}
	// Backdate it in place — the grant ends because TIME passed, with no logout,
	// no session change and no sweeper involved.
	past := time.Now().UTC().Add(-time.Second)
	b.ExpiresAt = &past
	if _, err := h.s.bindings.Add(b); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, held := h.elevationOf(t, "expiring"); held {
		t.Fatal("an EXPIRED elevation is still being honoured")
	}
	// And it is reaped, so it cannot come back.
	for _, x := range h.s.bindings.ListByPrincipal("expiring") {
		if x.IsElevation() {
			t.Fatalf("the expired elevation binding %s survived", x.ID)
		}
	}
}

func TestElevationRevokeIsImmediate(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "revokee", RoleReadOnly, TenantGlobal)
	h.ssoRoundTrip(t, "elev", "revokee", nil)
	b, ok := h.elevationOf(t, "revokee")
	if !ok {
		t.Fatal("no elevation binding")
	}
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	// REVOKE IS NEVER STEP-UP GATED: an admin with only standing rights must be
	// able to take access away even while an elevation provider is configured.
	if st, body := do(t, h.srv, "DELETE", "/api/bindings/"+url.PathEscape(b.ID), admin, nil); st != 204 {
		t.Fatalf("revoke: %d %s", st, body)
	}
	if _, held := h.elevationOf(t, "revokee"); held {
		t.Fatal("the elevation survived its revoke")
	}
}

// ── 6. step-up refusals name the provider ───────────────────────────────────

func TestStepUpRefusalNamesTheElevationProvider(t *testing.T) {
	h := newElevHarness(t)
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, body := do(t, h.srv, "POST", "/api/bindings", admin, map[string]any{
		"principal_id": "admin", "role_id": RoleOperator, "scope_id": scopeTenant(TenantGlobal),
	})
	if st != http.StatusForbidden {
		t.Fatalf("granting a binding with a standing session: %d %s, want 403", st, body)
	}
	var refusal struct {
		Code      string `json:"code"`
		Error     string `json:"error"`
		Providers []struct {
			ID, Name string
		} `json:"elevation_providers"`
	}
	if err := json.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("refusal body is not JSON: %s", body)
	}
	if refusal.Code != "ELEVATION_REQUIRED" {
		t.Errorf("code %q, want ELEVATION_REQUIRED", refusal.Code)
	}
	if len(refusal.Providers) != 1 || refusal.Providers[0].ID != "elev" {
		t.Fatalf("the refusal does not name the elevation provider: %+v", refusal.Providers)
	}
	if !strings.Contains(refusal.Error, "Break Glass IdP") {
		t.Errorf("refusal message %q does not name the provider", refusal.Error)
	}
	// Reading and revoking stay open — a control you cannot exercise without
	// first passing the control is not a control.
	if st, _ := do(t, h.srv, "GET", "/api/bindings", admin, nil); st != 200 {
		t.Errorf("listing bindings was gated: %d", st)
	}
}

func TestStepUpIsAPassThroughWithNoElevationProviderConfigured(t *testing.T) {
	srv, _ := newTestServerState(t) // no SSO at all — every existing deployment
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if st, body := do(t, srv, "POST", "/api/bindings", admin, map[string]any{
		"principal_id": "admin", "role_id": RoleOperator, "scope_id": scopeTenant(TenantGlobal),
	}); st == http.StatusForbidden && strings.Contains(string(body), "ELEVATION_REQUIRED") {
		t.Fatal("step-up fired with no elevation provider configured — the gate must be additive")
	}
}

// ── 7. the grant is on the audit trail, and the filter is tenant-scoped ─────

func TestAuditRowsCarryTheElevationBindingID(t *testing.T) {
	h := newElevHarness(t)
	h.seedFederatedUser(t, "auditor2", RoleSuperAdmin, TenantGlobal)
	h.ssoRoundTrip(t, "elev", "auditor2", map[string]any{"change_ticket": "CHG-99"})
	b, ok := h.elevationOf(t, "auditor2")
	if !ok {
		t.Fatal("no elevation binding")
	}
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, body := do(t, h.srv, "GET", "/api/audit?binding_id="+url.QueryEscape(b.ID), admin, nil)
	if st != 200 {
		t.Fatalf("audit by binding: %d %s", st, body)
	}
	var events []AuditEvent
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("audit body: %s", body)
	}
	found := false
	for _, e := range events {
		if e.BindingID != b.ID {
			t.Fatalf("binding_id filter returned a row for %q", e.BindingID)
		}
		if e.Path == "/elevation/ELEVATION_GRANTED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the grant itself is not on the trail under its binding id (%d rows)", len(events))
	}
}

func TestAuditBindingFilterStaysTenantScoped(t *testing.T) {
	h := newElevHarness(t)
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, h.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme2"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenant := idOf(t, b)
	if st, body := do(t, h.srv, "POST", "/api/users", admin, map[string]any{
		"username": "acme-admin", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenant,
	}); st != 201 {
		t.Fatalf("create tenant admin: %d %s", st, body)
	}
	// A grant in the GLOBAL realm…
	h.seedFederatedUser(t, "globaluser", RoleReadOnly, TenantGlobal)
	h.ssoRoundTrip(t, "elev", "globaluser", nil)
	grant, ok := h.elevationOf(t, "globaluser")
	if !ok {
		t.Fatal("no elevation binding")
	}
	// …must not be readable by another tenant's admin, even by exact id.
	other := login(t, h.srv, "acme-admin", "Passw0rd!2345").Token
	st, body := do(t, h.srv, "GET", "/api/audit?binding_id="+url.QueryEscape(grant.ID), other, nil)
	if st != 200 {
		t.Fatalf("scoped audit read: %d %s", st, body)
	}
	var events []AuditEvent
	if err := json.Unmarshal(body, &events); err != nil {
		t.Fatalf("audit body: %s", body)
	}
	if len(events) != 0 {
		t.Fatalf("a tenant admin read %d rows of another realm's elevation trail", len(events))
	}
}

// ── 8. a resource scope from another tenant is refused (§3a) ────────────────

func TestElevationResourceScopeFromAnotherTenantIsRefused(t *testing.T) {
	h := newElevHarness(t)
	admin := login(t, h.srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, h.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme3"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantA := idOf(t, b)
	st, b = do(t, h.srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme4"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantB := idOf(t, b)
	h.seedFederatedUser(t, "scoped", RoleReadOnly, tenantA)
	// A device that belongs to the OTHER tenant.
	if err := h.s.discovery.Upsert(models.Device{ID: "dev-b", Name: "b1", TenantID: tenantB}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	frag := h.ssoRoundTrip(t, "elev", "scoped", map[string]any{"target_device": "dev-b"})
	if frag.Get("token") != "" {
		t.Fatal("a token naming ANOTHER tenant's device was granted elevated access")
	}
	if _, held := h.elevationOf(t, "scoped"); held {
		t.Fatal("a cross-tenant resource scope produced a binding")
	}
	// The same claim naming the caller's OWN device is accepted, and confines
	// the grant to that resource rather than widening it to the tenant.
	if err := h.s.discovery.Upsert(models.Device{ID: "dev-a", Name: "a1", TenantID: tenantA}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if frag := h.ssoRoundTrip(t, "elev", "scoped", map[string]any{"target_device": "dev-a"}); frag.Get("token") == "" {
		t.Fatalf("own-tenant resource scope refused: %s", frag.Get("sso_error"))
	}
	grant, held := h.elevationOf(t, "scoped")
	if !held {
		t.Fatal("no elevation binding")
	}
	if grant.ScopeID != "resource:device:dev-a" {
		t.Errorf("scope %q, want the resource scope the claim asked for", grant.ScopeID)
	}
}

// ── 9. the caller's own view of its grant ───────────────────────────────────

func TestElevationStatusAndStepDown(t *testing.T) {
	h := newElevHarness(t)
	u := h.seedFederatedUser(t, "selfview", RoleReadOnly, TenantGlobal)
	frag := h.ssoRoundTrip(t, "elev", "selfview", nil)
	tok := frag.Get("token")
	if tok == "" {
		t.Fatalf("elevation login failed: %s", frag.Get("sso_error"))
	}
	_ = u
	st, body := do(t, h.srv, "GET", "/api/auth/elevation", tok, nil)
	if st != 200 {
		t.Fatalf("elevation status: %d %s", st, body)
	}
	var status elevationStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("status body: %s", body)
	}
	if !status.Active || status.Provider != "elev" || status.ExpiresAt == "" {
		t.Fatalf("status does not describe the live grant: %+v", status)
	}
	if st, body := do(t, h.srv, "DELETE", "/api/auth/elevation", tok, nil); st != 204 {
		t.Fatalf("step down: %d %s", st, body)
	}
	if _, held := h.elevationOf(t, "selfview"); held {
		t.Fatal("stepping down left the grant standing")
	}
	// Idempotent: stepping down twice is not an error.
	if st, _ := do(t, h.srv, "DELETE", "/api/auth/elevation", tok, nil); st != 204 {
		t.Errorf("second step down: %d, want 204", st)
	}
}
