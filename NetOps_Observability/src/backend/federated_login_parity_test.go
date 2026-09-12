// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// federated_login_parity_test.go — #146b: a federated (SSO/LDAP/TACACS) sign-in
// owes the same account-state gates as a local password login. Before these
// fixes, the SSO callback enforced NONE of: tenant suspension, the hard
// account-lifecycle denials (account_validity_days / account_inactivity_days),
// or F-68 concurrent_login=deny — an expired account, or every user of a
// suspended tenant, could still enter through the IdP, and SSO logins stacked
// unlimited concurrent sessions under a deny policy.
//
// The SSO tests drive the real callback handler (state txn + PKCE + RS256 ID
// token via the mintIDToken test IdP from oidc_pkce_nonce_test.go) against the
// full newTestServerState server, so every gate runs exactly where production
// runs it.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/jwks"
	"netops/backend/internal/oidc"
	"netops/backend/policy"
)

// ssoHarness drives repeated SSO callback logins against a full test server.
type ssoHarness struct {
	s        *server
	srv      *httptest.Server
	key      *rsa.PrivateKey
	jwksSrv  *httptest.Server
	tokenSrv *httptest.Server
	provider *oidcProvider
	nonce    string // nonce the token endpoint embeds in the next ID token
	logins   int
}

func newSSOHarness(t *testing.T, defaultTenant string) *ssoHarness {
	t.Helper()
	srv, s := newTestServerState(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "parity-kid"
	h := &ssoHarness{s: s, srv: srv, key: key}
	h.jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(h.jwksSrv.Close)
	p := oidc.NewProviderFromConfig(oidcConfig{
		Enabled: true, Issuer: "https://idp.example.test/realms/netops", ClientID: "netops-api",
		DefaultRole: RoleReadOnly, DefaultTenant: defaultTenant,
	}, 10*time.Minute)
	h.tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": mintIDToken(t, key, kid, p.Issuer(), p.ClientID(), h.nonce),
		})
	}))
	t.Cleanup(h.tokenSrv.Close)
	p.JWKS().SeedDiscoveryForTest(&jwks.Discovery{
		Issuer:        p.Issuer(),
		AuthEndpoint:  p.Issuer() + "/protocol/openid-connect/auth",
		TokenEndpoint: h.tokenSrv.URL,
		JWKSURI:       h.jwksSrv.URL,
	})
	h.provider = p
	s.oidc.Store(p)
	s.ssoTxns = newSSOTxnStore()
	return h
}

// login performs one full SSO callback and returns the redirect Location the
// browser would follow: a "#token=..." fragment on success, "#sso_error=..."
// on refusal.
func (h *ssoHarness) login(t *testing.T) string {
	t.Helper()
	h.logins++
	state := fmt.Sprintf("st-%d", h.logins)
	h.nonce = fmt.Sprintf("n-%d", h.logins)
	if err := h.s.ssoTxns.Create(state, h.nonce, fmt.Sprintf("v-%d", h.logins), time.Now()); err != nil {
		t.Fatalf("seed txn: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://app.example.test/api/auth/sso/callback?state="+state+"&code=xyz", nil)
	r.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: state})
	rec := httptest.NewRecorder()
	h.s.handleSSOCallback(rec, r)
	return rec.Header().Get("Location")
}

func assertSSOSuccess(t *testing.T, loc string) {
	t.Helper()
	if !strings.Contains(loc, "token=") || strings.Contains(loc, "sso_error") {
		t.Fatalf("expected a successful SSO redirect, got %q", loc)
	}
}

func assertSSORefused(t *testing.T, loc, wantSubstr string) {
	t.Helper()
	if !strings.Contains(loc, "sso_error") {
		t.Fatalf("expected an sso_error redirect, got %q", loc)
	}
	if !strings.Contains(strings.ToLower(loc), strings.ReplaceAll(wantSubstr, " ", "+")) &&
		!strings.Contains(strings.ToLower(loc), strings.ReplaceAll(wantSubstr, " ", "%20")) {
		t.Fatalf("sso_error should mention %q, got %q", wantSubstr, loc)
	}
}

// The mintIDToken test IdP always asserts subject "user-1".
const fedSSOUser = "user-1"

func TestSSOLoginRefusedForExpiredAccount(t *testing.T) {
	h := newSSOHarness(t, "acme")
	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	assertSSOSuccess(t, h.login(t)) // provisions the federated account
	before := len(activeSessions(h.s, fedSSOUser))

	setScopeSettings(t, h.s, "acme", func(ss *SecuritySettings) { ss.AccountValidityDays = 30 })
	backdateUser(t, h.s, fedSSOUser, func(u *User) { u.CreatedAt = time.Now().UTC().AddDate(0, 0, -60) })

	assertSSORefused(t, h.login(t), "expired")
	if got := len(activeSessions(h.s, fedSSOUser)); got != before {
		t.Errorf("refused SSO login minted a session: %d active, want %d", got, before)
	}
}

func TestSSOLoginRefusedForInactiveAccount(t *testing.T) {
	h := newSSOHarness(t, "acme")
	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	assertSSOSuccess(t, h.login(t))

	setScopeSettings(t, h.s, "acme", func(ss *SecuritySettings) { ss.AccountInactivityDays = 90 })
	backdateUser(t, h.s, fedSSOUser, func(u *User) { u.LastLoginAt = time.Now().UTC().AddDate(0, 0, -120) })

	assertSSORefused(t, h.login(t), "inactivity")
}

func TestSSOLoginRefusedWhenTenantSuspended(t *testing.T) {
	h := newSSOHarness(t, "acme")
	tn, err := h.s.tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	assertSSOSuccess(t, h.login(t))
	before := len(activeSessions(h.s, fedSSOUser))

	if _, err := h.s.tenants.SetStatus(tn.ID, TenantStatusSuspended); err != nil {
		t.Fatalf("suspend tenant: %v", err)
	}
	assertSSORefused(t, h.login(t), "tenant suspended")
	if got := len(activeSessions(h.s, fedSSOUser)); got != before {
		t.Errorf("refused SSO login minted a session: %d active, want %d", got, before)
	}

	// Reactivation restores the sign-in.
	if _, err := h.s.tenants.SetStatus(tn.ID, TenantStatusActive); err != nil {
		t.Fatalf("reactivate tenant: %v", err)
	}
	assertSSOSuccess(t, h.login(t))
}

func TestSSOConcurrentLoginDenyRevokesPriorSession(t *testing.T) {
	h := newSSOHarness(t, "acme")
	if _, err := h.s.tenants.Create("Acme", "acme", "", "", ""); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	setScopeSettings(t, h.s, "acme", func(ss *SecuritySettings) { ss.ConcurrentLogin = "deny" })

	assertSSOSuccess(t, h.login(t))
	first := activeSessions(h.s, fedSSOUser)
	if len(first) != 1 {
		t.Fatalf("after first SSO login: %d active sessions, want 1", len(first))
	}
	assertSSOSuccess(t, h.login(t))
	second := activeSessions(h.s, fedSSOUser)
	if len(second) != 1 {
		t.Fatalf("concurrent_login=deny: %d active sessions after second SSO login, want 1", len(second))
	}
	if second[0].ID == first[0].ID {
		t.Error("the surviving session is the OLD one — deny must be last-login-wins")
	}
}

func TestAdminCannotSetPasswordOnFederatedAccount(t *testing.T) {
	h := newSSOHarness(t, "")
	assertSSOSuccess(t, h.login(t)) // provisions the federated account

	a := login(t, h.srv, "admin", "Passw0rd!2345")
	st, b := do(t, h.srv, "PATCH", "/api/users/"+fedSSOUser, a.Token,
		map[string]string{"password": "NewPassw0rd!9999"})
	if st != http.StatusBadRequest {
		t.Fatalf("password set on federated account: status %d (%s), want 400", st, b)
	}
	// Profile edits (no password) remain allowed.
	st, b = do(t, h.srv, "PATCH", "/api/users/"+fedSSOUser, a.Token,
		map[string]string{"display_name": "Renamed By Admin"})
	if st != http.StatusOK {
		t.Fatalf("profile-only patch on federated account: status %d (%s), want 200", st, b)
	}
	if u, ok := h.s.users.Get(fedSSOUser); !ok || u.PasswordHash != "" {
		t.Errorf("federated account must remain passwordless, got hash %q", u.PasswordHash)
	}
}

// A per-USER policy override tightens the session policy for that user only —
// mirroring TestSessionPolicyPerRole. Before #146b the Subject carried no user,
// so an explicit per-user override written via the policy API was silently
// ignored at login.
func TestSessionPolicyPerUserOverrideApplies(t *testing.T) {
	dir := t.TempDir()
	ss, err := newSecuritySettingsStore(dir + "/sec.json")
	if err != nil {
		t.Fatal(err)
	}
	sp := policy.NewSecurityStore(dir+"/policy.json", platformKV{}, logError)
	if _, err := sp.SetOverride(policy.ScopeUser, "alice", "acme", "session.idle_timeout",
		policy.Override{Value: policy.Value{Kind: policy.KindDuration, Num: 600}}, "test"); err != nil {
		t.Fatalf("set user override: %v", err)
	}
	s := &server{securitySettings: ss, secPolicy: sp}
	if idle, _, _, _ := s.sessionPolicy("acme", "operator", "alice"); idle != 10*time.Minute {
		t.Errorf("alice idle = %v, want 10m (per-user override)", idle)
	}
	if idle, _, _, _ := s.sessionPolicy("acme", "operator", "bob"); idle != 30*time.Minute {
		t.Errorf("bob idle = %v, want 30m (scope default)", idle)
	}
}
