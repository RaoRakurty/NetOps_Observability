// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_tokencache_test.go — the isolation proof for the vendor OAuth token
// caches (§3a, §11).
//
// One CiscoSmartBondingConnector and one JuniperConnector serve every tenant on
// the server. These tests drive ONE connector object with TWO tenants'
// configurations and assert that the second tenant is never handed the bearer
// the first one minted — the leak that filed tenant B's case under tenant A's
// vendor account, spent A's quota, let B read A's case back, and made the Test
// button certify a client secret the vendor had never seen.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/ticketing/vendors/cisco"
	"netops/backend/internal/ticketing/vendors/juniper"
)

// ── Cisco ───────────────────────────────────────────────────────────────────

// ciscoTokenStub answers the OAuth exchange in process. It has to be a
// RoundTripper rather than an httptest server because the token host is PINNED
// to cisco.com (ciscoHostAllowlist), so no local listener can ever stand in for
// it — the same reason the e2e test proves the exchange at the client.
type ciscoTokenStub struct {
	mu       sync.Mutex
	mints    int
	accounts map[string]string // client id → the secret the vendor will accept
}

func newCiscoTokenStub(accounts map[string]string) *ciscoTokenStub {
	return &ciscoTokenStub{accounts: accounts}
}

func (s *ciscoTokenStub) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	id := form.Get("client_id")

	s.mu.Lock()
	want, known := s.accounts[id]
	if known && want == form.Get("client_secret") {
		s.mints++
	}
	s.mu.Unlock()

	reply := func(status int, payload string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(payload)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    r,
		}, nil
	}
	if !known || want != form.Get("client_secret") {
		return reply(http.StatusUnauthorized, `{"error":"invalid_client"}`)
	}
	// The minted bearer NAMES the credential and the environment it came from,
	// so a test can see exactly which one a caller was handed.
	return reply(http.StatusOK, `{"access_token":"cisco-bearer-`+r.URL.Host+`-`+id+`","expires_in":3600}`)
}

func (s *ciscoTokenStub) minted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mints
}

func ciscoStubConnector(s *ciscoTokenStub) *CiscoSmartBondingConnector {
	return NewCiscoSmartBondingConnector(&cisco.Client{HTTP: &http.Client{Transport: s}})
}

// ciscoTenantCfg is one tenant's Smart Bonding configuration.
func ciscoTenantCfg(clientID, secret, stagingHost, tokenURL string) TACConnectorConfig {
	return TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true,
		CCOID: "cco-" + clientID, CustomerSourceID: "src-" + clientID,
		ClientID: clientID, ClientSecret: secret,
		StagingHost: stagingHost, TokenURL: tokenURL,
		FieldMap: fullCiscoFieldMap(),
	}}
}

// Two tenants, two credentials, one connector object. Each must get its own
// bearer, and the cache must still be a cache.
func TestCiscoBearerIsMintedPerTenantCredential(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoTokenStub(map[string]string{
		"acme-client":   "acme-secret",
		"globex-client": "globex-secret",
	})
	c := ciscoStubConnector(stub)
	acme := ciscoTenantCfg("acme-client", "acme-secret", "", "")
	globex := ciscoTenantCfg("globex-client", "globex-secret", "", "")

	first, err := c.bearer(context.Background(), acme)
	if err != nil {
		t.Fatalf("acme bearer: %v", err)
	}
	second, err := c.bearer(context.Background(), globex)
	if err != nil {
		t.Fatalf("globex bearer: %v", err)
	}
	if first == second {
		t.Fatal("the second tenant was handed the first tenant's bearer — its case would be filed under the first tenant's Cisco account")
	}
	if want := "cisco-bearer-id.cisco.com-globex-client"; second != want {
		t.Fatalf("globex bearer = %q, want %q", second, want)
	}
	if n := stub.minted(); n != 2 {
		t.Fatalf("the token endpoint minted %d times, want one per credential", n)
	}
	// And it is still a cache: the tenant that already minted does not mint
	// again.
	again, err := c.bearer(context.Background(), acme)
	if err != nil {
		t.Fatalf("acme bearer (cached): %v", err)
	}
	if again != first || stub.minted() != 2 {
		t.Fatalf("cached bearer = %q after %d mints, want %q after 2", again, stub.minted(), first)
	}
}

// The same client id pointed at two DIFFERENT Cisco environments is two
// credentials. A staging bearer is not valid against production, and two
// tenants can legitimately share an id while being onboarded to different
// environments.
func TestCiscoBearerIsNotSharedBetweenStagingAndProduction(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoTokenStub(map[string]string{"shared-client": "shared-secret"})
	c := ciscoStubConnector(stub)
	prod := ciscoTenantCfg("shared-client", "shared-secret", "", "")
	staging := ciscoTenantCfg("shared-client", "shared-secret",
		"sb-staging.cisco.com", "https://sb-staging.cisco.com/oauth2/token")

	prodTok, err := c.bearer(context.Background(), prod)
	if err != nil {
		t.Fatalf("production bearer: %v", err)
	}
	stagingTok, err := c.bearer(context.Background(), staging)
	if err != nil {
		t.Fatalf("staging bearer: %v", err)
	}
	if prodTok == stagingTok {
		t.Fatal("staging and production share one cached bearer")
	}
	if !strings.Contains(stagingTok, "sb-staging.cisco.com") {
		t.Fatalf("staging bearer = %q, want one minted at the staging endpoint", stagingTok)
	}
	if n := stub.minted(); n != 2 {
		t.Fatalf("the token endpoint minted %d times, want one per environment", n)
	}
}

// The pin is a property of the CONFIGURATION, not of the mint: a cached bearer
// must not be a way past it. A tenant that points the token URL off cisco.com
// is refused even when the connector already holds a token.
func TestCiscoRefusesAnOffAllowlistTokenURLEvenWithATokenCached(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoTokenStub(map[string]string{"acme-client": "acme-secret"})
	c := ciscoStubConnector(stub)
	if _, err := c.bearer(context.Background(), ciscoTenantCfg("acme-client", "acme-secret", "", "")); err != nil {
		t.Fatalf("seed the cache: %v", err)
	}
	off := ciscoTenantCfg("acme-client", "acme-secret", "", "https://tokens.evil.example/oauth2/token")
	if _, err := c.bearer(context.Background(), off); err == nil {
		t.Fatal("a token URL off the pinned allowlist was accepted")
	}
}

func TestCiscoTokenCacheKeyNamesTheCredentialWithoutCarryingIt(t *testing.T) {
	base := ciscoTenantCfg("shared-client", "shared-secret", "", "").Cisco
	key := ciscoTokenCacheKey(base, cisco.DefaultTokenURL)

	if strings.Contains(key, base.ClientSecret) {
		t.Fatalf("the cache key carries the client secret: %q", key)
	}
	rotated := base
	rotated.ClientSecret = "rotated-secret"
	if ciscoTokenCacheKey(rotated, cisco.DefaultTokenURL) == key {
		t.Fatal("a rotated secret keeps the old cached bearer alive")
	}
	other := base
	other.ClientID = "other-client"
	if ciscoTokenCacheKey(other, cisco.DefaultTokenURL) == key {
		t.Fatal("two client ids share one cache entry")
	}
	staging := base
	staging.StagingHost = "sb-staging.cisco.com"
	if ciscoTokenCacheKey(staging, cisco.DefaultTokenURL) == key {
		t.Fatal("staging and production share one cache entry")
	}
	if ciscoTokenCacheKey(base, "https://sb-staging.cisco.com/oauth2/token") == key {
		t.Fatal("two token endpoints share one cache entry")
	}
}

// ── Juniper ─────────────────────────────────────────────────────────────────

// juniperTokenFake plays the gateway for the token exchange and /getlov. It
// refuses a credential it does not know, which is what makes the Test button
// test anything.
type juniperTokenFake struct {
	srv      *httptest.Server
	mu       sync.Mutex
	mints    int
	lovAuth  []string // the Authorization header each /getlov call presented
	accounts map[string]string
}

func newJuniperTokenFake(t *testing.T, accounts map[string]string) *juniperTokenFake {
	t.Helper()
	f := &juniperTokenFake{accounts: accounts}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case juniper.TokenPath:
			var body struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			want, known := f.accounts[body.ClientID]
			ok := known && want == body.ClientSecret
			if ok {
				f.mints++
			}
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"juniper-bearer-`+body.ClientID+`","expires_in":3600}`)
		case juniper.PathGetLOV:
			// The bearer is recorded, not checked: the fake must ANSWER a stolen
			// bearer, or the leak this file is about would hide behind the fake.
			f.mu.Lock()
			f.lovAuth = append(f.lovAuth, r.Header.Get("Authorization"))
			f.mu.Unlock()
			_, _ = io.WriteString(w, `{"values":["P1","P2","P3","P4"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *juniperTokenFake) minted() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints
}

func (f *juniperTokenFake) connector() *JuniperConnector {
	return NewJuniperConnector(juniper.NewForTest(f.srv.Client(), f.srv.URL))
}

func juniperTenantCfg(clientID, secret string) TACConnectorConfig {
	return TACConnectorConfig{Juniper: JuniperConnectorConfig{
		Enabled: true, AppID: "app-" + clientID, CustomerSourceID: "src-" + clientID,
		UserID: "user-" + clientID, AccountID: "acct-" + clientID,
		AuthMode: "oauth", ClientID: clientID, ClientSecret: secret,
		DefaultContactEmail: "jane.doe@customer.example",
	}}
}

func TestJuniperBearerIsMintedPerTenantCredential(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperTokenFake(t, map[string]string{
		"acme-client":   "acme-secret",
		"globex-client": "globex-secret",
	})
	c := f.connector()

	first, err := c.auth(context.Background(), juniperTenantCfg("acme-client", "acme-secret"))
	if err != nil {
		t.Fatalf("acme auth: %v", err)
	}
	second, err := c.auth(context.Background(), juniperTenantCfg("globex-client", "globex-secret"))
	if err != nil {
		t.Fatalf("globex auth: %v", err)
	}
	if first.Bearer == second.Bearer {
		t.Fatal("the second tenant was handed the first tenant's bearer — its case would be filed under the first tenant's Juniper account")
	}
	if want := "juniper-bearer-globex-client"; second.Bearer != want {
		t.Fatalf("globex bearer = %q, want %q", second.Bearer, want)
	}
	if n := f.minted(); n != 2 {
		t.Fatalf("the token endpoint minted %d times, want one per credential", n)
	}
	again, err := c.auth(context.Background(), juniperTenantCfg("acme-client", "acme-secret"))
	if err != nil {
		t.Fatalf("acme auth (cached): %v", err)
	}
	if again.Bearer != first.Bearer || f.minted() != 2 {
		t.Fatalf("cached bearer = %q after %d mints, want %q after 2", again.Bearer, f.minted(), first.Bearer)
	}
}

// The Test button must test the credential in front of the operator. A tenant
// that saves a wrong client secret has to be told, even when the connector
// already holds someone else's working bearer.
func TestJuniperProbeRefusesACredentialTheVendorNeverAccepted(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperTokenFake(t, map[string]string{"acme-client": "acme-secret"})
	c := f.connector()

	good := ProbeConnector(context.Background(), c, juniperTenantCfg("acme-client", "acme-secret"), time.Second, nil)
	if good.Outcome != ProbeOK {
		t.Fatalf("the tenant with a live credential probed %q (%s)", good.Outcome, good.Note)
	}
	// Same client id, the secret typed wrong. The vendor refuses it, so the
	// operator must see a refusal — not the previous tenant's success.
	bad := ProbeConnector(context.Background(), c, juniperTenantCfg("acme-client", "typo-secret"), time.Second, nil)
	if bad.Outcome == ProbeOK {
		t.Fatalf("a credential the vendor never accepted probed OK: %s", bad.Note)
	}
	if bad.Outcome != ProbeRefused {
		t.Fatalf("outcome = %q (%s), want %q", bad.Outcome, bad.Note, ProbeRefused)
	}
}

func TestJuniperTokenCacheKeyNamesTheCredentialWithoutCarryingIt(t *testing.T) {
	base := juniperTenantCfg("shared-client", "shared-secret").Juniper
	key := juniperTokenCacheKey(base)

	if strings.Contains(key, base.ClientSecret) {
		t.Fatalf("the cache key carries the client secret: %q", key)
	}
	rotated := base
	rotated.ClientSecret = "rotated-secret"
	if juniperTokenCacheKey(rotated) == key {
		t.Fatal("a rotated secret keeps the old cached bearer alive")
	}
	other := base
	other.ClientID = "other-client"
	if juniperTokenCacheKey(other) == key {
		t.Fatal("two client ids share one cache entry")
	}
	apikey := base
	apikey.AuthMode = "apikey"
	if juniperTokenCacheKey(apikey) == key {
		t.Fatal("two auth modes share one cache entry")
	}
}

// ── the cache itself ────────────────────────────────────────────────────────

func TestTheVendorTokenCacheIsBounded(t *testing.T) {
	var c vendorTokenCache
	for i := 0; i < maxVendorTokenCache*3; i++ {
		c.store(vendorTokenCacheKey("secret", "vendor", string(rune('a'+i%26))+strings.Repeat("x", i)), "t", time.Hour)
	}
	if n := c.size(); n > maxVendorTokenCache {
		t.Fatalf("cache grew to %d entries (ceiling %d)", n, maxVendorTokenCache)
	}
}

func TestTheVendorTokenCacheRefreshesBeforeExpiry(t *testing.T) {
	var c vendorTokenCache
	c.store("k", "tok", time.Hour)
	if got, ok := c.lookup("k"); !ok || got != "tok" {
		t.Fatalf("lookup = %q, %v, want the cached token", got, ok)
	}
	// Inside the one-minute refresh margin the entry is not served: a token that
	// expires in flight is a failed escalation.
	c.store("k", "tok", 30*time.Second)
	if _, ok := c.lookup("k"); ok {
		t.Fatal("a token 30s from expiry was served")
	}
	if _, ok := c.lookup("never-stored"); ok {
		t.Fatal("an unknown key returned a token")
	}
}
