// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// mailbox_auth_test.go — the OAuth token sources, asserted as CONVERSATIONS.
//
// What has to hold:
//
//	· the exact request sequence. A token grant is a protocol, not a shape: the
//	  fake providers record every request and the assertions are on the whole
//	  list, so an extra call — or a call in the wrong order — fails.
//	· the JWT is a real JWT. The assertion is decoded, its claims compared field
//	  by field, and its RS256 signature VERIFIED against the public key, because
//	  a signature that only looks right is a credential that fails at 3am.
//	· nothing ever quotes a secret. Every error path is asserted not to carry the
//	  client secret or anything derived from the private key.
//	· the cache is keyed by the CREDENTIAL. Two tenants sharing one connector
//	  instance can never be handed each other's token (§3a).

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── the fake identity providers ─────────────────────────────────────────────

// fakeMailbox is one httptest server standing in for Entra, Google's token
// endpoint, Microsoft Graph and Gmail at once. It records every request — method,
// path and the form or JSON body — so a test can assert the whole sequence.
type fakeMailbox struct {
	mu    sync.Mutex
	srv   *httptest.Server
	calls []fakeCall
	// status/body overrides, keyed by the path suffix they apply to.
	status map[string]int
	reply  map[string]string
	// once, when set for a suffix, makes the FIRST call to it answer that status
	// and every later one succeed — how a retry is exercised.
	once map[string]int
	hits map[string]int
	// retryAfter is stamped on any injected 429/5xx.
	retryAfter string
}

type fakeCall struct {
	Method string
	Path   string
	Query  string
	Form   url.Values
	Body   []byte
	Auth   string
}

func newFakeMailbox(t *testing.T) *fakeMailbox {
	t.Helper()
	f := &fakeMailbox{
		status: map[string]int{}, reply: map[string]string{},
		once: map[string]int{}, hits: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeMailbox) serve(w http.ResponseWriter, r *http.Request) {
	call := fakeCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization")}
	if r.Method == http.MethodPost {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			_ = r.ParseForm()
			call.Form = r.PostForm
		} else {
			buf := make([]byte, 8<<20)
			n, _ := r.Body.Read(buf)
			for n > 0 {
				call.Body = append(call.Body, buf[:n]...)
				n, _ = r.Body.Read(buf)
			}
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	key := f.matchKey(r.URL.Path)
	f.hits[key]++
	status, body := f.status[key], f.reply[key]
	if s, ok := f.once[key]; ok && f.hits[key] == 1 {
		status = s
	}
	retryAfter := f.retryAfter
	f.mu.Unlock()

	if status >= 400 {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"code":"injected","message":"the provider said no"}}`))
		return
	}
	if body != "" {
		_, _ = w.Write([]byte(body))
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"), strings.HasSuffix(r.URL.Path, "/token"):
		_, _ = w.Write([]byte(`{"access_token":"minted-bearer","expires_in":3600,"token_type":"Bearer"}`))
	case strings.HasSuffix(r.URL.Path, "/sendMail"):
		w.WriteHeader(http.StatusAccepted)
	case strings.HasSuffix(r.URL.Path, "/messages/send"):
		_, _ = w.Write([]byte(`{"id":"gmail-msg-1","threadId":"gmail-thread-1"}`))
	case strings.HasSuffix(r.URL.Path, "/profile"):
		_, _ = w.Write([]byte(`{"emailAddress":"noc@acme.example","messagesTotal":3}`))
	case strings.HasSuffix(r.URL.Path, "/messages"):
		_, _ = w.Write([]byte(`{"value":[]}`))
	default:
		_, _ = w.Write([]byte(`{"id":"mailbox-object-id","mail":"noc@acme.example"}`))
	}
}

// matchKey reduces a path to the suffix tests key overrides on.
func (f *fakeMailbox) matchKey(path string) string {
	for _, suffix := range []string{"/oauth2/v2.0/token", "/sendMail", "/messages/send", "/profile", "/messages"} {
		if strings.HasSuffix(path, suffix) {
			return suffix
		}
	}
	if strings.HasSuffix(path, "/token") {
		return "/token"
	}
	return "/users"
}

func (f *fakeMailbox) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.Method+" "+c.Path)
	}
	return out
}

func (f *fakeMailbox) recorded() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

func (f *fakeMailbox) endpoints() mailboxEndpoints {
	return mailboxEndpoints{
		EntraLogin:  f.srv.URL,
		Graph:       f.srv.URL + "/v1.0",
		GoogleToken: f.srv.URL + "/token",
		Gmail:       f.srv.URL + "/gmail/v1",
	}
}

// connector builds an email connector wired to this fake and to nothing else.
func (f *fakeMailbox) connector(t *testing.T, vendorID string) *EmailCaseConnector {
	t.Helper()
	c, err := NewEmailCaseConnector(vendorID)
	if err != nil {
		t.Fatalf("build %s: %v", vendorID, err)
	}
	c.tok = &mailboxTokens{http: f.srv.Client(), endpoints: f.endpoints(), cache: map[string]cachedMailboxToken{}}
	return c
}

func (f *fakeMailbox) tokens() *mailboxTokens {
	return &mailboxTokens{http: f.srv.Client(), endpoints: f.endpoints(), cache: map[string]cachedMailboxToken{}}
}

// ── test credentials ────────────────────────────────────────────────────────

// testRSAKey is generated once: 2048-bit key generation is the slowest thing in
// this file and every test wants the same key anyway.
var (
	testRSAOnce sync.Once
	testRSAKey  *rsa.PrivateKey
)

func rsaKeyT(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		testRSAKey = k
	})
	return testRSAKey
}

func pkcs8PEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func graphCfg() EmailConnectorConfig {
	return EmailConnectorConfig{
		Enabled: true, AuthMode: MailboxAuthGraph,
		Mailbox: "noc@acme.example", ReplyTo: "jane.doe@acme.example",
		EntraTenantID: "11111111-2222-3333-4444-555555555555",
		OAuthClientID: "app-client-id", OAuthClientSecret: "app-client-SECRET",
	}
}

func gmailCfg(t *testing.T) EmailConnectorConfig {
	t.Helper()
	return EmailConnectorConfig{
		Enabled: true, AuthMode: MailboxAuthGmail,
		Mailbox: "noc@acme.example", From: "noc@acme.example",
		ServiceAccountEmail: "correlix@project.iam.gserviceaccount.com",
		ServiceAccountKey:   pkcs8PEM(t, rsaKeyT(t)),
	}
}

// ── the pinned endpoints ────────────────────────────────────────────────────

// Every default base is https and on the allowlist. This is the guard that a
// typo in a base URL — the one mistake that would send a tenant's credential
// somewhere else entirely — cannot ship.
func TestTheDefaultMailboxEndpointsAreHTTPSAndPinned(t *testing.T) {
	eps := defaultMailboxEndpoints()
	allow := map[string]bool{}
	for _, h := range mailboxHostAllowlist() {
		allow[h] = true
	}
	for name, raw := range map[string]string{
		"entra": eps.EntraLogin, "graph": eps.Graph,
		"google token": eps.GoogleToken, "gmail": eps.Gmail,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %q does not parse: %v", name, raw, err)
		}
		if u.Scheme != "https" {
			t.Errorf("%s base %q is not https", name, raw)
		}
		if !allow[u.Hostname()] {
			t.Errorf("%s base %q is off the pinned allowlist %v", name, raw, mailboxHostAllowlist())
		}
	}
}

// A record written before OAuth existed keeps working, unchanged, forever.
func TestABlankAuthModeIsThePasswordRelay(t *testing.T) {
	e := EmailConnectorConfig{Enabled: true, Host: "smtp.acme.example:587", From: "noc@acme.example"}
	if e.authMode() != MailboxAuthPassword {
		t.Fatalf("mode = %q, want the password relay", e.authMode())
	}
	if e.tokenProvider() != "" {
		t.Fatalf("a password relay must name no token provider, got %q", e.tokenProvider())
	}
	if err := validateEmailConfig(e); err != nil {
		t.Fatalf("the relay configuration that worked yesterday must still validate: %v", err)
	}
}

// ── Microsoft: the client-credentials grant ─────────────────────────────────

func TestEntraClientCredentialsRequestSequence(t *testing.T) {
	f := newFakeMailbox(t)
	tok := f.tokens()
	cfg := graphCfg()

	got, err := tok.Token(context.Background(), cfg, graphDefaultScope)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "minted-bearer" {
		t.Fatalf("token = %q", got)
	}
	calls := f.recorded()
	if len(calls) != 1 {
		t.Fatalf("the grant took %d requests: %v", len(calls), f.seen())
	}
	c := calls[0]
	wantPath := "/" + url.PathEscape(cfg.EntraTenantID) + "/oauth2/v2.0/token"
	if c.Method != http.MethodPost || c.Path != wantPath {
		t.Fatalf("call = %s %s, want POST %s", c.Method, c.Path, wantPath)
	}
	for k, want := range map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "app-client-id",
		"client_secret": "app-client-SECRET",
		"scope":         graphDefaultScope,
	} {
		if got := c.Form.Get(k); got != want {
			t.Errorf("form %s = %q, want %q", k, got, want)
		}
	}

	// A second call is served from the cache: the identity provider is not asked
	// again for a token that is still good.
	if _, err := tok.Token(context.Background(), cfg, graphDefaultScope); err != nil {
		t.Fatalf("cached token: %v", err)
	}
	if n := len(f.recorded()); n != 1 {
		t.Fatalf("a cached token still cost %d requests", n)
	}

	// Rotating the secret changes the cache key, so the NEW secret is used at
	// once rather than the old token outliving it.
	rotated := cfg
	rotated.OAuthClientSecret = "rotated-SECRET"
	if _, err := tok.Token(context.Background(), rotated, graphDefaultScope); err != nil {
		t.Fatalf("rotated token: %v", err)
	}
	calls = f.recorded()
	if len(calls) != 2 {
		t.Fatalf("a rotated secret did not re-mint: %v", f.seen())
	}
	if calls[1].Form.Get("client_secret") != "rotated-SECRET" {
		t.Errorf("the rotated secret was not used: %q", calls[1].Form.Get("client_secret"))
	}
}

// The request body carries the client secret. No error derived from it may.
func TestARefusedTokenNeverQuotesTheSecret(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/oauth2/v2.0/token"] = http.StatusUnauthorized
	_, err := f.tokens().Token(context.Background(), graphCfg(), graphDefaultScope)
	if err == nil {
		t.Fatal("a 401 must be an error")
	}
	if strings.Contains(err.Error(), "app-client-SECRET") {
		t.Fatalf("the error quoted the client secret: %v", err)
	}
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Errorf("a rejected credential is permanent, got %v", err)
	}
	if !strings.Contains(err.Error(), "the provider said no") {
		t.Errorf("the provider's own words must survive: %v", err)
	}
}

// ── Google: the JWT-bearer grant ────────────────────────────────────────────

// The assertion is decoded, its claims compared one by one and its signature
// VERIFIED. A JWT that merely looks like a JWT is a credential that fails at 3am.
func TestTheGoogleAssertionIsARealSignedJWT(t *testing.T) {
	key := rsaKeyT(t)
	cfg := gmailCfg(t)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

	assertion, err := googleAssertion(cfg, gmailSendScope, "https://oauth2.googleapis.com/token", now)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("an assertion has three segments, got %d", len(parts))
	}
	var header map[string]string
	decodeSegT(t, parts[0], &header)
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("header = %v, want RS256/JWT", header)
	}
	var claims map[string]any
	decodeSegT(t, parts[1], &claims)
	for k, want := range map[string]any{
		"iss":   "correlix@project.iam.gserviceaccount.com",
		"sub":   "noc@acme.example", // domain-wide delegation impersonates the mailbox
		"scope": gmailSendScope,
		"aud":   "https://oauth2.googleapis.com/token",
	} {
		if got, _ := claims[k].(string); got != want {
			t.Errorf("claim %s = %v, want %v", k, claims[k], want)
		}
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int64(iat) != now.Unix() {
		t.Errorf("iat = %v, want %d", iat, now.Unix())
	}
	if int64(exp) != now.Add(googleAssertionTTL).Unix() {
		t.Errorf("exp = %v, want %d", exp, now.Add(googleAssertionTTL).Unix())
	}
	if exp-iat > 3600 {
		t.Error("Google refuses an assertion valid for more than an hour")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the assertion does not verify against the service-account key: %v", err)
	}
}

func decodeSegT(t *testing.T, seg string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("segment is not base64url: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("segment is not JSON: %v", err)
	}
}

func TestGoogleJWTBearerRequestSequence(t *testing.T) {
	f := newFakeMailbox(t)
	got, err := f.tokens().Token(context.Background(), gmailCfg(t), gmailSendScope)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "minted-bearer" {
		t.Fatalf("token = %q", got)
	}
	calls := f.recorded()
	if len(calls) != 1 || calls[0].Method != http.MethodPost || calls[0].Path != "/token" {
		t.Fatalf("sequence = %v, want one POST /token", f.seen())
	}
	if g := calls[0].Form.Get("grant_type"); g != jwtBearerGrantType {
		t.Errorf("grant_type = %q, want %q", g, jwtBearerGrantType)
	}
	if a := calls[0].Form.Get("assertion"); strings.Count(a, ".") != 2 {
		t.Errorf("assertion = %q, want three JWT segments", Truncate(a, 40))
	}
	// The private key itself is NEVER on the wire — only a signature over it.
	if strings.Contains(calls[0].Form.Encode(), "PRIVATE KEY") {
		t.Fatal("the service-account private key was sent to the token endpoint")
	}
}

func TestTheServiceAccountKeyIsParsedNotJustPresent(t *testing.T) {
	key := rsaKeyT(t)
	if _, err := parseRSAPrivateKey(pkcs8PEM(t, key)); err != nil {
		t.Fatalf("PKCS#8 (what Google issues) must parse: %v", err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if _, err := parseRSAPrivateKey(pkcs1); err != nil {
		t.Fatalf("PKCS#1 must parse too: %v", err)
	}
	for name, bad := range map[string]string{
		"not a pem":     "hunter2",
		"empty":         "",
		"wrong block":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})),
		"corrupt pkcs8": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-der")})),
	} {
		if _, err := parseRSAPrivateKey(bad); err == nil {
			t.Errorf("%s: was accepted as a signing key", name)
		}
	}
}

// ── SASL XOAUTH2 ────────────────────────────────────────────────────────────

// The two connection states a SASL mechanism has to distinguish.
var (
	smtpServerInfoTLS   = smtp.ServerInfo{Name: "smtp.office365.com", TLS: true, Auth: []string{"XOAUTH2"}}
	smtpServerInfoPlain = smtp.ServerInfo{Name: "relay.acme.example", TLS: false, Auth: []string{"XOAUTH2"}}
)

func TestXOAUTH2SpeaksTheExactMechanism(t *testing.T) {
	a := xoauth2Auth{user: "noc@acme.example", token: "minted-bearer"}
	mech, initial, err := a.Start(&smtpServerInfoTLS)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if mech != "XOAUTH2" {
		t.Fatalf("mechanism = %q", mech)
	}
	want := "user=noc@acme.example\x01auth=Bearer minted-bearer\x01\x01"
	if string(initial) != want {
		t.Fatalf("initial response = %q, want %q", initial, want)
	}
	// A rejected token arrives as a challenge; the protocol wants one empty line
	// before the server will say 535.
	reply, err := a.Next([]byte(`eyJzdGF0dXMiOiI0MDEifQ==`), true)
	if err != nil || len(reply) != 0 {
		t.Fatalf("challenge reply = %q, %v — want an empty response", reply, err)
	}
	if reply, err := a.Next(nil, false); err != nil || reply != nil {
		t.Fatalf("end of exchange = %q, %v", reply, err)
	}
}

// A bearer in the clear is strictly worse than a password in the clear.
func TestXOAUTH2RefusesAnUnencryptedConnection(t *testing.T) {
	a := xoauth2Auth{user: "noc@acme.example", token: "minted-bearer"}
	if _, _, err := a.Start(&smtpServerInfoPlain); err == nil {
		t.Fatal("XOAUTH2 was offered over an unencrypted connection")
	}
	if _, _, err := a.Start(nil); err == nil {
		t.Fatal("XOAUTH2 was offered with no server info at all")
	}
	empty := xoauth2Auth{}
	if _, _, err := empty.Start(&smtpServerInfoTLS); err == nil {
		t.Fatal("XOAUTH2 must refuse to send an empty token")
	}
}

// ── rate limits and outages ─────────────────────────────────────────────────

func TestA429IsARateLimitCarryingTheProvidersOwnWait(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/oauth2/v2.0/token"] = http.StatusTooManyRequests
	f.retryAfter = "7"
	_, err := f.tokens().Token(context.Background(), graphCfg(), graphDefaultScope)
	var rl RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want RateLimitedError", err)
	}
	if rl.After != 7*time.Second {
		t.Fatalf("Retry-After = %s, want 7s", rl.After)
	}
	if !retryable(err) {
		t.Error("a rate limit is retryable")
	}
}

func TestA5xxWithRetryAfterIsHonouredAndClampedToTheCap(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/oauth2/v2.0/token"] = http.StatusServiceUnavailable
	f.retryAfter = "30"
	_, err := f.tokens().Token(context.Background(), graphCfg(), graphDefaultScope)
	var ra RetryAfterError
	if !errors.As(err, &ra) {
		t.Fatalf("err = %v, want RetryAfterError", err)
	}
	if ra.After != 30*time.Second {
		t.Fatalf("After = %s, want 30s", ra.After)
	}
	if !retryable(err) {
		t.Error("a 5xx is retryable")
	}
	// The provider's wait is honoured, but never past our own ceiling: an
	// operator is watching this call.
	p := RetryPolicy{MaxAttempts: 3, Base: time.Second, Cap: 8 * time.Second}
	if d := retryDelay(p, err, 1, "k"); d != 8*time.Second {
		t.Fatalf("delay = %s, want the 8s cap", d)
	}
	// And a 5xx is an OUTAGE, not a refusal: the probe must not blame the
	// credential for it.
	if outcome, _ := classifyProbeError(err); outcome != ProbeUnreachable {
		t.Fatalf("a 503 probed as %q, want unreachable", outcome)
	}
}

// ── isolation ───────────────────────────────────────────────────────────────

// One connector instance serves every tenant. Two tenants' credentials must
// never share a cache entry — that would be a cross-tenant credential leak.
func TestTheTokenCacheIsKeyedByCredentialNotByConnector(t *testing.T) {
	acme := graphCfg()
	globex := graphCfg()
	globex.EntraTenantID = "99999999-8888-7777-6666-555555555555"
	globex.OAuthClientID = "globex-app"
	globex.OAuthClientSecret = "globex-SECRET"

	ka := mailboxTokenCacheKey(acme, MailboxProviderMicrosoft, graphDefaultScope)
	kb := mailboxTokenCacheKey(globex, MailboxProviderMicrosoft, graphDefaultScope)
	if ka == kb {
		t.Fatal("two tenants share a token cache key")
	}
	// The key identifies the secret without carrying it.
	if strings.Contains(ka, acme.OAuthClientSecret) {
		t.Fatalf("the cache key carries the client secret: %q", ka)
	}
	// The same credential asking for a DIFFERENT scope is a different token.
	if mailboxTokenCacheKey(acme, MailboxProviderMicrosoft, outlookSMTPScope) == ka {
		t.Fatal("two scopes share one cached token")
	}
}

func TestTheTokenCacheIsBounded(t *testing.T) {
	tok := &mailboxTokens{cache: map[string]cachedMailboxToken{}}
	for i := 0; i < maxMailboxTokenCache*3; i++ {
		tok.store(string(rune('a'+i%26))+strings.Repeat("x", i), "t", time.Hour)
	}
	if len(tok.cache) > maxMailboxTokenCache {
		t.Fatalf("cache grew to %d entries (ceiling %d)", len(tok.cache), maxMailboxTokenCache)
	}
}

// A mode with no provider chosen fails closed rather than guessing one.
func TestAnUnnamedTokenProviderIsRefused(t *testing.T) {
	cfg := EmailConnectorConfig{Enabled: true, AuthMode: MailboxAuthSMTPOAuth, Host: "smtp.office365.com:587"}
	_, err := (&mailboxTokens{cache: map[string]cachedMailboxToken{}}).Token(context.Background(), cfg, outlookSMTPScope)
	if err == nil {
		t.Fatal("a mailbox with no token provider must be refused")
	}
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Errorf("err = %v, want a permanent refusal", err)
	}
}
