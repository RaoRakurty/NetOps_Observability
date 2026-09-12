// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// mailbox_auth.go — OAuth 2.0 mailbox authentication for the email case
// connectors.
//
// WHY THIS EXISTS. The email connector is the ONLY path Arista publishes and the
// only attach path for Cisco's attach@cisco.com mailbox, and until now it could
// authenticate exactly one way: an SMTP username and password. Microsoft and
// Google have retired basic SMTP AUTH for most tenants — a customer on Microsoft
// 365 or Google Workspace has no password to give us. "Bring your own relay"
// stopped being an answer, so the connector learns the three ways those
// mailboxes are actually reachable today:
//
//	password        an on-prem or hosted relay that still takes a password.
//	                UNCHANGED, and still the default: nothing that works today
//	                stops working.
//	microsoft365    an Entra app registration (directory id + application id +
//	                client secret) → client_credentials → Graph sendMail.
//	google_workspace a service account with domain-wide delegation → a signed
//	                JWT-bearer assertion → Gmail users.messages.send.
//	smtp_oauth      a provider that still exposes SMTP, authenticated with
//	                SASL XOAUTH2 using either token source above.
//
// STDLIB ONLY (CLAUDE.md §6). A JWT is three base64url segments and one
// signature; crypto/rsa + encoding/json do all of it, and an OAuth token
// exchange is a form POST. Nothing here needed a module.
//
// SECRETS (§8). The client secret and the service-account private key are
// write-only in the store, never serialized out, and never quoted in an error:
// the token-request body carries both, so a failed token request reports that
// the identity provider refused — never what we sent it. The cache key carries a
// DIGEST of the secret, never the secret, which also means a rotation
// invalidates the cached token instead of outliving it.
//
// TENANT ISOLATION (§3a). One connector instance serves every tenant, so the
// token cache is keyed by the CREDENTIAL (provider, directory, client, mailbox,
// scope, secret digest). Two tenants cannot collide on a key, and no tenant can
// be handed a bearer minted from another's credential.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"netops/backend/safehttp"
)

// ── the four modes ──────────────────────────────────────────────────────────

// MailboxAuthMode names how the email connector proves who it is to the mailbox
// it sends through. It is part of the stored configuration and of the wire form.
type MailboxAuthMode string

const (
	// MailboxAuthPassword is the historical path: an SMTP relay that accepts a
	// username and password. Blank means this, so an existing tenant's stored
	// configuration keeps working untouched.
	MailboxAuthPassword MailboxAuthMode = "password"
	// MailboxAuthGraph sends through Microsoft Graph's sendMail on behalf of one
	// mailbox, with an Entra app registration's client credentials.
	MailboxAuthGraph MailboxAuthMode = "microsoft365"
	// MailboxAuthGmail sends through the Gmail API with a service account that
	// holds domain-wide delegation for the mailbox.
	MailboxAuthGmail MailboxAuthMode = "google_workspace"
	// MailboxAuthSMTPOAuth keeps SMTP as the transport but authenticates with
	// SASL XOAUTH2 against one of the two token sources above.
	MailboxAuthSMTPOAuth MailboxAuthMode = "smtp_oauth"
)

// MailboxAuthModes lists the modes in the order the settings form offers them.
func MailboxAuthModes() []MailboxAuthMode {
	return []MailboxAuthMode{MailboxAuthPassword, MailboxAuthGraph, MailboxAuthGmail, MailboxAuthSMTPOAuth}
}

// MailboxAuthLabel is the operator-facing name of a mode. It is the same phrase
// the settings form and the connector's Info line use, so an operator reading
// either sees one vocabulary.
func MailboxAuthLabel(m MailboxAuthMode) string {
	switch m {
	case MailboxAuthGraph:
		return "Microsoft 365"
	case MailboxAuthGmail:
		return "Google Workspace"
	case MailboxAuthSMTPOAuth:
		return "SMTP with OAuth"
	default:
		return "Password relay"
	}
}

// The two identity providers a token can come from. Both API modes imply one;
// the SMTP mode has to state it, because either provider can sit behind a plain
// SMTP endpoint.
const (
	MailboxProviderMicrosoft = "microsoft"
	MailboxProviderGoogle    = "google"
)

// authMode resolves the stored mode, defaulting to the password relay so a
// record written before this feature existed keeps its behaviour exactly.
func (e EmailConnectorConfig) authMode() MailboxAuthMode {
	switch MailboxAuthMode(strings.ToLower(strings.TrimSpace(string(e.AuthMode)))) {
	case MailboxAuthGraph:
		return MailboxAuthGraph
	case MailboxAuthGmail:
		return MailboxAuthGmail
	case MailboxAuthSMTPOAuth:
		return MailboxAuthSMTPOAuth
	default:
		return MailboxAuthPassword
	}
}

// tokenProvider names which identity provider mints this mailbox's bearer.
func (e EmailConnectorConfig) tokenProvider() string {
	switch e.authMode() {
	case MailboxAuthGraph:
		return MailboxProviderMicrosoft
	case MailboxAuthGmail:
		return MailboxProviderGoogle
	case MailboxAuthSMTPOAuth:
		return strings.ToLower(strings.TrimSpace(e.OAuthProvider))
	}
	return ""
}

// sender is the address the message claims to be from. The API modes send as
// the mailbox itself, so a blank From is not a gap there — it is the mailbox.
func (e EmailConnectorConfig) sender() string {
	if f := strings.TrimSpace(e.From); f != "" {
		return f
	}
	return strings.TrimSpace(e.Mailbox)
}

// smtpLogin is the identity XOAUTH2 announces. It is the mailbox, not a
// separate service account: XOAUTH2 authorizes a bearer FOR one mailbox.
func (e EmailConnectorConfig) smtpLogin() string {
	for _, v := range []string{e.User, e.Mailbox, e.From} {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// ── the pinned endpoints ────────────────────────────────────────────────────

// The hosts the mailbox transports may reach. A tenant configures WHICH mailbox,
// never which host: an operator-supplied Graph or token endpoint would be an
// invitation to point a credential at an attacker (research §5.5, CLAUDE.md §3).
const (
	entraLoginHost  = "login.microsoftonline.com"
	graphAPIHost    = "graph.microsoft.com"
	googleOAuthHost = "oauth2.googleapis.com"
	gmailAPIHost    = "gmail.googleapis.com"
)

// The scopes each mode asks for. Every one is the provider's own published
// value; none is derived from configuration.
const (
	// graphDefaultScope is the client-credentials scope: the app's own granted
	// application permissions, which must include Mail.Send.
	graphDefaultScope = "https://graph.microsoft.com/.default"
	// outlookSMTPScope is the Exchange Online SMTP scope for XOAUTH2.
	outlookSMTPScope = "https://outlook.office365.com/.default"
	// gmailSendScope is the least-privilege Gmail API scope: send, nothing else.
	gmailSendScope = "https://www.googleapis.com/auth/gmail.send"
	// gmailSMTPScope is what Google's SMTP endpoint requires for XOAUTH2.
	gmailSMTPScope = "https://mail.google.com/"
	// jwtBearerGrantType is RFC 7523's grant for a signed assertion.
	jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 -- RFC 7523's published grant-type URN, not a credential
)

// mailboxEndpoints are the service bases. Production uses defaults built from
// the pinned hosts above; tests substitute httptest bases through the
// in-package constructor, which is why they are a value and not a constant.
type mailboxEndpoints struct {
	EntraLogin  string // base, e.g. https://login.microsoftonline.com
	Graph       string // base, e.g. https://graph.microsoft.com/v1.0
	GoogleToken string // full token URL
	Gmail       string // base, e.g. https://gmail.googleapis.com/gmail/v1
}

func defaultMailboxEndpoints() mailboxEndpoints {
	return mailboxEndpoints{
		EntraLogin:  "https://" + entraLoginHost,
		Graph:       "https://" + graphAPIHost + "/v1.0",
		GoogleToken: "https://" + googleOAuthHost + "/token",
		Gmail:       "https://" + gmailAPIHost + "/gmail/v1",
	}
}

// mailboxHostAllowlist is the PINNED host set. validatePinnedURL is asserted
// against the defaults by a test, so a typo in a base can never ship.
func mailboxHostAllowlist() []string {
	return []string{entraLoginHost, graphAPIHost, googleOAuthHost, gmailAPIHost}
}

// Bounds every mailbox call (§9). One token mint or one sendMail is an
// interactive operation an operator is waiting on.
const (
	mailboxCallTimeout  = 30 * time.Second
	maxMailboxRespBytes = 64 << 10
	// maxMailboxTokenCache bounds the cache so a deployment with many tenants
	// cannot grow it without limit (§9: all queues are bounded).
	maxMailboxTokenCache = 256
)

// ── the token source ────────────────────────────────────────────────────────

type cachedMailboxToken struct {
	token   string
	expires time.Time
}

// mailboxTokens mints and caches bearers. One instance is shared by all tenants
// on a connector; see the isolation note at the top of the file.
type mailboxTokens struct {
	mu        sync.Mutex
	http      *http.Client
	endpoints mailboxEndpoints
	cache     map[string]cachedMailboxToken
}

func newMailboxTokens() *mailboxTokens {
	return &mailboxTokens{
		http:      safehttp.Client(mailboxCallTimeout),
		endpoints: defaultMailboxEndpoints(),
		cache:     map[string]cachedMailboxToken{},
	}
}

func (t *mailboxTokens) client() *http.Client {
	if t.http != nil {
		return t.http
	}
	return safehttp.Client(mailboxCallTimeout)
}

// mailboxTokenCacheKey identifies a credential WITHOUT carrying it: the secret
// and the private key contribute only a digest, so the key is safe to hold in
// memory beside the token and a rotated secret produces a different key.
func mailboxTokenCacheKey(e EmailConnectorConfig, provider, scope string) string {
	sum := sha256.Sum256([]byte(e.OAuthClientSecret + "\x00" + e.ServiceAccountKey))
	return strings.Join([]string{
		provider, e.EntraTenantID, e.OAuthClientID, e.ServiceAccountEmail,
		strings.ToLower(strings.TrimSpace(e.Mailbox)), scope,
		hex.EncodeToString(sum[:8]),
	}, "|")
}

// Token returns a bearer for one credential and scope, minting it when the
// cached one is inside a minute of expiry.
//
// The mint happens OUTSIDE the lock on purpose: holding it across a network call
// would serialize every tenant behind the slowest identity provider, and the
// worst a concurrent mint costs is one extra token, which both providers issue
// idempotently.
func (t *mailboxTokens) Token(ctx context.Context, e EmailConnectorConfig, scope string) (string, error) {
	provider := e.tokenProvider()
	key := mailboxTokenCacheKey(e, provider, scope)

	t.mu.Lock()
	if hit, ok := t.cache[key]; ok && time.Now().Before(hit.expires.Add(-time.Minute)) {
		t.mu.Unlock()
		return hit.token, nil
	}
	t.mu.Unlock()

	var (
		tok string
		ttl time.Duration
		err error
	)
	switch provider {
	case MailboxProviderMicrosoft:
		tok, ttl, err = t.entraToken(ctx, e, scope)
	case MailboxProviderGoogle:
		tok, ttl, err = t.googleToken(ctx, e, scope)
	default:
		return "", PermanentDeliveryError{fmt.Errorf("mailbox: %q is not a token provider (%s or %s)",
			Truncate(provider, 40), MailboxProviderMicrosoft, MailboxProviderGoogle)}
	}
	if err != nil {
		return "", err
	}
	t.store(key, tok, ttl)
	return tok, nil
}

// store caches one token and keeps the cache bounded: expired entries go first,
// and a cache still at its ceiling after that is dropped wholesale rather than
// grown. Losing a cached token costs one extra mint, never a wrong answer.
func (t *mailboxTokens) store(key, tok string, ttl time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.cache) >= maxMailboxTokenCache {
		now := time.Now()
		for k, v := range t.cache {
			if !now.Before(v.expires) {
				delete(t.cache, k)
			}
		}
		if len(t.cache) >= maxMailboxTokenCache {
			t.cache = map[string]cachedMailboxToken{}
		}
	}
	t.cache[key] = cachedMailboxToken{token: tok, expires: time.Now().Add(ttl)}
}

// entraToken runs the client-credentials grant against the tenant's own Entra
// token endpoint. Microsoft issues a 1 h token; expires_in is honoured.
func (t *mailboxTokens) entraToken(ctx context.Context, e EmailConnectorConfig, scope string) (string, time.Duration, error) {
	tenant := strings.TrimSpace(e.EntraTenantID)
	if tenant == "" || strings.TrimSpace(e.OAuthClientID) == "" || strings.TrimSpace(e.OAuthClientSecret) == "" {
		return "", 0, PermanentDeliveryError{errors.New(
			"microsoft 365: the directory (tenant) id, the application (client) id and the client secret are all required")}
	}
	endpoint := strings.TrimSuffix(t.endpoints.EntraLogin, "/") + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", strings.TrimSpace(e.OAuthClientID))
	form.Set("client_secret", e.OAuthClientSecret)
	form.Set("scope", scope)
	return t.postForm(ctx, "microsoft 365 token", endpoint, form)
}

// googleToken runs RFC 7523's JWT-bearer grant: the service account signs an
// assertion naming the mailbox it impersonates (that impersonation is exactly
// what domain-wide delegation authorizes) and Google returns an access token.
func (t *mailboxTokens) googleToken(ctx context.Context, e EmailConnectorConfig, scope string) (string, time.Duration, error) {
	assertion, err := googleAssertion(e, scope, t.endpoints.GoogleToken, time.Now().UTC())
	if err != nil {
		return "", 0, err
	}
	form := url.Values{}
	form.Set("grant_type", jwtBearerGrantType)
	form.Set("assertion", assertion)
	return t.postForm(ctx, "google workspace token", t.endpoints.GoogleToken, form)
}

// postForm is the one token exchange both providers use. The request body
// carries a client secret or a signed assertion, so no error it can return ever
// quotes what was sent (§8).
func (t *mailboxTokens) postForm(ctx context.Context, op, endpoint string, form url.Values) (string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, mailboxCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, PermanentDeliveryError{fmt.Errorf("%s: the token endpoint is not a usable URL", op)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := t.client().Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%s: the identity provider did not answer", op)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on a close failure
	// raw is only ever a diagnostic snippet; the STATUS below is what decides
	// the outcome, so a short read cannot change it — best-effort by design.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxMailboxRespBytes))
	if cerr := classifyMailboxStatus(op, resp, raw); cerr != nil {
		return "", 0, cerr
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &out) != nil || out.AccessToken == "" {
		return "", 0, PermanentDeliveryError{fmt.Errorf("%s: the response carried no access_token", op)}
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour // both providers document one hour
	}
	return out.AccessToken, ttl, nil
}

// ── the signed assertion ────────────────────────────────────────────────────

// googleAssertionTTL is the signed window. Google refuses an assertion more than
// an hour out; a short window bounds what a leaked one is worth.
const googleAssertionTTL = 30 * time.Minute

// googleAssertion builds and signs the RS256 JWT. json.Marshal of a map emits
// its keys sorted, so the same inputs always produce the same bytes — which is
// what lets a test assert the claim set exactly.
func googleAssertion(e EmailConnectorConfig, scope, audience string, now time.Time) (string, error) {
	issuer := strings.TrimSpace(e.ServiceAccountEmail)
	mailbox := strings.TrimSpace(e.Mailbox)
	if issuer == "" || mailbox == "" {
		return "", PermanentDeliveryError{errors.New(
			"google workspace: the service-account address and the mailbox it sends as are both required")}
	}
	key, err := parseRSAPrivateKey(e.ServiceAccountKey)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("google workspace: assertion header: %w", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss":   issuer,
		"sub":   mailbox, // domain-wide delegation: send AS this mailbox
		"scope": scope,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(googleAssertionTTL).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("google workspace: assertion claims: %w", err)
	}
	signing := b64url(header) + "." + b64url(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		// The key is the input; never let the error carry anything derived from it.
		return "", PermanentDeliveryError{errors.New("google workspace: the service-account key could not sign the assertion")}
	}
	return signing + "." + b64url(sig), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// parseRSAPrivateKey reads the PEM Google hands out in the service-account JSON.
// Both PKCS#8 ("PRIVATE KEY", what Google issues) and PKCS#1 are accepted so an
// operator who converted the key with openssl is not stuck.
func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, PermanentDeliveryError{errors.New(
			"google workspace: the service-account key is not a PEM private key — paste the private_key value from the service-account JSON, newlines and all")}
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, PermanentDeliveryError{errors.New("google workspace: the service-account key could not be parsed")}
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, PermanentDeliveryError{errors.New("google workspace: the service-account key could not be parsed")}
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, PermanentDeliveryError{errors.New("google workspace: the service-account key must be RSA — that is what Google issues")}
		}
		return key, nil
	}
	return nil, PermanentDeliveryError{fmt.Errorf("google workspace: unexpected PEM block %q in the service-account key", Truncate(block.Type, 40))}
}

// ── SASL XOAUTH2 ────────────────────────────────────────────────────────────

// xoauth2Auth is the SASL mechanism Microsoft and Google accept on SMTP now that
// basic AUTH is gone. The stdlib ships PLAIN and CRAM-MD5 only; the mechanism is
// one formatted string, so it lives here rather than becoming a dependency.
type xoauth2Auth struct{ user, token string }

// Start refuses an unencrypted connection outright. The initial response carries
// a bearer in the clear, which is strictly worse than a password would be — and
// this transport already requires TLS for the bundle itself.
func (a xoauth2Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if server == nil || !server.TLS {
		return "", nil, PermanentDeliveryError{errors.New(
			"smtp: XOAUTH2 carries a bearer token and is never offered on an unencrypted connection")}
	}
	if strings.TrimSpace(a.user) == "" || strings.TrimSpace(a.token) == "" {
		return "", nil, PermanentDeliveryError{errors.New("smtp: XOAUTH2 needs both the mailbox and a token")}
	}
	return "XOAUTH2", []byte("user=" + a.user + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}

// Next answers the failure challenge. On a rejected token the server sends a
// base64 JSON error and waits for one empty line before it will report 535, so
// an empty response is how the protocol asks for the real reply.
func (a xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return []byte{}, nil
	}
	return nil, nil
}

var _ smtp.Auth = xoauth2Auth{}

// ── provider error classification ───────────────────────────────────────────

// classifyMailboxStatus maps one HTTP answer onto this package's typed outcomes:
// 429 is a rate limit, a 5xx that named a Retry-After is a retryable wait of
// that length, any other 5xx is retryable on our own curve, and every remaining
// non-2xx is permanent. The provider's own words are quoted and truncated; the
// request body never is.
func classifyMailboxStatus(op string, resp *http.Response, body []byte) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return RateLimitedError{After: retryAfterOr(resp, 2*time.Second)}
	case resp.StatusCode >= 500:
		err := fmt.Errorf("%s: the provider replied %d: %s", op, resp.StatusCode, Truncate(mailboxErrorText(body), 200))
		if after := retryAfterOr(resp, 0); after > 0 {
			return RetryAfterError{Err: err, After: after}
		}
		return err
	default:
		return PermanentDeliveryError{fmt.Errorf("%s: the provider refused with %d: %s",
			op, resp.StatusCode, Truncate(mailboxErrorText(body), 200))}
	}
}

// mailboxErrorText lifts the human sentence out of the two error envelopes these
// APIs use, and falls back to the raw snippet rather than inventing a message.
func mailboxErrorText(body []byte) string {
	var graphish struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &graphish) == nil && strings.TrimSpace(graphish.Error.Message) != "" {
		if graphish.Error.Code != "" {
			return graphish.Error.Code + ": " + graphish.Error.Message
		}
		return graphish.Error.Message
	}
	var oauthish struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &oauthish) == nil && strings.TrimSpace(oauthish.Error) != "" {
		if oauthish.Description != "" {
			return oauthish.Error + ": " + oauthish.Description
		}
		return oauthish.Error
	}
	return strings.TrimSpace(string(body))
}
