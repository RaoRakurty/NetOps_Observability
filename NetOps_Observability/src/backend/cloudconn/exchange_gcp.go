package cloudconn

// exchange_gcp.go — LIVE GCP credential exchange, stdlib-only.
//
//   - static_key (legacy SA JSON key) → self-signed RS256 JWT (crypto/rsa +
//     crypto/sha256) presented to the OAuth2 assertion grant at
//     https://oauth2.googleapis.com/token → short-lived access token.
//   - workload_identity_federation → STS token exchange at
//     https://sts.googleapis.com/v1/token (Correlix's workload OIDC assertion
//     as subject_token) → federated token; when the identity names an observer
//     service account, followed by iamcredentials generateAccessToken
//     impersonation → short-lived SA access token.

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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	gcpTokenEndpoint       = "https://oauth2.googleapis.com/token" // #nosec G101 -- endpoint URL, not a credential
	gcpSTSEndpoint         = "https://sts.googleapis.com/v1/token" // #nosec G101 -- endpoint URL, not a credential
	gcpIAMCredentialsBase  = "https://iamcredentials.googleapis.com"
	gcpReadOnlyScope       = "https://www.googleapis.com/auth/cloud-platform.read-only"
	gcpJWTBearerGrant      = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	gcpTokenExchangeGrant  = "urn:ietf:params:oauth:grant-type:token-exchange"
	gcpAccessTokenType     = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- RFC 8693 type URN
	gcpSubjectJWTTokenType = "urn:ietf:params:oauth:token-type:jwt"          // #nosec G101 -- RFC 8693 type URN
)

// GCPSTSExchanger implements TokenExchanger for GCP. All fields injectable;
// zero values use production endpoints and the env-backed assertion source.
type GCPSTSExchanger struct {
	Client       *http.Client
	TokenURL     string // override for tests
	STSURL       string // override for tests
	IAMCredsBase string // override for tests
	Scope        string // OAuth scope; default read-only cloud-platform
	Assertions   WorkloadAssertionSource
	Now          func() time.Time
}

// NewGCPSTSExchanger returns the production exchanger.
func NewGCPSTSExchanger() *GCPSTSExchanger {
	return &GCPSTSExchanger{
		Client:     newExchangeHTTPClient(),
		Assertions: EnvWorkloadAssertionSource{},
		Now:        func() time.Time { return time.Now().UTC() },
	}
}

func (x *GCPSTSExchanger) now() time.Time {
	if x.Now != nil {
		return x.Now().UTC()
	}
	return time.Now().UTC()
}

func (x *GCPSTSExchanger) scope() string {
	if x.Scope != "" {
		return x.Scope
	}
	return gcpReadOnlyScope
}

// Exchange mints a short-lived GCP access token for the request identity.
func (x *GCPSTSExchanger) Exchange(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	switch req.Identity.Method {
	case AuthMethodStaticKey:
		return x.exchangeSAKey(ctx, req)
	case AuthMethodWorkloadFederation:
		return x.exchangeWIF(ctx, req)
	default:
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "auth method " + string(req.Identity.Method) + " has no GCP exchange path"}
	}
}

// gcpSAKey is the subset of a service-account JSON key the exchange needs.
// The struct is never logged or serialized.
type gcpSAKey struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
}

// exchangeSAKey: legacy SA JSON key → self-signed RS256 JWT → assertion grant.
func (x *GCPSTSExchanger) exchangeSAKey(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	if strings.TrimSpace(req.LegacySecret) == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "service-account key material missing"}
	}
	var key gcpSAKey
	if err := json.Unmarshal([]byte(req.LegacySecret), &key); err != nil || key.ClientEmail == "" || key.PrivateKey == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "stored secret is not a service-account JSON key"}
	}
	priv, err := parseRSAPrivateKeyPEM(key.PrivateKey)
	if err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "service-account private key unparseable"}
	}

	tokenURL := x.TokenURL
	if tokenURL == "" {
		tokenURL = gcpTokenEndpoint
	}
	now := x.now()
	// Google caps assertion validity at 1h; the broker caps overall anyway.
	lifetime := clampLifetime(req.MaxLifetime, time.Hour, time.Minute, time.Hour)
	claims := map[string]any{
		"iss":   key.ClientEmail,
		"scope": x.scope(),
		"aud":   gcpTokenEndpoint, // audience is the GOOGLE token endpoint even when x.TokenURL is a test server
		"iat":   now.Unix(),
		"exp":   now.Add(lifetime).Unix(),
	}
	assertion, err := signRS256JWT(priv, key.PrivateKeyID, claims)
	if err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "signing the service-account assertion failed"}
	}

	form := url.Values{}
	form.Set("grant_type", gcpJWTBearerGrant)
	form.Set("assertion", assertion)
	payload := form.Encode()

	status, body, attempts, err := doExchangeHTTP(ctx, x.Client, ProviderGCP, func() (*http.Request, error) {
		hreq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(payload))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return hreq, nil
	})
	if err != nil {
		return ScopedToken{}, err
	}
	if status != http.StatusOK {
		return ScopedToken{}, gcpTokenError(status, body, attempts)
	}
	return parseOAuthTokenResponse(ProviderGCP, body, x.now(), attempts)
}

// exchangeWIF: workload federation → STS token exchange (+ optional SA
// impersonation via generateAccessToken).
func (x *GCPSTSExchanger) exchangeWIF(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	id := req.Identity
	if strings.TrimSpace(id.ProjectNumber) == "" || strings.TrimSpace(id.WorkloadPool) == "" || strings.TrimSpace(id.WorkloadProvider) == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "workload federation needs project number + pool + provider"}
	}
	if x.Assertions == nil {
		return ScopedToken{}, ErrWorkloadAssertionMissing
	}
	audience := "//iam.googleapis.com/projects/" + id.ProjectNumber +
		"/locations/global/workloadIdentityPools/" + id.WorkloadPool +
		"/providers/" + id.WorkloadProvider
	subjectToken, err := x.Assertions.Assertion(ctx, audience)
	if err != nil {
		return ScopedToken{}, err
	}

	stsURL := x.STSURL
	if stsURL == "" {
		stsURL = gcpSTSEndpoint
	}
	form := url.Values{}
	form.Set("grant_type", gcpTokenExchangeGrant)
	form.Set("audience", audience)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", gcpSubjectJWTTokenType)
	form.Set("requested_token_type", gcpAccessTokenType)
	form.Set("scope", "https://www.googleapis.com/auth/cloud-platform")
	payload := form.Encode()

	status, body, attempts, err := doExchangeHTTP(ctx, x.Client, ProviderGCP, func() (*http.Request, error) {
		hreq, err := http.NewRequest(http.MethodPost, stsURL, strings.NewReader(payload))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return hreq, nil
	})
	if err != nil {
		return ScopedToken{}, err
	}
	if status != http.StatusOK {
		return ScopedToken{}, gcpTokenError(status, body, attempts)
	}
	fedTok, err := parseOAuthTokenResponse(ProviderGCP, body, x.now(), attempts)
	if err != nil {
		return ScopedToken{}, err
	}
	sa := strings.TrimSpace(id.ServiceAccount)
	if sa == "" {
		// Direct federated access (no impersonation): the federated token itself
		// carries the pool's IAM bindings.
		return fedTok, nil
	}
	return x.impersonate(ctx, sa, fedTok.Value, req.MaxLifetime)
}

// impersonate exchanges a federated token for a short-lived observer-SA token
// via iamcredentials.googleapis.com generateAccessToken.
func (x *GCPSTSExchanger) impersonate(ctx context.Context, serviceAccount, federatedToken string, maxLifetime time.Duration) (ScopedToken, error) {
	base := x.IAMCredsBase
	if base == "" {
		base = gcpIAMCredentialsBase
	}
	lifetime := clampLifetime(maxLifetime, time.Hour, time.Minute, time.Hour)
	reqBody, err := json.Marshal(map[string]any{
		"scope":    []string{x.scope()},
		"lifetime": strconv.Itoa(int(lifetime/time.Second)) + "s",
	})
	if err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "impersonation request unserializable"}
	}
	endpoint := base + "/v1/projects/-/serviceAccounts/" + url.PathEscape(serviceAccount) + ":generateAccessToken"

	status, body, attempts, err := doExchangeHTTP(ctx, x.Client, ProviderGCP, func() (*http.Request, error) {
		hreq, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(reqBody)))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/json")
		hreq.Header.Set("Authorization", "Bearer "+federatedToken)
		return hreq, nil
	})
	if err != nil {
		return ScopedToken{}, err
	}
	if status != http.StatusOK {
		return ScopedToken{}, gcpTokenError(status, body, attempts)
	}
	var resp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.AccessToken == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "malformed_response", Msg: "generateAccessToken response missing accessToken", Attempts: attempts}
	}
	expiry, err := time.Parse(time.RFC3339, resp.ExpireTime)
	if err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "malformed_response", Msg: "generateAccessToken expireTime unparseable", Attempts: attempts}
	}
	return ScopedToken{Provider: ProviderGCP, Value: resp.AccessToken, TokenType: "Bearer", Expiry: expiry.UTC()}, nil
}

// gcpTokenError maps a non-200 Google token/STS/IAM response to a sanitized
// ExchangeError. Handles both the OAuth error shape and the Google RPC shape.
func gcpTokenError(status int, body []byte, attempts int) error {
	var er oauthErrorResponse
	_ = json.Unmarshal(body, &er) // best-effort
	code := "provider_error"
	msg := er.Error
	if er.ErrorDescription != "" {
		msg += ": " + truncateForError(er.ErrorDescription)
	}
	if er.Error == "" {
		var rpc struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &rpc)
		msg = rpc.Error.Status
		if rpc.Error.Message != "" {
			msg += ": " + truncateForError(rpc.Error.Message)
		}
		if rpc.Error.Status == "PERMISSION_DENIED" || rpc.Error.Status == "UNAUTHENTICATED" {
			code = "denied"
		}
		if rpc.Error.Status == "RESOURCE_EXHAUSTED" {
			code = "throttled"
		}
	}
	switch er.Error {
	case "invalid_grant", "unauthorized_client", "access_denied", "invalid_client":
		code = "denied"
	case "invalid_request", "invalid_scope", "invalid_target":
		code = "request_invalid"
	}
	if code == "provider_error" && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		code = "denied"
	}
	if strings.TrimSpace(msg) == "" || msg == ":" {
		msg = "token endpoint returned status " + strconv.Itoa(status)
	}
	return &ExchangeError{Provider: ProviderGCP, Code: code, HTTPStatus: status, Msg: msg, Attempts: attempts}
}

// ── RS256 JWT minting (stdlib crypto) ─────────────────────────────────────────

// parseRSAPrivateKeyPEM parses a PKCS#8 or PKCS#1 RSA private key PEM block.
func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, &ContractError{Code: "pem_invalid", Msg: "no PEM block found"}
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, &ContractError{Code: "key_not_rsa", Msg: "private key is not RSA"}
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// signRS256JWT mints a compact JWS (RS256) over the given claims. kid is
// optional. The signature is PKCS#1 v1.5 over SHA-256 per RFC 7518 §3.3.
func signRS256JWT(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
