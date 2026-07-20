package cloudconn

// exchange_azure.go — LIVE Azure Entra token acquisition, stdlib-only.
//
//   - workload_identity_federation → OAuth2 client-credentials grant with a
//     client_assertion (Correlix's own signed workload OIDC JWT presented to
//     the customer app registration's federated credential). No stored secret.
//   - client_secret (legacy) → client-credentials grant with the Vault-
//     decrypted client secret.
//   - certificate → client-credentials grant with a client_assertion signed by
//     the customer app certificate's private key (Vault-stored PEM bundle,
//     decrypted only at exchange time; x5t thumbprint header — see
//     exchange_azure_cert.go).
//
// Endpoint: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
// (form-encoded POST). Scope defaults to ARM (.default) — the audience the
// azure-observer capability pack reads through.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	azureLoginBase            = "https://login.microsoftonline.com"
	azureDefaultScope         = "https://management.azure.com/.default"
	azureDefaultFederationAud = "api://AzureADTokenExchange"
	azureClientAssertionType  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// AzureEntraExchanger implements TokenExchanger against the Entra (Azure AD)
// v2.0 token endpoint. All fields injectable; zero values use production
// endpoints, the default scope and the env-backed assertion source.
type AzureEntraExchanger struct {
	Client     *http.Client
	BaseURL    string // override for tests (httptest server URL)
	Scope      string // OAuth scope; default ARM .default
	Assertions WorkloadAssertionSource
	Now        func() time.Time
}

// NewAzureEntraExchanger returns the production exchanger.
func NewAzureEntraExchanger() *AzureEntraExchanger {
	return &AzureEntraExchanger{
		Client:     newExchangeHTTPClient(),
		Assertions: EnvWorkloadAssertionSource{},
		Now:        func() time.Time { return time.Now().UTC() },
	}
}

// Exchange acquires a short-lived Entra access token for the connector's app
// identity via the client-credentials grant.
func (x *AzureEntraExchanger) Exchange(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	tenant := strings.TrimSpace(req.Identity.AzureTenantID)
	clientID := strings.TrimSpace(req.Identity.ClientID)
	if tenant == "" || clientID == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "azure tenant id and client id are required"}
	}
	scope := x.Scope
	if scope == "" {
		scope = azureDefaultScope
	}

	base := x.BaseURL
	if base == "" {
		base = azureLoginBase
	}
	endpoint := base + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	now := time.Now().UTC()
	if x.Now != nil {
		now = x.Now().UTC()
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("scope", scope)

	switch req.Identity.Method {
	case AuthMethodWorkloadFederation:
		if x.Assertions == nil {
			return ScopedToken{}, ErrWorkloadAssertionMissing
		}
		audience := strings.TrimSpace(req.Identity.Audience)
		if audience == "" {
			audience = azureDefaultFederationAud
		}
		assertion, err := x.Assertions.Assertion(ctx, audience, WorkloadSubject(req.Identity))
		if err != nil {
			return ScopedToken{}, err
		}
		form.Set("client_assertion_type", azureClientAssertionType)
		form.Set("client_assertion", assertion)
	case AuthMethodClientSecret:
		if strings.TrimSpace(req.LegacySecret) == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "client secret material missing"}
		}
		form.Set("client_secret", req.LegacySecret)
	case AuthMethodCertificate:
		if strings.TrimSpace(req.LegacySecret) == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate credential material missing — upload the certificate PEM bundle"}
		}
		material, cerr := parseAzureCertBundle(req.LegacySecret, now)
		if cerr != nil {
			return ScopedToken{}, cerr
		}
		if !azureThumbprintMatches(req.Identity.CertThumbprint, material) {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "uploaded certificate does not match the configured thumbprint"}
		}
		assertion, aerr := azureCertClientAssertion(material, clientID, endpoint, now)
		if aerr != nil {
			return ScopedToken{}, aerr
		}
		form.Set("client_assertion_type", azureClientAssertionType)
		form.Set("client_assertion", assertion)
	default:
		return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "auth method " + string(req.Identity.Method) + " has no Azure exchange path"}
	}

	payload := form.Encode()

	status, body, attempts, err := doExchangeHTTP(ctx, x.Client, ProviderAzure, func() (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
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
		return ScopedToken{}, azureTokenError(status, body, attempts)
	}
	return parseOAuthTokenResponse(ProviderAzure, body, now, attempts)
}

// oauthTokenResponse is the standard OAuth2 token-endpoint success shape
// (shared by Entra and Google endpoints).
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// parseOAuthTokenResponse parses a standard OAuth2 success body into a
// ScopedToken. Never logs any part of the response.
func parseOAuthTokenResponse(p Provider, body []byte, now time.Time, attempts int) (ScopedToken, error) {
	var tr oauthTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return ScopedToken{}, &ExchangeError{Provider: p, Code: "malformed_response", Msg: "token response is not parseable JSON", Attempts: attempts}
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return ScopedToken{}, &ExchangeError{Provider: p, Code: "malformed_response", Msg: "token response missing access_token/expires_in", Attempts: attempts}
	}
	tokenType := tr.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return ScopedToken{
		Provider:  p,
		Value:     tr.AccessToken,
		TokenType: tokenType,
		Expiry:    now.Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

// oauthErrorResponse is the standard OAuth2 error shape.
type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// azureTokenError maps a non-200 Entra response to a sanitized ExchangeError.
func azureTokenError(status int, body []byte, attempts int) error {
	var er oauthErrorResponse
	_ = json.Unmarshal(body, &er) // best-effort: fall through to status mapping
	code := "provider_error"
	switch er.Error {
	case "invalid_client", "unauthorized_client", "invalid_grant", "access_denied":
		code = "denied"
	case "invalid_request", "invalid_scope":
		code = "request_invalid"
	case "temporarily_unavailable":
		code = "throttled"
	default:
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			code = "denied"
		}
	}
	msg := er.Error
	if er.ErrorDescription != "" {
		msg += ": " + truncateForError(er.ErrorDescription)
	}
	if msg == "" {
		msg = "token endpoint returned status " + strconv.Itoa(status)
	}
	return &ExchangeError{Provider: ProviderAzure, Code: code, HTTPStatus: status, Msg: msg, Attempts: attempts}
}
