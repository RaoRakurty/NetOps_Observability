package cloudconn

// exchange_azure_test.go — table-driven tests for the live Azure Entra token
// acquisition against httptest fixtures: client-secret happy path, WIF
// client_assertion happy path, denied / malformed / throttled surfaces, and
// the certificate + missing-assertion deferrals.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticAssertion struct {
	jwt          string
	lastAudience string
}

func (s *staticAssertion) Assertion(_ context.Context, audience string) (string, error) {
	s.lastAudience = audience
	return s.jwt, nil
}

type missingAssertion struct{}

func (missingAssertion) Assertion(context.Context, string) (string, error) {
	return "", ErrWorkloadAssertionMissing
}

func azureSecretRequest() ExchangeRequest {
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider: ProviderAzure, Method: AuthMethodClientSecret,
			ConnectorID: "ccn_az1", AzureTenantID: "11111111-2222-3333-4444-555555555555",
			ClientID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", LegacySecretRef: "csr_az",
		},
		LegacySecret: "azure-client-secret-value",
		MaxLifetime:  time.Hour,
	}
}

func TestAzureExchangeClientSecretHappyPath(t *testing.T) {
	var gotPath string
	var gotForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"entra-access-token"}`)
	}))
	defer ts.Close()

	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL, Assertions: missingAssertion{}}
	tok, err := x.Exchange(context.Background(), azureSecretRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotPath != "/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token" {
		t.Errorf("token endpoint path = %q", gotPath)
	}
	if gotForm.Get("grant_type") != "client_credentials" ||
		gotForm.Get("client_id") != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ||
		gotForm.Get("client_secret") != "azure-client-secret-value" {
		t.Errorf("client-credentials form wrong: %v", gotForm.Encode()[:0])
	}
	if gotForm.Get("scope") != azureDefaultScope {
		t.Errorf("scope = %q want ARM default", gotForm.Get("scope"))
	}
	if tok.Value != "entra-access-token" || tok.TokenType != "Bearer" || tok.Provider != ProviderAzure {
		t.Errorf("token fields wrong: type=%q provider=%q", tok.TokenType, tok.Provider)
	}
	if until := time.Until(tok.Expiry); until < 59*time.Minute || until > 60*time.Minute {
		t.Errorf("expiry not ~3599s out: %v", until)
	}
}

func TestAzureExchangeWorkloadFederationAssertion(t *testing.T) {
	var gotForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"wif-access-token"}`)
	}))
	defer ts.Close()

	src := &staticAssertion{jwt: "correlix-workload-oidc-jwt"}
	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL, Assertions: src}
	req := azureSecretRequest()
	req.Identity.Method = AuthMethodWorkloadFederation
	req.Identity.Issuer = "https://issuer.correlix.example"
	req.Identity.FederatedSubject = "correlix:connector:ccn_az1"
	req.Identity.LegacySecretRef = ""
	req.LegacySecret = ""

	tok, err := x.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotForm.Get("client_assertion_type") != azureClientAssertionType {
		t.Errorf("client_assertion_type = %q", gotForm.Get("client_assertion_type"))
	}
	if gotForm.Get("client_assertion") != "correlix-workload-oidc-jwt" {
		t.Error("client_assertion is not the workload OIDC JWT")
	}
	if gotForm.Get("client_secret") != "" {
		t.Error("WIF exchange must not carry a client_secret")
	}
	if src.lastAudience != azureDefaultFederationAud {
		t.Errorf("assertion audience = %q want Entra default", src.lastAudience)
	}
	if tok.Value != "wif-access-token" {
		t.Error("token value wrong")
	}
}

func TestAzureExchangeErrorSurfaces(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{
			name:     "denied invalid client",
			status:   401,
			body:     `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`,
			wantCode: "denied",
		},
		{
			name:     "denied expired secret",
			status:   400,
			body:     `{"error":"invalid_client","error_description":"AADSTS7000222: The provided client secret keys are expired."}`,
			wantCode: "denied",
		},
		{
			name:     "invalid scope",
			status:   400,
			body:     `{"error":"invalid_scope","error_description":"scope is malformed"}`,
			wantCode: "request_invalid",
		},
		{
			name:     "malformed json",
			status:   200,
			body:     `<html>not json</html>`,
			wantCode: "malformed_response",
		},
		{
			name:     "missing access token",
			status:   200,
			body:     `{"token_type":"Bearer","expires_in":3600}`,
			wantCode: "malformed_response",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL}
			_, err := x.Exchange(context.Background(), azureSecretRequest())
			var xe *ExchangeError
			if !errors.As(err, &xe) {
				t.Fatalf("want *ExchangeError, got %v", err)
			}
			if xe.Code != tc.wantCode {
				t.Fatalf("code = %q want %q (err: %v)", xe.Code, tc.wantCode, err)
			}
			if strings.Contains(err.Error(), "azure-client-secret-value") {
				t.Fatal("error text leaked the client secret")
			}
		})
	}
}

func TestAzureExchangeThrottledRetries(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		_, _ = io.WriteString(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"after-retry"}`)
	}))
	defer ts.Close()
	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL}
	tok, err := x.Exchange(context.Background(), azureSecretRequest())
	if err != nil {
		t.Fatalf("5xx should retry then succeed: %v", err)
	}
	if calls.Load() != 2 || tok.Value != "after-retry" {
		t.Fatalf("calls=%d token=%q", calls.Load(), tok.Value)
	}
}

func TestAzureExchangeDeferrals(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("deferral paths must not reach the wire")
		w.WriteHeader(500)
	}))
	defer ts.Close()

	// Certificate without uploaded material → request_invalid, never the wire
	// (the live cert path itself is covered in exchange_azure_cert_test.go).
	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL}
	req := azureSecretRequest()
	req.Identity.Method = AuthMethodCertificate
	req.Identity.CertThumbprint = "AABBCC"
	req.LegacySecret = ""
	var xe *ExchangeError
	if _, err := x.Exchange(context.Background(), req); !errors.As(err, &xe) || xe.Code != "request_invalid" {
		t.Fatalf("certificate without material: want request_invalid, got %v", err)
	}

	// WIF without an assertion source → assertion-missing deferral.
	x2 := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL, Assertions: missingAssertion{}}
	req2 := azureSecretRequest()
	req2.Identity.Method = AuthMethodWorkloadFederation
	if _, err := x2.Exchange(context.Background(), req2); !errors.Is(err, ErrWorkloadAssertionMissing) {
		t.Fatalf("WIF without assertion: want ErrWorkloadAssertionMissing, got %v", err)
	}
}
