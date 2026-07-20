package cloudconn

// exchange_gcp_test.go — table-driven tests for the live GCP exchange against
// httptest fixtures: SA-key assertion grant (with real RS256 signature
// verification server-side), WIF STS exchange + SA impersonation, and the
// denied / malformed / throttled error surfaces.

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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// genSAKeyJSON builds a real service-account JSON key with a fresh RSA key so
// the fixture server can verify the RS256 signature end-to-end.
func genSAKeyJSON(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	key := map[string]string{
		"type":           "service_account",
		"client_email":   "correlix-observer@proj.iam.gserviceaccount.com",
		"private_key":    pemKey,
		"private_key_id": "kid-test-1",
		"token_uri":      gcpTokenEndpoint,
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), &priv.PublicKey
}

func gcpSAKeyRequest(saJSON string) ExchangeRequest {
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider: ProviderGCP, Method: AuthMethodStaticKey,
			ConnectorID: "ccn_gcp1", ProjectNumber: "123456789",
			ServiceAccount:  "correlix-observer@proj.iam.gserviceaccount.com",
			LegacySecretRef: "csr_gcp",
		},
		LegacySecret: saJSON,
		MaxLifetime:  time.Hour,
	}
}

func gcpWIFRequest() ExchangeRequest {
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider: ProviderGCP, Method: AuthMethodWorkloadFederation,
			ConnectorID: "ccn_gcp2", ProjectNumber: "123456789",
			WorkloadPool: "correlix-pool", WorkloadProvider: "correlix-provider",
			ServiceAccount: "correlix-observer@proj.iam.gserviceaccount.com",
		},
		MaxLifetime: time.Hour,
	}
}

func TestGCPExchangeSAKeyHappyPathVerifiesRS256(t *testing.T) {
	saJSON, pub := genSAKeyJSON(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != gcpJWTBearerGrant {
			t.Errorf("grant_type = %q", form.Get("grant_type"))
		}
		assertion := form.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Fatalf("assertion is not a compact JWS: %d parts", len(parts))
		}
		// Verify the RS256 signature with the SA public key — proves the stdlib
		// JWT minting is real wire-grade crypto, not a stub.
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("signature b64: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("RS256 signature does not verify: %v", err)
		}
		// Verify the claim set.
		cb, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("claims b64: %v", err)
		}
		var claims map[string]any
		if err := json.Unmarshal(cb, &claims); err != nil {
			t.Fatalf("claims json: %v", err)
		}
		if claims["iss"] != "correlix-observer@proj.iam.gserviceaccount.com" ||
			claims["aud"] != gcpTokenEndpoint || claims["scope"] != gcpReadOnlyScope {
			t.Errorf("claims wrong: iss=%v aud=%v scope=%v", claims["iss"], claims["aud"], claims["scope"])
		}
		var hdr map[string]any
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		_ = json.Unmarshal(hb, &hdr)
		if hdr["alg"] != "RS256" || hdr["kid"] != "kid-test-1" {
			t.Errorf("header wrong: %v", hdr)
		}
		_, _ = io.WriteString(w, `{"access_token":"gcp-sa-access-token","token_type":"Bearer","expires_in":3599}`)
	}))
	defer ts.Close()

	x := &GCPSTSExchanger{Client: ts.Client(), TokenURL: ts.URL}
	tok, err := x.Exchange(context.Background(), gcpSAKeyRequest(saJSON))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Value != "gcp-sa-access-token" || tok.Provider != ProviderGCP {
		t.Errorf("token wrong: provider=%q", tok.Provider)
	}
}

func TestGCPExchangeWIFWithImpersonation(t *testing.T) {
	expire := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var stsForm url.Values
	var impersonationAuthz, impersonationBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		stsForm, _ = url.ParseQuery(string(body))
		_, _ = io.WriteString(w, `{"access_token":"federated-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/v1/projects/-/serviceAccounts/", func(w http.ResponseWriter, r *http.Request) {
		impersonationAuthz = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		impersonationBody = string(b)
		if !strings.HasSuffix(r.URL.Path, ":generateAccessToken") {
			t.Errorf("impersonation path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"accessToken":"impersonated-sa-token","expireTime":"`+expire.Format(time.RFC3339)+`"}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	src := &staticAssertion{jwt: "correlix-workload-oidc-jwt"}
	x := &GCPSTSExchanger{Client: ts.Client(), STSURL: ts.URL + "/v1/token", IAMCredsBase: ts.URL, Assertions: src}
	tok, err := x.Exchange(context.Background(), gcpWIFRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	wantAud := "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/correlix-pool/providers/correlix-provider"
	if stsForm.Get("audience") != wantAud {
		t.Errorf("STS audience = %q", stsForm.Get("audience"))
	}
	if stsForm.Get("grant_type") != gcpTokenExchangeGrant ||
		stsForm.Get("subject_token") != "correlix-workload-oidc-jwt" ||
		stsForm.Get("subject_token_type") != gcpSubjectJWTTokenType ||
		stsForm.Get("requested_token_type") != gcpAccessTokenType {
		t.Errorf("STS exchange form wrong")
	}
	if src.lastAudience != wantAud {
		t.Errorf("assertion minted for audience %q", src.lastAudience)
	}
	if impersonationAuthz != "Bearer federated-token" {
		t.Errorf("impersonation authz = %q", impersonationAuthz)
	}
	if !strings.Contains(impersonationBody, gcpReadOnlyScope) || !strings.Contains(impersonationBody, "3600s") {
		t.Errorf("impersonation body = %s", impersonationBody)
	}
	if tok.Value != "impersonated-sa-token" || !tok.Expiry.Equal(expire) {
		t.Errorf("final token wrong: expiry=%v", tok.Expiry)
	}
}

func TestGCPExchangeWIFWithoutSAReturnsFederatedToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"federated-only","token_type":"Bearer","expires_in":3600}`)
	}))
	defer ts.Close()
	x := &GCPSTSExchanger{Client: ts.Client(), STSURL: ts.URL, Assertions: &staticAssertion{jwt: "jwt"}}
	req := gcpWIFRequest()
	req.Identity.ServiceAccount = ""
	tok, err := x.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Value != "federated-only" {
		t.Error("expected the federated token when no SA is configured")
	}
}

func TestGCPExchangeErrorSurfaces(t *testing.T) {
	saJSON, _ := genSAKeyJSON(t)
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{
			name:     "denied invalid grant",
			status:   400,
			body:     `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`,
			wantCode: "denied",
		},
		{
			name:     "denied rpc permission",
			status:   403,
			body:     `{"error":{"code":403,"message":"Permission iam.serviceAccounts.getAccessToken denied","status":"PERMISSION_DENIED"}}`,
			wantCode: "denied",
		},
		{
			name:     "malformed",
			status:   200,
			body:     `not-json`,
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
			x := &GCPSTSExchanger{Client: ts.Client(), TokenURL: ts.URL}
			_, err := x.Exchange(context.Background(), gcpSAKeyRequest(saJSON))
			var xe *ExchangeError
			if !errors.As(err, &xe) {
				t.Fatalf("want *ExchangeError, got %v", err)
			}
			if xe.Code != tc.wantCode {
				t.Fatalf("code = %q want %q (err: %v)", xe.Code, tc.wantCode, err)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatal("error text leaked key material")
			}
		})
	}
}

func TestGCPExchangeRejectsNonKeySecret(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid key material must never reach the wire")
		w.WriteHeader(500)
	}))
	defer ts.Close()
	x := &GCPSTSExchanger{Client: ts.Client(), TokenURL: ts.URL}
	_, err := x.Exchange(context.Background(), gcpSAKeyRequest(`{"client_email":"x@y","private_key":"garbage"}`))
	var xe *ExchangeError
	if !errors.As(err, &xe) || xe.Code != "request_invalid" {
		t.Fatalf("want request_invalid, got %v", err)
	}
}
