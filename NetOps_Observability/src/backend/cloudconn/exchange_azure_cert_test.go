// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// exchange_azure_cert_test.go — the Azure certificate credential path (Wave 4
// #13): live client-assertion flow against an httptest Entra that VERIFIES the
// assertion (x5t header, RS256 signature, aud/iss/sub/exp claims), plus the
// zero-trust refusal paths (bad bundle, key/cert mismatch, thumbprint
// mismatch, expired cert) — none of which may reach the wire.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- x5t thumbprint verification in tests
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testCertBundle mints a fresh RSA key + self-signed cert and returns the PEM
// bundle (cert + PKCS#8 key), the parsed cert and the key.
func testCertBundle(t *testing.T, notBefore, notAfter time.Time) (string, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "correlix-test-connector"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var b strings.Builder
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem cert: %v", err)
	}
	if err := pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("pem key: %v", err)
	}
	return b.String(), cert, key
}

func azureCertRequest(bundle string, cert *x509.Certificate) ExchangeRequest {
	sum := sha1.Sum(cert.Raw) // #nosec G401 -- test thumbprint
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider: ProviderAzure, Method: AuthMethodCertificate,
			ConnectorID: "ccn_azcert", AzureTenantID: "11111111-2222-3333-4444-555555555555",
			ClientID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			CertThumbprint:  strings.ToUpper(hex.EncodeToString(sum[:])), // portal-style uppercase
			LegacySecretRef: "csr_cert",
		},
		LegacySecret: bundle,
		MaxLifetime:  time.Hour,
	}
}

func TestAzureExchangeCertificateHappyPath(t *testing.T) {
	now := time.Now()
	bundle, cert, key := testCertBundle(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	var gotForm url.Values
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token_type":"Bearer","expires_in":3599,"access_token":"cert-access-token"}`)
	}))
	defer ts.Close()

	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL}
	req := azureCertRequest(bundle, cert)
	tok, err := x.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Value != "cert-access-token" || tok.Provider != ProviderAzure {
		t.Errorf("token fields wrong: %q %q", tok.Value, tok.Provider)
	}
	if gotForm.Get("client_assertion_type") != azureClientAssertionType {
		t.Errorf("client_assertion_type = %q", gotForm.Get("client_assertion_type"))
	}
	if gotForm.Get("client_secret") != "" {
		t.Error("certificate flow must not send a client_secret")
	}

	// Verify the assertion like Entra would: x5t header, RS256 signature with
	// the cert's public key, aud = token endpoint, iss = sub = client id.
	assertion := gotForm.Get("client_assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion is not a compact JWS: %d parts", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header b64: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		X5t string `json:"x5t"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	sum := sha1.Sum(cert.Raw) // #nosec G401 -- x5t check
	if header.Alg != "RS256" || header.Typ != "JWT" || header.X5t != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("assertion header wrong: %+v", header)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("sig b64: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, 5, digest[:], sig); err != nil { // 5 = crypto.SHA256
		t.Errorf("assertion signature does not verify: %v", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("claims b64: %v", err)
	}
	var claims struct {
		Aud string `json:"aud"`
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims json: %v", err)
	}
	wantAud := ts.URL + gotPath
	if claims.Aud != wantAud {
		t.Errorf("aud = %q want %q", claims.Aud, wantAud)
	}
	if claims.Iss != req.Identity.ClientID || claims.Sub != req.Identity.ClientID {
		t.Errorf("iss/sub = %q/%q want client id", claims.Iss, claims.Sub)
	}
	if claims.Jti == "" || claims.Exp <= claims.Iat {
		t.Errorf("jti/exp invalid: jti=%q iat=%d exp=%d", claims.Jti, claims.Iat, claims.Exp)
	}
	if lifetime := claims.Exp - claims.Iat; lifetime > int64(azureCertAssertionLifetime/time.Second) {
		t.Errorf("assertion lifetime %ds exceeds the %v bound", lifetime, azureCertAssertionLifetime)
	}
}

// TestAzureCertificateRefusalsNeverReachTheWire covers the zero-trust refusal
// paths: each must fail request_invalid BEFORE any HTTP call.
func TestAzureCertificateRefusalsNeverReachTheWire(t *testing.T) {
	now := time.Now()
	bundle, cert, _ := testCertBundle(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("refusal paths must not reach the wire")
		w.WriteHeader(500)
	}))
	defer ts.Close()
	x := &AzureEntraExchanger{Client: ts.Client(), BaseURL: ts.URL}

	cases := []struct {
		name   string
		mutate func(*ExchangeRequest)
	}{
		{"garbage bundle", func(r *ExchangeRequest) { r.LegacySecret = "not a pem bundle" }},
		{"thumbprint mismatch", func(r *ExchangeRequest) {
			r.Identity.CertThumbprint = strings.Repeat("ab", 20)
		}},
		{"key/cert mismatch", func(r *ExchangeRequest) {
			otherBundle, _, _ := testCertBundle(t, now.Add(-time.Hour), now.Add(24*time.Hour))
			// splice: cert from the original, key from another bundle
			keyStart := strings.Index(otherBundle, "-----BEGIN PRIVATE KEY-----")
			certEnd := strings.Index(r.LegacySecret, "-----BEGIN PRIVATE KEY-----")
			r.LegacySecret = r.LegacySecret[:certEnd] + otherBundle[keyStart:]
		}},
		{"expired cert", func(r *ExchangeRequest) {
			expBundle, expCert, _ := testCertBundle(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
			*r = azureCertRequest(expBundle, expCert)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := azureCertRequest(bundle, cert)
			tc.mutate(&req)
			var xe *ExchangeError
			if _, err := x.Exchange(context.Background(), req); !errors.As(err, &xe) || xe.Code != "request_invalid" {
				t.Fatalf("want request_invalid ExchangeError, got %v", err)
			}
		})
	}
}

func TestAzureCertBundleThumbprintUploadCheck(t *testing.T) {
	now := time.Now()
	bundle, cert, _ := testCertBundle(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	thumb, err := AzureCertBundleThumbprint(bundle, now)
	if err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	sum := sha1.Sum(cert.Raw) // #nosec G401 -- expected thumbprint
	if thumb != hex.EncodeToString(sum[:]) {
		t.Errorf("thumbprint = %q", thumb)
	}
	if _, err := AzureCertBundleThumbprint("garbage", now); err == nil {
		t.Error("garbage bundle must be rejected at upload time")
	}
	// Portal-style normalization: uppercase + colons must match.
	pretty := strings.ToUpper(hex.EncodeToString(sum[:]))
	var withColons strings.Builder
	for i := 0; i < len(pretty); i += 2 {
		if i > 0 {
			withColons.WriteByte(':')
		}
		withColons.WriteString(pretty[i : i+2])
	}
	if NormalizeAzureThumbprint(withColons.String()) != thumb {
		t.Errorf("normalize(%q) != %q", withColons.String(), thumb)
	}
}
