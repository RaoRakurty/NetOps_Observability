package main

// cloud_workload_issuer.go — Wave 4 #13: the platform's own workload OIDC
// issuer. When CLOUD_WORKLOAD_ISSUER_URL is set (the public HTTPS URL the
// customer's cloud reaches this appliance at, e.g. via nginx), the backend:
//
//   1. holds a platform RSA signing key — generated on first boot, private
//      half Vault-sealed at rest (same custody pattern as the internal CA);
//   2. serves OIDC discovery + JWKS at /.well-known/openid-configuration and
//      /.well-known/jwks.json so AWS/Azure/GCP can verify what we mint —
//      DELIBERATELY unauthenticated: cloud providers fetch anonymously, and
//      the documents carry ONLY public key material + static metadata, never
//      tenant data (the §3a scope rule is about data-returning surfaces;
//      this is platform-global public trust material);
//   3. rewires the Identity Broker's adapters so every federated exchange
//      (Entra WIF client_assertion, GCP STS subject_token, AWS
//      AssumeRoleWithWebIdentity) mints a fresh short-lived assertion instead
//      of reading a projected token from the environment.
//
// Unset = dormant: adapters keep the EnvWorkloadAssertionSource fallback and
// the well-known endpoints return 404. A configured-but-broken issuer (vault
// failure, corrupt key) is a LOUD boot error and stays dormant — exchanges
// then fail with the standard "not configured" deferral, never silently.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/vault"
	"strings"

	"netops/backend/cloudconn"
)

const (
	workloadIssuerKeyField = "cloudconn.workload.issuer.key" // Vault AAD field-id (platform DEK)
	workloadIssuerKeyBits  = 2048                            // RS256 interop floor for AWS/Azure/GCP OIDC federation
)

// kv key for the sealed signing key — a var (not const) so tests redirect it
// to a temp path (the file backend treats a kv key as a path), mirroring the
// tls_ca.go pattern.
var kvWorkloadIssuerKeyKey = "cloud_workload_issuer_key.enc"

// workloadIssuer is the loaded platform issuer identity.
type workloadIssuer struct {
	key    *rsa.PrivateKey
	kid    string // RFC 7638 JWK thumbprint of the public key
	issuer string // normalized public issuer URL (no trailing slash)
}

// loadOrCreateWorkloadIssuer loads the sealed signing key from the kv store
// or, on first run, generates and persists one. issuerURL must be an absolute
// http(s) URL — it becomes the `iss` every relying provider pins.
func loadOrCreateWorkloadIssuer(vault *vault.Vault, issuerURL string) (*workloadIssuer, error) {
	u := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, fmt.Errorf("workload issuer: CLOUD_WORKLOAD_ISSUER_URL must be an absolute http(s) URL, got %q", issuerURL)
	}
	if enc, err := kvLoad(kvWorkloadIssuerKeyKey); err == nil && len(enc) > 0 {
		keyPEM, err := vault.Decrypt("", workloadIssuerKeyField, string(enc))
		if err != nil {
			return nil, fmt.Errorf("workload issuer: decrypt signing key: %w", err)
		}
		key, err := parseRSAPrivatePEM([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("workload issuer: parse signing key: %w", err)
		}
		return &workloadIssuer{key: key, kid: cloudconn.RSAJWKThumbprintKid(&key.PublicKey), issuer: u}, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, workloadIssuerKeyBits)
	if err != nil {
		return nil, fmt.Errorf("workload issuer: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sealed, err := vault.Encrypt("", workloadIssuerKeyField, string(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("workload issuer: seal signing key: %w", err)
	}
	if err := kvSave(kvWorkloadIssuerKeyKey, []byte(sealed)); err != nil {
		return nil, fmt.Errorf("workload issuer: persist signing key: %w", err)
	}
	return &workloadIssuer{key: key, kid: cloudconn.RSAJWKThumbprintKid(&key.PublicKey), issuer: u}, nil
}

// parseRSAPrivatePEM decodes a PKCS#8 (or legacy PKCS#1) RSA private key PEM.
func parseRSAPrivatePEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return rk, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// source returns the assertion source the broker's adapters mint with.
func (wi *workloadIssuer) source() cloudconn.MintedWorkloadAssertionSource {
	return cloudconn.MintedWorkloadAssertionSource{
		Key: wi.key, Kid: wi.kid, Issuer: wi.issuer,
	}
}

// handleWorkloadOIDCDiscovery serves GET /.well-known/openid-configuration.
// 404 when the issuer is dormant (env unset / failed bootstrap).
func (s *server) handleWorkloadOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.workloadIssuer == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	doc := map[string]any{
		"issuer":                                s.workloadIssuer.issuer,
		"jwks_uri":                              s.workloadIssuer.issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleWorkloadJWKS serves GET /.well-known/jwks.json — the public signing
// key(s) relying providers verify our assertions against.
func (s *server) handleWorkloadJWKS(w http.ResponseWriter, r *http.Request) {
	if s.workloadIssuer == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	body, err := cloudconn.RSAPublicJWKS(&s.workloadIssuer.key.PublicKey, s.workloadIssuer.kid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("jwks render failed"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}

// bootstrapWorkloadIssuer activates the issuer on the server + broker when
// configured. Called from newServer after the broker exists. Never aborts
// boot: a broken explicit config logs loudly and leaves the feature dormant
// (exchanges then surface the standard deferral — observable, not silent).
func (s *server) bootstrapWorkloadIssuer(vault *vault.Vault, issuerURL string) {
	if strings.TrimSpace(issuerURL) == "" {
		return
	}
	wi, err := loadOrCreateWorkloadIssuer(vault, issuerURL)
	if err != nil {
		logError("cloudconn", "workload issuer bootstrap FAILED — federated exchanges will defer", errf(err))
		return
	}
	s.workloadIssuer = wi
	src := wi.source()
	s.cloudBroker.SetAdapter(func(p cloudconn.Provider) cloudconn.CloudIdentityProvider {
		return cloudconn.AdapterForWithAssertions(p, src)
	})
	logInfo("cloudconn", "workload OIDC issuer active", map[string]any{
		"issuer": wi.issuer, "kid": wi.kid})
}
