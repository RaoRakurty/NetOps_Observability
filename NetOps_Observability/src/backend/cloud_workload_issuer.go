// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_workload_issuer.go — main-side wiring for the platform workload OIDC
// issuer (custody in cloudconn/issuer.go, extracted P2 RA.11). When
// CLOUD_WORKLOAD_ISSUER_URL is set, the backend serves OIDC discovery + JWKS
// at the well-known paths (DELIBERATELY unauthenticated: providers fetch
// anonymously and the documents carry ONLY public key material + static
// metadata, never tenant data) and rewires the Identity Broker's adapters to
// mint fresh short-lived assertions. Unset = dormant (404s + env fallback); a
// configured-but-broken issuer is a LOUD boot error and stays dormant.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"netops/backend/cloudconn"
	"netops/backend/internal/vault"
)

type workloadIssuer = cloudconn.WorkloadIssuer

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
		"issuer":                                s.workloadIssuer.Issuer(),
		"jwks_uri":                              s.workloadIssuer.Issuer() + "/.well-known/jwks.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc) // best-effort: static JSON document; a failed write means the client is gone
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
	body, err := cloudconn.RSAPublicJWKS(s.workloadIssuer.PublicKey(), s.workloadIssuer.Kid())
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("jwks render failed"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body) // best-effort: static JSON document; a failed write means the client is gone
}

// bootstrapWorkloadIssuer activates the issuer on the server + broker when
// configured. Called from newServer after the broker exists. Never aborts
// boot: a broken explicit config logs loudly and leaves the feature dormant
// (exchanges then surface the standard deferral — observable, not silent).
func (s *server) bootstrapWorkloadIssuer(vault *vault.Vault, issuerURL string) {
	if strings.TrimSpace(issuerURL) == "" {
		return
	}
	wi, err := cloudconn.LoadOrCreateWorkloadIssuer(vault, issuerURL)
	if err != nil {
		logError("cloudconn", "workload issuer bootstrap FAILED — federated exchanges will defer", errf(err))
		return
	}
	s.workloadIssuer = wi
	src := wi.Source()
	s.cloudBroker.SetAdapter(func(p cloudconn.Provider) cloudconn.CloudIdentityProvider {
		return cloudconn.AdapterForWithAssertions(p, src)
	})
	logInfo("cloudconn", "workload OIDC issuer active", map[string]any{
		"issuer": wi.Issuer(), "kid": wi.Kid()})
}
