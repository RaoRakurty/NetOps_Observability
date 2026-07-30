package main

// cloud_workload_issuer_test.go — Wave 4 #13: platform OIDC issuer custody +
// trust-material endpoints. Pins: key load-or-create round-trip (sealed at
// rest, same kid across boots), URL validation, dormant-404 vs active
// discovery/JWKS, method gating, and the broker adapter swap.

import (
	"encoding/json"
	"net/http/httptest"
	"netops/backend/internal/platformdb"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/cloudconn"
)

func redirectIssuerKV(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "issuer.key.enc")
	t.Cleanup(cloudconn.SetIssuerKeyPathForTest(p))
	return p
}

func TestLoadOrCreateWorkloadIssuerPersists(t *testing.T) {
	keyPath := redirectIssuerKV(t)
	v := newTestVault(t)
	wi, err := cloudconn.LoadOrCreateWorkloadIssuer(v, "https://correlix.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if wi.Issuer() != "https://correlix.example.com" { // trailing slash normalized
		t.Fatalf("issuer: %q", wi.Issuer())
	}
	// At rest the key is sealed — never plaintext PEM.
	raw, err := platformdb.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("signing key stored unsealed")
	}
	// Second load = same identity (kid), not a regenerated key.
	wi2, err := cloudconn.LoadOrCreateWorkloadIssuer(v, "https://correlix.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if wi2.Kid() != wi.Kid() {
		t.Fatalf("kid changed across loads: %s vs %s", wi.Kid(), wi2.Kid())
	}
}

func TestLoadOrCreateWorkloadIssuerRejectsBadURL(t *testing.T) {
	redirectIssuerKV(t)
	v := newTestVault(t)
	for _, bad := range []string{"", "correlix.example.com", "ftp://x"} {
		if _, err := cloudconn.LoadOrCreateWorkloadIssuer(v, bad); err == nil {
			t.Fatalf("URL %q must be rejected", bad)
		}
	}
}

func TestWorkloadWellKnownEndpoints(t *testing.T) {
	redirectIssuerKV(t)
	v := newTestVault(t)
	s := &server{}
	// Dormant: both endpoints 404.
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		rr := httptest.NewRecorder()
		s.handleWorkloadOIDCDiscovery(rr, httptest.NewRequest("GET", path, nil))
		if path == "/.well-known/openid-configuration" && rr.Code != 404 {
			t.Fatalf("dormant discovery: want 404, got %d", rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	s.handleWorkloadJWKS(rr, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rr.Code != 404 {
		t.Fatalf("dormant jwks: want 404, got %d", rr.Code)
	}

	wi, err := cloudconn.LoadOrCreateWorkloadIssuer(v, "https://correlix.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.workloadIssuer = wi

	rr = httptest.NewRecorder()
	s.handleWorkloadOIDCDiscovery(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rr.Code != 200 {
		t.Fatalf("discovery: %d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "https://correlix.example.com" ||
		doc["jwks_uri"] != "https://correlix.example.com/.well-known/jwks.json" {
		t.Fatalf("bad discovery doc: %v", doc)
	}

	rr = httptest.NewRecorder()
	s.handleWorkloadJWKS(rr, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rr.Code != 200 {
		t.Fatalf("jwks: %d", rr.Code)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != wi.Kid() {
		t.Fatalf("bad jwks: %s", rr.Body.String())
	}

	// Method gating.
	rr = httptest.NewRecorder()
	s.handleWorkloadOIDCDiscovery(rr, httptest.NewRequest("POST", "/.well-known/openid-configuration", nil))
	if rr.Code != 405 {
		t.Fatalf("discovery POST: want 405, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.handleWorkloadJWKS(rr, httptest.NewRequest("PUT", "/.well-known/jwks.json", nil))
	if rr.Code != 405 {
		t.Fatalf("jwks PUT: want 405, got %d", rr.Code)
	}
}

func TestBootstrapWorkloadIssuerSwapsBrokerAdapters(t *testing.T) {
	redirectIssuerKV(t)
	v := newTestVault(t)
	s := &server{cloudBroker: cloudconn.NewIdentityBroker(nil, v, nil)}

	// Unset env → dormant, adapter untouched.
	s.bootstrapWorkloadIssuer(v, "")
	if s.workloadIssuer != nil {
		t.Fatal("unset URL must stay dormant")
	}

	// Broken config → loud dormant, never a panic/abort.
	s.bootstrapWorkloadIssuer(v, "not-a-url")
	if s.workloadIssuer != nil {
		t.Fatal("bad URL must stay dormant")
	}

	s.bootstrapWorkloadIssuer(v, "https://correlix.example.com")
	if s.workloadIssuer == nil {
		t.Fatal("issuer not activated")
	}
	for _, p := range []cloudconn.Provider{cloudconn.ProviderAWS, cloudconn.ProviderAzure, cloudconn.ProviderGCP} {
		if s.cloudBroker.AdapterFor(p) == nil {
			t.Fatalf("broker adapter missing for %s after issuer activation", p)
		}
	}
}
