// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewFromMetadataReadsANonStandardDocument: the Bot Framework publishes
// its key metadata at a non-standard path and with no token endpoint. A cache
// built from that document verifies a token signed by its keys, the issuer is
// still checked per token, and the standard well-known path is never asked.
func TestNewFromMetadataReadsANonStandardDocument(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	const kid = "bf-1"
	keys := idpServer(t, key, kid) // serves /jwks for the key
	defer keys.Close()

	wellKnownHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/openidconfiguration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://api.botframework.com", "jwks_uri": keys.URL + "/jwks"})
	})
	mux.HandleFunc("/v1/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		wellKnownHit = true
		http.NotFound(w, r)
	})
	meta := httptest.NewServer(mux)
	defer meta.Close()

	c := NewFromMetadata(meta.URL+"/v1/.well-known/openidconfiguration", 0)
	tok := signRS256(t, key, kid, map[string]any{
		"iss": "https://api.botframework.com", "aud": "bot-app-id",
		"serviceurl": "https://smba.trafficmanager.net/emea/",
		"exp":        time.Now().Add(time.Hour).Unix(),
	})
	claims, err := c.VerifyRS256(tok, "https://api.botframework.com", "bot-app-id")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if su, ok := claims.Claim("serviceurl"); !ok || su != "https://smba.trafficmanager.net/emea/" {
		t.Fatalf("serviceurl claim = %q, %v", su, ok)
	}
	if _, err := c.VerifyRS256(tok, "https://login.example.com", "bot-app-id"); err == nil {
		t.Fatal("a token checked against another issuer must be refused")
	}
	if _, err := c.VerifyRS256(tok, "https://api.botframework.com", "another-bot"); err == nil {
		t.Fatal("a token for another bot must be refused")
	}
	if wellKnownHit {
		t.Fatal("the standard well-known path must not be fetched in metadata mode")
	}
}
