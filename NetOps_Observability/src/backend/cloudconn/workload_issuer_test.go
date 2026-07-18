package cloudconn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMintedAssertionSignsVerifiableRS256(t *testing.T) {
	key := testKey(t)
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	src := MintedWorkloadAssertionSource{
		Key: key, Kid: RSAJWKThumbprintKid(&key.PublicKey),
		Issuer: "https://correlix.example.com", TTL: 5 * time.Minute,
		Now: func() time.Time { return now },
	}
	tok, err := src.Assertion(context.Background(), "sts.amazonaws.com", "correlix:connector:ccn_1")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 JWT segments, got %d", len(parts))
	}
	// Signature verifies against the public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	hdr := decodeSegment(t, parts[0])
	if hdr["alg"] != "RS256" || hdr["kid"] != src.Kid {
		t.Fatalf("bad header: %v", hdr)
	}
	claims := decodeSegment(t, parts[1])
	if claims["iss"] != "https://correlix.example.com" ||
		claims["sub"] != "correlix:connector:ccn_1" ||
		claims["aud"] != "sts.amazonaws.com" {
		t.Fatalf("bad claims: %v", claims)
	}
	if int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != 300 {
		t.Fatalf("want 5m validity, got claims %v", claims)
	}
	if claims["jti"] == "" {
		t.Fatal("missing jti")
	}
	// jti is unique per mint.
	tok2, err := src.Assertion(context.Background(), "sts.amazonaws.com", "correlix:connector:ccn_1")
	if err != nil {
		t.Fatal(err)
	}
	if decodeSegment(t, strings.Split(tok2, ".")[1])["jti"] == claims["jti"] {
		t.Fatal("jti must be unique per assertion")
	}
}

func TestMintedAssertionRefusals(t *testing.T) {
	key := testKey(t)
	src := MintedWorkloadAssertionSource{Key: key, Issuer: "https://correlix.example.com"}
	if _, err := (MintedWorkloadAssertionSource{Issuer: "https://x"}).Assertion(context.Background(), "aud", "sub"); !errors.Is(err, ErrWorkloadAssertionMissing) {
		t.Fatalf("nil key: want ErrWorkloadAssertionMissing, got %v", err)
	}
	if _, err := (MintedWorkloadAssertionSource{Key: key}).Assertion(context.Background(), "aud", "sub"); !errors.Is(err, ErrWorkloadAssertionMissing) {
		t.Fatalf("empty issuer: want ErrWorkloadAssertionMissing, got %v", err)
	}
	if _, err := src.Assertion(context.Background(), "", "sub"); err == nil {
		t.Fatal("empty audience must refuse")
	}
	if _, err := src.Assertion(context.Background(), "aud", ""); err == nil {
		t.Fatal("empty subject must refuse")
	}
	// WorkloadSubject default with an empty connector id ends in ":" — refused.
	if _, err := src.Assertion(context.Background(), "aud", "correlix:connector:"); err == nil {
		t.Fatal("empty-connector default subject must refuse")
	}
}

func TestWorkloadSubjectPrecedence(t *testing.T) {
	id := IdentityConfig{ConnectorID: "ccn_9"}
	if got := WorkloadSubject(id); got != "correlix:connector:ccn_9" {
		t.Fatalf("default: %q", got)
	}
	id.Anchor.OIDCSubject = "correlix:platform"
	if got := WorkloadSubject(id); got != "correlix:platform" {
		t.Fatalf("anchor: %q", got)
	}
	id.FederatedSubject = "correlix:connector:ccn_9:custom"
	if got := WorkloadSubject(id); got != "correlix:connector:ccn_9:custom" {
		t.Fatalf("federated wins: %q", got)
	}
}

func TestJWKSRoundTripsPublicKey(t *testing.T) {
	key := testKey(t)
	kid := RSAJWKThumbprintKid(&key.PublicKey)
	if kid != RSAJWKThumbprintKid(&key.PublicKey) {
		t.Fatal("kid must be deterministic")
	}
	body, err := RSAPublicJWKS(&key.PublicKey, kid)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["kid"] != kid {
		t.Fatalf("bad JWK metadata: %v", k)
	}
	// Rebuild the public key from (n, e) and confirm it matches.
	nb, err := base64.RawURLEncoding.DecodeString(k["n"])
	if err != nil {
		t.Fatal(err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k["e"])
	if err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.Cmp(key.PublicKey.N) != 0 || e.Int64() != int64(key.PublicKey.E) {
		t.Fatal("JWKS (n,e) does not round-trip the public key")
	}
	// No private material anywhere in the document.
	for _, priv := range []string{"\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\""} {
		if strings.Contains(string(body), priv) {
			t.Fatalf("JWKS leaks private field %s", priv)
		}
	}
}

func TestAdapterForWithAssertionsOverridesAllProviders(t *testing.T) {
	key := testKey(t)
	src := MintedWorkloadAssertionSource{Key: key, Kid: "k", Issuer: "https://correlix.example.com"}
	for _, p := range []Provider{ProviderAWS, ProviderAzure, ProviderGCP} {
		a := AdapterForWithAssertions(p, src)
		if a == nil {
			t.Fatalf("nil adapter for %s", p)
		}
		if a.Provider() != p {
			t.Fatalf("provider mismatch: %s", p)
		}
	}
	if AdapterForWithAssertions(Provider("nope"), src) != nil {
		t.Fatal("unknown provider must return nil")
	}
}
