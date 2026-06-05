package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func newTestKeyStore(t *testing.T) *apiKeyStore {
	t.Helper()
	s, err := newAPIKeyStore(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatalf("newAPIKeyStore: %v", err)
	}
	return s
}

func TestCreateHappyPath(t *testing.T) {
	s := newTestKeyStore(t)
	rec, secret, err := s.Create(apiKeyInput{
		Label:       "ci-pipeline",
		Scopes:      []string{"read:metrics"},
		GrantTypes:  []string{"client_credentials", "refresh_token"},
		SourceCIDRs: []string{"10.0.0.0/8"},
		Contacts:    []string{"ops@example.com"},
		ClientURI:   "https://example.com/app",
	}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if secret == "" || rec.ID == "" {
		t.Fatalf("expected secret and id, got %q / %q", secret, rec.ID)
	}
	if len(rec.GrantTypes) != 2 {
		t.Fatalf("grant types not persisted: %v", rec.GrantTypes)
	}
	if len(rec.SourceCIDRs) != 1 || rec.Contacts[0] != "ops@example.com" {
		t.Fatalf("metadata not persisted: %+v", rec)
	}
}

func TestCreateDefaultsGrantTypes(t *testing.T) {
	s := newTestKeyStore(t)
	rec, _, err := s.Create(apiKeyInput{Label: "machine"}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(rec.GrantTypes) != 1 || rec.GrantTypes[0] != "client_credentials" {
		t.Fatalf("expected default client_credentials, got %v", rec.GrantTypes)
	}
}

func TestCreateValidation(t *testing.T) {
	s := newTestKeyStore(t)
	cases := []struct {
		name string
		in   apiKeyInput
		want string
	}{
		{"password grant", apiKeyInput{Label: "x", GrantTypes: []string{"password"}}, "password grant is deprecated (RFC 9700 §2.4)"},
		{"bad grant", apiKeyInput{Label: "x", GrantTypes: []string{"implicit"}}, "unsupported grant type"},
		{"bad cidr", apiKeyInput{Label: "x", SourceCIDRs: []string{"not-a-cidr"}}, "invalid source CIDR"},
		{"bad email", apiKeyInput{Label: "x", Contacts: []string{"no-at-sign"}}, "invalid contact email"},
		{"bad client uri", apiKeyInput{Label: "x", ClientURI: "::::"}, "invalid client URI"},
		{"missing label", apiKeyInput{}, "key label required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := s.Create(c.in, "admin")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("expected error containing %q, got %q", c.want, err.Error())
			}
		})
	}
}

func TestVerifyExpiredSecret(t *testing.T) {
	s := newTestKeyStore(t)
	past := time.Now().UTC().Add(-time.Hour)
	_, secret, err := s.Create(apiKeyInput{Label: "expired", SecretExpiresAt: &past}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Verify(secret); ok {
		t.Fatalf("expected Verify to fail for expired secret")
	}
}

func TestVerifyExpiredClient(t *testing.T) {
	s := newTestKeyStore(t)
	past := time.Now().UTC().Add(-time.Hour)
	_, secret, err := s.Create(apiKeyInput{Label: "expired", ClientExpiresAt: &past}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Verify(secret); ok {
		t.Fatalf("expected Verify to fail for expired client")
	}
}

func TestVerifyValid(t *testing.T) {
	s := newTestKeyStore(t)
	future := time.Now().UTC().Add(time.Hour)
	_, secret, err := s.Create(apiKeyInput{Label: "ok", SecretExpiresAt: &future}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Verify(secret); !ok {
		t.Fatalf("expected Verify to succeed for unexpired key")
	}
}

func TestSourceAllowed(t *testing.T) {
	// Empty list allows any source.
	open := APIKey{}
	if !open.sourceAllowed(net.ParseIP("203.0.113.5")) {
		t.Fatalf("empty SourceCIDRs should allow any IP")
	}
	gated := APIKey{SourceCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"}}
	if !gated.sourceAllowed(net.ParseIP("10.5.6.7")) {
		t.Fatalf("10.5.6.7 should be allowed by 10.0.0.0/8")
	}
	if !gated.sourceAllowed(net.ParseIP("192.168.1.42")) {
		t.Fatalf("192.168.1.42 should be allowed by 192.168.1.0/24")
	}
	if gated.sourceAllowed(net.ParseIP("203.0.113.5")) {
		t.Fatalf("203.0.113.5 should be denied")
	}
	if gated.sourceAllowed(nil) {
		t.Fatalf("nil IP should be denied when CIDRs are set")
	}
}

// TestRevokeBlocksVerify is the cache-invalidation guarantee for the auth hot
// path: once a key is revoked, Verify must reject it immediately within the same
// process (write-through, no stale window). Guards against a refactor silently
// dropping the RevokedAt check.
func TestRevokeBlocksVerify(t *testing.T) {
	s := newTestKeyStore(t)
	rec, secret, err := s.Create(apiKeyInput{Label: "to-revoke"}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Verify(secret); !ok {
		t.Fatalf("Verify should succeed before revocation")
	}
	if err := s.Revoke(rec.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := s.Verify(secret); ok {
		t.Fatalf("Verify must fail immediately after revocation (cache-invalidation gap)")
	}
}

// TestReloadPropagatesRevocation simulates two API replicas sharing one backend
// store (the default fileKV here): a key revoked on instance A must stop
// authenticating on instance B after B reloads — the multi-instance fix. Before
// reload, B is intentionally stale (proving the gap exists); after reload it
// converges.
func TestReloadPropagatesRevocation(t *testing.T) {
	path := t.TempDir() + "/shared-keys.json"
	a, err := newAPIKeyStore(path)
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	rec, secret, err := a.Create(apiKeyInput{Label: "shared"}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Both run as replicas (multiWriter) so neither rewrites the shared blob from a
	// stale map on the auth hot path — exactly how the reload loop configures them.
	a.multiWriter = true
	// Instance B comes up after the key exists and loads it from the shared store.
	b, err := newAPIKeyStore(path)
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	b.multiWriter = true
	if _, ok := b.Verify(secret); !ok {
		t.Fatalf("B should authenticate the key before it is revoked")
	}
	// A revokes (write-through to the shared store).
	if err := a.Revoke(rec.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// B is still stale until it reloads — this is the gap the loop closes.
	if _, ok := b.Verify(secret); !ok {
		t.Fatalf("precondition: B's cache should still be stale before reload")
	}
	if err := b.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := b.Verify(secret); ok {
		t.Fatalf("after reload, B must reject the revoked key (multi-instance gap)")
	}
}
