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
