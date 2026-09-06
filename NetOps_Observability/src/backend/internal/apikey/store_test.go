package apikey

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// fileKV is a plain file backend for tests.
type fileKV struct{}

func (fileKV) Load(key string) ([]byte, error)    { return os.ReadFile(key) }
func (fileKV) Save(key string, data []byte) error { return os.WriteFile(key, data, 0o600) }

func newTestKeyStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir()+"/k.json", DefaultRateLimit, "global", fileKV{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestCreateHappyPath(t *testing.T) {
	s := newTestKeyStore(t)
	rec, secret, err := s.Create(Input{
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
	rec, _, err := s.Create(Input{Label: "machine"}, "admin")
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
		in   Input
		want string
	}{
		{"password grant", Input{Label: "x", GrantTypes: []string{"password"}}, "password grant is deprecated (RFC 9700 §2.4)"},
		{"bad grant", Input{Label: "x", GrantTypes: []string{"implicit"}}, "unsupported grant type"},
		{"bad cidr", Input{Label: "x", SourceCIDRs: []string{"not-a-cidr"}}, "invalid source CIDR"},
		{"bad email", Input{Label: "x", Contacts: []string{"no-at-sign"}}, "invalid contact email"},
		{"bad client uri", Input{Label: "x", ClientURI: "::::"}, "invalid client URI"},
		{"missing label", Input{}, "key label required"},
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
	_, secret, err := s.Create(Input{Label: "expired", SecretExpiresAt: &past}, "admin")
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
	_, secret, err := s.Create(Input{Label: "expired", ClientExpiresAt: &past}, "admin")
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
	_, secret, err := s.Create(Input{Label: "ok", SecretExpiresAt: &future}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Verify(secret); !ok {
		t.Fatalf("expected Verify to succeed for unexpired key")
	}
}

func TestSourceAllowed(t *testing.T) {
	// Empty list allows any source.
	open := Key{}
	if !open.SourceAllowed(net.ParseIP("203.0.113.5")) {
		t.Fatalf("empty SourceCIDRs should allow any IP")
	}
	gated := Key{SourceCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"}}
	if !gated.SourceAllowed(net.ParseIP("10.5.6.7")) {
		t.Fatalf("10.5.6.7 should be allowed by 10.0.0.0/8")
	}
	if !gated.SourceAllowed(net.ParseIP("192.168.1.42")) {
		t.Fatalf("192.168.1.42 should be allowed by 192.168.1.0/24")
	}
	if gated.SourceAllowed(net.ParseIP("203.0.113.5")) {
		t.Fatalf("203.0.113.5 should be denied")
	}
	if gated.SourceAllowed(nil) {
		t.Fatalf("nil IP should be denied when CIDRs are set")
	}
}

// TestRevokeBlocksVerify is the cache-invalidation guarantee for the auth hot
// path: once a key is revoked, Verify must reject it immediately within the same
// process (write-through, no stale window). Guards against a refactor silently
// dropping the RevokedAt check.
func TestRevokeBlocksVerify(t *testing.T) {
	s := newTestKeyStore(t)
	rec, secret, err := s.Create(Input{Label: "to-revoke"}, "admin")
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
	a, err := NewStore(path, DefaultRateLimit, "global", fileKV{})
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	rec, secret, err := a.Create(Input{Label: "shared"}, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Both run as replicas (multiWriter) so neither rewrites the shared blob from a
	// stale map on the auth hot path — exactly how the reload loop configures them.
	a.multiWriter = true
	// Instance B comes up after the key exists and loads it from the shared store.
	b, err := NewStore(path, DefaultRateLimit, "global", fileKV{})
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
	if err := b.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := b.Verify(secret); ok {
		t.Fatalf("after reload, B must reject the revoked key (multi-instance gap)")
	}
}

// ---- scope vocabulary (tracker 226) ---------------------------------------

// The closed vocabulary and its display list must not drift apart: KnownScopes
// is what the UI and the docs render, knownScopes is what Create validates
// against. A scope in one and not the other is a mint that the UI offers and
// the API refuses (or worse, the reverse).
func TestKnownScopesMatchesTheValidationTable(t *testing.T) {
	display := KnownScopes()
	if len(display) != len(knownScopes) {
		t.Fatalf("KnownScopes has %d entries, validation table has %d", len(display), len(knownScopes))
	}
	seen := map[string]bool{}
	for _, s := range display {
		if !knownScopes[s] {
			t.Errorf("KnownScopes offers %q, which Create would reject", s)
		}
		if seen[s] {
			t.Errorf("KnownScopes lists %q twice", s)
		}
		seen[s] = true
	}
	for s := range knownScopes {
		if !seen[s] {
			t.Errorf("scope %q is accepted but never offered by KnownScopes", s)
		}
	}
}

func TestNormalizeScopes(t *testing.T) {
	got, err := NormalizeScopes([]string{" READ:Metrics ", "read:metrics", "", "admin:*"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(got) != 2 || got[0] != "read:metrics" || got[1] != ScopeAdminAll {
		t.Fatalf("normalize = %v, want [read:metrics admin:*]", got)
	}
	// An empty request stays empty (a key with no scopes is read-only, not an error).
	if got, err := NormalizeScopes(nil); err != nil || len(got) != 0 {
		t.Fatalf("nil scopes = %v, %v; want empty, nil", got, err)
	}
	for _, bad := range []string{"write:tenants", "admin:tenants", "*", "read:"} {
		if _, err := NormalizeScopes([]string{bad}); err == nil {
			t.Errorf("scope %q accepted; the vocabulary must be closed", bad)
		}
	}
	if !ScopeKnown(" Admin:* ") || ScopeKnown("write:everything") {
		t.Error("ScopeKnown disagrees with the vocabulary")
	}
}

// Create is the enforcement point: an unknown scope must never reach the store.
func TestCreateRejectsUnknownScope(t *testing.T) {
	s := newTestKeyStore(t)
	if _, _, err := s.Create(Input{Label: "typo", Scopes: []string{"write:tenants"}}, "root"); err == nil {
		t.Fatal("Create accepted an unknown scope")
	}
	rec, _, err := s.Create(Input{Label: "ok", Scopes: []string{" ADMIN:* ", "admin:*"}}, "root")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(rec.Scopes) != 1 || rec.Scopes[0] != ScopeAdminAll {
		t.Fatalf("stored scopes = %v, want [admin:*]", rec.Scopes)
	}
}
