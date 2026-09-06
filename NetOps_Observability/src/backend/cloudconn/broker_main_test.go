// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// fakeAdapter is a test double for a provider that returns a deterministic token
// so the broker's caching / isolation / lifetime logic is testable without any
// cloud network. It records the last ExchangeRequest so tests can assert the
// broker passed the decrypted legacy secret only when appropriate.
func testConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return ConnectorIDPrefix + hex.EncodeToString(b)
}

type fakeAdapter struct {
	provider Provider
	issued   int
	lastReq  ExchangeRequest
	ttl      time.Duration
	now      func() time.Time // controllable clock; nil = time.Now
}

func (f *fakeAdapter) Provider() Provider { return f.provider }
func (f *fakeAdapter) ValidateConfiguration(IdentityConfig) ValidationResult {
	return ValidationResult{OK: true}
}
func (f *fakeAdapter) SetupInstructions(IdentityConfig, CapabilityPack) (SetupBundle, error) {
	return SetupBundle{}, nil
}
func (f *fakeAdapter) ExchangeCredential(_ context.Context, req ExchangeRequest) (ScopedToken, error) {
	f.issued++
	f.lastReq = req
	ttl := f.ttl
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	now := time.Now
	if f.now != nil {
		now = f.now
	}
	// The value is bound to the connector's ExternalId + mint count, so tests can
	// prove WHICH connector a served credential was minted for (isolation) and
	// WHEN it was refreshed.
	return ScopedToken{
		Provider: f.provider,
		Value:    "tok-" + req.Identity.ExternalID + "-" + itoaTest(f.issued),
		Expiry:   now().UTC().Add(ttl),
	}, nil
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
func (f *fakeAdapter) DiscoverScopes(context.Context, DiscoverRequest) ([]Scope, error) {
	return nil, nil
}
func (f *fakeAdapter) ValidateCapabilities(context.Context, CapabilityCheckRequest) (CapabilityReport, error) {
	return CapabilityReport{}, nil
}
func (f *fakeAdapter) Revoke(context.Context, RevokeRequest) error { return nil }

func newTestBroker(t *testing.T, fake *fakeAdapter) (*IdentityBroker, Repo) {
	t.Helper()
	store := NewMemStore()
	b := NewIdentityBroker(store, nil /* dormant vault: passthrough */, nil)
	b.SetAdapter(func(Provider) CloudIdentityProvider { return fake })
	return b, store
}

func mkActiveConnector(t *testing.T, store Repo, tenant, role string) Connector {
	t.Helper()
	c := Connector{
		TenantID: tenant, ConnectorID: testConnID(), Provider: ProviderAWS,
		AuthMethod: AuthMethodCloudRole, State: StateActive,
		Identity: IdentityConfig{Provider: ProviderAWS, RoleARN: role, ExternalID: NewExternalID()},
	}
	created, err := store.Create(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestBrokerTokenCacheTenantConnectorIsolation(t *testing.T) {
	fake := &fakeAdapter{provider: ProviderAWS}
	b, store := newTestBroker(t, fake)
	// Two tenants, IDENTICAL role ARN + provider account — the cache must NOT
	// collapse them into one entry.
	const sameRole = "arn:aws:iam::123456789012:role/correlix-observer"
	ca := mkActiveConnector(t, store, "tenant-a", sameRole)
	cb := mkActiveConnector(t, store, "tenant-b", sameRole)

	reqA := ScopedTokenRequest{Tenant: "tenant-a", ConnectorID: ca.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}
	reqB := ScopedTokenRequest{Tenant: "tenant-b", ConnectorID: cb.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}

	if _, err := b.TokenFor(context.Background(), reqA); err != nil {
		t.Fatalf("A token: %v", err)
	}
	if _, err := b.TokenFor(context.Background(), reqB); err != nil {
		t.Fatalf("B token: %v", err)
	}
	// Distinct tenants+connectors → two separate exchanges (no shared cache entry).
	if fake.issued != 2 {
		t.Fatalf("expected 2 distinct exchanges for 2 tenants, got %d", fake.issued)
	}
	// A repeat for A is served from cache (no new exchange).
	if _, err := b.TokenFor(context.Background(), reqA); err != nil {
		t.Fatalf("A token repeat: %v", err)
	}
	if fake.issued != 2 {
		t.Fatalf("cache miss on repeat: exchanges=%d", fake.issued)
	}
	// Cross-tenant request for A's connector under tenant B fails closed (Get scoped).
	if _, err := b.TokenFor(context.Background(), ScopedTokenRequest{Tenant: "tenant-b", ConnectorID: ca.ConnectorID, ProviderAccount: "123456789012"}); !errors.Is(err, ErrBrokerNotFound) {
		t.Fatalf("cross-tenant token request must fail closed, got %v", err)
	}
}

// TestBrokerCachedCredentialNeverCrossesTenants proves tenant A's connector can
// NEVER be served tenant B's cached credential: with identical role ARNs,
// provider accounts and capability sets, each tenant receives a credential
// minted for ITS OWN connector (bound to its ExternalId), from mint through
// cache hit.
func TestBrokerCachedCredentialNeverCrossesTenants(t *testing.T) {
	fake := &fakeAdapter{provider: ProviderAWS}
	b, store := newTestBroker(t, fake)
	const sameRole = "arn:aws:iam::123456789012:role/correlix-observer"
	ca := mkActiveConnector(t, store, "tenant-a", sameRole)
	cb := mkActiveConnector(t, store, "tenant-b", sameRole)

	reqA := ScopedTokenRequest{Tenant: "tenant-a", ConnectorID: ca.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}
	reqB := ScopedTokenRequest{Tenant: "tenant-b", ConnectorID: cb.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}

	// B mints first and warms the cache.
	tokB, err := b.TokenFor(context.Background(), reqB)
	if err != nil {
		t.Fatal(err)
	}
	// A then asks with an otherwise-identical request; it must NOT receive B's
	// cached credential.
	tokA, err := b.TokenFor(context.Background(), reqA)
	if err != nil {
		t.Fatal(err)
	}
	if tokA.Value == tokB.Value {
		t.Fatal("tenant A received tenant B's cached credential — cross-tenant cache leak")
	}
	wantA := "tok-" + ca.Identity.ExternalID + "-2"
	if tokA.Value != wantA {
		t.Fatalf("A's credential is not bound to A's connector identity: got %q want %q", tokA.Value, wantA)
	}
	// Cache hits keep the binding: A's repeat still gets A's credential.
	tokA2, err := b.TokenFor(context.Background(), reqA)
	if err != nil {
		t.Fatal(err)
	}
	if tokA2.Value != tokA.Value {
		t.Fatalf("A's cache hit changed identity: %q -> %q", tokA.Value, tokA2.Value)
	}
	if fake.issued != 2 {
		t.Fatalf("expected 2 mints (one per tenant), got %d", fake.issued)
	}
}

// TestBrokerRefreshesAtEightyPercentTTL proves the expiry-aware refresh: a
// cached token is served before 80% of its lifetime and proactively re-minted
// after.
func TestBrokerRefreshesAtEightyPercentTTL(t *testing.T) {
	t0 := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	current := t0
	clock := func() time.Time { return current }
	fake := &fakeAdapter{provider: ProviderAWS, ttl: 10 * time.Minute, now: clock}
	b, store := newTestBroker(t, fake)
	b.now = clock
	c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
	req := ScopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID}

	if _, err := b.TokenFor(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// 7 min elapsed (70% of TTL) → still cached.
	current = t0.Add(7 * time.Minute)
	if _, err := b.TokenFor(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if fake.issued != 1 {
		t.Fatalf("token inside the refresh window must be served from cache, mints=%d", fake.issued)
	}
	// 8.5 min elapsed (85% of TTL, still >30s before expiry) → proactive refresh.
	current = t0.Add(8*time.Minute + 30*time.Second)
	if _, err := b.TokenFor(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if fake.issued != 2 {
		t.Fatalf("token past 80%% TTL must be refreshed, mints=%d", fake.issued)
	}
}

// TestBrokerClampsFixedProviderLifetimes: providers with fixed token lifetimes
// the caller cannot shorten (Azure Entra: 60–90 min) are CLAMPED to the cap,
// not rejected; far-out lifetimes (>2× cap) are still rejected (see
// TestBrokerMaxLifetimeCap).
func TestBrokerClampsFixedProviderLifetimes(t *testing.T) {
	t0 := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return t0 }
	fake := &fakeAdapter{provider: ProviderAzure, ttl: 90 * time.Minute, now: clock}
	b, store := newTestBroker(t, fake)
	b.now = clock
	c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
	tok, err := b.TokenFor(context.Background(), ScopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatalf("a 90m provider token must be clamped, not rejected: %v", err)
	}
	if !tok.Expiry.Equal(t0.Add(time.Hour)) {
		t.Fatalf("expiry must be clamped to the 1h cap, got %v", tok.Expiry)
	}
}

func TestBrokerMaxLifetimeCap(t *testing.T) {
	// Provider returns a token valid far beyond the broker's max lifetime.
	fake := &fakeAdapter{provider: ProviderAWS, ttl: 24 * time.Hour}
	b, store := newTestBroker(t, fake)
	c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
	_, err := b.TokenFor(context.Background(), ScopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID, MaxLifetime: 24 * time.Hour})
	if !errors.Is(err, errBrokerTokenTooLong) {
		t.Fatalf("token exceeding max lifetime must be rejected, got %v", err)
	}
}

func TestBrokerFailsClosedForDisabledRevoked(t *testing.T) {
	fake := &fakeAdapter{provider: ProviderAWS}
	b, store := newTestBroker(t, fake)
	for _, state := range []LifecycleState{StateDisabled, StateRevoked, StateDraft, StateDeleted} {
		c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
		c.State = state
		if _, _, err := store.Update(context.Background(), c, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := b.TokenFor(context.Background(), ScopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID}); !errors.Is(err, ErrBrokerNotActive) {
			t.Fatalf("state %s must fail closed, got %v", state, err)
		}
	}
	if fake.issued != 0 {
		t.Fatalf("no token should be minted for non-collecting states, got %d", fake.issued)
	}
}

func TestBrokerSecretEncryptStoreResolveRedaction(t *testing.T) {
	fake := &fakeAdapter{provider: ProviderAWS}
	b, store := newTestBroker(t, fake)
	// Legacy static-key connector.
	c := Connector{
		TenantID: "t", ConnectorID: testConnID(), Provider: ProviderAWS,
		AuthMethod: AuthMethodStaticKey, State: StateActive,
		Identity: IdentityConfig{Provider: ProviderAWS},
	}
	created, err := store.Create(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := b.StoreSecret(context.Background(), "t", created.ConnectorID, ProviderAWS, "aws_secret_access_key", "AKIA123", "top-secret-value")
	if err != nil {
		t.Fatalf("store secret: %v", err)
	}
	// The API-facing secret ref never exposes the plaintext (ciphertext is json:"-").
	sr, found, _ := store.GetSecretRef(context.Background(), "t", false, ref)
	if !found {
		t.Fatal("secret ref not stored")
	}
	if sr.KeyHint != "AKIA123" {
		t.Fatalf("key hint mismatch: %q", sr.KeyHint)
	}
	// Attach ref to the connector and resolve via the broker (only path that decrypts).
	created.Identity.LegacySecretRef = ref
	if _, _, err := store.Update(context.Background(), created, 0); err != nil {
		t.Fatal(err)
	}
	got := mkActiveConnectorWithRef(t, store, created.ConnectorID)
	plain, err := b.resolveSecret(context.Background(), "t", got)
	if err != nil {
		t.Fatalf("resolve secret: %v", err)
	}
	if plain != "top-secret-value" {
		t.Fatalf("decrypted secret mismatch: %q", plain)
	}
	// Rotation bumps version and keeps the ref.
	found2, err := b.RotateSecret(context.Background(), "t", ref, created.ConnectorID, "AKIA999", "rotated-value")
	if err != nil || !found2 {
		t.Fatalf("rotate: found=%v err=%v", found2, err)
	}
	sr2, _, _ := store.GetSecretRef(context.Background(), "t", false, ref)
	if sr2.Version != 2 || sr2.KeyHint != "AKIA999" {
		t.Fatalf("rotation did not bump version/hint: %+v", sr2)
	}
}

func mkActiveConnectorWithRef(t *testing.T, store Repo, id string) Connector {
	t.Helper()
	c, found, err := store.Get(context.Background(), "t", false, id)
	if err != nil || !found {
		t.Fatalf("reload connector: found=%v err=%v", found, err)
	}
	return c
}
