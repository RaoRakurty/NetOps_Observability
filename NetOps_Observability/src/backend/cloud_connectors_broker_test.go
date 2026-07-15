package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/cloudconn"
)

// fakeAdapter is a test double for a provider that returns a deterministic token
// so the broker's caching / isolation / lifetime logic is testable without any
// cloud network. It records the last ExchangeRequest so tests can assert the
// broker passed the decrypted legacy secret only when appropriate.
type fakeAdapter struct {
	provider cloudconn.Provider
	issued   int
	lastReq  cloudconn.ExchangeRequest
	ttl      time.Duration
}

func (f *fakeAdapter) Provider() cloudconn.Provider { return f.provider }
func (f *fakeAdapter) ValidateConfiguration(cloudconn.IdentityConfig) cloudconn.ValidationResult {
	return cloudconn.ValidationResult{OK: true}
}
func (f *fakeAdapter) SetupInstructions(cloudconn.IdentityConfig, cloudconn.CapabilityPack) (cloudconn.SetupBundle, error) {
	return cloudconn.SetupBundle{}, nil
}
func (f *fakeAdapter) ExchangeCredential(_ context.Context, req cloudconn.ExchangeRequest) (cloudconn.ScopedToken, error) {
	f.issued++
	f.lastReq = req
	ttl := f.ttl
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return cloudconn.ScopedToken{Provider: f.provider, Value: "tok-secret-value", Expiry: time.Now().UTC().Add(ttl)}, nil
}
func (f *fakeAdapter) DiscoverScopes(context.Context, cloudconn.DiscoverRequest) ([]cloudconn.Scope, error) {
	return nil, nil
}
func (f *fakeAdapter) ValidateCapabilities(context.Context, cloudconn.CapabilityCheckRequest) (cloudconn.CapabilityReport, error) {
	return cloudconn.CapabilityReport{}, nil
}
func (f *fakeAdapter) Revoke(context.Context, cloudconn.RevokeRequest) error { return nil }

func newTestBroker(t *testing.T, fake *fakeAdapter) (*cloudIdentityBroker, cloudConnRepo) {
	t.Helper()
	store := newMemCloudConnStore()
	b := newCloudIdentityBroker(store, nil /* dormant vault: passthrough */, nil)
	b.adapter = func(cloudconn.Provider) cloudconn.CloudIdentityProvider { return fake }
	return b, store
}

func mkActiveConnector(t *testing.T, store cloudConnRepo, tenant, role string) cloudConnector {
	t.Helper()
	c := cloudConnector{
		TenantID: tenant, ConnectorID: newOpaqueID(ccnIDPrefix), Provider: cloudconn.ProviderAWS,
		AuthMethod: cloudconn.AuthMethodCloudRole, State: cloudconn.StateActive,
		Identity: cloudconn.IdentityConfig{Provider: cloudconn.ProviderAWS, RoleARN: role, ExternalID: cloudconn.NewExternalID()},
	}
	created, err := store.Create(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestBrokerTokenCacheTenantConnectorIsolation(t *testing.T) {
	fake := &fakeAdapter{provider: cloudconn.ProviderAWS}
	b, store := newTestBroker(t, fake)
	// Two tenants, IDENTICAL role ARN + provider account — the cache must NOT
	// collapse them into one entry.
	const sameRole = "arn:aws:iam::123456789012:role/correlix-observer"
	ca := mkActiveConnector(t, store, "tenant-a", sameRole)
	cb := mkActiveConnector(t, store, "tenant-b", sameRole)

	reqA := scopedTokenRequest{Tenant: "tenant-a", ConnectorID: ca.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}
	reqB := scopedTokenRequest{Tenant: "tenant-b", ConnectorID: cb.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}

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
	if _, err := b.TokenFor(context.Background(), scopedTokenRequest{Tenant: "tenant-b", ConnectorID: ca.ConnectorID, ProviderAccount: "123456789012"}); !errors.Is(err, errBrokerNotFound) {
		t.Fatalf("cross-tenant token request must fail closed, got %v", err)
	}
}

func TestBrokerMaxLifetimeCap(t *testing.T) {
	// Provider returns a token valid far beyond the broker's max lifetime.
	fake := &fakeAdapter{provider: cloudconn.ProviderAWS, ttl: 24 * time.Hour}
	b, store := newTestBroker(t, fake)
	c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
	_, err := b.TokenFor(context.Background(), scopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID, MaxLifetime: 24 * time.Hour})
	if !errors.Is(err, errBrokerTokenTooLong) {
		t.Fatalf("token exceeding max lifetime must be rejected, got %v", err)
	}
}

func TestBrokerFailsClosedForDisabledRevoked(t *testing.T) {
	fake := &fakeAdapter{provider: cloudconn.ProviderAWS}
	b, store := newTestBroker(t, fake)
	for _, state := range []cloudconn.LifecycleState{cloudconn.StateDisabled, cloudconn.StateRevoked, cloudconn.StateDraft, cloudconn.StateDeleted} {
		c := mkActiveConnector(t, store, "t", "arn:aws:iam::1:role/x")
		c.State = state
		if _, _, err := store.Update(context.Background(), c, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := b.TokenFor(context.Background(), scopedTokenRequest{Tenant: "t", ConnectorID: c.ConnectorID}); !errors.Is(err, errBrokerNotActive) {
			t.Fatalf("state %s must fail closed, got %v", state, err)
		}
	}
	if fake.issued != 0 {
		t.Fatalf("no token should be minted for non-collecting states, got %d", fake.issued)
	}
}

func TestBrokerSecretEncryptStoreResolveRedaction(t *testing.T) {
	fake := &fakeAdapter{provider: cloudconn.ProviderAWS}
	b, store := newTestBroker(t, fake)
	// Legacy static-key connector.
	c := cloudConnector{
		TenantID: "t", ConnectorID: newOpaqueID(ccnIDPrefix), Provider: cloudconn.ProviderAWS,
		AuthMethod: cloudconn.AuthMethodStaticKey, State: cloudconn.StateActive,
		Identity: cloudconn.IdentityConfig{Provider: cloudconn.ProviderAWS},
	}
	created, err := store.Create(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := b.StoreSecret(context.Background(), "t", created.ConnectorID, cloudconn.ProviderAWS, "aws_secret_access_key", "AKIA123", "top-secret-value")
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

func mkActiveConnectorWithRef(t *testing.T, store cloudConnRepo, id string) cloudConnector {
	t.Helper()
	c, found, err := store.Get(context.Background(), "t", false, id)
	if err != nil || !found {
		t.Fatalf("reload connector: found=%v err=%v", found, err)
	}
	return c
}
