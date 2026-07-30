package backend

import (
	"context"
	"time"

	"crypto/rand"
	"encoding/hex"
	"netops/backend/cloudconn"
	"testing"
)

// Duplicated fixture (test files cannot cross packages): the fake cloud
// identity adapter shared by ingest/isolation/org suites.
// fakeAdapter is a test double for a provider that returns a deterministic token
// so the broker's caching / isolation / lifetime logic is testable without any
// cloud network. It records the last cloudconn.ExchangeRequest so tests can assert the
// broker passed the decrypted legacy secret only when appropriate.
type fakeAdapter struct {
	provider cloudconn.Provider
	issued   int
	lastReq  cloudconn.ExchangeRequest
	ttl      time.Duration
	now      func() time.Time // controllable clock; nil = time.Now
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
	now := time.Now
	if f.now != nil {
		now = f.now
	}
	// The value is bound to the connector's ExternalId + mint count, so tests can
	// prove WHICH connector a served credential was minted for (isolation) and
	// WHEN it was refreshed.
	return cloudconn.ScopedToken{
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
func (f *fakeAdapter) DiscoverScopes(context.Context, cloudconn.DiscoverRequest) ([]cloudconn.Scope, error) {
	return nil, nil
}
func (f *fakeAdapter) ValidateCapabilities(context.Context, cloudconn.CapabilityCheckRequest) (cloudconn.CapabilityReport, error) {
	return cloudconn.CapabilityReport{}, nil
}
func (f *fakeAdapter) Revoke(context.Context, cloudconn.RevokeRequest) error { return nil }

// mkActiveConnector duplicates the package fixture: an ACTIVE AWS-role
// connector seeded straight into the store.
func mkActiveConnector(t *testing.T, store cloudconn.Repo, tenant, role string) cloudconn.Connector {
	t.Helper()
	c := cloudconn.Connector{
		TenantID: tenant, ConnectorID: testConnID(), Provider: cloudconn.ProviderAWS,
		AuthMethod: cloudconn.AuthMethodCloudRole, State: cloudconn.StateActive,
		Identity: cloudconn.IdentityConfig{Provider: cloudconn.ProviderAWS, RoleARN: role, ExternalID: cloudconn.NewExternalID()},
	}
	created, err := store.Create(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func testConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return cloudconn.ConnectorIDPrefix + hex.EncodeToString(b)
}
