package advisory

import (
	"context"
	"strings"

	"netops/backend/internal/vuln"
)

// MockProvider is an in-memory, scripted VendorAdvisoryProvider for tests. It
// carries advisories keyed by (vendor, normalized-platform) and returns those
// whose AffectedVersion constraint the query version satisfies (via
// VersionConstraint.Matches, the owned matcher). Set Fail to exercise a
// provider that cannot assess (ErrNotProvisioned / ErrNotConfigured / any error).
type MockProvider struct {
	name    string
	Fail    error // when non-nil, AdvisoriesFor returns it (models unassessed)
	scripts []scriptedAdvisory
}

type scriptedAdvisory struct {
	vendor   string // lowercased
	platform string // vuln.NormProduct-normalized
	adv      Advisory
}

// NewMockProvider makes an empty scripted provider. An empty name defaults to
// "mock".
func NewMockProvider(name string) *MockProvider {
	if name == "" {
		name = "mock"
	}
	return &MockProvider{name: name}
}

// Add scripts one advisory as affecting (vendor, platform) under adv's
// AffectedVersion constraint. It stamps adv.Source to the provider name (unless
// the caller already set one) and returns the receiver for chaining.
func (m *MockProvider) Add(vendor, platform string, adv Advisory) *MockProvider {
	if adv.Source == "" {
		adv.Source = m.name
	}
	m.scripts = append(m.scripts, scriptedAdvisory{
		vendor:   strings.ToLower(strings.TrimSpace(vendor)),
		platform: vuln.NormProduct(platform),
		adv:      adv,
	})
	return m
}

// Name identifies the mock provider.
func (m *MockProvider) Name() string { return m.name }

// AdvisoriesFor returns the scripted advisories matching the query. When Fail is
// set it is returned instead (models an unassessed provider).
func (m *MockProvider) AdvisoriesFor(ctx context.Context, q Query) ([]Advisory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.Fail != nil {
		return nil, m.Fail
	}
	vendor := strings.ToLower(strings.TrimSpace(q.Vendor))
	platform := vuln.NormProduct(q.Platform)
	var out []Advisory
	for _, s := range m.scripts {
		if s.vendor == vendor && s.platform == platform && s.adv.AffectedVersion.Matches(q.Version) {
			out = append(out, s.adv)
		}
	}
	return out, nil
}
