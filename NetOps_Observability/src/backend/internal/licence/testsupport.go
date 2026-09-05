package licence

import (
	"fmt"
	"io/fs"
	"time"

	"netops/backend/internal/entitlement"
)

// testsupport.go — a Store backed by a fixed State, for tests and harnesses.
//
// It exists for ONE job, and the job is worth being explicit about.
//
// The gates this package feeds sit on real admission paths — creating a device,
// creating a tenant, adding a watched prefix. The backend's test corpus builds
// fleets and multi-org fixtures through those very handlers, and none of that
// is about licensing: an isolation test asserting that tenant A cannot see
// tenant B's rows must assert exactly that, at full strength, and must not
// start failing because its fixture happened to need a second tenant.
//
// So the shared harness wires a StaticStore that grants everything, which makes
// the test corpus LICENCE-NEUTRAL — every existing test behaves exactly as it
// did before the licence mechanism existed. The gates themselves are proved
// separately and deliberately, against real signed documents, in
// licence_routes_test.go and this package's own tests.
//
// This is test support, not a back door: it is ordinary in-process Go, so
// anything able to call it could equally well skip the gate. Real deployments
// are gated by the signed file (and, per the design, by contract). What it must
// never become is a production code path — nothing outside a test or a test
// harness may construct one, and `Source` deliberately reports the state it was
// given so a StaticStore-backed deployment would be visibly wrong on the admin
// page rather than quietly plausible.

// StaticStore is a Store over a fixed State. Installs are refused: a fixed
// state is fixed, and silently accepting a write nobody can read back would be
// the worst of both worlds.
type StaticStore struct{ state State }

// NewStaticStore returns a Store that always reports st.
func NewStaticStore(st State) *StaticStore { return &StaticStore{state: st} }

// Unlimited is the licence-neutral state: every ceiling unlimited and every
// feature in the closed vocabulary granted.
//
// Its tier is Enterprise for display purposes only — nothing branches on tier,
// which is the whole point of the semantic entitlement model.
func Unlimited() State {
	return State{
		Source:       SourceFile,
		Tier:         entitlement.TierEnterprise,
		LicensedTier: entitlement.TierEnterprise,
		Customer:     "test harness",
		LicenceID:    "test-harness-unlimited",
		Ceilings: entitlement.Ceilings{
			Devices:              entitlement.Unlimited,
			Tenants:              entitlement.Unlimited,
			Orgs:                 entitlement.Unlimited,
			RetentionDays:        entitlement.Unlimited,
			WatchedPrefixes:      entitlement.Unlimited,
			Skills:               entitlement.Unlimited,
			ProviderTokensPerDay: entitlement.Unlimited,
		},
		Features:  entitlement.Features(),
		IssuedAt:  time.Unix(0, 0).UTC(),
		ExpiresAt: time.Unix(0, 0).UTC().AddDate(100, 0, 0),
	}
}

// NewUnlimitedService is the licence-neutral entitlement service the shared
// test harness wires. See this file's doc comment for why.
func NewUnlimitedService() *Service { return NewService(NewStaticStore(Unlimited())) }

func (s *StaticStore) State() State  { return s.state }
func (s *StaticStore) Reload() State { return s.state }

func (s *StaticStore) Install([]byte, time.Time) (State, error) {
	return s.state, fmt.Errorf("licence: this deployment's licence is fixed and cannot be replaced through the API")
}

func (s *StaticStore) Raw() ([]byte, error) {
	return nil, fmt.Errorf("licence: no document backs this state: %w", fs.ErrNotExist)
}

func (s *StaticStore) Remove() (State, error) {
	return s.state, fmt.Errorf("licence: this deployment's licence is fixed and cannot be removed through the API")
}

func (s *StaticStore) Path() string { return "(fixed, not a file)" }
