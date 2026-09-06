package backend

// audit_platform_trail_guard_test.go — the completeness guard under the
// retained audit trail (tracker 235).
//
// internal/audit decides which requests survive the 5,000-event request ring by
// matching a closed list of PLATFORM-GLOBAL path prefixes. A list like that
// rots the moment someone adds a route: the new platform surface would be
// audited into a ring that spans four hours on this deployment, and nobody
// would find out until the next "who changed this, and when?" went unanswered.
//
// So the list is not trusted — it is checked against the route isolation
// ledger, in BOTH directions:
//
//   - every route the ledger classifies "platform" MUST be retained. That is
//     the §3a rule-3 class: auth providers, LLM keys, token policy,
//     notification channels, stack config — precisely the changes the row was
//     opened for.
//   - no "public", "selfScoped" or "token" route may be. Those are login,
//     refresh, MFA self-service and inbound webhooks: the highest-frequency
//     POSTs on the platform. Retaining them would evict real config changes out
//     of a trail sized for a handful a week, re-creating the defect one level
//     down.

import (
	"testing"

	"netops/backend/internal/audit"
)

func TestEveryPlatformRouteIsRetainedInTheAuditTrail(t *testing.T) {
	platform, excluded := 0, 0
	for route, cat := range routeIsolationLedger {
		switch cat {
		case "platform":
			platform++
			if !audit.IsPlatformPath(route) {
				t.Errorf("PLATFORM ROUTE %q is not retained by the audit trail — a change to it "+
					"would age out of the request ring within hours. Add its prefix to "+
					"platformPathPrefixes in internal/audit/platformtrail.go.", route)
			}
		case "public", "selfScoped", "token":
			excluded++
			if audit.IsPlatformPath(route) {
				t.Errorf("%s route %q IS retained by the audit trail (category %q). These are the "+
					"highest-volume requests on the platform; retaining them evicts the config "+
					"changes the trail exists for. Add it to platformPathExclusions in "+
					"internal/audit/platformtrail.go.", cat, route, cat)
			}
		}
	}
	// Floors, so a ledger that stopped being parsed cannot make this guard a
	// silent no-op.
	if platform < 40 || excluded < 15 {
		t.Fatalf("the guard saw only %d platform and %d public/self/token routes — "+
			"it is not reading the ledger", platform, excluded)
	}
}
