package backend

// route_isolation_coverage_test.go — CLAUDE.md §3a RULE 5 enforcement.
//
// route_isolation_test.go requires every route to be CLASSIFIED. It does not
// enforce the second half of the rule: a route classified "scoped" (per-tenant
// DATA) must be BACKED BY a cross-org isolation test. That gap is exactly what
// let the cross-tenant alert-episode leak exist (fixed 3d22bb44): a scoped route
// shipped, correctly classified, with no test proving another tenant gets a 404.
//
// This guard closes the class GOING FORWARD, the way TestNoVoidSaveLocked did:
//   - a scoped route whose path is exercised by a real isolation test is COVERED;
//   - the routes that were scoped-but-not-HTTP-isolation-tested at the time this
//     guard landed are frozen in isolationCoverageBaseline below — they ARE
//     isolation-enforced (store RLS / chTenantScope / row policies, per the
//     ledger notes), they just lack a DEDICATED HTTP-path isolation test;
//   - a NEW scoped route that is neither covered nor baselined FAILS the build.
//
// The baseline only shrinks: write the dedicated isolation test and the route
// leaves the baseline naturally (it becomes auto-detected). Do NOT add to it —
// a new scoped route gets a test, not a baseline entry.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// isolationCoverageBaseline: scoped routes without a dedicated HTTP-path
// isolation test AT THE TIME THIS GUARD LANDED (2026-07-23). Each is
// isolation-enforced at the store/RLS layer (see routeIsolationLedger notes);
// the dedicated HTTP isolation test is backlog. FROZEN — do not grow.
var isolationCoverageBaseline = map[string]string{
	"/api/ai/modules":                         "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/apikeys/":                           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/appid/fusion/status":                "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/app-rca":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/apps":                         "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/attribution/coverage":         "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/business-services":            "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/business-services/":           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/changes":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/evidence":                     "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/identity-map":                 "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/investigations/":              "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/provider-events":              "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/resource-mappings":            "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/resource-mappings/":           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/seam-telemetry":               "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/cloud/security":                     "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/compliance":                         "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/copilot/chat":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/correlations/rca-reports":           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/correlations/stats":                 "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/correlations/summary":               "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/events":                             "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/events/feed":                        "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/findings":                           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/flows/by-proto":                     "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/flows/fanout":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/flows/flags":                        "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/flows/geo":                          "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/flows/timeseries":                   "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/infrastructure/port-filter-options": "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/integrations":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/integrations/":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/itsm/jira":                          "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/itsm/servicenow":                    "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/logs/export":                        "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/logs/export/rows":                   "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/logs/indices":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/logs/retention":                     "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/logs/search":                        "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/metrics/names":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/metrics/query":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/metrics/query_range":                "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/notify/contact-points":              "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/notify/contact-points/":             "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/notify/itsm":                        "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/regions/topology":                   "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/reliability/chronic-offenders":      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/reliability/trends":                 "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/reports/executions":                 "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/reports/executions/":                "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/reports/preview":                    "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/seams":                              "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/seams/":                             "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/seams/groups":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/seams/groups/":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/search/global":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/services":                           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/services/":                          "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/sessions":                           "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/sessions/":                          "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/snmp/options":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/tickets/audit":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/topology/links":                     "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/wan/circuits":                       "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/wan/endpoints":                      "store/RLS-scoped; dedicated HTTP isolation test is backlog",
	"/api/wan/policy":                         "store/RLS-scoped; dedicated HTTP isolation test is backlog",
}

// isolationTestFiles returns the non-test-ledger files that constitute real
// cross-org isolation tests: named *isolation*_test.go, or any test that asserts
// a cross-tenant 404 / as_tenant rejection.
func isolationTestCorpus(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var b strings.Builder
	markers := regexp.MustCompile(`cross-tenant|CrossOrg|as_tenant|StatusNotFound`)
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, "_test.go") || n == "route_isolation_test.go" || n == "route_isolation_coverage_test.go" {
			continue
		}
		data, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		if strings.Contains(n, "isolation") || markers.Match(data) {
			b.Write(data)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func TestEveryScopedRouteHasIsolationCoverage(t *testing.T) {
	corpus := isolationTestCorpus(t)
	if len(corpus) < 5000 {
		t.Fatalf("isolation-test corpus is suspiciously small (%d bytes) — the guard would pass vacuously", len(corpus))
	}
	scoped := 0
	for route, cat := range routeIsolationLedger {
		if cat != "scoped" {
			continue
		}
		scoped++
		if strings.Contains(corpus, route) {
			// A frozen baseline entry that now HAS a real test should be removed
			// from the baseline — keep the baseline honest (only genuine gaps).
			if _, ok := isolationCoverageBaseline[route]; ok {
				t.Errorf("%s now has a real isolation test — remove it from isolationCoverageBaseline "+
					"(the baseline must only list genuinely-untested routes).", route)
			}
			continue
		}
		if _, ok := isolationCoverageBaseline[route]; ok {
			continue // known pre-existing gap, store/RLS-covered
		}
		t.Errorf(`SCOPED ROUTE WITHOUT AN ISOLATION TEST: %q (CLAUDE.md §3a rule 5).

  A per-tenant "scoped" route must be backed by a cross-org isolation test
  proving another tenant gets a 404 (existence hidden), own-only list, and that
  as_tenant into another org is ignored. org_isolation_test.go is the template.
  This is the gap that let the cross-tenant episode leak ship.

  Fix: add an isolation test that exercises %q. Do NOT add it to
  isolationCoverageBaseline — that set is frozen for pre-existing routes.`, route, route)
	}
	if scoped == 0 {
		t.Fatal("no scoped routes found — the ledger regex changed; guard is blind")
	}
}
