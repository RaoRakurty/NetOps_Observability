package main

// route_isolation_test.go — the isolation COVERAGE GUARD (CLAUDE.md §3a).
//
// It extracts every /api/* route registered in main.go and fails if any route is
// not classified in routeIsolationLedger below. A new data endpoint therefore
// cannot ship unclassified — the author MUST consciously declare how it is
// isolated (and, for tenant-scoped data, back it with an isolation test). This is
// the structural backstop that would have caught the unscoped sites endpoint on
// day one.
//
// Categories (the declared isolation posture of each route):
//   scoped      — per-tenant DATA: must filter by principalTenant(claims); a
//                 cross-org isolation test is expected (org_isolation_test.go).
//   adminScoped — identity/admin data scoped to the caller's tenant/org by the
//                 handler (users, tenants, orgs, bindings, audit, policy).
//   platform    — platform-GLOBAL plumbing, platform-owner only
//                 (requirePlatformAdmin / requireCrossTenant / isPlatformOwner).
//   globalRef   — platform-wide reference data, readable by admins, mutated only
//                 by the platform owner (roles, snmp profiles, region catalog).
//   infra       — stack-wide infrastructure monitoring, intentionally global,
//                 platform/cross gated (collectors, stack health, probe paths).
//   selfScoped  — the caller's OWN identity only (me, mfa, scopes, permissions).
//   token       — capability-link / token-authenticated, not principal-scoped
//                 (export links, report view, inbound webhooks).
//   public      — unauthenticated or pure auth-flow; returns no tenant data.
//
// To add a route: add it here with the right category. If it returns tenant data,
// use `scoped` and add/extend a cross-org isolation test.

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

var routeIsolationLedger = map[string]string{
	// ── per-tenant data (scoped) ──
	"/api/alerts":                 "scoped",
	"/api/compliance":             "scoped",
	"/api/correlations":           "scoped",
	"/api/correlations/":          "scoped", // incl. {id}/time-metrics + {id}/time-events (#84): chRows(chTenantScope) reads + tenant-stamped RLS writes (store isolation test); manual writes audited
	"/api/correlations/stats":     "scoped",
	// RCA Time Intelligence reliability rollups (#84) — aggregate ONLY the caller's
	// own incidents: chRows injects chTenantScope, ClickHouse row policies enforce it
	// (TestChTenantScope). A tenant never sees another tenant's MTTI/MTBF/offenders.
	"/api/reliability/rollups":           "scoped",
	"/api/reliability/trends":            "scoped",
	"/api/reliability/chronic-offenders": "scoped",
	"/api/credentials":            "scoped",
	"/api/devices":                "scoped",
	"/api/devices/":               "scoped",
	"/api/events":                 "scoped",
	"/api/events/feed":            "scoped",
	"/api/findings":               "scoped",
	"/api/flows/by-proto":         "scoped",
	"/api/flows/by-type":          "scoped",
	"/api/flows/fanout":           "scoped",
	"/api/flows/flags":            "scoped",
	"/api/flows/geo":              "scoped",
	"/api/flows/services":         "scoped",
	"/api/flows/timeseries":       "scoped",
	"/api/flows/top":              "scoped",
	"/api/flows/topn":             "scoped",
	"/api/geomap":                 "scoped",
	"/api/graphql":                "scoped",
	"/api/health/score":           "scoped",
	"/api/incidents":              "scoped",
	"/api/incidents/":             "scoped",
	"/api/integrations":           "scoped",
	"/api/integrations/":          "scoped",
	"/api/itsm/jira":              "scoped",
	"/api/itsm/servicenow":        "scoped",
	"/api/logs/export":            "scoped",
	"/api/logs/export/rows":       "scoped",
	"/api/logs/indices":           "scoped",
	"/api/logs/search":            "scoped",
	"/api/metrics":                "scoped",
	"/api/metrics/forecast":       "scoped",
	"/api/metrics/names":          "scoped",
	"/api/metrics/query":          "scoped",
	"/api/metrics/query_range":    "scoped",
	"/api/notify/contact-points":  "scoped",
	"/api/notify/contact-points/": "scoped",
	"/api/notify/itsm":            "scoped",
	"/api/regions/topology":       "scoped",
	"/api/reports/channels":       "scoped",
	"/api/reports/executions":     "scoped",
	"/api/reports/executions/":    "scoped",
	"/api/reports/preview":        "scoped",
	"/api/reports/run":            "scoped",
	"/api/reports/runs":           "scoped",
	"/api/rules":                  "scoped",
	"/api/saved":                  "scoped",
	"/api/saved/":                 "scoped",
	"/api/search/global":          "scoped",
	"/api/seams":                  "scoped",
	"/api/seams/":                 "scoped",
	"/api/seams/groups":           "scoped",
	"/api/seams/groups/":          "scoped",
	"/api/services":               "scoped",
	"/api/services/":              "scoped",
	"/api/sites":                  "scoped",
	"/api/sites/":                 "scoped",
	"/api/sot/import":             "scoped",
	"/api/snmp/credentials":       "scoped",
	"/api/snmp/credentials/":      "scoped",
	"/api/snmp/options":           "scoped",
	"/api/tunnels":                "scoped",
	"/api/topology/links":         "scoped",
	"/api/topology/view":          "scoped",
	"/api/topology/graph":         "scoped",
	"/api/vulns":                  "scoped",
	"/api/apikeys":                "scoped",
	"/api/apikeys/":               "scoped",
	"/api/sessions":               "scoped",
	"/api/sessions/":              "scoped",
	"/api/copilot/chat":           "scoped",

	// ── Application Identification + Cloud App Observability (#81), tenant-scoped ──
	// appid resolve/status reflect the caller's tenant view (operator overrides +
	// NGFW + cloud identity-map are all default-closed per tenant); cloud inventory
	// + applications are principalTenant-scoped with store isolation tests
	// (TestCloudStoreIsolation, appid_isolation_test.go, cloud_appid_resolver_test.go).
	"/api/appid/resolve":               "scoped",
	"/api/appid/status":                "scoped",
	"/api/appid/catalog":               "scoped",
	"/api/appid/catalog/":              "scoped",
	"/api/applications":                "scoped",
	"/api/applications/":               "scoped",
	"/api/flows/apps":                  "scoped",
	"/api/cloud/apps":                  "scoped",
	"/api/cloud/resources":            "scoped",
	"/api/cloud/identity-map":          "scoped",
	"/api/cloud/attribution/coverage":  "scoped",

	// ── identity/admin, scoped to caller's tenant/org by the handler ──
	"/api/audit":             "adminScoped",
	"/api/users":             "adminScoped",
	"/api/users/":            "adminScoped",
	"/api/users/mfa-reset":   "adminScoped",
	"/api/tenants":           "adminScoped",
	"/api/tenants/":          "adminScoped",
	"/api/orgs":              "adminScoped",
	"/api/orgs/":             "adminScoped",
	"/api/bindings":          "adminScoped",
	"/api/bindings/":         "adminScoped",
	"/api/access/explain":    "adminScoped",
	"/api/security-settings": "adminScoped",
	"/api/policy/catalog":    "adminScoped",
	"/api/policy/document":   "adminScoped",
	"/api/policy/documents":  "adminScoped",
	"/api/policy/effective":  "adminScoped",
	"/api/policy/validate":   "adminScoped",

	// ── platform-GLOBAL plumbing, platform-owner only ──
	"/api/auth/ldap/config":       "platform",
	"/api/auth/ldap/test":         "platform",
	"/api/auth/tacacs/config":     "platform",
	"/api/auth/tacacs/test":       "platform",
	"/api/auth/oidc/config":       "platform",
	"/api/auth/sso/config":        "platform",
	"/api/auth/token-policy":      "platform",
	"/api/copilot/config":         "platform",
	"/api/automation/netbox":      "platform",
	"/api/automation/netbox/sync": "platform",
	"/api/notify/smtp":            "platform",
	"/api/notify/smtp/test":       "platform",
	"/api/notify/slack":           "platform",
	"/api/notify/slack/test":      "platform",
	"/api/notify/twilio":          "platform",
	"/api/notify/twilio/test":     "platform",
	"/api/notify/ntfy":            "platform",
	"/api/notify/ntfy/test":       "platform",
	"/api/notify/pagerduty":       "platform",
	"/api/notify/pagerduty/test":  "platform",
	"/api/exports/policy":         "platform",
	"/api/breakglass":             "platform",
	"/api/breakglass/":            "platform",
	"/api/onboard":                "platform",
	"/api/discovery/refresh":      "platform",
	"/api/integrations/reconcile": "platform",

	// ── platform-wide reference data (admin-readable, owner-mutated) ──
	"/api/roles":          "globalRef",
	"/api/roles/":         "globalRef",
	"/api/snmp/profiles":  "globalRef",
	"/api/snmp/profiles/": "globalRef",
	"/api/regions":        "globalRef",

	// ── stack-wide infrastructure monitoring (intentionally global) ──
	"/api/collectors":   "infra",
	"/api/stack/health": "infra",
	"/api/health":       "infra",
	"/api/paths/health": "infra",
	"/api/probe/paths":  "infra",

	// ── caller's OWN identity only ──
	"/api/auth/me":              "selfScoped",
	"/api/auth/change-password": "selfScoped",
	"/api/auth/permissions":     "selfScoped",
	"/api/auth/mfa/activate":    "selfScoped",
	"/api/auth/mfa/disable":     "selfScoped",
	"/api/auth/mfa/setup":       "selfScoped",
	"/api/auth/mfa/status":      "selfScoped",
	"/api/scopes":               "selfScoped",

	// ── capability-link / token-authenticated (not principal-scoped) ──
	"/api/exports/":              "token",
	"/api/exports/view/":         "token",
	"/api/reports/view/":         "token",
	"/api/integrations/webhook/": "token",

	// ── unauthenticated / pure auth-flow (no tenant data) ──
	"/api/auth/login":           "public",
	"/api/auth/logout":          "public",
	"/api/auth/methods":         "public",
	"/api/auth/refresh":         "public",
	"/api/auth/console-gate":    "public",
	"/api/auth/osd-gate":        "public",
	"/api/auth/password-policy": "public",
	"/api/auth/sso/callback":    "public",
	"/api/auth/sso/login":       "public",
	"/api/auth/ldap/login":      "public",
	"/api/auth/tacacs/login":    "public",
	"/api/auth/mfa/login":       "public",
	"/api/openapi.json":         "public",
}

var validRouteCategories = map[string]bool{
	"scoped": true, "adminScoped": true, "platform": true, "globalRef": true,
	"infra": true, "selfScoped": true, "token": true, "public": true,
}

// registeredAPIRoutes parses main.go for every mux.HandleFunc("/api/...") pattern.
func registeredAPIRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(/api/[^"]+)"`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryRouteClassified — the guard. Every registered /api route MUST be in the
// ledger with a valid category; every ledger entry MUST still be a real route.
func TestEveryRouteClassified(t *testing.T) {
	routes := registeredAPIRoutes(t)
	if len(routes) == 0 {
		t.Fatal("no /api routes parsed from main.go — guard would be a no-op")
	}
	live := map[string]bool{}
	for _, r := range routes {
		live[r] = true
		cat, ok := routeIsolationLedger[r]
		if !ok {
			t.Errorf("UNCLASSIFIED ROUTE %q — classify it in routeIsolationLedger "+
				"(CLAUDE.md §3a): tenant DATA → \"scoped\" + a cross-org isolation test; "+
				"platform plumbing → \"platform\"; else infra/globalRef/selfScoped/token/public with intent.", r)
			continue
		}
		if !validRouteCategories[cat] {
			t.Errorf("route %q has unknown category %q", r, cat)
		}
	}
	// Stale ledger entries (route removed/renamed) — keep the ledger honest.
	for r := range routeIsolationLedger {
		if !live[r] {
			t.Errorf("STALE ledger entry %q — no longer registered in main.go; remove it.", r)
		}
	}
}
