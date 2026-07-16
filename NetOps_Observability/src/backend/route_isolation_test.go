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
	// Iris AI: /ask is tenant DATA — the orchestrator reads only via the
	// tenant-scoped aiDataSource (corr_objects/flows/findings row policies; scope
	// from chTenantScope), proven by ai/orchestrator_test.go cross-tenant tests.
	// /modules lists the caller's enabled modules (tenant config).
	"/api/ai/ask":     "scoped",
	"/api/ai/modules": "scoped",
	// Per-tenant AI settings (P4a): the record read/written is ALWAYS the
	// caller's own tenant (principalTenant, §3a.2 — tenant never taken from the
	// request); the BYO key is write-only and sealed under the tenant DEK.
	// Cross-tenant isolation proven by ai_tenant_config_test.go.
	"/api/ai/tenant-config": "scoped",
	// Static, identical-for-everyone reference: the slash-command registry + the
	// caller's own answer feedback (audited). No tenant data crosses these.
	"/api/ai/commands":                         "selfScoped",
	"/api/ai/commands/suggestions":             "selfScoped",
	"/api/ai/feedback":                         "scoped", // POST own rating (tenant-stamped); GET tenant-scoped aggregate (store RLS)
	"/api/alerts":                              "scoped",
	"/api/compliance":                          "scoped",
	"/api/correlations":                        "scoped",
	"/api/correlations/":                       "scoped", // incl. {id}/time-metrics + {id}/time-events (#84): chRows(chTenantScope) reads + tenant-stamped RLS writes (store isolation test); manual writes audited
	"/api/correlations/stats":                  "scoped",
	"/api/correlations/undetermined-frequency": "scoped", // #80: chRows(chTenantScope) over corr_objects — a tenant ranks only its OWN undetermined gaps
	"/api/rca/":                                "scoped", // Service Path Graph §7 ordered spine: principalTenant → pathGraphStore (tenant-keyed store / RLS+row-policy) + chTenantScope for the corr→path lookup; two-tenant isolation test = path_graph_isolation_test.go
	// RCA Time Intelligence reliability rollups (#84) — aggregate ONLY the caller's
	// own incidents: chRows injects chTenantScope, ClickHouse row policies enforce it
	// (TestChTenantScope). A tenant never sees another tenant's MTTI/MTBF/offenders.
	"/api/reliability/rollups":           "scoped",
	"/api/reliability/trends":            "scoped",
	"/api/reliability/chronic-offenders": "scoped",
	// GET lists the caller's OWN persisted snapshots (principalTenant + store
	// default-closed filter / RLS); POST triggers the cross-tenant backfill worker
	// behind requirePlatformAdmin. The data surface is tenant-scoped.
	"/api/reliability/time-metrics": "scoped",
	"/api/credentials":              "scoped",
	"/api/devices":                  "scoped",
	"/api/devices/":                 "scoped",
	// Port Intelligence (#94): every port/interface/optics read is tenant DATA,
	// scoped by requirePerm(infrastructure:read) + the portStore RLS/tenant
	// filter (cross-tenant get → 404); proven by port_handlers_test.go.
	"/api/infrastructure/interfaces":           "scoped",
	"/api/infrastructure/interfaces/":          "scoped",
	"/api/infrastructure/port-summary":         "scoped",
	"/api/infrastructure/port-filter-options":  "scoped",
	// Static reference (identical for everyone; no tenant data).
	"/api/infrastructure/module-types":   "selfScoped",
	"/api/infrastructure/port-signatures": "selfScoped",
	"/api/events":                   "scoped",
	"/api/events/feed":              "scoped",
	"/api/findings":                 "scoped",
	"/api/flows/by-proto":           "scoped",
	"/api/flows/by-type":            "scoped",
	"/api/flows/fanout":             "scoped",
	"/api/flows/flags":              "scoped",
	"/api/flows/geo":                "scoped",
	"/api/flows/services":           "scoped",
	"/api/flows/timeseries":         "scoped",
	"/api/flows/top":                "scoped",
	"/api/flows/topn":               "scoped",
	"/api/geomap":                   "scoped",
	"/api/graphql":                  "scoped",
	"/api/health/score":             "scoped",
	"/api/incidents":                "scoped",
	"/api/incidents/":               "scoped",
	// RCA auto-ticketing #78 P3: incident policies + outbox/audit are per-tenant
	// data — requirePerm + principalTenant scope, tenant stamped from token, store
	// isolation + HTTP cross-tenant tests (ticketing_isolation_test/ticketing_http_test).
	"/api/incident-policies":      "scoped",
	"/api/incident-policies/":     "scoped",
	"/api/tickets/audit":          "scoped",
	"/api/tickets/outbox":         "scoped",
	// #103 UX-1 notified-via read: per-tenant ticket links (requirePerm +
	// principalTenant; store-level scope). Cross-org test: ticketing_links_test.go.
	"/api/tickets/links": "scoped",
	"/api/integrations":           "scoped",
	"/api/integrations/":          "scoped",
	// NMS vendor-controller integrations (#95): per-tenant config/health/state,
	// tenant stamped from the principal, cross-tenant id → 404. Cross-org
	// isolation test: nms_isolation_test.go (TestNMSCrossOrgIsolation).
	"/api/nms/integrations":  "scoped",
	"/api/nms/integrations/": "scoped",
	"/api/itsm/jira":              "scoped",
	"/api/itsm/servicenow":        "scoped",
	// #103 tenant RCA policy destinations: per-tenant connection config (routing
	// key / webhook are write-only secrets, tenant from the principal). Isolation
	// coverage: ticketing_pagerduty_test.go (two-tenant key isolation) +
	// ticketing_http_test.go.
	"/api/itsm/pagerduty-rca": "scoped",
	"/api/itsm/slack-rca":     "scoped",
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
	"/api/wan/interfaces":         "scoped",
	"/api/wan/endpoints":          "scoped",
	"/api/wan/circuits":           "scoped",
	"/api/wan/policy":             "scoped",
	"/api/topology/links":         "scoped",
	"/api/topology/view":          "scoped",
	"/api/topology/graph":         "scoped",
	"/api/topology/cloud":         "scoped",
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
	"/api/appid/resolve":              "scoped",
	"/api/appid/status":               "scoped",
	"/api/appid/fusion/status":        "scoped",
	"/api/appid/catalog":              "scoped",
	"/api/appid/catalog/":             "scoped",
	"/api/applications":               "scoped",
	"/api/applications/":              "scoped",
	"/api/flows/apps":                 "scoped",
	"/api/cloud/apps":                 "scoped",
	"/api/cloud/resources":            "scoped",
	"/api/cloud/identity-map":         "scoped",
	"/api/cloud/attribution/coverage": "scoped",
	"/api/cloud/app-rca":              "scoped",
	// Cloud Network Overview roll-up (P1): tenant DATA — inventory via
	// principalTenant-scoped cloud store, issues via tenant_scope row policies;
	// cross-org proof in cloud_network_overview_test.go.
	"/api/cloud/network/overview": "scoped",
	// Business Service mapping + manual overrides (migration 0024): tenant DATA,
	// requirePerm + principalTenant + FORCE-RLS; cross-org proof in
	// business_service_isolation_test.go.
	"/api/cloud/business-services":     "scoped",
	"/api/cloud/business-services/":    "scoped",
	"/api/cloud/resource-mappings":     "scoped",
	"/api/cloud/resource-mappings/":    "scoped",
	// #81 P3H cloud telemetry reads — every query carries the caller's tenant_scope,
	// which the corr_signals / corr_signals_archive / corr_objects FORCE row policies
	// enforce in ClickHouse (see cloud_signals.go, cloud_ingestion.go).
	"/api/cloud/ingestion": "scoped",
	"/api/cloud/health":    "scoped",
	"/api/cloud/changes":   "scoped",
	"/api/cloud/evidence":  "scoped",

	// ── Cloud Connector framework ──
	// Connectors are per-tenant DATA (each tenant's cloud connections); scoped +
	// backed by cloud_connectors_isolation_test.go.
	"/api/cloud/connectors":  "scoped",
	"/api/cloud/connectors/": "scoped",
	// Provider/method/capability-pack catalog: static, platform-wide reference
	// data (identical for every tenant), infra-read gated.
	"/api/cloud/providers": "globalRef",

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
	// AI entitlement per tenant is platform PACKAGING (which tenants get the
	// assistant / the agent loop) — requirePlatformAdmin, a tenant admin must
	// never grant itself investigations (§3a.3).
	"/api/ai/tenants":             "platform",
	"/api/ai/tenants/":            "platform",
	"/api/auth/ldap/config":       "platform",
	"/api/auth/ldap/test":         "platform",
	"/api/auth/tacacs/config":     "platform",
	"/api/auth/tacacs/test":       "platform",
	"/api/auth/oidc/config":       "platform",
	"/api/auth/sso/config":        "platform",
	"/api/auth/token-policy":      "platform",
	"/api/copilot/config":         "platform",
	// Per-tenant ingestion service surface (Wave 1 #2): the cloud-ingest poller's
	// platform credential (ingest:cloud API key in the global realm). It fans one
	// poller across EVERY tenant's connectors, so it is platform plumbing by
	// definition — requireCloudIngestService fails tenant-bound principals closed
	// (cloud_ingest_service_test.go covers the isolation matrix).
	"/api/cloud/ingest/connectors":  "platform",
	"/api/cloud/ingest/connectors/": "platform",
	"/api/system/network":         "platform",
	"/api/system/network/test":    "platform",
	"/api/automation/netbox":      "platform",
	"/api/automation/netbox/sync": "platform",
	"/api/discovery/config":       "platform", // subnet-scan scope: directs the platform prober (#91)
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
	// SNMP config generator — platform-owner action that mints a credential.
	"/api/onboard/snmp-config":    "platform",
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
	// NMS controller webhook: JWT-exempt; authenticated by opaque path token +
	// the connector's signature verification, tenant derived from the token row.
	"/api/nms/webhook/": "token",
	// NMS connector catalog: static vendor specs (no tenant data, auth required).
	"/api/nms/connectors": "globalRef",

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
