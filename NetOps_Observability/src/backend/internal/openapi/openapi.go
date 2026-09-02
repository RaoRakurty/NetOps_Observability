package openapi

import ()

// openapi.go — a self-describing OpenAPI 3.0 document for the public REST API.
//
// It is assembled from a small in-code route registry so it can't drift far
// from reality, and served at GET /api/openapi.json. The Administration → API
// Access page renders a reference from it; any OpenAPI client (Swagger UI,
// Postman, codegen) can consume it directly. See docs/API_ACCESS.md.

// apiRoute is one documented operation.
type apiRoute struct {
	method  string
	path    string
	tag     string
	summary string
}

// apiRoutes is the curated surface we advertise. It deliberately omits internal
// /admin/* probes and the WebSocket hub.
var apiRoutes = []apiRoute{
	{"POST", "/api/auth/login", "Auth", "Exchange username/password for an access + refresh token"},
	{"POST", "/api/auth/refresh", "Auth", "Rotate a refresh token for a fresh access token"},
	{"POST", "/api/auth/logout", "Auth", "Revoke a refresh token"},
	{"GET", "/api/auth/me", "Auth", "Current principal"},
	{"GET", "/api/auth/permissions", "Auth", "Effective module→level permission grid"},
	{"GET", "/api/auth/sso/config", "Auth", "SSO availability + provider buttons"},
	{"GET", "/api/auth/sso/login", "Auth", "Begin the OIDC Authorization Code flow"},
	{"GET", "/api/devices", "Inventory", "List devices visible to the caller's tenant"},
	{"POST", "/api/devices", "Inventory", "Create/update a device (scoped to the caller's tenant)"},
	{"GET", "/api/devices/{id}", "Inventory", "Fetch a device by id"},
	{"DELETE", "/api/devices/{id}", "Inventory", "Delete a device"},
	{"GET", "/api/collectors", "Inventory", "Collector pool status"},
	{"GET", "/api/alerts", "Alerts", "Active alerts visible to the caller's tenant"},
	{"GET", "/api/rules", "Alerts", "Alert rules"},
	{"POST", "/api/rules", "Alerts", "Add an alert rule"},
	{"GET", "/api/findings", "Alerts", "Correlation findings (ClickHouse)"},
	{"POST", "/api/correlations/{id}/feedback", "RCA", "Record an operator verdict on an RCA case (correct | wrong | partial, with the wrong part)"},
	{"GET", "/api/correlations/{id}/feedback", "RCA", "List the operator verdicts on an RCA case, newest first (caller's tenant only)"},
	{"GET", "/api/correlations/feedback/summary", "RCA", "Windowed verdict counts + false-positive RCA rate for the caller's tenant"},
	// Security (CTEM) — Project 3 P3-API. Findings are read from the per-tenant
	// OpenSearch index through TenantIndexPattern + TenantFilter; the rules and
	// views routes are the small per-tenant control-plane state.
	{"GET", "/api/security/findings", "Security", "List security findings (cursor-paged; current=true collapses to the latest verdict per finding identity)"},
	{"GET", "/api/security/findings/{id}", "Security", "Fetch one finding (404 outside the caller's tenant)"},
	{"GET", "/api/security/findings/facets", "Security", "Facet counts by severity/status/seam/framework/evidence class"},
	{"GET", "/api/security/findings/trend", "Security", "Verdict trend over time (date histogram by status)"},
	{"GET", "/api/security/posture", "Security", "CTEM funnel, assessment coverage and last scan for the caller's tenant"},
	{"GET", "/api/security/exposure-stories", "Security", "Correlation objects grounded on security evidence"},
	{"GET", "/api/security/exposure-stories/{id}", "Security", "One exposure story (delegates to the correlation detail)"},
	{"GET", "/api/security/rules", "Security", "Detection catalog with the tenant's enable state"},
	{"PUT", "/api/security/rules", "Security", "Enable/disable detections for the caller's tenant (administration:write)"},
	{"GET", "/api/security/views", "Security", "Saved findings filter sets for the caller's tenant"},
	{"POST", "/api/security/views", "Security", "Save a findings filter set (infrastructure:write)"},
	{"DELETE", "/api/security/views/{id}", "Security", "Delete a saved filter set (404 outside the caller's tenant)"},
	// P3-EMIT producer lane (internal/seclane). Registered ONLY when
	// FEATURE_SECURITY_LANE=true, so a flag-off deployment 404s both.
	{"GET", "/api/security/lane/status", "Security", "Security producer lane status: last scan id/time/outcome per tenant (own-only; cross-tenant for the platform admin)"},
	{"POST", "/api/security/scan", "Security", "Queue a bounded security scan for the caller's own tenant (administration:write; 429 when one is already queued or running)"},
	// Config Backup & Drift (P3-CFG, internal/configstore + internal/configdrift).
	// Registered ONLY when FEATURE_CONFIG_BACKUP=true, so a flag-off deployment
	// 404s every one of them. Version text and diffs are SECRET-REDACTED and the
	// read is audited with a `sensitive` tag; the sealed copy keeps the original.
	{"POST", "/api/devices/{id}/config/backup", "Config Backup", "Queue a running-configuration capture for one device over the SSH gateway (infrastructure:write; 202 + job id, 429 when one is already running)"},
	{"GET", "/api/devices/{id}/config/versions", "Config Backup", "List a device's stored configuration versions, newest first (infrastructure:read; 404 outside the caller's tenant)"},
	{"GET", "/api/devices/{id}/config/versions/{sha}", "Config Backup", "Fetch one stored configuration version as secret-redacted text (infrastructure:read; audited as a sensitive read)"},
	{"GET", "/api/devices/{id}/config/diff", "Config Backup", "Bounded, secret-redacted unified diff between two configuration versions (from, to)"},
	{"POST", "/api/devices/{id}/config/golden", "Config Backup", "Mark a stored version as the device's golden baseline (infrastructure:write)"},
	{"GET", "/api/devices/{id}/config/status", "Config Backup", "One device's configuration sync status: in_sync | changed | drifted | unknown"},
	{"GET", "/api/config/drift", "Config Backup", "Configuration drift across the caller's devices, paged and filterable by state (infrastructure:read)"},
	{"GET", "/api/tunnels", "Telemetry", "Overlay tunnel telemetry (IPsec/SD-WAN/GRE)"},
	{"GET", "/api/flows/top", "Telemetry", "Top talkers (NetFlow/ClickHouse)"},
	{"POST", "/api/logs/search", "Telemetry", "Search logs (OpenSearch)"},
	{"GET", "/api/metrics/query", "Telemetry", "Instant PromQL query"},
	{"GET", "/api/metrics/query_range", "Telemetry", "Range PromQL query"},
	// Parser coverage (programme A6, parsercov/). The stats route is
	// platform-GLOBAL plumbing — engine counters for the whole fleet's parser,
	// not one tenant's rows — so it takes the platform-admin gate, while the
	// two /api/telemetry routes are per-tenant data read through
	// TenantIndexPattern + TenantFilter. The propose route APPLIES NOTHING: it
	// returns a drafted catalog row as text, which a human lands by pull
	// request against telemetry-catalog/events.yaml.
	{"GET", "/api/admin/parser/stats", "Telemetry", "Parser rule corpus, per-rule hit counts, promotion rate and ingest pre-filter split, summed across the correlation replicas (platform admin)"},
	{"GET", "/api/telemetry/unrecognized", "Telemetry", "Mined templates of the caller's log lines the parser would not admit (days, limit, lane)"},
	{"POST", "/api/telemetry/unrecognized/{template_id}/propose", "Telemetry", "Draft a telemetry-catalog rule row and fixture for one unrecognized template — returned as text, applied nowhere (alerts:write)"},
	{"GET", "/api/users", "Identity", "List users (administration:admin)"},
	{"POST", "/api/users", "Identity", "Create a user (administration:admin)"},
	{"GET", "/api/roles", "Identity", "List roles + modules (administration:admin)"},
	{"GET", "/api/tenants", "Identity", "List tenants (administration:admin)"},
	{"GET", "/api/orgs", "Identity", "List organizations (administration:admin)"},
	{"POST", "/api/orgs", "Identity", "Create an organization (platform owner)"},
	{"GET", "/api/regions", "Identity", "List data-residency regions (administration:admin)"},
	{"GET", "/api/bindings", "Identity", "List role bindings the caller may see (administration:admin)"},
	{"POST", "/api/bindings", "Identity", "Grant a role binding — principal→role→scope (platform owner / org-admin)"},
	{"POST", "/api/breakglass", "Identity", "Open a time-boxed, audited break-glass session into a restricted tenant (platform operator)"},
	{"GET", "/api/apikeys", "Identity", "List API keys (administration:admin)"},
	{"POST", "/api/apikeys", "Identity", "Mint a scoped API key (administration:admin)"},
	{"GET", "/api/policy/catalog", "Security Policy", "NIST-aligned security-control catalog (administration:admin)"},
	{"GET", "/api/policy/effective", "Security Policy", "Resolve effective policy for a subject — the Policy Simulator (administration:admin)"},
	{"GET", "/api/policy/documents", "Security Policy", "List override documents visible to the caller (administration:admin)"},
	{"PUT", "/api/policy/document", "Security Policy", "Set a validated override at a scope; system/global = platform owner"},
	{"POST", "/api/policy/validate", "Security Policy", "Dry-run a proposed override against the write gate (administration:admin)"},
	{"GET", "/api/itsm/servicenow", "ITSM", "ServiceNow connector status + open tickets"},
	{"GET", "/api/itsm/jira", "ITSM", "Jira connector status + open issues"},
	{"POST", "/api/graphql", "Query", "GraphQL endpoint (devices/alerts/findings/health)"},
}

// Spec builds the OpenAPI document. Pure: it takes the build version rather
// than reading a package-main global, so the document can be generated and
// asserted without standing up a server. The HTTP handler stays in package
// main, where the routing layer belongs (CLAUDE.md §2).
func Spec(version string) map[string]any {
	paths := map[string]any{}
	for _, rt := range apiRoutes {
		op := map[string]any{
			"tags":    []string{rt.tag},
			"summary": rt.summary,
			"responses": map[string]any{
				"200": map[string]any{"description": "OK"},
				"401": map[string]any{"description": "Unauthorized"},
			},
		}
		entry, ok := paths[rt.path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[rt.path] = entry
		}
		entry[lowerMethod(rt.method)] = op
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "NetOps Observability API",
			"version":     version,
			"description": "API-first network observability. Authenticate with a Bearer JWT (interactive) or a scoped API key via Authorization: Bearer ntk_… / X-API-Key.",
		},
		"servers": []any{map[string]any{"url": "/"}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
				"apiKey":     map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key"},
			},
		},
		"security": []any{
			map[string]any{"bearerAuth": []any{}},
			map[string]any{"apiKey": []any{}},
		},
		"paths": paths,
	}
	return doc
}

func lowerMethod(m string) string {
	switch m {
	case "GET":
		return "get"
	case "POST":
		return "post"
	case "PUT":
		return "put"
	case "PATCH":
		return "patch"
	case "DELETE":
		return "delete"
	default:
		return "get"
	}
}
