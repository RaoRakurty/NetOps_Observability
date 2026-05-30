package main

import (
	"net/http"
)

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
	{"GET", "/api/tunnels", "Telemetry", "Overlay tunnel telemetry (IPsec/SD-WAN/GRE)"},
	{"GET", "/api/flows/top", "Telemetry", "Top talkers (NetFlow/ClickHouse)"},
	{"POST", "/api/logs/search", "Telemetry", "Search logs (OpenSearch)"},
	{"GET", "/api/metrics/query", "Telemetry", "Instant PromQL query"},
	{"GET", "/api/metrics/query_range", "Telemetry", "Range PromQL query"},
	{"GET", "/api/users", "Identity", "List users (administration:admin)"},
	{"POST", "/api/users", "Identity", "Create a user (administration:admin)"},
	{"GET", "/api/roles", "Identity", "List roles + modules (administration:admin)"},
	{"GET", "/api/tenants", "Identity", "List tenants (administration:admin)"},
	{"GET", "/api/apikeys", "Identity", "List API keys (administration:admin)"},
	{"POST", "/api/apikeys", "Identity", "Mint a scoped API key (administration:admin)"},
	{"GET", "/api/itsm/servicenow", "ITSM", "ServiceNow connector status + open tickets"},
	{"POST", "/api/graphql", "Query", "GraphQL endpoint (devices/alerts/findings/health)"},
}

func (s *server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
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
	writeJSON(w, http.StatusOK, doc)
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
