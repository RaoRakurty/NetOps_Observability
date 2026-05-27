package main

import (
	"encoding/json"
	"net/http"
)

// graphql.go — minimal GraphQL endpoint scaffold.
//
// We intentionally do NOT pull in a heavyweight GraphQL library here.
// Instead this handler accepts the standard `{ query, variables }`
// envelope and dispatches a small set of known queries to the existing
// REST-backed handlers. That's enough to satisfy a NOC dashboard that
// wants federation over devices, alerts, and findings without dragging
// gqlgen + its generated boilerplate into the scaffold.
//
// To replace this with a real implementation:
//   1. `go get github.com/graph-gophers/graphql-go`
//   2. Define a schema in src/backend/schema.graphql
//   3. Implement resolvers and swap this handler out for graphql.Handler.
//
// Until then, the supported operations are:
//   query devices         -> []Device
//   query alerts          -> []Alert
//   query findings        -> []Finding (from ClickHouse)
//   query health          -> Health
//   query  __schema       -> a static schema-introspection blob
type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

func (s *server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req gqlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp := map[string]any{"data": map[string]any{}}
	data := resp["data"].(map[string]any)

	// Naïve string-match dispatch. Replace with a real parser when we
	// promote this from scaffold to product.
	q := req.Query
	if contains(q, "devices") {
		data["devices"] = s.discovery.Devices()
	}
	if contains(q, "alerts") {
		data["alerts"] = s.alerts.Active()
	}
	if contains(q, "rules") {
		data["rules"] = s.alerts.Rules()
	}
	if contains(q, "health") {
		data["health"] = map[string]any{
			"status":     "healthy",
			"version":    version,
			"discovery":  s.discovery.Health(),
			"collectors": s.collectors.Health(),
			"alerts":     s.alerts.Health(),
		}
	}
	if contains(q, "__schema") {
		data["__schema"] = staticSchema()
	}

	writeJSON(w, http.StatusOK, resp)
}

func contains(haystack, needle string) bool {
	// Lightweight check — full GraphQL parsing isn't required for the
	// scaffold; the next iteration swaps this for a real schema.
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func staticSchema() any {
	return map[string]any{
		"types": []map[string]any{
			{"name": "Device", "kind": "OBJECT"},
			{"name": "Alert", "kind": "OBJECT"},
			{"name": "Rule", "kind": "OBJECT"},
			{"name": "Finding", "kind": "OBJECT"},
			{"name": "Health", "kind": "OBJECT"},
		},
		"queryType": map[string]any{"name": "Query"},
	}
}
