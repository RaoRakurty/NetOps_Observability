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
//  1. `go get github.com/graph-gophers/graphql-go`
//  2. Define a schema in src/backend/schema.graphql
//  3. Implement resolvers and swap this handler out for graphql.Handler.
//
// Until then, the supported operations are:
//
//	query devices         -> []Device
//	query alerts          -> []Alert
//	query findings        -> []Finding (from ClickHouse)
//	query health          -> Health
//	query  __schema       -> a static schema-introspection blob
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

	// Tenant isolation: a scoped principal sees only its own devices/alerts here,
	// matching the REST surface (this endpoint is behind the same auth middleware).
	claims, _ := userFrom(r.Context())
	_, cross := principalTenant(claims)

	// Naïve string-match dispatch. Replace with a real parser when we
	// promote this from scaffold to product.
	q := req.Query
	if contains(q, "devices") {
		data["devices"] = visibleDevices(s.discovery.Devices(), claims)
	}
	if contains(q, "alerts") {
		active := s.alerts.Active()
		if ids, cross := s.visibleDeviceIDs(claims); !cross {
			filtered := active[:0:0]
			for _, a := range active {
				if a.DeviceID == "" || ids[a.DeviceID] {
					filtered = append(filtered, a)
				}
			}
			active = filtered
		}
		data["alerts"] = active
	}
	if contains(q, "rules") {
		// SR-004/SR-010: rules are platform-global (cross-tenant leak of infra
		// topology); match the REST gate — platform owner only.
		if cross {
			data["rules"] = s.alerts.Rules()
		} else {
			data["rules"] = []any{}
		}
	}
	if contains(q, "health") {
		// SR-010: collectors/discovery health is a fleet-wide aggregate the REST
		// handleCollectors restricts to the platform owner; don't leak it to a
		// scoped tenant via GraphQL. Tenant callers get only liveness + their
		// own alert health.
		health := map[string]any{
			"status":  "healthy",
			"version": version,
			"alerts":  s.alerts.Health(),
		}
		if cross {
			health["discovery"] = s.discovery.Health()
			health["collectors"] = s.collectors.Health()
		}
		data["health"] = health
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
