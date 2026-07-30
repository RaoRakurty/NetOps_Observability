package main

// cloud_service_map.go — GET /api/cloud/service-map (cloud-platform-backlog #9).
// The graph domain (SQL builders, wire types, the pure fold) lives in
// cloud/service_map.go (P2 W4.19); this file keeps the endpoint resolver (it
// reads the caller's tenant-scoped identity map + inventory through srv) and
// the handler (scope resolution + the CH transport).

import (
	"net/http"
	"strings"
	"time"

	"netops/backend/cloud"
)

// cloudEndpointResolver resolves an observed address to the service it belongs
// to, in trust order: the tenant's identity map first (cloud_appid_resolver —
// tag/graph mappings keyed by IP/ENI/resource-id), then the declared inventory
// (cloudResourceIndex — keyed by every handle a resource carries, incl. IPs).
// Default-closed: both stores are principalTenant-scoped, and an address
// neither claims resolves to nothing — never a guess.
func (s *server) cloudEndpointResolver(r *http.Request) func(string) (string, bool) {
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	idx := s.cloudResourceIndex(r)
	return func(key string) (string, bool) {
		key = strings.TrimSpace(key)
		if key == "" {
			return "", false
		}
		if sig, ok := s.cloudApp.signalFor(tenant, cross, key); ok && sig.App != "" {
			return sig.App, true
		}
		if c, ok := lookupCloudResource(idx, key); ok {
			if c.AppName != "" {
				return c.AppName, true
			}
			if c.ResourceName != "" {
				return c.ResourceName, true
			}
		}
		return "", false
	}
}

// handleCloudServiceMap serves GET /api/cloud/service-map — the observed
// service dependency graph for the caller's tenant over ?window_hours= (1..168,
// clamped + echoed like /api/cloud/health).
func (s *server) handleCloudServiceMap(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	window, werr := s.tenantWindowHours(r)
	if werr != nil {
		writeError(w, http.StatusBadRequest, werr)
		return
	}
	scope := cloud.SafeScopeLiteral(chTenantScope(r))
	pairs := chJSONRows[cloud.FlowPairRow](cloud.ServiceMapPairSQL(window, cloud.ServiceMapMaxPairRows, scope))
	rejects := chJSONRows[cloud.FlowPairRow](cloud.ServiceMapRejectSQL(window, cloud.ServiceMapMaxRejectRows, scope))
	graph := cloud.BuildServiceMap(pairs, rejects, s.cloudEndpointResolver(r), cloud.ServiceMapMaxUnattributed)
	graph.Meta.WindowHours = window
	graph.Meta.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": graph.Nodes,
		"edges": graph.Edges,
		"meta":  graph.Meta,
	})
}
