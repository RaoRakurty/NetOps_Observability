package main

// cloud_topology_api.go — GET /api/topology/cloud : the in-cloud NETWORK topology
// (VPC/VNet → subnets → route tables → gateways/NVAs) the Topology Operating
// Canvas's Cloud tab renders. It serves the SAME renderer-agnostic topology.View
// contract as /api/topology/view and /graph, mapped from the discovered egress
// topologies (cloud.LoadTopologies) by the pure cloud.BuildTopologyView projection.
//
// TENANT SCOPING (CLAUDE.md §3a, default-closed): the discovery fixtures are
// provider-GLOBAL, owned by CLOUD_FIXTURE_TENANT (default "" = platform/global —
// the same owner startCloudInventory stamps the inventory with). A caller sees the
// cloud topology ONLY when it owns those fixtures: cross-tenant (the platform owner
// on the Global view) OR its own tenant == the fixtures' owner tenant. Any other
// tenant gets an honest EMPTY view — never another tenant's network. The regression
// guard is TestCloudTopologyIsolation.

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/cloud"
)

func (s *server) handleCloudTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	now := time.Now()

	// Default-closed gate: only the fixtures' owner (cross-tenant, or the matching
	// tenant) may read them. Everyone else gets a well-formed EMPTY view.
	fixtureTenant := strings.ToLower(strings.TrimSpace(os.Getenv("CLOUD_FIXTURE_TENANT")))
	if !cross && tenant != fixtureTenant {
		writeJSON(w, http.StatusOK, cloud.BuildTopologyView(nil, tenant, now))
		return
	}

	topos, err := cloud.LoadTopologiesLayered(os.Getenv("CLOUD_FIXTURES_DIR"), os.Getenv("CLOUD_RUNTIME_DIR"))
	if err != nil {
		// A malformed/unreadable fixture degrades to an honest empty view (graceful
		// like /topology/graph) rather than a 500 that blanks the tab.
		logError("cloud", "topology fixture load failed", map[string]any{"err": err.Error()})
		writeJSON(w, http.StatusOK, cloud.BuildTopologyView(nil, tenant, now))
		return
	}
	writeJSON(w, http.StatusOK, cloud.BuildTopologyView(topos, tenant, now))
}
