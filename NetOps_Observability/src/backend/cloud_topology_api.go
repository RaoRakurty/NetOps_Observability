// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"netops/backend/models"
	"netops/backend/topology"
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
	// The inventory is read ONCE and used twice: to paint live state onto the
	// nodes, and to derive the LATERAL seam links from the Attached* facts
	// (#131c). Both joins live in the pure cloud package so the canvas and the
	// path graph can never build a different seam from the same inventory.
	writeJSON(w, http.StatusOK, cloud.BuildTopologyViewWithInventory(topos, tenant, now, s.cloudInventory(r, tenant, cross)))
}

// cloudInventory reads the caller's LIVE cloud resource inventory, already
// tenant-scoped by the store.
//
// Returns nil when it cannot be read. That is deliberate: a nil inventory leaves
// every node at "not measured" and produces NO seam links, which is the honest
// rendering of "we could not ask". Defaulting to healthy — or to a seam we did
// not confirm — on a failed read would paint a map from no data at all.
func (s *server) cloudInventory(r *http.Request, tenant string, cross bool) []cloud.CloudResource {
	if s.cloud == nil {
		return nil
	}
	res, err := s.cloud.ListResources(r.Context(), tenant, cross)
	if err != nil {
		logError("cloud", "topology inventory join failed — nodes render as not measured", map[string]any{"err": err.Error()})
		return nil
	}
	return res
}

// cloudPathGraph returns the CLOUD half of the path graph (#130a): the projected
// cloud nodes, their route + lateral seam edges, and the DISCOVERED on-prem seam
// edges that let Dijkstra cross from the fabric into a VPC.
//
// TENANCY. It re-applies the SAME default-closed gate `/api/topology/cloud`
// enforces — the fixtures are provider-global and owned by CLOUD_FIXTURE_TENANT,
// and the two surfaces do not share a tenancy rule with the device fabric. A
// caller who may not read the cloud slice gets NOTHING here, so the path trace
// behaves for them exactly as it did before this existed.
//
// Returns empty slices (never nil-with-meaning) when the gate closes or the
// fixtures cannot be read: no cloud vertices, so a cloud endpoint simply does
// not resolve — never a fabricated one.
func (s *server) cloudPathGraph(r *http.Request, tenant string, cross bool, devs []models.Device) ([]topology.Node, []topology.Edge, []topology.Group) {
	fixtureTenant := strings.ToLower(strings.TrimSpace(os.Getenv("CLOUD_FIXTURE_TENANT")))
	if !cross && tenant != fixtureTenant {
		return nil, nil, nil
	}
	topos, err := cloud.LoadTopologiesLayered(os.Getenv("CLOUD_FIXTURES_DIR"), os.Getenv("CLOUD_RUNTIME_DIR"))
	if err != nil {
		logError("cloud", "path-graph fixture load failed — the trace stays on-prem", map[string]any{"err": err.Error()})
		return nil, nil, nil
	}
	now := time.Now()
	inv := s.cloudInventory(r, tenant, cross)
	view := cloud.BuildTopologyViewWithInventory(topos, tenant, now, inv)
	edges := append(view.Edges, cloud.BuildOnPremSeamEdges(view.Nodes, inv, deviceByPeerAddress(devs), now)...)
	return view.Nodes, edges, view.Groups
}

// deviceByPeerAddress builds the address → managed device resolver the on-prem
// seam join uses.
//
// The address index is the same one `topoLinkMaps` builds for neighbour
// resolution, and it carries the same warning: the SLICE defines the resolution
// universe. It is additionally TENANT-CHECKED here, because a cross-tenant
// principal holds both a wider device list and a wider cloud inventory, and two
// tenants that both use 203.0.113.4 must not be wired to each other's gateway.
func deviceByPeerAddress(devs []models.Device) cloud.DeviceResolver {
	type owned struct{ id, tenant string }
	byAddr := make(map[string]owned, len(devs))
	for _, d := range devs {
		addr := strings.TrimSpace(d.Address)
		if addr == "" || d.ID == "" {
			continue
		}
		if _, taken := byAddr[addr]; !taken {
			byAddr[addr] = owned{id: d.ID, tenant: d.TenantID}
		}
	}
	return func(resourceTenant, addr string) (string, bool) {
		d, ok := byAddr[strings.TrimSpace(addr)]
		if !ok {
			return "", false
		}
		// An untenanted (platform-global) fixture may join any visible device;
		// a tenant-stamped resource only ever joins its OWN tenant's device.
		if resourceTenant != "" && d.tenant != "" && !strings.EqualFold(resourceTenant, d.tenant) {
			return "", false
		}
		return d.id, true
	}
}
