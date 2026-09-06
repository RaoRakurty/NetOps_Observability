// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// region_router.go — the ROUTING / EDGE LAYER of the SaaS topology
// (control plane → routing → per-region data planes). This is the MODEL: it
// resolves a tenant to the data plane that should serve its telemetry, by
// tenant → region → data-plane endpoints. It is dormant by default — every
// region resolves to the LOCAL stack — so the platform runs single-region today
// while being structurally ready for real regions. Lighting up a real region is
// configuration (one env var per region), not a code change.
//
// Topology:
//
//	CONTROL PLANE (global)  orgs · identity · RBAC · bindings · tenants  (this process)
//	        │
//	ROUTING / EDGE LAYER    tenant → region mapping + data-plane resolution (here)
//	        │
//	DATA PLANES (per region)  us-east · eu-central · …  (ClickHouse · OpenSearch · Kafka · VM)
//
// Config (per region, optional): REGION_DATAPLANE_<REGION_UPPER_SNAKE>, e.g.
//
//	REGION_DATAPLANE_EU_CENTRAL="ch=https://ch.eu;os=https://os.eu;vm=https://vm.eu;kafka=eu-broker:9092"
//
// Unset → the region uses the local in-cluster stack (CLICKHOUSE_URL, etc.).

import (
	"net/http"
	"os"
	"sort"
	"strings"
)

// DataPlane is one region's telemetry backend set — a "data plane" box in the
// topology diagram. Local=true means it is the in-cluster stack (the single
// data plane every region collapses onto until a real region is configured).
type DataPlane struct {
	Region          string `json:"region"`
	Local           bool   `json:"local"`
	ClickHouse      string `json:"clickhouse,omitempty"`
	OpenSearch      string `json:"opensearch,omitempty"`
	VictoriaMetrics string `json:"victoria_metrics,omitempty"`
	Kafka           string `json:"kafka,omitempty"`
}

// localDataPlane describes the in-cluster stack (the default for every region).
func localDataPlane(region string) DataPlane {
	return DataPlane{
		Region:          region,
		Local:           true,
		ClickHouse:      envOr("CLICKHOUSE_URL", "http://clickhouse:8123"),
		OpenSearch:      envOr("OPENSEARCH_URL", "http://opensearch:9200"),
		VictoriaMetrics: envOr("VICTORIA_URL", "http://victoriametrics:8428"),
		Kafka:           envOr("BROKER_URLS", "kafka:9092"),
	}
}

// dataPlaneEnvKey maps a region id to its override env var, e.g.
// "eu-central" → "REGION_DATAPLANE_EU_CENTRAL".
func dataPlaneEnvKey(region string) string {
	up := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(region), "-", "_"))
	return "REGION_DATAPLANE_" + up
}

// parseDataPlaneSpec parses "ch=...;os=...;vm=...;kafka=..." into a DataPlane.
func parseDataPlaneSpec(region, spec string) DataPlane {
	dp := DataPlane{Region: region}
	for _, part := range strings.Split(spec, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "ch", "clickhouse":
			dp.ClickHouse = strings.TrimSpace(kv[1])
		case "os", "opensearch":
			dp.OpenSearch = strings.TrimSpace(kv[1])
		case "vm", "victoria", "victoria_metrics":
			dp.VictoriaMetrics = strings.TrimSpace(kv[1])
		case "kafka", "redpanda":
			dp.Kafka = strings.TrimSpace(kv[1])
		}
	}
	return dp
}

// dataPlaneFor resolves a region to its data plane: a configured override if the
// region's env var is set, otherwise the local stack.
func dataPlaneFor(region string) DataPlane {
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		region = RegionDefault
	}
	if spec := strings.TrimSpace(os.Getenv(dataPlaneEnvKey(region))); spec != "" {
		return parseDataPlaneSpec(region, spec)
	}
	return localDataPlane(region)
}

// effectiveTenantRegion resolves where a tenant's data lives: its own region, or
// (blank) its org's home_region, or the platform default. The tenant→region
// mapping of the routing layer.
func (s *server) effectiveTenantRegion(t Tenant) string {
	if r := strings.ToLower(strings.TrimSpace(t.Region)); r != "" {
		return r
	}
	if s.orgs != nil {
		if o, ok := s.orgs.Get(orgOf(t)); ok && o.HomeRegion != "" {
			return o.HomeRegion
		}
	}
	return RegionDefault
}

// RegionTopology is one region row of the topology view: its data plane plus the
// orgs/tenants that live in it.
type RegionTopology struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	DataPlane DataPlane `json:"data_plane"`
	Tenants   int       `json:"tenants"`
	Orgs      int       `json:"orgs"`
}

// handleRegionTopology serves the full control-plane → routing → data-plane
// picture for the governance/Regions view. Platform owner only (infra topology).
func (s *server) handleRegionTopology(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	// Count tenants/orgs per effective region.
	tenantsBy := map[string]int{}
	orgRegions := map[string]map[string]bool{} // region -> set of org ids
	for _, t := range s.tenants.List() {
		reg := s.effectiveTenantRegion(t)
		tenantsBy[reg]++
		if orgRegions[reg] == nil {
			orgRegions[reg] = map[string]bool{}
		}
		orgRegions[reg][orgOf(t)] = true
	}
	regions := make([]RegionTopology, 0)
	for _, r := range RegionList() {
		regions = append(regions, RegionTopology{
			ID: r.ID, Label: r.Label, DataPlane: dataPlaneFor(r.ID),
			Tenants: tenantsBy[r.ID], Orgs: len(orgRegions[r.ID]),
		})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].ID < regions[j].ID })

	writeJSON(w, http.StatusOK, map[string]any{
		"control_plane": map[string]any{
			"orgs": len(s.orgs.List()), "tenants": len(s.tenants.List()), "users": s.users.Count(),
		},
		"regions": regions,
	})
}
