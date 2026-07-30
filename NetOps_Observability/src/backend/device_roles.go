package backend

// device_roles.go — gathers the discovery facts the topology role classifier
// (topology/roles.go) consumes, and stamps the resulting canonical device roles
// onto the payloads the frontend already reads:
//   · /api/topology/view nodes (via toDeviceFacts → topology.Project), and
//   · the RCA timeline's §7 spine (rcaPathBlock → stampSpineRoles).
//
// TENANT ISOLATION (§3a): every index here is built from the CALLER-VISIBLE
// device set only (visibleDevices), so a role — or the existence of a device —
// can never leak across tenants through a role stamp. The stamping functions
// are pure over their inputs (unit-tested with mock facts).

import (
	"context"
	"strings"

	"netops/backend/pathgraph"
	"netops/backend/topology"
)

// adjSummary is one device's LLDP/CDP/BGP-LS neighbourhood shape.
type adjSummary struct {
	total    int
	switches int
	routers  int
	igp      bool
}

// adjacencySummaries folds the deduped undirected link set into per-device
// neighbourhood shapes. Pure. Unresolved ("ext:") neighbours count toward the
// total (they are real adjacencies) but not toward a device-type bucket.
func adjacencySummaries(links []topoLink, typeByID map[string]string) map[string]*adjSummary {
	out := map[string]*adjSummary{}
	get := func(id string) *adjSummary {
		a := out[id]
		if a == nil {
			a = &adjSummary{}
			out[id] = a
		}
		return a
	}
	count := func(self, other string, igp bool) {
		a := get(self)
		a.total++
		switch typeByID[other] {
		case "switch":
			a.switches++
		case "router":
			a.routers++
		}
		if igp {
			a.igp = true
		}
	}
	for _, l := range links {
		if l.Source == "" || l.Target == "" {
			continue
		}
		igp := l.IGP != "" || strings.Contains(l.SourceProto, "bgp_ls")
		count(l.Source, l.Target, igp)
		if l.Resolved {
			count(l.Target, l.Source, igp)
		}
	}
	return out
}

// deviceRoleIndex classifies the CALLER-VISIBLE devices and indexes the results
// by device id, lowercased name, and management address — the three identities a
// spine hop can resolve through. Devices the classifier leaves unknown are not
// indexed (absence is honest). Best-effort: link facts may be empty (collectors
// off) — identity-string signals still classify.
func (s *server) deviceRoleIndex(ctx context.Context, claims jwtClaims) map[string]topology.RoleResult {
	devs := visibleDevices(s.discovery.Devices(), claims)
	if len(devs) == 0 {
		return map[string]topology.RoleResult{}
	}
	links := s.gatherTopoLinks(ctx, devs)
	idx := make(map[string]topology.RoleResult)
	for _, f := range toDeviceFacts(devs, nil, nil, links) {
		rr := topology.ClassifyDeviceRole(f)
		if rr.Role == topology.DevRoleUnknown {
			continue
		}
		for _, k := range []string{f.ID, strings.ToLower(strings.TrimSpace(f.Name)), strings.TrimSpace(f.MgmtIP)} {
			if k != "" {
				idx[k] = rr
			}
		}
	}
	return idx
}

// stampSpineRoles stamps the canonical device role onto spine hops that resolve
// to an indexed (caller-visible) device — by entity_ref, address, or label.
// Pure: hops that resolve to nothing are left untouched (unknown stays absent).
func stampSpineRoles(spine []pathgraph.SpineNode, idx map[string]topology.RoleResult) {
	if len(idx) == 0 {
		return
	}
	for i := range spine {
		n := &spine[i]
		for _, k := range []string{
			strings.TrimSpace(n.EntityRef),
			strings.TrimSpace(n.Address),
			strings.ToLower(strings.TrimSpace(n.Label)),
		} {
			if k == "" {
				continue
			}
			if rr, ok := idx[k]; ok {
				n.DeviceRole = rr.Role
				n.RoleConfidence = rr.Confidence
				break
			}
		}
	}
}
