package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/topology"
)

// topology_view.go — GET /api/topology/view?mode=<explore|investigate|path_trace|
// dependency>[&src=&dst=] : the resolved, renderer-agnostic TopologyView the
// Topology Operating Canvas consumes.
//
// This handler is the I/O boundary; ALL projection logic lives in the pure,
// unit-tested `topology` package. The handler only GATHERS tenant-scoped inputs
// (inventory, deduped links, active alerts, device CPU/mem) and TRANSLATES them
// into a topology.Input. It reuses the exact same link normalization + tenant
// scoping as /api/topology/links so the two endpoints can never disagree.

// topologyModes is the set of modes the projection serves with real data today.
// Unknown/unimplemented modes fall back to "explore" rather than erroring, so the
// frontend mode switcher degrades gracefully.
func topologyModeOrDefault(m string) string {
	switch m {
	case topology.ModeExplore, topology.ModeInvestigate, topology.ModePathTrace,
		topology.ModeDependency, topology.ModeExecutiveGeo:
		return m
	default:
		return topology.ModeExplore
	}
}

// gatherTopoLinks builds the deduped, evidence-bearing adjacency set for a device
// slice: it constructs the same id/name/address resolution maps /links and /view
// use, fetches the raw LLDP/CDP/BGP-LS neighbours + interface-address map, and runs
// the shared normalizer. Extracted so /api/topology/view, /links and the persistent
// reconciler all derive links identically and can never disagree.
func (s *server) gatherTopoLinks(ctx context.Context, devs []models.Device) []topoLink {
	ownedID := make(map[string]string, len(devs))
	byName := make(map[string]string, len(devs))
	byAddr := make(map[string]string, len(devs))
	for _, d := range devs {
		ownedID[d.ID] = d.Name
		if d.Name != "" {
			byName[strings.ToLower(strings.TrimSpace(d.Name))] = d.ID
		}
		if d.Address != "" {
			byAddr[strings.TrimSpace(d.Address)] = d.ID
		}
	}
	neighbors, _ := collectors.FetchTopologyLinks(ctx)
	ifaddr, _ := collectors.FetchIfAddrMap(ctx)
	return normalizeLLDP(neighbors, ownedID, byName, byAddr, ifaddr)
}

// topoMetrics is the live signal bundle the topology surfaces overlay: device
// CPU/mem (by device id) and per-interface oper-status + in/out utilization (by
// canonical (device, ifName)). Empty maps when VictoriaMetrics is unreachable, so
// callers degrade to honest "unknown" rather than fabricating health.
type topoMetrics struct {
	cpu, mem                    map[string]float64
	operStatus, inUtil, outUtil map[[2]string]float64
}

// gatherTopoMetrics fetches the live metric bundle shared by /api/topology/view and
// /api/topology/graph. Status comes from ifOperStatus (1=up, else down); util is
// the busier direction as a fraction of ifSpeed (rate(octets)*8 / speed_mbps*1e6).
// Interface keys are re-canonicalized so abbreviated LLDP/CDP port-ids ("Et1")
// match full SNMP ifNames ("Ethernet1").
func (s *server) gatherTopoMetrics(ctx context.Context) topoMetrics {
	mctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cpu, _ := s.qVecBy(mctx, `max by (device) (device_cpu_percent)`, "device")
	mem, _ := s.qVecBy(mctx, `max by (device) (device_mem_percent)`, "device")
	return topoMetrics{
		cpu:        cpu,
		mem:        mem,
		operStatus: canonIfaceMap(s.qVecBy2(mctx, `max by (device, interface) (device_if_oper_status)`, "device", "interface")),
		inUtil:     canonIfaceMap(s.qVecBy2(mctx, `rate(device_if_in_octets[5m])*8 / ((device_if_speed > 0)*1000000)`, "device", "interface")),
		outUtil:    canonIfaceMap(s.qVecBy2(mctx, `rate(device_if_out_octets[5m])*8 / ((device_if_speed > 0)*1000000)`, "device", "interface")),
	}
}

func (s *server) handleTopologyView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}

	mode := topologyModeOrDefault(strings.TrimSpace(r.URL.Query().Get("mode")))
	tenant, _ := principalTenant(claims) // "" for a platform-owner all-tenants view

	// ── inventory + deduped, evidence-bearing links (same normalizer as /links) ──
	devs := visibleDevices(s.discovery.Devices(), claims)
	links := s.gatherTopoLinks(r.Context(), devs)

	// ── active alerts, scoped to devices the caller can see (same rule as /alerts) ──
	alerts := s.alerts.Active()
	if ids, cross := s.visibleDeviceIDs(claims); !cross {
		filtered := alerts[:0:0]
		for _, a := range alerts {
			if a.DeviceID == "" || ids[a.DeviceID] {
				filtered = append(filtered, a)
			}
		}
		alerts = filtered
	}

	// ── live device + link metrics (best-effort; same source /graph enrichment uses) ──
	lm := s.gatherTopoMetrics(r.Context())
	linkFacts := toLinkFacts(links, lm.operStatus, lm.inUtil, lm.outUtil)

	// Executive geo is a SITE-level projection: it aggregates the same evidence-
	// bearing device links into WAN circuits between SoT-placed sites. It needs
	// the links + site placement, not the device-level node facts.
	if mode == topology.ModeExecutiveGeo {
		writeJSON(w, http.StatusOK, s.projectGeoView(r.Context(), claims, tenant, linkFacts))
		return
	}

	in := topology.Input{
		Mode:     mode,
		TenantID: tenant,
		Now:      time.Now(),
		SrcID:    strings.TrimSpace(r.URL.Query().Get("src")),
		DstID:    strings.TrimSpace(r.URL.Query().Get("dst")),
		Devices:  toDeviceFacts(devs, lm.cpu, lm.mem),
		Links:    linkFacts,
		Alerts:   toAlertFacts(alerts),
	}

	writeJSON(w, http.StatusOK, topology.Project(in))
}

// projectGeoView builds the executive_geo View from SoT site placement + the
// deduped device links. When no geo intent source is configured it returns a
// well-formed EMPTY view, so the frontend falls back to the labeled sample (same
// graceful-degradation contract as every other not-yet-real surface).
func (s *server) projectGeoView(ctx context.Context, claims jwtClaims, tenant string, links []topology.LinkFact) topology.View {
	now := time.Now()
	empty := topology.View{
		ViewID:      "geo-" + tenant,
		Mode:        topology.ModeExecutiveGeo,
		Scope:       topology.Scope{TenantID: tenant},
		LayoutType:  "wan_geo",
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Nodes:       []topology.Node{},
		Edges:       []topology.Edge{},
		Groups:      []topology.Group{},
		Overlays:    []string{"health", "utilization"},
	}

	rows, deviceSite, _, enabled, _, _ := s.geomapResolve(ctx, claims)
	if !enabled {
		return empty
	}

	sites := make([]topology.GeoSiteFact, 0, len(rows))
	for _, g := range rows {
		sites = append(sites, topology.GeoSiteFact{
			Slug:      g.Slug,
			Name:      g.Name,
			Lat:       g.Lat,
			Lng:       g.Lng,
			HasCoords: g.HasCoords,
			Devices:   g.Devices,
			Up:        g.Up,
			Down:      g.Down,
			Status:    g.Status,
			Source:    g.Source, // "internal" | "netbox" | "manual"
		})
	}
	return topology.ProjectGeo(topology.GeoInput{
		TenantID:   tenant,
		Now:        now,
		Sites:      sites,
		Links:      links,
		DeviceSite: deviceSite,
	})
}

// toDeviceFacts translates inventory + metric vectors into projection input. The
// metric vectors are keyed by device id (the "device" label = inventory id).
func toDeviceFacts(devs []models.Device, cpu, mem map[string]float64) []topology.DeviceFact {
	out := make([]topology.DeviceFact, 0, len(devs))
	for _, d := range devs {
		f := topology.DeviceFact{
			ID:       d.ID,
			Name:     d.Name,
			Vendor:   d.Vendor,
			Model:    d.Model,
			Type:     inferDeviceType(d),
			MgmtIP:   d.Address,
			LastSeen: d.LastSeen,
		}
		// Operator overrides / enrichment from labels (best-effort).
		if d.Labels != nil {
			f.Site = firstNonEmpty(d.Labels["site"], d.Labels["location"])
			f.Rack = d.Labels["rack"]
			f.Owner = firstNonEmpty(d.Labels["owner"], d.Labels["team"])
			f.Role = d.Labels["role"]
		}
		if v, ok := cpu[d.ID]; ok {
			f.CPUPct, f.HasCPU = v, true
		}
		if v, ok := mem[d.ID]; ok {
			f.MemPct, f.HasMem = v, true
		}
		out = append(out, f)
	}
	return out
}

func toLinkFacts(links []topoLink, operStatus, inUtil, outUtil map[[2]string]float64) []topology.LinkFact {
	out := make([]topology.LinkFact, 0, len(links))
	for _, l := range links {
		lf := topology.LinkFact{
			Source:        l.Source,
			Target:        l.Target,
			SourceName:    l.SourceName,
			TargetName:    l.TargetName,
			LocalPort:     l.LocalPort,
			RemotePort:    l.RemotePort,
			Protocol:      l.SourceProto,
			IGP:           l.IGP,
			Area:          l.Area,
			Resolved:      l.Resolved,
			Bidirectional: l.Bidirectional,
			LastSeen:      time.UnixMilli(l.LastSeen),
		}
		lf.Utilization, lf.HasUtil, lf.Status = resolveLinkMetric(l, operStatus, inUtil, outUtil)
		out = append(out, lf)
	}
	return out
}

// resolveLinkMetric folds per-interface oper-status and utilization (keyed by
// device+ifName) onto a single link. Pure (no I/O) so it is unit-testable.
//
// Honesty rules (zero-trust on telemetry — never invent a healthy reading):
//   - Utilization is the BUSIEST observation across both endpoints and both
//     directions, expressed as a percentage of link speed. HasUtil is true only
//     when at least one endpoint actually reported a sample, so "0%" (measured
//     idle) stays distinct from "unmeasured".
//   - Status is "down" if any endpoint's interface is oper-down, "up" only when
//     an endpoint is confirmed up and none is down, and "" (→ "unknown" in the
//     projection) when no endpoint reported oper-status. An unresolved target
//     ("ext:<sysname>") carries no metrics, so only the local side contributes.
func resolveLinkMetric(l topoLink, operStatus, inUtil, outUtil map[[2]string]float64) (util float64, hasUtil bool, status string) {
	return resolveLinkMetricBy(l.Source, l.LocalPort, l.Target, l.RemotePort, operStatus, inUtil, outUtil)
}

// resolveLinkMetricBy is the endpoint-keyed core of resolveLinkMetric, so callers
// holding source/target + ports (the persisted /graph edges) reuse the exact same
// honesty rules without reconstructing a topoLink.
func resolveLinkMetricBy(srcDev, srcPort, tgtDev, tgtPort string, operStatus, inUtil, outUtil map[[2]string]float64) (util float64, hasUtil bool, status string) {
	src := [2]string{srcDev, canonIface(srcPort)}
	dst := [2]string{tgtDev, canonIface(tgtPort)}

	for _, m := range []map[[2]string]float64{inUtil, outUtil} {
		for _, k := range [][2]string{src, dst} {
			if k[1] == "" {
				continue // no port to key on
			}
			if v, ok := m[k]; ok {
				if frac := v * 100; frac > util {
					util = frac
				}
				hasUtil = true
			}
		}
	}

	anyUp, anyDown := false, false
	for _, k := range [][2]string{src, dst} {
		if k[1] == "" {
			continue
		}
		if v, ok := operStatus[k]; ok {
			if v == 1 {
				anyUp = true
			} else {
				anyDown = true
			}
		}
	}
	switch {
	case anyDown:
		status = "down"
	case anyUp:
		status = "up"
	}
	return util, hasUtil, status
}

// ifaceAlias maps a vendor interface-type spelling (long forms AND the few
// abbreviations that aren't a prefix of their long name) to a canonical token.
// Short forms that already prefix their long name (gi, te, fa, …) fall through
// to themselves, so both ends of the alias collapse to the same token.
var ifaceAlias = map[string]string{
	"ethernet":                  "et",
	"eth":                       "et",
	"gigabitethernet":           "gi",
	"gige":                      "gi",
	"gig":                       "gi",
	"tengigabitethernet":        "te",
	"tengige":                   "te",
	"twentyfivegige":            "twe",
	"twentyfivegigabitethernet": "twe",
	"fortygigabitethernet":      "fo",
	"fortygige":                 "fo",
	"fiftygige":                 "fi",
	"hundredgige":               "hu",
	"hundredgigabitethernet":    "hu",
	"fastethernet":              "fa",
	"portchannel":               "po",
	"bundleether":               "be", // IOS-XR Bundle-Ether → BE
	"management":                "ma",
	"mgmt":                      "ma",
	"loopback":                  "lo",
	"vlan":                      "vl",
	"tunnel":                    "tu",
	"serial":                    "se",
}

// canonIface normalizes an interface/port name so abbreviated LLDP/CDP port-ids
// and full SNMP ifNames resolve to the same key. It lowercases, splits the
// alphabetic type prefix from the numeric port part (at the first digit),
// canonicalizes the prefix via ifaceAlias, and strips punctuation from the
// prefix only — the numeric part (slots/slashes/dots) is preserved so distinct
// ports never collapse. Unknown prefixes are kept verbatim (still matches when
// both ends spell it the same). Empty in → empty out.
//
// Examples: "Ethernet1"→"et1", "Et1"→"et1", "GigabitEthernet0/1"→"gi0/1",
// "Gi0/1"→"gi0/1", "ethernet-1/1"→"et1/1", "ge-0/0/0"→"ge0/0/0".
func canonIface(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	// Split at the first digit: everything before is the type prefix.
	d := strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' })
	prefix, rest := s, ""
	if d >= 0 {
		prefix, rest = s[:d], s[d:]
	}
	// Keep only letters in the prefix (drops hyphens: "port-channel"→"portchannel").
	prefix = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r
		}
		return -1
	}, prefix)
	if c, ok := ifaceAlias[prefix]; ok {
		prefix = c
	}
	return prefix + rest
}

// canonIfaceMap re-keys a (device, ifName) metric map by (device, canonIface),
// keeping the max value when two raw ifNames canonicalize to the same port.
func canonIfaceMap(m map[[2]string]float64) map[[2]string]float64 {
	if m == nil {
		return nil
	}
	out := make(map[[2]string]float64, len(m))
	for k, v := range m {
		nk := [2]string{k[0], canonIface(k[1])}
		if cur, ok := out[nk]; !ok || v > cur {
			out[nk] = v
		}
	}
	return out
}

func toAlertFacts(alerts []models.Alert) []topology.AlertFact {
	out := make([]topology.AlertFact, 0, len(alerts))
	for _, a := range alerts {
		if a.DeviceID == "" {
			continue // device-less (stack-level) alerts don't bind to a node
		}
		out = append(out, topology.AlertFact{
			DeviceID: a.DeviceID,
			Severity: a.Severity,
			Summary:  a.Summary,
			FiredAt:  a.FiredAt,
		})
	}
	return out
}
