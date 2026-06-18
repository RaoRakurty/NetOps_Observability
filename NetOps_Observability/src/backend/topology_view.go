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
	case topology.ModeExplore, topology.ModeInvestigate, topology.ModePathTrace, topology.ModeDependency:
		return m
	default:
		return topology.ModeExplore
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

	// ── inventory + tenant-scoped resolution maps (identical to /links) ──
	devs := visibleDevices(s.discovery.Devices(), claims)
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

	// ── deduped, evidence-bearing links (same normalizer as /links) ──
	neighbors, _ := collectors.FetchTopologyLinks(r.Context())
	ifaddr, _ := collectors.FetchIfAddrMap(r.Context())
	links := normalizeLLDP(neighbors, ownedID, byName, byAddr, ifaddr)

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

	// ── device CPU/mem (best-effort; empty when VictoriaMetrics is unreachable) ──
	mctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	cpu, _ := s.qVecBy(mctx, `max by (device) (device_cpu_percent)`, "device")
	mem, _ := s.qVecBy(mctx, `max by (device) (device_mem_percent)`, "device")

	// ── per-interface link metrics (best-effort): oper status + utilization ──
	// Keyed by (device, interface=ifName). Status comes from ifOperStatus
	// (1=up, others=down). Utilization is the link's busier direction as a
	// fraction of ifSpeed — the same canonical formula the health scorer uses
	// (rate(octets)*8 / speed_mbps*1e6). Left nil when VictoriaMetrics is
	// unreachable so edges stay honestly "unknown" rather than fabricated.
	operStatus := s.qVecBy2(mctx, `max by (device, interface) (device_if_oper_status)`, "device", "interface")
	inUtil := s.qVecBy2(mctx, `rate(device_if_in_octets[5m])*8 / ((device_if_speed > 0)*1000000)`, "device", "interface")
	outUtil := s.qVecBy2(mctx, `rate(device_if_out_octets[5m])*8 / ((device_if_speed > 0)*1000000)`, "device", "interface")

	in := topology.Input{
		Mode:     mode,
		TenantID: tenant,
		Now:      time.Now(),
		SrcID:    strings.TrimSpace(r.URL.Query().Get("src")),
		DstID:    strings.TrimSpace(r.URL.Query().Get("dst")),
		Devices:  toDeviceFacts(devs, cpu, mem),
		Links:    toLinkFacts(links, operStatus, inUtil, outUtil),
		Alerts:   toAlertFacts(alerts),
	}

	writeJSON(w, http.StatusOK, topology.Project(in))
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
	src := [2]string{l.Source, l.LocalPort}
	dst := [2]string{l.Target, l.RemotePort}

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
