// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"strings"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/devreach"
	"netops/backend/internal/vendorprofile"
	"netops/backend/models"
)

// inferDeviceType classifies a device into a functional NOC type from its
// SNMP-derived signals (vendor + model + sysDescr/OS + name) — the same text an
// operator reads. Returns one of: router, switch, firewall, load-balancer, ap,
// wlc, cloud-gw, generic. An operator override in labels["device_type"] always
// wins (the "manual" half of the SNMP-infer + manual policy).
//
// WHERE THE HINTS LIVE. In the Vendor Profile registry, under each vendor
// document's `device_type.text_hints` — Cisco's "catalyst"/"9800"/"ws-c",
// Juniper's " mx"/"qfx", Ubiquiti's "uap-", and the vendor-NEUTRAL role words
// ("firewall", "switch", "router") in the vendor-neutral document. This file
// owns the POLICY, not the vocabulary: which text is read, that an operator
// override wins, and that an unmatched device is "generic" rather than a guess.
//
// The ORDER is policy too and stays with the registry's DeviceTypeOrder:
// specific roles (firewall/LB/WLC/AP/cloud-gw) are tested before the generic
// switch-vs-router split, so a firewall is never mislabelled a router.
func inferDeviceType(d models.Device) string {
	if d.Labels != nil {
		if t := strings.TrimSpace(d.Labels["device_type"]); t != "" {
			return t // operator override
		}
	}
	h := strings.ToLower(d.Vendor + " " + d.Model + " " + d.OS + " " + d.Name)
	if t, ok := vendorprofile.Default().DeviceTypeForText(h); ok {
		return t
	}
	return "generic"
}

// withDeviceType fills the Type on each device (infer-on-read) without touching
// the discovery store — so re-discovery never clobbers it and there's no migration.
func withDeviceType(ds []models.Device) []models.Device {
	for i := range ds {
		if ds[i].Type == "" {
			ds[i].Type = inferDeviceType(ds[i])
		}
	}
	return ds
}

// controllerReportedVersion is the version a controller reported for a device
// it manages (OSVersionSource "api:<system>", nms.ToInventoryDevice): already a
// clean version string, but its OS label ("Catalyst SD-WAN") is not one the
// vendor's sysDescr patterns parse, so without this the inventory showed "—"
// for every controller-only device. Only a controller's own report is used
// this way — never a free-form OS text.
func controllerReportedVersion(d models.Device) string {
	if !strings.HasPrefix(d.OSVersionSource, "api:") {
		return ""
	}
	return strings.TrimSpace(d.OSVersion)
}

// reportedSite is the site id the device itself reports (its SD-WAN overlay
// facts, keyed by THIS device's id — so it is this tenant's row), else the one
// its controller reports for it (the controller_site_id label the controller
// discovery source stamps). Pure.
func reportedSite(d models.Device, facts collectors.OverlayDeviceFacts) (id, source string) {
	if s := strings.TrimSpace(facts.SiteID); s != "" {
		return s, "device"
	}
	if s := strings.TrimSpace(d.Labels["controller_site_id"]); s != "" {
		sys := strings.TrimSpace(d.Labels["source_system"])
		if sys == "" {
			sys = "controller"
		}
		return s, sys
	}
	return "", ""
}

// errReachabilityUnread: the collectors' liveness could not be read.
var errReachabilityUnread = errors.New("device reachability could not be read")

// collectorReachability reads per-device max/min of collector_target_up over
// the last 3 minutes (devreach.Fold's input), under the caller's metric scope
// filters f (metricsScopeFiltersFor — the chokepoint rule), bounded to 3 s.
// ok is false when either read failed; both maps are then nil.
func (s *server) collectorReachability(ctx context.Context, f []string) (maxUp, minUp map[string]float64, ok bool) {
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	const q = `last_over_time(collector_target_up{collector!="netconf"}[3m])`
	maxUp, okMax := s.qVecKeyedScoped(qctx, "max by (device) ("+q+")", "device", f)
	minUp, okMin := s.qVecKeyedScoped(qctx, "min by (device) ("+q+")", "device", f)
	if !okMax || !okMin {
		return nil, nil, false
	}
	return maxUp, minUp, true
}

// qVecKeyedScoped is one value per key from a by-key VM vector query under
// the caller's filters, KEEPING zeros. qVecByScoped drops a 0 (it keeps a
// running max from 0), which for collector_target_up erased exactly the
// answer that matters: a device whose every poll failed (max 0) read
// "unknown" instead of "down", and one with a failing collector (min 0) read
// "up" instead of "partial" (found by the phrasing eval, 2026-11-12). The
// query is already aggregated by key, so a key appears once.
func (s *server) qVecKeyedScoped(ctx context.Context, query, key string, filters []string) (map[string]float64, bool) {
	samples, err := s.vmInstantScoped(ctx, query, filters)
	if err != nil {
		return nil, false
	}
	out := map[string]float64{}
	for _, sm := range samples {
		if k := sm.Labels[key]; k != "" {
			if v, seen := out[k]; !seen || sm.Value > v {
				out[k] = sm.Value
			}
		}
	}
	return out, true
}

// stampDeviceReadFields fills the read-only, server-stamped fields of an
// inventory read (tracker 349 follow-up, owner report 2026-10-10):
//
//   - Reachability from collector_target_up over the last 3 minutes, scoped
//     to the caller's devices (metricsScopeFiltersFor — the chokepoint rule);
//   - SoftwareVersion from the device's own description;
//   - ConfiguredLocation from the sysLocation the SNMP collector publishes;
//   - ReportedSiteID from the device's SD-WAN overlay facts or its controller.
//
// Every source is best-effort and an unread one leaves its field empty /
// "unknown" — never a guessed value — and is logged (§10).
func (s *server) stampDeviceReadFields(ctx context.Context, claims jwtClaims, ds []models.Device) []models.Device {
	if len(ds) == 0 {
		return ds
	}
	maxUp, minUp, ok := s.collectorReachability(ctx, s.metricsScopeFiltersFor(claims))
	if !ok {
		logWarn("devices", "collector reachability unread — every device reads 'unknown' this request", map[string]any{"devices": len(ds)})
	}
	locs, err := collectors.FetchSysLocationMap(ctx)
	if err != nil {
		logWarn("devices", "configured device locations unread — the device-configured site is blank this request", map[string]any{"error": err.Error()})
	}
	swRevs, err := collectors.FetchSoftwareRevMap(ctx)
	if err != nil {
		logWarn("devices", "ENTITY-MIB software revisions unread — the software version falls back to the device description only", map[string]any{"error": err.Error()})
	}
	overlay, err := collectors.FetchOverlayFacts(ctx)
	if err != nil {
		logWarn("devices", "SD-WAN overlay facts unread — the device-reported site id is blank this request", map[string]any{"error": err.Error()})
	}
	for i := range ds {
		ds[i].ReportedSiteID, ds[i].ReportedSiteSource = reportedSite(ds[i], overlay[ds[i].ID])
		ds[i].Reachability = devreach.Fold(maxUp, minUp, ds[i].ID)
		// The device's own description first (the version advisories are matched
		// on), then the ENTITY-MIB software revision every vendor's agent can
		// report per component.
		ds[i].SoftwareVersion = firstNonEmpty(
			collectors.ResolveDeviceOS(strings.ToLower(ds[i].Vendor), ds[i].OS, ds[i].OSVersion).Version,
			swRevs[ds[i].ID],
			controllerReportedVersion(ds[i]))
		ds[i].ConfiguredLocation = locs[ds[i].ID]
	}
	return ds
}
