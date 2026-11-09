// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
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

// stampDeviceReadFields fills the read-only, server-stamped fields of an
// inventory read (tracker 349 follow-up, owner report 2026-10-10):
//
//   - Reachability from collector_target_up over the last 3 minutes, scoped
//     to the caller's devices (metricsScopeFiltersFor — the chokepoint rule);
//   - SoftwareVersion from the device's own description;
//   - ConfiguredLocation from the sysLocation the SNMP collector publishes.
//
// Every source is best-effort and an unread one leaves its field empty /
// "unknown" — never a guessed value — and is logged (§10).
func (s *server) stampDeviceReadFields(ctx context.Context, claims jwtClaims, ds []models.Device) []models.Device {
	if len(ds) == 0 {
		return ds
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	f := s.metricsScopeFiltersFor(claims)
	const q = `last_over_time(collector_target_up{collector!="netconf"}[3m])`
	maxUp, okMax := s.qVecByScoped(qctx, "max by (device) ("+q+")", "device", f)
	minUp, okMin := s.qVecByScoped(qctx, "min by (device) ("+q+")", "device", f)
	if !okMax || !okMin {
		logWarn("devices", "collector reachability unread — every device reads 'unknown' this request", map[string]any{"devices": len(ds)})
		maxUp, minUp = nil, nil
	}
	locs, err := collectors.FetchSysLocationMap(ctx)
	if err != nil {
		logWarn("devices", "configured device locations unread — the device-configured site is blank this request", map[string]any{"error": err.Error()})
	}
	swRevs, err := collectors.FetchSoftwareRevMap(ctx)
	if err != nil {
		logWarn("devices", "ENTITY-MIB software revisions unread — the software version falls back to the device description only", map[string]any{"error": err.Error()})
	}
	for i := range ds {
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
