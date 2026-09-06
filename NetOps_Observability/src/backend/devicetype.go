// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"

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
