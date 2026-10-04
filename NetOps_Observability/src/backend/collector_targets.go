// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"

	"netops/backend/collectors"
	"netops/backend/internal/snmpcred"
	"netops/backend/models"
)

// collectorTargetFor builds one device's poll target for the collector pool.
//
// Credentials come only from the SNMP profiles, through
// snmpcred.ResolveForDevice: the sentinel's learned override wins while it
// stands, else the bound credential_ref, both tenant-checked (§3a). The override
// applies WHETHER OR NOT a credential_ref is bound — the previous inline builder
// consulted it only inside `if dev.CredentialRef != ""`, so every
// scan-discovered device (no ref) whose working profile the sentinel had
// adopted kept polling with the SNMP_COMMUNITY/"public" fallback and stayed
// down (proven live 2026-10-04). No profile → empty creds → the poller's
// global SNMP_COMMUNITY fallback.
func collectorTargetFor(dev models.Device, creds *snmpcred.Store, overrides *credOverrideStore) collectors.Target {
	tgt := collectors.Target{
		ID: dev.ID,
		// The stored name (raw sysName for scan devices) rides along so the trap
		// receiver's NAT-surviving sysName rescue can match a trap's sysName
		// varbind against what the device actually reports — the derived id
		// (sanitized + addr-hash) never can.
		Name:    dev.Name,
		Address: dev.Address,
		// §3a.2 / F-56: the owning tenant travels with the target so a collector
		// that persists rows stamps it from the inventory, never from anything
		// the device says on the wire.
		TenantID: dev.TenantID,
		Protocol: dev.PreferredProtocol,
		// gNMI-capable devices (a gnmic subscription exists) declare it via the
		// `gnmi: "true"` label; the SNMP collector then yields gNMI-owned metric
		// families (BGP/IS-IS) to gNMI on them, staying the floor elsewhere.
		GNMICapable: strings.EqualFold(dev.Labels["gnmi"], "true"),
	}
	if c, ok := snmpcred.ResolveForDevice(creds, overrides, dev); ok {
		snmpcred.ApplyCredToTarget(&tgt, c)
	}
	return tgt
}
