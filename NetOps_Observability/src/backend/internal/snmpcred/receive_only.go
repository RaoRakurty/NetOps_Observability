// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

import (
	"strings"

	"netops/backend/collectors"
	"netops/backend/models"
)

// ReceiveOnlyTargets builds the trap receiver's RECEIVE-ONLY identity targets
// for controller-only devices (tracker 371 R2).
//
// A device an integration reports and no collector of ours polls has no bound
// SNMP profile, so the receiver had no credential to prove its traps against
// and they stayed unattributed. Each such device now gets one target per
// profile its OWNER may use — ScanCandidatesFor, owner-strict: a tenant's own
// profiles only, the platform's only for a platform device, never another
// tenant's (owner decision D2). The credential is the channel proof; the tenant
// a trap lands under is the device's own, never derived from an address.
//
// isControllerOnly selects the devices (the caller passes devmon's rule). A
// device that is not monitored (past the licence ceiling) gets none, the same
// gate direct targets have. A v2c profile with no community is skipped: an
// empty community proves nothing, and the receiver never falls back to
// SNMP_COMMUNITY or "public" for a receive-only target.
func ReceiveOnlyTargets(devs []models.Device, creds *Store, isControllerOnly func(models.Device) bool) []collectors.Target {
	if creds == nil || isControllerOnly == nil {
		return nil
	}
	var out []collectors.Target
	byOwner := map[string][]Credential{}
	for _, d := range devs {
		if d.ID == "" || !d.Monitored || !isControllerOnly(d) {
			continue
		}
		owner := strings.ToLower(strings.TrimSpace(d.TenantID))
		cands, ok := byOwner[owner]
		if !ok {
			cands = creds.ScanCandidatesFor(d.TenantID)
			byOwner[owner] = cands
		}
		for _, c := range cands {
			if !strings.EqualFold(c.Version, "v3") && strings.TrimSpace(c.Community) == "" {
				continue
			}
			t := collectors.Target{
				ID: d.ID, Name: d.Name, Address: d.Address, TenantID: d.TenantID,
				ReceiveOnly: true,
			}
			ApplyCredToTarget(&t, c)
			out = append(out, t)
		}
	}
	return out
}
