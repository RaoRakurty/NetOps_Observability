// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package devname is the ONE server-side rule for the name an operator reads
// for a device.
//
// A device id is `<sanitized sysName>-<address hash>` (internal/discovery
// ScanDeviceID): the hash keeps two "edge-1"s apart in every store, and it is
// the key of every metric, alert and RCA row. It is internal. An operator reads
// the device's hostname (owner, 2026-11-23: "keep hostname as it is; if random
// IDs are required for internal assignments keep it internal, don't show it").
//
// The rule mirrors the frontend's lib/deviceNames.ts buildDeviceNames:
//
//   - the device's own name, trimmed;
//   - two devices of the SAME tenant with the same name are told apart by
//     their management address ("edge-1 (10.0.0.1)") — never by a hash;
//   - a device with no name (or whose name is its id) has no entry, so the
//     caller keeps showing the id rather than inventing a name.
//
// Duplicates are counted per tenant (§3a): another tenant's device never
// changes how this tenant's device reads, and never reveals that it exists.
package devname

import "strings"

// Entry is the slice of a device record the rule reads.
type Entry struct {
	ID      string
	Name    string
	Address string
	Tenant  string
}

// Names returns id → display name for every entry that has a usable name.
func Names(devs []Entry) map[string]string {
	type key struct{ tenant, name string }
	count := make(map[key]int, len(devs))
	for _, d := range devs {
		if n := strings.TrimSpace(d.Name); n != "" {
			count[key{normTenant(d.Tenant), n}]++
		}
	}
	out := make(map[string]string, len(devs))
	for _, d := range devs {
		id := strings.TrimSpace(d.ID)
		n := strings.TrimSpace(d.Name)
		if id == "" || n == "" || n == id {
			continue
		}
		if count[key{normTenant(d.Tenant), n}] > 1 {
			if a := strings.TrimSpace(d.Address); a != "" {
				out[id] = n + " (" + a + ")"
				continue
			}
		}
		out[id] = n
	}
	return out
}

func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }
