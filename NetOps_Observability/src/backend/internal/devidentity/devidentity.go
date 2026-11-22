// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package devidentity decides which identities of a CONTROLLER-ONLY device may
// enter the device→tenant registry (device_tenant.csv) beside the rows every
// directly collected device already writes (tracker 371).
//
// Before it, a device an integration reports and no collector of ours polls got
// no registry row of any kind, so its traps, syslog and flows reached the engine
// unattributed (and, with sealing on, quarantined). The fix is deliberately
// narrow, because the owner ruled on 2026-11-01 (NMS_DEVICE_IDENTITY §7: "tenant
// = channel") that nothing on the shared listener is attributed to a TENANT by
// address, name or serial:
//
//   - Every controller-only device, whatever its owner, gets its inventory ID
//     row (`ctl-<system>-<hash>`). The id hashes the owner, so it can never
//     name another tenant's device, and nothing reaches the listener spelled
//     that way except what our own receiver stamped after proving it.
//   - A PLATFORM-owned controller device also gets its name, its management
//     address and its interface addresses — the shared listener is the
//     platform's own channel, so this only turns "unknown sender" into "known
//     platform device" on a single-company appliance.
//   - A tenant-owned controller device gets nothing derived from an address or a
//     name (tracker 372 is the plan of record for that).
//
// Two rules keep a controller claim from ever costing anyone attribution:
//
//  1. A directly collected device always stands: an identity any direct device
//     presents (written or left out as ambiguous) is never claimed by a
//     controller row.
//  2. An identity more than one device holds — two controller devices, or a
//     controller device and any other device's interface — names nobody.
//
// Pure: no IO, no clock, no globals; the caller supplies the inventory and the
// merged interface map.
package devidentity

import (
	"sort"
	"strings"
	"unicode"

	"netops/backend/internal/owner"
)

// Tiers of a controller-derived registry claim.
const (
	// TierID is a controller-only device's own inventory id.
	TierID = "controller_id"
	// TierPlatform is a platform-owned controller device's name, management
	// address or interface address.
	TierPlatform = "controller_platform"
)

// Outcomes of a claim.
const (
	// OutcomeWritten: the claim becomes a registry row.
	OutcomeWritten = "written"
	// OutcomeDirectStands: a directly collected device presents the identity.
	OutcomeDirectStands = "direct_stands"
	// OutcomeShared: more than one device holds the identity.
	OutcomeShared = "shared"
	// OutcomeInvalid: empty, oversized or carrying control characters.
	OutcomeInvalid = "invalid"
)

// MaxIdentityLen bounds an identity the registry will carry. Controller rows are
// upstream input (§3): a name or address longer than any real one is refused.
const MaxIdentityLen = 253

// Device is the part of a controller-only inventory device the decision reads.
type Device struct {
	ID      string
	Name    string
	Address string
	// Owner is the device's owning tenant in either platform spelling.
	Owner string
}

// Claim is one identity a controller-only device may carry in the registry.
type Claim struct {
	Identity string
	DeviceID string
	Tier     string
}

// StatKey is one gauge cell.
type StatKey struct {
	Tier    string
	Outcome string
}

// Claims decides the controller-derived registry claims.
//
// directHeld is every identity a directly collected device presented this cycle
// (written or left out as ambiguous). devices are the controller-only devices.
// ifAddr is the merged interface map, device id → address → interface name, for
// EVERY device (SNMP and controller rows alike): an address another device's
// interface carries is held by that device too.
//
// The result is sorted by (identity, device id) and is the same for the same
// input in any order.
func Claims(directHeld map[string]bool, devices []Device, ifAddr map[string]map[string]string) ([]Claim, map[StatKey]int) {
	stats := map[StatKey]int{}
	// holders: identity → the distinct devices that present it anywhere.
	holders := map[string]map[string]bool{}
	hold := func(identity, device string) {
		if identity == "" || device == "" {
			return
		}
		if holders[identity] == nil {
			holders[identity] = map[string]bool{}
		}
		holders[identity][device] = true
	}
	for dev, m := range ifAddr {
		for addr := range m {
			hold(strings.TrimSpace(addr), dev)
		}
	}
	for _, d := range devices {
		id := strings.TrimSpace(d.ID)
		hold(id, id)
		hold(strings.TrimSpace(d.Name), id)
		hold(strings.TrimSpace(d.Address), id)
	}

	var out []Claim
	seen := map[[2]string]bool{}
	consider := func(identity, deviceID, tier string) {
		identity = strings.TrimSpace(identity)
		if identity == "" {
			return
		}
		key := [2]string{identity, deviceID}
		if seen[key] {
			return // one device presenting the same identity twice is one claim
		}
		seen[key] = true
		switch {
		case !valid(identity):
			stats[StatKey{tier, OutcomeInvalid}]++
		case directHeld[identity]:
			stats[StatKey{tier, OutcomeDirectStands}]++
		case len(holders[identity]) != 1:
			stats[StatKey{tier, OutcomeShared}]++
		default:
			stats[StatKey{tier, OutcomeWritten}]++
			out = append(out, Claim{Identity: identity, DeviceID: deviceID, Tier: tier})
		}
	}
	for _, d := range devices {
		id := strings.TrimSpace(d.ID)
		if id == "" {
			continue
		}
		consider(id, id, TierID)
		if !owner.IsPlatform(d.Owner) {
			continue // tenant = channel: nothing derived from a name or address
		}
		consider(d.Name, id, TierPlatform)
		consider(d.Address, id, TierPlatform)
		addrs := make([]string, 0, len(ifAddr[id]))
		for a := range ifAddr[id] {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)
		for _, a := range addrs {
			consider(a, id, TierPlatform)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Identity != out[j].Identity {
			return out[i].Identity < out[j].Identity
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	return out, stats
}

// valid refuses an identity no real device carries: oversized, or holding a
// control or non-printing character (it would be a key nobody can send).
func valid(s string) bool {
	if len(s) > MaxIdentityLen {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
