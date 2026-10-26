// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// entity_inventory.go — ENTITY-MIB physical inventory (RFC 6933/4133), a
// documented baseline gap. Per-FRU serial / model / class for asset tracking and
// for grounding a hardware-fault signal to a SPECIFIC field-replaceable unit
// (a failing PSU/fan/line-card), not just "the device". Emitted as an info
// series — value 1 with the attributes as labels (the Prometheus metadata
// idiom) — and VM-only: inventory is slow-changing metadata, not a CUSUM metric,
// so it never goes on the correlation bus.

var (
	entPhysicalDescrOID  = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 2}  // entPhysicalDescr
	entPhysicalClassOID  = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 5}  // entPhysicalClass
	entPhysicalSerialOID = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 11} // entPhysicalSerialNum
	entPhysicalModelOID  = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 13} // entPhysicalModelName
	// entPhysicalSoftwareRev — the standard per-component software revision
	// (RFC 6933). The device's software version when its sysDescr carries
	// none (owner report 2026-10-10: the inventory's Software column was blank).
	entPhysicalSoftwareRevOID = []int{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 10}
)

// pickSoftwareRev chooses the device's software revision from the per-entity
// column: the chassis row first, then the first module (IOS XE reports it on
// the route-processor module, not the chassis), then any row that has one.
// "" when no entity reports a revision. Pure.
func pickSoftwareRev(swrev, class map[string]string) string {
	idxs := make([]string, 0, len(swrev))
	for idx, v := range swrev {
		if strings.TrimSpace(v) != "" {
			idxs = append(idxs, idx)
		}
	}
	// Numeric order of the ENTITY-MIB indexes (integers). A malformed index
	// sorts as 0 — the order only decides which revision string wins a tie.
	sort.Slice(idxs, func(i, j int) bool { return atoiOrZero(idxs[i]) < atoiOrZero(idxs[j]) })
	for _, want := range []string{"3", "9", ""} { // chassis, module, anything
		for _, idx := range idxs {
			if want == "" || strings.TrimSpace(class[idx]) == want {
				return sanitizeLabel(swrev[idx])
			}
		}
	}
	return ""
}

// ChassisIdentity is the device's chassis serial and model as its own
// ENTITY-MIB reports them (the chassis row, entPhysicalClass=3).
type ChassisIdentity struct {
	Serial string `json:"serial"`
	Model  string `json:"model,omitempty"`
}

// junkSerials are values agents put in entPhysicalSerialNum when there is no
// serial (virtual platforms, containers, unprogrammed EEPROMs). Compared
// case-insensitively after trimming.
var junkSerials = map[string]bool{
	"": true, "n/a": true, "na": true, "none": true, "unknown": true, "null": true,
	"not available": true, "not specified": true, "default string": true, "to be filled by o.e.m.": true,
}

// usableSerial reports whether a serial is a real one: not a placeholder, not
// all zeros / all the same character, and made of the characters serials are
// made of (the same alphabet nms.cleanSerial accepts).
func usableSerial(s string) bool {
	s = strings.TrimSpace(s)
	if junkSerials[strings.ToLower(s)] || len(s) < 3 || len(s) > 64 {
		return false
	}
	same := true
	for i, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
		if i > 0 && byte(r) != s[0] {
			same = false
		}
	}
	return !same
}

// pickChassisIdentity chooses the device's chassis identity: the LOWEST-indexed
// chassis row (entPhysicalClass=3) that carries a usable serial. A stack or a
// multi-chassis system reports several chassis rows; the lowest index is the
// one agents list first (the stack master / the primary chassis on Cisco,
// Juniper, Arista and SONiC alike), and the choice is stable across polls. A
// device with no chassis row, or none with a real serial, has no identity here
// — the CLI rung of the identity ladder (internal/osprobe) still can. Pure.
func pickChassisIdentity(serial, model, class map[string]string) (ChassisIdentity, bool) {
	idxs := make([]string, 0, len(class))
	for idx, c := range class {
		if strings.TrimSpace(c) == "3" && usableSerial(serial[idx]) {
			idxs = append(idxs, idx)
		}
	}
	if len(idxs) == 0 {
		return ChassisIdentity{}, false
	}
	sort.Slice(idxs, func(i, j int) bool { return atoiOrZero(idxs[i]) < atoiOrZero(idxs[j]) })
	idx := idxs[0]
	return ChassisIdentity{Serial: strings.TrimSpace(serial[idx]), Model: sanitizeLabel(model[idx])}, true
}

// entClassName maps the ENTITY-MIB entPhysicalClass enum to a readable label.
var entClassName = map[string]string{
	"1": "other", "2": "unknown", "3": "chassis", "4": "backplane",
	"5": "container", "6": "powerSupply", "7": "fan", "8": "sensor",
	"9": "module", "10": "port", "11": "stack", "12": "cpu",
}

// sanitizeLabel (now in caps.go) makes an SNMP string safe for a Prometheus label
// value: strip control chars, collapse whitespace, and bound the length. It moved
// so every collector that decodes an untrusted device string shares one bound.

// buildEntityInfoLines joins the ENTITY-MIB columns by physical index and emits
// one info line per FRU — an entity that reports a serial OR a model (a real
// field-replaceable unit, not every nested container/port). Pure + unit-tested.
func buildEntityInfoLines(device, vendor string, descr, model, serial, class map[string]string, tsMillis int64) []string {
	seen := map[string]bool{}
	var idxs []string
	for _, m := range []map[string]string{descr, model, serial, class} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				idxs = append(idxs, k)
			}
		}
	}
	sort.Strings(idxs)

	var lines []string
	for _, idx := range idxs {
		sn := sanitizeLabel(serial[idx])
		md := sanitizeLabel(model[idx])
		if sn == "" && md == "" {
			continue // not a FRU (no serial/model) — skip sub-containers/ports
		}
		cls := entClassName[strings.TrimSpace(class[idx])]
		if cls == "" {
			cls = "unknown"
		}
		lines = append(lines, fmt.Sprintf(
			"device_entity_info{device=%q,vendor=%q,phys_index=%q,descr=%q,model=%q,serial=%q,class=%q} 1 %d",
			device, vendor, idx, sanitizeLabel(descr[idx]), md, sn, cls, tsMillis))
	}
	return lines
}

// collectEntityInventory walks the ENTITY-MIB columns and returns FRU info
// lines, the software revision and the chassis identity (ok=false when the
// device reports none). Best-effort: a device that does not implement
// ENTITY-MIB yields nothing (the walks return empty), so this is safe to call
// every poll.
func collectEntityInventory(ctx context.Context, addr string, creds snmpCreds, device, vendor string, tsMillis int64) ([]string, string, ChassisIdentity, bool) {
	// Descr/Model/Serial are OCTET STRING → raw bytes are the text.
	walkStr := func(oid []int) map[string]string {
		out := map[string]string{}
		if rows, err := snmpWalkColumn(ctx, addr, creds, oid); err == nil {
			for idx, v := range rows {
				out[idx] = string(v.raw)
			}
		}
		return out
	}
	// entPhysicalClass is an INTEGER enum — decode to its decimal string so it
	// matches entClassName (string(v.raw) would yield the raw BER byte, not "3").
	walkInt := func(oid []int) map[string]string {
		out := map[string]string{}
		if rows, err := snmpWalkColumn(ctx, addr, creds, oid); err == nil {
			for idx, v := range rows {
				out[idx] = strconv.FormatInt(valueInt(v), 10)
			}
		}
		return out
	}
	class := walkInt(entPhysicalClassOID)
	model, serial := walkStr(entPhysicalModelOID), walkStr(entPhysicalSerialOID)
	lines := buildEntityInfoLines(device, vendor, walkStr(entPhysicalDescrOID), model, serial, class, tsMillis)
	chassis, ok := pickChassisIdentity(serial, model, class)
	if !ok {
		chassis, ok = vendorChassisIdentity(ctx, addr, creds, vendor)
	}
	return lines, pickSoftwareRev(walkStr(entPhysicalSoftwareRevOID), class), chassis, ok
}

// Vendor chassis scalars for platforms whose ENTITY-MIB carries no chassis row
// with a serial. Junos: JUNIPER-MIB jnxBoxSerialNo / jnxBoxDescr (scalars,
// instance .0; verified against the vendored MIB index). Nokia SR OS / SR
// Linux are identified by the CLI rung (vendorprofile nokia identity probes),
// so they need no SNMP fallback here.
var (
	jnxBoxSerialNoOID = []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 3, 0}
	jnxBoxDescrOID    = []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 2, 0}
)

// vendorChassisIdentity reads the vendor chassis scalars (two GETs, only for
// a vendor that has them and only when ENTITY-MIB had no chassis serial).
func vendorChassisIdentity(ctx context.Context, addr string, creds snmpCreds, vendor string) (ChassisIdentity, bool) {
	if vendor != "juniper" {
		return ChassisIdentity{}, false
	}
	sv, err := snmpGet(ctx, addr, creds, jnxBoxSerialNoOID)
	if err != nil {
		return ChassisIdentity{}, false
	}
	var descr string
	if dv, err := snmpGet(ctx, addr, creds, jnxBoxDescrOID); err == nil {
		descr = string(dv.raw)
	}
	return juniperChassis(string(sv.raw), descr)
}

// juniperChassis validates the Junos chassis scalars. Pure.
func juniperChassis(serial, descr string) (ChassisIdentity, bool) {
	if !usableSerial(serial) {
		return ChassisIdentity{}, false
	}
	return ChassisIdentity{Serial: strings.TrimSpace(serial), Model: sanitizeLabel(descr)}, true
}

// atoiOrZero parses a decimal index; anything else is 0 (see the caller).
func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
