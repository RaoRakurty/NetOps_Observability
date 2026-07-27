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
)

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

// collectEntityInventory walks the four ENTITY-MIB columns and returns FRU info
// lines. Best-effort: a device that does not implement ENTITY-MIB yields no
// lines (the walks return empty), so this is safe to call every poll.
func collectEntityInventory(ctx context.Context, addr string, creds snmpCreds, device, vendor string, tsMillis int64) []string {
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
	return buildEntityInfoLines(device, vendor,
		walkStr(entPhysicalDescrOID), walkStr(entPhysicalModelOID),
		walkStr(entPhysicalSerialOID), walkInt(entPhysicalClassOID), tsMillis)
}
