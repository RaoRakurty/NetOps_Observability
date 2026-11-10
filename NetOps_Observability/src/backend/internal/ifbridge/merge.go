// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"sort"
	"strings"
)

// merge.go — the SNMP rows and the NMS rows as ONE bridge.
//
// The wire format of the merged maps is the SNMP collector's, unchanged
// (device → address → ifName, device → ifIndex → ifName), so every consumer and
// entity_resolver.json read them exactly as before. What the merged view adds
// is beside them: the VRF of each NMS address, the source of each row, and the
// interface descriptions.

// Merge outcomes per source, a closed set (the metrics' outcome label).
const (
	MergeBridged      = "bridged"       // the row stands in the merged bridge
	MergeAgreed       = "agreed"        // both sources name the same port; the SNMP spelling stands
	MergeConflictWon  = "conflict_won"  // the sources disagree and this one is newer
	MergeConflictLost = "conflict_lost" // the sources disagree and the other one is newer
	MergeSharedAddr   = "shared_address"
)

// SNMP is the SNMP half as the collector publishes it.
type SNMP struct {
	Addr  map[string]map[string]string // device → interface IP → ifName
	Index map[string]map[string]string // device → ifIndex → ifName
	Alias map[string]map[string]string // device → ifIndex → ifAlias
	// AddrAt / IndexAt are each device's unix-ms walk time for that map. An
	// absent device is a walk of unknown age, older than any NMS reading.
	AddrAt, IndexAt map[string]int64
}

// StatKey is one (source, outcome) pair.
type StatKey struct{ Source, Outcome string }

// Merged is the one bridge.
type Merged struct {
	Addr  map[string]map[string]string // device → interface IP → ifName
	Index map[string]map[string]string // device → ifIndex → ifName
	Alias map[string]map[string]string // device → ifIndex → description
	// IndexSource / AddrSource name the source of each row that stands.
	IndexSource map[string]map[string]string
	AddrSource  map[string]map[string]string
	// AddrVRF is the VRF of each NMS-reported (device, address) that stands;
	// SNMP's ipAddrTable states none.
	AddrVRF map[string]map[string]string
	// Stats counts address and ifIndex rows by source and outcome.
	Stats map[StatKey]int
}

// SamePort reports whether two spellings name one port. The api passes the
// canonical comparison topology uses (canonIface: "Gi3" ≡ "GigabitEthernet3").
type SamePort func(a, b string) bool

func defaultSamePort(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

type nmsVal struct {
	name, vrf string
	at        int64
}

// put sets m[dev][k] = v, creating the inner map.
func put(m map[string]map[string]string, dev, k, v string) {
	if m[dev] == nil {
		m[dev] = map[string]string{}
	}
	m[dev][k] = v
}

// mergeOne folds one NMS value into one SNMP-seeded map entry and reports the
// NMS side's outcome: whether the NMS value now stands, and the stat to count
// ("" = no comparison happened: SNMP had nothing there).
func mergeOne(snmpRows map[string]string, k string, v nmsVal, snmpAt int64, same SamePort) (nmsStands bool, outcome string) {
	cur, has := snmpRows[k]
	switch {
	case !has:
		return true, ""
	case same(cur, v.name):
		return false, MergeAgreed
	case v.at > snmpAt:
		return true, MergeConflictWon
	default:
		return false, MergeConflictLost
	}
}

// Merge builds the one bridge. owners (device id → owner) is used only to
// count addresses two devices of one owner share; nil skips that count. The
// shared address itself stays on both devices: the resolvers name neither.
func Merge(snmp SNMP, nms State, same SamePort, owners map[string]string) Merged {
	if same == nil {
		same = defaultSamePort
	}
	out := Merged{
		Addr: map[string]map[string]string{}, Index: map[string]map[string]string{},
		Alias: map[string]map[string]string{}, IndexSource: map[string]map[string]string{},
		AddrSource: map[string]map[string]string{}, AddrVRF: map[string]map[string]string{},
		Stats: map[StatKey]int{},
	}
	count := func(src, outcome string) { out.Stats[StatKey{src, outcome}]++ }

	for dev, rows := range snmp.Addr {
		for ip, name := range rows {
			put(out.Addr, dev, ip, name)
			put(out.AddrSource, dev, ip, SourceSNMP)
		}
	}
	for dev, rows := range snmp.Index {
		for idx, name := range rows {
			put(out.Index, dev, idx, name)
			put(out.IndexSource, dev, idx, SourceSNMP)
		}
	}
	for dev, rows := range snmp.Alias {
		for idx, a := range rows {
			if a != "" {
				put(out.Alias, dev, idx, a)
			}
		}
	}

	for _, dev := range sortedKeys(nms.Devices) {
		d := nms.Devices[dev]
		idx, addr, alias := map[string]nmsVal{}, map[string]nmsVal{}, map[string]nmsVal{}
		for _, r := range d.Rows {
			if r.IfIndex != "" {
				idx[r.IfIndex] = nmsVal{name: r.IfName, at: d.At}
				if r.Alias != "" {
					alias[r.IfIndex] = nmsVal{name: r.Alias, at: d.At}
				}
			}
			for _, a := range r.Addrs {
				addr[a] = nmsVal{name: r.IfName, vrf: r.VRF, at: d.At}
			}
		}
		for _, k := range sortedKeys(idx) {
			v := idx[k]
			stands, outcome := mergeOne(snmp.Index[dev], k, v, snmp.IndexAt[dev], same)
			if outcome != "" {
				count(SourceNMS, outcome)
			}
			if outcome == MergeConflictWon {
				count(SourceSNMP, MergeConflictLost)
			}
			if outcome == MergeConflictLost {
				count(SourceSNMP, MergeConflictWon)
			}
			if stands {
				put(out.Index, dev, k, v.name)
				put(out.IndexSource, dev, k, SourceNMS)
			}
		}
		for _, k := range sortedKeys(addr) {
			v := addr[k]
			stands, outcome := mergeOne(snmp.Addr[dev], k, v, snmp.AddrAt[dev], same)
			if outcome != "" {
				count(SourceNMS, outcome)
			}
			if outcome == MergeConflictWon {
				count(SourceSNMP, MergeConflictLost)
			}
			if outcome == MergeConflictLost {
				count(SourceSNMP, MergeConflictWon)
			}
			if stands {
				put(out.Addr, dev, k, v.name)
				put(out.AddrSource, dev, k, SourceNMS)
			}
			// The VRF is a fact about the address, true whichever spelling of
			// the port stands; only a losing conflict means the address is not
			// where the NMS said.
			if outcome != MergeConflictLost && v.vrf != "" {
				put(out.AddrVRF, dev, k, v.vrf)
			}
		}
		for _, k := range sortedKeys(alias) {
			v := alias[k]
			cur, has := out.Alias[dev][k]
			if !has || cur == v.name || v.at > snmp.IndexAt[dev] {
				put(out.Alias, dev, k, v.name)
			}
		}
	}

	for _, rows := range out.IndexSource {
		for _, src := range rows {
			count(src, MergeBridged)
		}
	}
	type ownedAddr struct{ owner, ip string }
	holders := map[ownedAddr]int{}
	if owners != nil {
		for dev, rows := range out.Addr {
			if o, ok := owners[dev]; ok {
				for ip := range rows {
					holders[ownedAddr{normOwner(o), ip}]++
				}
			}
		}
	}
	for dev, rows := range out.AddrSource {
		o, known := owners[dev]
		for ip, src := range rows {
			count(src, MergeBridged)
			if known && holders[ownedAddr{normOwner(o), ip}] > 1 {
				count(src, MergeSharedAddr)
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
