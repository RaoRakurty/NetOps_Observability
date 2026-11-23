// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"regexp"
	"sort"
	"strconv"
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
	// MergeMultiPort counts (device, address) pairs the controller reported on
	// more than one port of ONE device (cEdge: Tunnel1 rides GigabitEthernet1's
	// address). The bridge names one of them (pickAddrPort); the count says how
	// often it had to choose.
	MergeMultiPort = "multi_port_address"
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
	// NMS is each device's controller-reported rows as stored, VRF, role and
	// kind intact (a deep copy: callers cannot mutate the bridge through it).
	// The address maps above keep one name per address, so they cannot say that
	// `Tunnel1` rides `GigabitEthernet1`, and AddrVRF drops the VRF of an
	// address whose port spelling lost a conflict. Per-interface facts (the WAN
	// classifier) read these rows instead.
	NMS map[string]DeviceRows
}

// copyDeviceRows deep-copies one device's rows, address slices included.
func copyDeviceRows(d DeviceRows) DeviceRows {
	rows := make([]Row, len(d.Rows))
	for i, r := range d.Rows {
		r.Addrs = append([]string(nil), r.Addrs...)
		rows[i] = r
	}
	d.Rows = rows
	return d
}

// SamePort reports whether two spellings name one port. The api passes the
// canonical comparison topology uses (canonIface: "Gi3" ≡ "GigabitEthernet3").
type SamePort func(a, b string) bool

func defaultSamePort(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// tunnelNamePattern names a tunnel virtual interface by its vendor spelling:
// Cisco IOS/IOS-XE/NX-OS and Arista `Tunnel1`/`Tu1`, IOS-XR `tunnel-ip1` /
// `tunnel-te1`, Juniper `gr-` (GRE), `ip-` (IP-IP), `st0` (secure tunnel),
// `fti0` (flexible tunnel), Nokia `tunnel-1`, vEdge/Linux `ipsec1`, `gre1`,
// `vti0`. A digit must follow, so `Stack1` or a bare word is not a tunnel.
var tunnelNamePattern = regexp.MustCompile(`(?i)^(tunnel(-ip|-te|-mte|-tp)?|tu|gr-|ip-|st|fti|ipsec|vti|gre)-?\d`)

// TunnelPort reports a tunnel virtual interface: by the IANA ifType the
// controller states (KindTunnel), else by its name. A tunnel borrows the
// address of the port it rides (`ip unnumbered`, an SD-WAN TLOC); it never
// owns it.
func TunnelPort(ifName, kind string) bool {
	return kind == KindTunnel || tunnelNamePattern.MatchString(strings.TrimSpace(ifName))
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

// pickAddrPort names the ONE port of a device an address stands for when the
// controller lists it on several (tracker 437). The row order is never the
// answer: the store sorts rows by name, so `Tunnel1` would beat
// `GigabitEthernet1` and Juniper `gr-`/`st0` would beat `ge-` on every poll.
// In order:
//
//  1. the port the device's own SNMP walk names for the address (ipAddrTable
//     maps an address to exactly one ifIndex), so a controller reading agrees
//     with the walk instead of overriding it;
//  2. a port that is not a tunnel (TunnelPort): a tunnel borrows the address
//     of the port it rides and never owns it;
//  3. the lowest ifIndex (a row without one last), then the name,
//     case-insensitively, then the VRF — a stable tie-break.
//
// multi reports that the rows name more than one port (canonically: two
// spellings of one port are one port).
func pickAddrPort(rows []Row, snmpName string, same SamePort) (pick Row, multi bool) {
	pick = rows[0]
	for _, r := range rows[1:] {
		if !same(r.IfName, pick.IfName) {
			multi = true
		}
		if betterAddrPort(r, pick, snmpName, same) {
			pick = r
		}
	}
	return pick, multi
}

// betterAddrPort reports whether a ranks before b under pickAddrPort's order.
func betterAddrPort(a, b Row, snmpName string, same SamePort) bool {
	if snmpName != "" {
		if sa, sb := same(a.IfName, snmpName), same(b.IfName, snmpName); sa != sb {
			return sa
		}
	}
	if ta, tb := TunnelPort(a.IfName, a.Kind), TunnelPort(b.IfName, b.Kind); ta != tb {
		return tb
	}
	ia, oka := ifIndexOrder(a.IfIndex)
	ib, okb := ifIndexOrder(b.IfIndex)
	if oka != okb {
		return oka
	}
	if ia != ib {
		return ia < ib
	}
	if na, nb := strings.ToLower(a.IfName), strings.ToLower(b.IfName); na != nb {
		return na < nb
	}
	if a.IfName != b.IfName {
		return a.IfName < b.IfName
	}
	return a.VRF < b.VRF
}

// ifIndexOrder reads a validated ifIndex for ordering; ok=false when absent.
func ifIndexOrder(s string) (uint64, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return n, err == nil
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
		Stats: map[StatKey]int{}, NMS: map[string]DeviceRows{},
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
		if d == nil {
			continue
		}
		out.NMS[dev] = copyDeviceRows(*d)
		idx, addr, alias := map[string]nmsVal{}, map[string]nmsVal{}, map[string]nmsVal{}
		holders := map[string][]Row{} // address → every row of this device that lists it
		for _, r := range d.Rows {
			if r.IfIndex != "" {
				idx[r.IfIndex] = nmsVal{name: r.IfName, at: d.At}
				if r.Alias != "" {
					alias[r.IfIndex] = nmsVal{name: r.Alias, at: d.At}
				}
			}
			for _, a := range r.Addrs {
				holders[a] = append(holders[a], r)
			}
		}
		for a, rows := range holders {
			r, multi := pickAddrPort(rows, snmp.Addr[dev][a], same)
			if multi {
				count(SourceNMS, MergeMultiPort)
			}
			addr[a] = nmsVal{name: r.IfName, vrf: r.VRF, at: d.At}
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
