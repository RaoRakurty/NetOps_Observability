// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package ifbridge is the interface bridge's NMS half and its merge with the
// SNMP half (tracker 387 PR 13a).
//
// The bridge is two maps every consumer of interface identity reads: interface
// address → ifName, and ifIndex → ifName, per inventory device. The SNMP
// collector has fed them from IF-MIB and ipAddrTable since C7.1
// (collectors/if_rows_retention.go). Owner rule 2026-10-24: the NMS is the
// primary source and SNMP a bonus, so a device known only through its
// controller (lab: cedge-81 answers no SNMP walk, vManage reports all of its
// interfaces) must reach the same maps. This package holds what the controller
// said, keyed by the inventory device the controller's key resolved to, and
// merges it with the SNMP rows.
//
// Rules, in the order they bind:
//
//  1. A row reaches the bridge only under a device the integration's OWN owner
//     owns (nms.InventoryResolver is owner-strict). A controller key that
//     matched no device, or more than one, contributes nothing: an address is
//     never the device match itself.
//  2. Interfaces of the internal VPNs (65528 and up: the controller's own
//     loopbacks, which reuse one address on every device) are skipped at the
//     source, and so are addresses that cannot name one box (loopback,
//     link-local, unspecified, multicast).
//  3. Each row keeps its VPN/VRF. An address is unique per (tenant, VRF); a
//     lookup that does not know the VRF (a trap's source address) treats an
//     address two devices hold in ANY VRF as held by neither.
//  4. An address two devices of one tenant hold stays held by both, so the
//     resolvers find it ambiguous and name neither.
//  5. SNMP and NMS rows for one device merge. Where they name the same port
//     (canonically: "Gi3" and "GigabitEthernet3") they agree and the SNMP
//     spelling stays, because it is the one the device_if_* series carry.
//     Where they disagree the newer reading wins, and the merge records both
//     sources.
//  6. A device's NMS rows outlive its polls for MaxAge (seven days, the same
//     bound as the SNMP rows #167 retains), and go at once when the device
//     leaves the inventory or changes owner.
//
// Pure: no IO, no clock. Time comes in as an argument; the caller (the api)
// reads and writes the key-value store.
package ifbridge

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"netops/backend/internal/owner"
)

// Sources of a bridge row, a closed set.
const (
	SourceSNMP = "snmp"
	SourceNMS  = "nms"
)

const (
	// StateVersion is the persisted NMS state schema. A payload of any other
	// version is treated as absent, never reinterpreted.
	StateVersion = 1
	// MaxAge bounds how long a device's NMS rows outlive the last poll that
	// listed them: collectors.ifRowMaxAge, the SNMP side's bound (#167).
	MaxAge = 7 * 24 * time.Hour
	// MaxDevices bounds the state (nms.maxControllerDevices).
	MaxDevices = 20000
	// MaxRowsPerDevice bounds one device's interfaces (a hostile or broken
	// controller must not grow the state without limit).
	MaxRowsPerDevice = 4096
	// MaxAddrsPerRow bounds one interface's addresses.
	MaxAddrsPerRow = 16
	// MaxTotalRows bounds the whole state: ~1k devices x 200 ports, the same
	// budget flownames.MaxRows uses.
	MaxTotalRows = 200_000
	// maxTextRunes bounds one controller-reported name, VRF or description.
	maxTextRunes = 128
	// maxIfIndexDigits bounds an ifIndex (IF-MIB: 1..2147483647).
	maxIfIndexDigits = 10
)

// Row is one interface as a controller reported it, after validation.
type Row struct {
	// IfIndex is the IF-MIB index the controller reports, decimal; "" when it
	// reports none (the row still names addresses).
	IfIndex string `json:"ifindex,omitempty"`
	IfName  string `json:"ifname"`
	// VRF is the VPN / VRF the interface belongs to ("" = the controller did
	// not say). Kept with every address: an address is unique per (tenant, VRF).
	VRF string `json:"vrf,omitempty"`
	// Alias is the operator's description of the interface.
	Alias string `json:"alias,omitempty"`
	// Addrs are the interface's identifying addresses, canonical IP text.
	Addrs []string `json:"addrs,omitempty"`
}

// DeviceRows is one inventory device's interfaces from one controller poll.
type DeviceRows struct {
	// Tenant is the owner the rows were resolved under: the integration's. A
	// change of the device's owner discards them, never relabels them.
	Tenant      string `json:"tenant"`
	Integration string `json:"integration"`
	// System is the controller kind ("vmanage"), for operators.
	System string `json:"system"`
	// At is the unix-ms time of the poll that listed these rows.
	At   int64 `json:"at"`
	Rows []Row `json:"rows"`
}

// State is every device's NMS rows, keyed by inventory device id.
type State struct {
	Version int                    `json:"version"`
	Devices map[string]*DeviceRows `json:"devices"`
}

// NewState returns an empty state of the current version.
func NewState() State {
	return State{Version: StateVersion, Devices: map[string]*DeviceRows{}}
}

// InternalVPN reports a VPN number the SD-WAN controller reserves for itself
// (65528 and up): its interfaces are the system's own loopbacks, which reuse
// one address on every device (lab: 192.168.1.1 is Loopback65528 on every
// cEdge). They are not interfaces of the managed network.
func InternalVPN(vpn string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(vpn))
	return err == nil && n >= 65528
}

// InternalLoopback reports an interface NAMED as a loopback of an internal VPN
// (lo65528, Loopback65530, loopback65531): the number is the VPN. A source
// that reports no VPN (SNMP's ipAddrTable) is caught by the name.
func InternalLoopback(ifName string) bool {
	n := strings.ToLower(strings.TrimSpace(ifName))
	for _, p := range []string{"loopback", "lo"} {
		if rest, ok := strings.CutPrefix(n, p); ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return InternalVPN(rest)
		}
	}
	return false
}

// IdentifyingAddr reports whether an address can name the ONE device that
// holds it. Never: loopback, link-local, unspecified or multicast addresses
// (the same on every box, or not an address of one), and the internal VPN
// loopbacks.
func IdentifyingAddr(ip net.IP, ifName string) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return !InternalLoopback(ifName)
}

// cleanText trims, strips control characters and bounds a controller-reported
// string. Controller output is untrusted input (§3).
func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > maxTextRunes {
		s = strings.TrimSpace(string(r[:maxTextRunes]))
	}
	return s
}

// cleanIfIndex keeps a positive decimal ifIndex; anything else is "".
func cleanIfIndex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxIfIndexDigits || strings.Trim(s, "0123456789") != "" {
		return ""
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 || n == 4294967295 {
		return "" // 0 and 2^32-1 are IPFIX's "no interface", never an index
	}
	return strconv.FormatUint(n, 10)
}

// ParseAddr reads one controller-reported address: "a.b.c.d", "a.b.c.d/len",
// an IPv6 address with or without a prefix length. "-" and anything unparsable
// is nil.
func ParseAddr(s string) net.IP {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return net.ParseIP(s)
}

// Skip reasons for an interface or an address, a closed set (the metrics'
// outcome label).
const (
	SkipInternalVPN = "internal_vpn"
	SkipAddress     = "unidentifying_address"
)

// Normalize validates one row. It returns ok=false when the row is skipped
// whole (an internal VPN, or nothing to name), and how many addresses it
// dropped as unidentifying.
func Normalize(r Row) (out Row, ok bool, droppedAddrs int) {
	out = Row{
		IfIndex: cleanIfIndex(r.IfIndex),
		IfName:  cleanText(r.IfName),
		VRF:     cleanText(r.VRF),
		Alias:   cleanText(r.Alias),
	}
	if out.IfName == "" || InternalVPN(out.VRF) || InternalLoopback(out.IfName) {
		return Row{}, false, 0
	}
	seen := map[string]bool{}
	for _, a := range r.Addrs {
		ip := ParseAddr(a)
		if !IdentifyingAddr(ip, out.IfName) {
			droppedAddrs++
			continue
		}
		k := ip.String()
		if seen[k] || len(out.Addrs) >= MaxAddrsPerRow {
			continue
		}
		seen[k] = true
		out.Addrs = append(out.Addrs, k)
	}
	sort.Strings(out.Addrs)
	return out, true, droppedAddrs
}

// normOwner is the bridge's spelling of an owner (owner.Of: lower-cased,
// trimmed, the platform realm's "" and "global" as one).
func normOwner(t string) string { return owner.Of(t) }

// SameOwner reports whether two owner spellings name one owner.
func SameOwner(a, b string) bool { return owner.Same(a, b) }

// Sanitize drops what a loaded state must not be believed about (§3: never
// trust cached data without validation): a version it does not know, a stamp
// from the future (it would defeat the age bound), rows past MaxAge, and every
// row the validator refuses. It enforces the bounds again.
func (st *State) Sanitize(now time.Time) {
	if st.Version != StateVersion || st.Devices == nil {
		*st = NewState()
		return
	}
	nowMs := now.UnixMilli()
	total := 0
	ids := make([]string, 0, len(st.Devices))
	for id := range st.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	kept := 0
	for _, id := range ids {
		d := st.Devices[id]
		if strings.TrimSpace(id) == "" || d == nil || d.At <= 0 || d.At > nowMs ||
			nowMs-d.At >= MaxAge.Milliseconds() || kept >= MaxDevices {
			delete(st.Devices, id)
			continue
		}
		rows := make([]Row, 0, len(d.Rows))
		for _, r := range d.Rows {
			if len(rows) >= MaxRowsPerDevice || total >= MaxTotalRows {
				break
			}
			if n, ok, _ := Normalize(r); ok {
				rows = append(rows, n)
				total++
			}
		}
		if len(rows) == 0 {
			delete(st.Devices, id)
			continue
		}
		d.Rows = rows
		d.Tenant = normOwner(d.Tenant)
		d.Integration, d.System = cleanText(d.Integration), cleanText(d.System)
		kept++
	}
}
