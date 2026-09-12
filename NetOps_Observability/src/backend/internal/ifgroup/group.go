// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifgroup

import (
	"math"
	"sort"
	"strings"
)

// group.go — the PURE model: everything that decides what an operator reads is
// a function of samples only, so it is unit-testable without a network, a mux
// or a clock. Nothing here does IO.

// Membership says how an interface's routing-instance binding was established.
const (
	// MembershipObserved — the interface series itself carried a `vrf` label.
	MembershipObserved = "observed"
	// MembershipNotCollected — no transport collecting this device reports an
	// interface→instance binding. NOT the same as "the default instance".
	MembershipNotCollected = "not_collected"
)

// Transport vocabulary for coverage.transport.
const (
	TransportNone  = "none"  // no interface series at all for this device
	TransportGNMI  = "gnmi"  // every series stamped transport=gnmi
	TransportSNMP  = "snmp"  // every series UNSTAMPED — the SNMP lane (see below)
	TransportMixed = "mixed" // both, or an unrecognized stamp alongside another
)

// Interface is one interface row.
//
// Every measured field is a POINTER: null means "no series", which is a
// different fact from zero. A missing error counter must never render as
// "0 errors" — that is the number an operator would wrongly trust.
type Interface struct {
	Name       string   `json:"ifname"`
	Alias      string   `json:"ifalias,omitempty"`
	Index      string   `json:"index,omitempty"`
	VRF        string   `json:"vrf,omitempty"`
	Transport  string   `json:"transport,omitempty"`
	Oper       string   `json:"oper"`
	OperValue  *int     `json:"oper_value"`
	Admin      string   `json:"admin"`
	AdminValue *int     `json:"admin_value"`
	InBps      *float64 `json:"in_bps"`
	OutBps     *float64 `json:"out_bps"`
	SpeedBps   *float64 `json:"speed_bps"`
	InUtilPct  *float64 `json:"in_util_pct"`
	OutUtilPct *float64 `json:"out_util_pct"`
	InErrPerS  *float64 `json:"in_errors_per_s"`
	OutErrPerS *float64 `json:"out_errors_per_s"`
}

// Up reports whether the interface is operationally up. It is deliberately
// three-valued at the source: a nil OperValue means we do not know, and the
// caller must not round that up to healthy.
func (i Interface) Up() bool { return i.OperValue != nil && *i.OperValue == 1 }

// Group is one routing instance and the interfaces bound to it.
type Group struct {
	// VRF is the instance name. It is EMPTY exactly when Membership is
	// not_collected — an unnamed bucket, never the string "default".
	VRF        string      `json:"vrf"`
	Label      string      `json:"label"`
	Membership string      `json:"membership"`
	Count      int         `json:"count"`
	Up         int         `json:"up"`
	Down       int         `json:"down"`
	Unknown    int         `json:"unknown"`
	Members    []Interface `json:"members"`
}

// RoutingInstance is an instance the device is KNOWN to have, from a lane that
// does carry the concept, with no claim about which interfaces are in it.
type RoutingInstance struct {
	Name   string `json:"name"`
	Source string `json:"source"` // e.g. "bgp_control_plane"
}

// Dialect is the vendor's own vocabulary for the concept.
type Dialect struct {
	Term        string `json:"term"`
	TermPlural  string `json:"term_plural"`
	Vendor      string `json:"vendor,omitempty"`
	VendorKnown bool   `json:"vendor_known"`
}

// Coverage is the honesty block. Every consumer is expected to render it.
type Coverage struct {
	// VRFLabels is PROBED, never assumed: did any interface series actually
	// carry a non-empty `vrf` label on this request?
	VRFLabels bool `json:"vrf_labels"`
	// Transport is the lane the interface series came from. TransportSNMP is
	// INFERRED from the absence of a `transport` stamp (the gNMI lane stamps
	// transport=gnmi; the SNMP lane stamps nothing today), which is why
	// TransportInferred exists — the response never presents an inference as a
	// measurement.
	Transport         string   `json:"transport"`
	TransportInferred bool     `json:"transport_inferred"`
	Interfaces        int      `json:"interfaces"`
	InGroups          int      `json:"in_groups"`
	Ungrouped         int      `json:"ungrouped"`
	Utilisation       bool     `json:"utilisation"`
	Errors            bool     `json:"errors"`
	Truncated         bool     `json:"truncated"`
	Notes             []string `json:"notes"`
}

// Response is the wire shape of GET /api/devices/{id}/interfaces/by-vrf.
type Response struct {
	Device           DeviceView        `json:"device"`
	Window           string            `json:"window"`
	Dialect          Dialect           `json:"dialect"`
	Coverage         Coverage          `json:"coverage"`
	Groups           []Group           `json:"groups"`
	RoutingInstances []RoutingInstance `json:"routing_instances"`
}

// DeviceView is the subject of the read, echoed back so a client never has to
// re-derive which device it asked about.
type DeviceView struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// ── decoding ────────────────────────────────────────────────────────────────

// ifStateName decodes an IF-MIB ifOperStatus / ifAdminStatus numeric. Both
// transports were normalized onto this numbering (normalization.yaml enum,
// gnmic canon-status-enums), so one decoder is the whole vocabulary. An
// unrecognized value is "unknown" — never rounded to up or down.
func ifStateName(v int) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "not_present"
	case 7:
		return "lower_layer_down"
	}
	return "unknown"
}

// seriesKey is the interface identity within one device: the ifName the
// canonical label set carries, falling back to the SNMP ifIndex when a platform
// leaves ifName blank. "" means the sample identifies no interface and is
// dropped rather than merged into a nameless row.
func seriesKey(labels map[string]string) string {
	if n := strings.TrimSpace(labels["ifName"]); n != "" {
		return n
	}
	return strings.TrimSpace(labels["index"])
}

// finite returns a pointer to v, or nil when v is not a finite number. A NaN or
// an Inf is an absent measurement, not a value.
func finite(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	out := v
	return &out
}

// ── assembly ────────────────────────────────────────────────────────────────

// Series is the set of instant-query results one request collected. A nil slice
// means that series was not read or came back empty — both render as null
// fields, never as zeros.
type Series struct {
	Oper    []Sample
	Admin   []Sample
	InBps   []Sample
	OutBps  []Sample
	Speed   []Sample // canonical device_if_speed is in Mbit/s (ifHighSpeed)
	InErr   []Sample
	OutErr  []Sample
	BGPVRFs []Sample // control-plane lane, for the known-instance list
}

// BuildInterfaces folds the series into one row per interface.
//
// Oper is the SPINE: an interface exists for this view when its state series
// exists. A counter with no state series would be a row we cannot say anything
// true about ("2 Mb/s on an interface whose state we never read").
func BuildInterfaces(s Series, max int) ([]Interface, bool) {
	rows := make(map[string]*Interface, len(s.Oper))
	order := make([]string, 0, len(s.Oper))
	for _, sm := range s.Oper {
		key := seriesKey(sm.Labels)
		if key == "" || rows[key] != nil {
			continue
		}
		v := int(sm.Value)
		iface := &Interface{
			Name:      key,
			Alias:     strings.TrimSpace(sm.Labels["ifAlias"]),
			Index:     strings.TrimSpace(sm.Labels["index"]),
			VRF:       strings.TrimSpace(sm.Labels["vrf"]),
			Transport: strings.TrimSpace(sm.Labels["transport"]),
			Oper:      ifStateName(v),
			OperValue: &v,
			Admin:     "unknown",
		}
		rows[key] = iface
		order = append(order, key)
	}

	apply := func(samples []Sample, set func(*Interface, Sample)) {
		for _, sm := range samples {
			if iface := rows[seriesKey(sm.Labels)]; iface != nil {
				set(iface, sm)
			}
		}
	}
	apply(s.Admin, func(i *Interface, sm Sample) {
		v := int(sm.Value)
		i.Admin, i.AdminValue = ifStateName(v), &v
		if i.VRF == "" {
			i.VRF = strings.TrimSpace(sm.Labels["vrf"])
		}
	})
	apply(s.InBps, func(i *Interface, sm Sample) { i.InBps = finite(sm.Value) })
	apply(s.OutBps, func(i *Interface, sm Sample) { i.OutBps = finite(sm.Value) })
	apply(s.Speed, func(i *Interface, sm Sample) {
		if bps := finite(sm.Value * 1e6); bps != nil && *bps > 0 {
			i.SpeedBps = bps
		}
	})
	apply(s.InErr, func(i *Interface, sm Sample) { i.InErrPerS = finite(sm.Value) })
	apply(s.OutErr, func(i *Interface, sm Sample) { i.OutErrPerS = finite(sm.Value) })

	for _, key := range order {
		i := rows[key]
		i.InUtilPct = utilPct(i.InBps, i.SpeedBps)
		i.OutUtilPct = utilPct(i.OutBps, i.SpeedBps)
	}

	out := make([]Interface, 0, len(order))
	for _, key := range order {
		out = append(out, *rows[key])
	}
	sort.SliceStable(out, func(a, b int) bool { return naturalLess(out[a].Name, out[b].Name) })
	truncated := false
	if max > 0 && len(out) > max {
		out, truncated = out[:max], true
	}
	return out, truncated
}

// utilPct is bps/capacity as a percentage, or nil when either is absent. A
// missing speed series means the percentage is UNKNOWN, not zero.
func utilPct(bps, speed *float64) *float64 {
	if bps == nil || speed == nil || *speed <= 0 {
		return nil
	}
	return finite(*bps / *speed * 100)
}

// naturalLess orders interface names the way an operator reads them:
// Ethernet2 before Ethernet10, ge-0/0/2 before ge-0/0/10. Plain lexical order
// puts Ethernet10 first, which makes a long port list unreadable.
func naturalLess(a, b string) bool {
	ai, bi := 0, 0
	for ai < len(a) && bi < len(b) {
		ad, bd := isDigit(a[ai]), isDigit(b[bi])
		if ad && bd {
			an, aNext := runOfDigits(a, ai)
			bn, bNext := runOfDigits(b, bi)
			if an != bn {
				return an < bn
			}
			ai, bi = aNext, bNext
			continue
		}
		if a[ai] != b[bi] {
			return a[ai] < b[bi]
		}
		ai++
		bi++
	}
	return len(a)-ai < len(b)-bi
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// runOfDigits reads the digit run at i as a number, capped so a pathological
// all-digits name cannot overflow into a wrong ordering.
func runOfDigits(s string, i int) (uint64, int) {
	var n uint64
	for i < len(s) && isDigit(s[i]) {
		if n < 1<<50 {
			n = n*10 + uint64(s[i]-'0')
		}
		i++
	}
	return n, i
}

// ── grouping ────────────────────────────────────────────────────────────────

// GroupByVRF buckets interfaces by their observed `vrf` label.
//
// When NO interface carries one, the result is a SINGLE group with an empty
// name and membership not_collected. It is never named "default": claiming
// every interface sits in the default instance is a statement about the device
// that no collected series supports.
//
// term is the device's dialect word ("VRF", "routing-instance", …) and is used
// only for the human label.
func GroupByVRF(ifaces []Interface, term string) (groups []Group, vrfLabels bool) {
	byVRF := map[string][]Interface{}
	var names []string
	var loose []Interface
	for _, i := range ifaces {
		if i.VRF == "" {
			loose = append(loose, i)
			continue
		}
		if _, seen := byVRF[i.VRF]; !seen {
			names = append(names, i.VRF)
		}
		byVRF[i.VRF] = append(byVRF[i.VRF], i)
		vrfLabels = true
	}
	sort.Strings(names)
	for _, n := range names {
		groups = append(groups, newGroup(n, n, MembershipObserved, byVRF[n]))
	}
	if len(loose) > 0 {
		// A genuine mix (some series labelled, some not) is a different
		// sentence from "this transport carries no vrf label at all".
		label := term + " membership not collected on this transport"
		if vrfLabels {
			label = term + " membership not collected for these interfaces"
		}
		groups = append(groups, newGroup("", label, MembershipNotCollected, loose))
	}
	return groups, vrfLabels
}

func newGroup(name, label, membership string, members []Interface) Group {
	g := Group{VRF: name, Label: label, Membership: membership, Count: len(members), Members: members}
	for _, m := range members {
		switch {
		case m.OperValue == nil:
			g.Unknown++
		case *m.OperValue == 1:
			g.Up++
		default:
			g.Down++
		}
	}
	return g
}

// ── coverage ────────────────────────────────────────────────────────────────

// TransportOf reports which collector lane the interface series came from.
//
// The gNMI lane stamps transport=gnmi (gnmic's transport-tag processor); the
// SNMP lane stamps nothing today. So an UNSTAMPED series is the SNMP lane by
// deployment convention, not by measurement — inferred=true says so, and the
// caller must not present it as a fact the device reported.
func TransportOf(ifaces []Interface) (transport string, inferred bool) {
	if len(ifaces) == 0 {
		return TransportNone, false
	}
	stamped, unstamped := map[string]bool{}, false
	for _, i := range ifaces {
		if i.Transport == "" {
			unstamped = true
			continue
		}
		stamped[i.Transport] = true
	}
	switch {
	case len(stamped) == 0:
		return TransportSNMP, true
	case len(stamped) == 1 && !unstamped:
		for t := range stamped {
			return t, false
		}
	}
	return TransportMixed, unstamped
}

// KnownRoutingInstances lists the instances the device's CONTROL-PLANE series
// report, deduplicated and ordered. This is the only lane on this platform that
// carries the concept at all, and it says nothing about interface membership.
func KnownRoutingInstances(samples []Sample, max int) []RoutingInstance {
	seen := map[string]bool{}
	var names []string
	for _, sm := range samples {
		n := strings.TrimSpace(sm.Labels["vrf"])
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	if max > 0 && len(names) > max {
		names = names[:max]
	}
	out := make([]RoutingInstance, 0, len(names))
	for _, n := range names {
		out = append(out, RoutingInstance{Name: n, Source: "bgp_control_plane"})
	}
	return out
}

// BuildCoverage assembles the honesty block, including the notes that name
// every absent source. A source that is not collected is reported ABSENT with a
// reason — never as a zero and never as "healthy".
func BuildCoverage(ifaces []Interface, groups []Group, vrfLabels, truncated bool, term string, instances []RoutingInstance) Coverage {
	transport, inferred := TransportOf(ifaces)
	cov := Coverage{
		VRFLabels:         vrfLabels,
		Transport:         transport,
		TransportInferred: inferred,
		Interfaces:        len(ifaces),
		Truncated:         truncated,
	}
	for _, g := range groups {
		if g.Membership == MembershipObserved {
			cov.InGroups += g.Count
		} else {
			cov.Ungrouped += g.Count
		}
	}
	for _, i := range ifaces {
		if i.SpeedBps != nil && (i.InBps != nil || i.OutBps != nil) {
			cov.Utilisation = true
		}
		if i.InErrPerS != nil || i.OutErrPerS != nil {
			cov.Errors = true
		}
	}

	notes := make([]string, 0, 5)
	switch {
	case len(ifaces) == 0:
		notes = append(notes, "No interface state series exists for this device — nothing is collecting device_if_oper_status for it, so there are no interfaces to group.")
	case !vrfLabels:
		notes = append(notes, term+" membership is not collected on this transport: the canonical interface series carry {device, vendor, ifName, transport} and no vrf label. SNMP IF-MIB has no VRF column, and the gNMI interface subscriptions sit outside the /network-instances tree that carries the instance name.")
		notes = append(notes, "These interfaces are shown ungrouped on purpose. They are NOT reported as members of a default "+term+" — that would be a claim about the device that no collected series supports.")
	case cov.Ungrouped > 0:
		notes = append(notes, "Some interface series carry a vrf label and some do not; the unlabelled ones are listed separately rather than folded into an instance.")
	}
	if len(instances) > 0 && !vrfLabels {
		notes = append(notes, "The device does report routing instances on its BGP control-plane series; they are listed under routing_instances. That lane carries the instance name but not which interfaces belong to it.")
	}
	if !cov.Utilisation && len(ifaces) > 0 {
		notes = append(notes, "Utilisation percentages are null: no device_if_speed series was returned, so there is no link capacity to divide by.")
	}
	if !cov.Errors && len(ifaces) > 0 {
		notes = append(notes, "Error rates are null: no device_if_in_errors/device_if_out_errors series was returned. Null means not collected, not zero errors.")
	}
	if truncated {
		notes = append(notes, "The interface list was truncated at the response cap; the counts above describe only the returned rows.")
	}
	cov.Notes = notes
	return cov
}
