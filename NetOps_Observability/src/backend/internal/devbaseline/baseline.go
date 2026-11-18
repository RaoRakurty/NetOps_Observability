// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package devbaseline is the before/after change baseline for one device: a
// time-stamped, tenant-scoped record of the device's interfaces, routing
// neighbours, routing-table size, software version and overlay sessions, read
// with the read-only state battery, and a comparison of a later read against it
// ("what came back, what did not, which counts changed").
//
// Nothing here changes a device. A baseline is built from typed rows the
// showparse library already produced from read-only command output; the
// package never runs a command itself and has no write path to any device.
//
// The idea — take a baseline before a change and verify against it afterwards —
// is re-expressed from NetClaw's change-management skill (Apache-2.0, see
// NOTICE); its configuration-deployment step is deliberately not taken.
package devbaseline

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/showparse"
)

// Bounds (§9 — every list is bounded). A device with more interfaces or
// neighbours than this is still baselined; the truncation is recorded in
// NotRead so a comparison never reads a capped list as a lost entry.
const (
	MaxInterfaces   = 512
	MaxNeighbors    = 512
	MaxRouteSources = 32
	MaxNotRead      = 32
	maxText         = 128
	// MaxPerDevice is how many baselines one device keeps; the oldest is
	// dropped when a new one is taken (retention).
	MaxPerDevice = 10
	// MaxLabel bounds the operator's optional label.
	MaxLabel = 80
)

// Interface is one interface's state as the device printed it.
type Interface struct {
	Name  string `json:"name"`
	Admin string `json:"admin,omitempty"`
	Oper  string `json:"oper,omitempty"`
}

// Neighbor is one routing adjacency or session: an OSPF or IS-IS neighbour or
// a BGP peer.
type Neighbor struct {
	Proto    string `json:"proto"` // ospf | isis | bgp
	ID       string `json:"id"`
	Iface    string `json:"iface,omitempty"`
	State    string `json:"state"`
	Prefixes *int64 `json:"prefixes,omitempty"` // BGP prefixes received
}

// Overlay is the SD-WAN overlay's session counts, read by Correlix's own
// overlay collector (not a device command).
type Overlay struct {
	ControlUp    int `json:"control_up"`
	ControlTotal int `json:"control_total"`
	BFDUp        int `json:"bfd_up"`
	BFDTotal     int `json:"bfd_total"`
}

// Snapshot is one baseline.
type Snapshot struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"-"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	TakenAt    time.Time `json:"taken_at"`
	TakenBy    string    `json:"taken_by"`
	Label      string    `json:"label,omitempty"`

	Version       string           `json:"version,omitempty"`
	BootImage     string           `json:"boot_image,omitempty"`
	Interfaces    []Interface      `json:"interfaces"`
	Neighbors     []Neighbor       `json:"neighbors"`
	RouteTotal    *int64           `json:"route_total,omitempty"`
	RouteBySource map[string]int64 `json:"route_by_source,omitempty"`
	Overlay       *Overlay         `json:"overlay,omitempty"`
	// NotRead names every section that could not be read, with the reason
	// ("bgp: the command did not run: timeout"). A section listed here is
	// CANNOT COMPARE, never "everything was lost".
	NotRead []string `json:"not_read"`
}

// Summary is the list view of a baseline (no section bodies).
type Summary struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	TakenAt    time.Time `json:"taken_at"`
	TakenBy    string    `json:"taken_by"`
	Label      string    `json:"label,omitempty"`
	Interfaces int       `json:"interfaces"`
	Neighbors  int       `json:"neighbors"`
	NotRead    int       `json:"not_read"`
}

// Summarize returns the list view of s.
func (s Snapshot) Summarize() Summary {
	return Summary{ID: s.ID, DeviceID: s.DeviceID, DeviceName: s.DeviceName, TakenAt: s.TakenAt,
		TakenBy: s.TakenBy, Label: s.Label, Interfaces: len(s.Interfaces), Neighbors: len(s.Neighbors), NotRead: len(s.NotRead)}
}

// Describe is the one-line inventory of what a baseline holds ("5 interfaces
// (5 up), 3 routing neighbours, 10 routes, version 17.03.02").
func (s Snapshot) Describe() string {
	up := 0
	for _, x := range s.Interfaces {
		if isUp(x.Oper) {
			up++
		}
	}
	parts := []string{fmt.Sprintf("%d interfaces (%d up)", len(s.Interfaces), up)}
	n := "routing neighbours"
	if len(s.Neighbors) == 1 {
		n = "routing neighbour"
	}
	parts = append(parts, fmt.Sprintf("%d %s", len(s.Neighbors), n))
	if s.RouteTotal != nil {
		parts = append(parts, fmt.Sprintf("%d routes", *s.RouteTotal))
	}
	if s.Version != "" {
		parts = append(parts, "version "+s.Version)
	}
	if o := s.Overlay; o != nil {
		parts = append(parts, fmt.Sprintf("overlay %d of %d control and %d of %d BFD sessions up", o.ControlUp, o.ControlTotal, o.BFDUp, o.BFDTotal))
	}
	return strings.Join(parts, ", ")
}

// Section names: the battery areas a baseline reads (the Read.Section values).
const (
	SectionInterfaces = "interfaces"
	SectionIGP        = "igp"
	SectionBGP        = "bgp"
	SectionUpgrade    = "upgrade"
	SectionOverlay    = "overlay"
)

// Scopes: what one comparison rests on. A NotRead note starts with its scope
// ("ospf: …"), so a router that runs no IS-IS (its IS-IS read does not parse)
// still has its OSPF neighbours compared, and an unparsed boot-variable read
// never hides a version change.
const (
	ScopeInterfaces = "interfaces"
	ScopeOSPF       = "ospf"
	ScopeISIS       = "isis"
	ScopeBGP        = "bgp"
	ScopeVersion    = "version"
	ScopeRoutes     = "routes"
	ScopeOverlay    = "overlay"
)

// sectionScopes is what an area that did not run at all leaves unread.
var sectionScopes = map[string][]string{
	SectionInterfaces: {ScopeInterfaces},
	SectionIGP:        {ScopeOSPF, ScopeISIS},
	SectionBGP:        {ScopeBGP},
	SectionUpgrade:    {ScopeVersion, ScopeRoutes},
	SectionOverlay:    {ScopeOverlay},
}

// commandScope is what one unparsed command leaves unread. Commands not listed
// (the boot variable, filesystem and redundancy reads) feed upgrade readiness,
// not the baseline comparison.
var commandScope = map[string]string{
	showparse.CmdInterfaceDetail: ScopeInterfaces,
	showparse.CmdInterfaceBrief:  ScopeInterfaces,
	showparse.CmdOSPFNeighbor:    ScopeOSPF,
	showparse.CmdISISNeighbor:    ScopeISIS,
	showparse.CmdBGPSummary:      ScopeBGP,
	showparse.CmdUpgradeVersion:  ScopeVersion,
	showparse.CmdPlatformUptime:  ScopeVersion,
	showparse.CmdRouteSummary:    ScopeRoutes,
}

// Read is one battery area's outcome as the caller collected it: the typed
// parse results, or the reason the area was not read.
type Read struct {
	Section string
	Results []showparse.Result
	// NotRead is the reason the whole section was not read; empty when it was.
	NotRead string
}

// Build assembles a snapshot from the collected reads. Every field comes from
// a typed row; a skipped parse is recorded as not read, never as an empty
// section (an unparsed BGP table is not "no BGP peers").
func Build(reads []Read, overlay *Overlay) Snapshot {
	s := Snapshot{Interfaces: []Interface{}, Neighbors: []Neighbor{}, NotRead: []string{}, Overlay: overlay}
	skippedIf := false
	for _, rd := range reads {
		if rd.NotRead != "" {
			for _, sc := range sectionScopes[rd.Section] {
				s.addNotRead(sc + ": " + rd.NotRead)
			}
			continue
		}
		for _, res := range rd.Results {
			if !res.Skipped {
				s.absorb(res)
				continue
			}
			sc, ok := commandScope[res.CmdID]
			switch {
			case !ok:
			case sc == ScopeInterfaces:
				skippedIf = true // decided below: another interface read may have answered
			default:
				s.addNotRead(sc + ": " + res.CmdID + " output could not be parsed")
			}
		}
	}
	if skippedIf && len(s.Interfaces) == 0 {
		s.addNotRead(ScopeInterfaces + ": no interface read could be parsed")
	}
	sort.Slice(s.Interfaces, func(i, j int) bool { return s.Interfaces[i].Name < s.Interfaces[j].Name })
	sort.Slice(s.Neighbors, func(i, j int) bool { return neighborKey(s.Neighbors[i]) < neighborKey(s.Neighbors[j]) })
	return s
}

func (s *Snapshot) addNotRead(note string) {
	switch {
	case len(s.NotRead) < MaxNotRead:
		s.NotRead = append(s.NotRead, clamp(note, 2*maxText))
	case len(s.NotRead) == MaxNotRead:
		s.NotRead = append(s.NotRead, "more sections were not read")
	}
}

func (s *Snapshot) absorb(res showparse.Result) {
	seenIf := map[string]bool{}
	for _, x := range s.Interfaces {
		seenIf[x.Name] = true
	}
	for _, x := range res.Interfaces {
		name := clamp(x.Name, maxText)
		if name == "" || seenIf[name] {
			continue
		}
		if len(s.Interfaces) >= MaxInterfaces {
			s.addNotRead(SectionInterfaces + ": more than " + fmt.Sprint(MaxInterfaces) + " interfaces; the rest were not kept")
			break
		}
		seenIf[name] = true
		s.Interfaces = append(s.Interfaces, Interface{Name: name, Admin: clamp(deref(x.Admin), 32), Oper: clamp(deref(x.Oper), 32)})
	}
	for _, n := range res.IGPNeighbors {
		s.addNeighbor(Neighbor{Proto: strings.ToLower(clamp(n.Proto, 8)), ID: clamp(n.ID, maxText), Iface: clamp(n.Iface, maxText), State: clamp(n.State, 32)})
	}
	for _, p := range res.BGPPeers {
		s.addNeighbor(Neighbor{Proto: "bgp", ID: clamp(p.Peer, maxText), State: clamp(p.State, 32), Prefixes: p.PrefixesRx})
	}
	if ph := res.Platform; ph != nil {
		if v := clamp(deref(ph.Version), maxText); v != "" && s.Version == "" {
			s.Version = v
		}
		if v := clamp(deref(ph.BootImage), maxText); v != "" && s.BootImage == "" {
			s.BootImage = v
		}
	}
	if rs := res.RouteSummary; rs != nil && s.RouteTotal == nil {
		total := rs.Total
		s.RouteTotal = &total
		s.RouteBySource = map[string]int64{}
		for k, v := range rs.BySource {
			if len(s.RouteBySource) >= MaxRouteSources {
				break
			}
			s.RouteBySource[clamp(k, 40)] = v
		}
	}
}

func (s *Snapshot) addNeighbor(n Neighbor) {
	if n.ID == "" || n.Proto == "" {
		return
	}
	for _, have := range s.Neighbors {
		if neighborKey(have) == neighborKey(n) {
			return
		}
	}
	if len(s.Neighbors) >= MaxNeighbors {
		if len(s.NotRead) == 0 || !strings.Contains(s.NotRead[len(s.NotRead)-1], "neighbours") {
			s.addNotRead("neighbours: more than " + fmt.Sprint(MaxNeighbors) + "; the rest were not kept")
		}
		return
	}
	s.Neighbors = append(s.Neighbors, n)
}

func neighborKey(n Neighbor) string { return n.Proto + "|" + n.ID + "|" + n.Iface }

// ── comparison ──────────────────────────────────────────────────────────────

// Change kinds, worst first in the rendered report.
const (
	KindInterfaceDown    = "interface_down"
	KindInterfaceMissing = "interface_missing"
	KindNeighborLost     = "neighbor_lost"
	KindNeighborState    = "neighbor_state"
	KindPrefixes         = "prefixes_changed"
	KindRoutes           = "routes_changed"
	KindOverlay          = "overlay_changed"
	KindVersion          = "version_changed"
	KindInterfaceUp      = "interface_up"
	KindInterfaceNew     = "interface_new"
	KindNeighborNew      = "neighbor_new"
)

var kindRank = map[string]int{
	KindInterfaceDown: 0, KindInterfaceMissing: 1, KindNeighborLost: 2, KindNeighborState: 3,
	KindPrefixes: 4, KindRoutes: 5, KindOverlay: 6, KindVersion: 7,
	KindInterfaceUp: 8, KindInterfaceNew: 9, KindNeighborNew: 10,
}

// Change is one observed difference between the baseline and the current read.
type Change struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Before  string `json:"before"`
	After   string `json:"after"`
}

// Diff is the comparison of a current read against a baseline.
type Diff struct {
	Baseline  Summary   `json:"baseline"`
	ReadAt    time.Time `json:"read_at"`
	Changes   []Change  `json:"changes"`
	Unchanged int       `json:"unchanged"`
	// CannotCompare names sections read on only one side (or neither): their
	// absence on the other side is not a change.
	CannotCompare []string `json:"cannot_compare"`
}

// Compare diffs cur against base. Sections that either side could not read
// are CANNOT COMPARE, not losses: an interface list that the current read did
// not collect is never reported as every interface gone.
func Compare(base, cur Snapshot) Diff {
	d := Diff{Baseline: base.Summarize(), ReadAt: cur.TakenAt, Changes: []Change{}, CannotCompare: []string{}}
	baseMissing := sectionsNotRead(base)
	curMissing := sectionsNotRead(cur)
	skip := func(section string) bool {
		if baseMissing[section] || curMissing[section] {
			who := "the current read"
			if baseMissing[section] {
				who = "the baseline"
			}
			d.CannotCompare = append(d.CannotCompare, section+" (not read in "+who+")")
			return true
		}
		return false
	}

	if !skip(ScopeInterfaces) {
		d.compareInterfaces(base.Interfaces, cur.Interfaces)
	}
	skipped := map[string]bool{ScopeOSPF: skip(ScopeOSPF), ScopeISIS: skip(ScopeISIS), ScopeBGP: skip(ScopeBGP)}
	d.compareNeighbors(base.Neighbors, cur.Neighbors, skipped)
	if !skip(ScopeVersion) {
		if base.Version != "" && cur.Version != "" && base.Version != cur.Version {
			d.Changes = append(d.Changes, Change{Kind: KindVersion, Subject: "software version", Before: base.Version, After: cur.Version})
		} else if base.Version != "" && base.Version == cur.Version {
			d.Unchanged++
		}
	}
	if !skip(ScopeRoutes) {
		d.compareRoutes(base, cur)
	}
	if base.Overlay != nil && cur.Overlay != nil {
		d.compareOverlay(*base.Overlay, *cur.Overlay)
	} else if base.Overlay != nil || cur.Overlay != nil {
		d.CannotCompare = append(d.CannotCompare, SectionOverlay+" (read on one side only)")
	}
	sort.SliceStable(d.Changes, func(i, j int) bool {
		if kindRank[d.Changes[i].Kind] != kindRank[d.Changes[j].Kind] {
			return kindRank[d.Changes[i].Kind] < kindRank[d.Changes[j].Kind]
		}
		return d.Changes[i].Subject < d.Changes[j].Subject
	})
	return d
}

// sectionsNotRead maps the scopes a snapshot lists as not read (by the
// "<scope>:" prefix of each NotRead note).
func sectionsNotRead(s Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, n := range s.NotRead {
		sc, _, ok := strings.Cut(n, ":")
		if !ok {
			continue
		}
		switch sc {
		case ScopeInterfaces, ScopeOSPF, ScopeISIS, ScopeBGP, ScopeVersion, ScopeRoutes, ScopeOverlay:
			// A capped list is not an unread scope: only a read that did not
			// run, or did not parse, makes it incomparable.
			if !strings.Contains(n, "the rest were not kept") {
				out[sc] = true
			}
		}
	}
	return out
}

func isUp(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "up" || strings.HasPrefix(s, "up ") || s == "connected"
}

func ifState(x Interface) string {
	switch {
	case x.Admin != "" && x.Oper != "":
		return x.Admin + "/" + x.Oper
	case x.Oper != "":
		return x.Oper
	default:
		return x.Admin
	}
}

func (d *Diff) compareInterfaces(base, cur []Interface) {
	curBy := map[string]Interface{}
	for _, x := range cur {
		curBy[x.Name] = x
	}
	baseBy := map[string]bool{}
	for _, b := range base {
		baseBy[b.Name] = true
		c, ok := curBy[b.Name]
		switch {
		case !ok:
			d.Changes = append(d.Changes, Change{Kind: KindInterfaceMissing, Subject: b.Name, Before: ifState(b), After: "not in the current read"})
		case isUp(b.Oper) && !isUp(c.Oper):
			d.Changes = append(d.Changes, Change{Kind: KindInterfaceDown, Subject: b.Name, Before: ifState(b), After: ifState(c)})
		case !isUp(b.Oper) && isUp(c.Oper):
			d.Changes = append(d.Changes, Change{Kind: KindInterfaceUp, Subject: b.Name, Before: ifState(b), After: ifState(c)})
		default:
			d.Unchanged++
		}
	}
	for _, c := range cur {
		if !baseBy[c.Name] {
			d.Changes = append(d.Changes, Change{Kind: KindInterfaceNew, Subject: c.Name, Before: "not in the baseline", After: ifState(c)})
		}
	}
}

func neighborLabel(n Neighbor) string {
	label := strings.ToUpper(n.Proto) + " " + n.ID
	if n.Iface != "" {
		label += " on " + n.Iface
	}
	return label
}

func neighborHealthy(n Neighbor) bool {
	s := strings.ToLower(n.State)
	switch n.Proto {
	case "bgp":
		return s == "established" || isNumeric(s)
	case "ospf":
		return strings.HasPrefix(s, "full")
	default:
		return s == "up"
	}
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (d *Diff) compareNeighbors(base, cur []Neighbor, skipped map[string]bool) {
	skipProto := func(p string) bool { return skipped[p] }
	curBy := map[string]Neighbor{}
	for _, n := range cur {
		curBy[neighborKey(n)] = n
	}
	baseBy := map[string]bool{}
	for _, b := range base {
		if skipProto(b.Proto) {
			continue
		}
		k := neighborKey(b)
		baseBy[k] = true
		c, ok := curBy[k]
		switch {
		case !ok:
			d.Changes = append(d.Changes, Change{Kind: KindNeighborLost, Subject: neighborLabel(b), Before: b.State, After: "not in the current read"})
		case neighborHealthy(b) && !neighborHealthy(c):
			d.Changes = append(d.Changes, Change{Kind: KindNeighborState, Subject: neighborLabel(b), Before: b.State, After: c.State})
		case b.Prefixes != nil && c.Prefixes != nil && *b.Prefixes != *c.Prefixes:
			d.Changes = append(d.Changes, Change{Kind: KindPrefixes, Subject: neighborLabel(b),
				Before: fmt.Sprintf("%d prefixes", *b.Prefixes), After: fmt.Sprintf("%d prefixes", *c.Prefixes)})
		default:
			d.Unchanged++
		}
	}
	for _, c := range cur {
		if skipProto(c.Proto) || baseBy[neighborKey(c)] {
			continue
		}
		d.Changes = append(d.Changes, Change{Kind: KindNeighborNew, Subject: neighborLabel(c), Before: "not in the baseline", After: c.State})
	}
}

func (d *Diff) compareRoutes(base, cur Snapshot) {
	if base.RouteTotal == nil || cur.RouteTotal == nil {
		if base.RouteTotal != nil || cur.RouteTotal != nil {
			d.CannotCompare = append(d.CannotCompare, "routing-table size (read on one side only)")
		}
		return
	}
	if *base.RouteTotal != *cur.RouteTotal {
		d.Changes = append(d.Changes, Change{Kind: KindRoutes, Subject: "routing table",
			Before: fmt.Sprintf("%d routes", *base.RouteTotal), After: fmt.Sprintf("%d routes", *cur.RouteTotal)})
	} else {
		d.Unchanged++
	}
	srcs := map[string]bool{}
	for k := range base.RouteBySource {
		srcs[k] = true
	}
	for k := range cur.RouteBySource {
		srcs[k] = true
	}
	keys := make([]string, 0, len(srcs))
	for k := range srcs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, c := base.RouteBySource[k], cur.RouteBySource[k]
		if b != c {
			d.Changes = append(d.Changes, Change{Kind: KindRoutes, Subject: k + " routes",
				Before: fmt.Sprintf("%d", b), After: fmt.Sprintf("%d", c)})
		}
	}
}

func (d *Diff) compareOverlay(base, cur Overlay) {
	if base.ControlUp != cur.ControlUp || base.ControlTotal != cur.ControlTotal {
		d.Changes = append(d.Changes, Change{Kind: KindOverlay, Subject: "overlay control sessions",
			Before: fmt.Sprintf("%d of %d up", base.ControlUp, base.ControlTotal), After: fmt.Sprintf("%d of %d up", cur.ControlUp, cur.ControlTotal)})
	} else {
		d.Unchanged++
	}
	if base.BFDUp != cur.BFDUp || base.BFDTotal != cur.BFDTotal {
		d.Changes = append(d.Changes, Change{Kind: KindOverlay, Subject: "overlay BFD sessions",
			Before: fmt.Sprintf("%d of %d up", base.BFDUp, base.BFDTotal), After: fmt.Sprintf("%d of %d up", cur.BFDUp, cur.BFDTotal)})
	} else {
		d.Unchanged++
	}
}

// Lines renders the diff as plain OBSERVED statements, worst first. Each line
// says what the baseline held and what the current read shows — never why it
// changed.
func (d Diff) Lines() []string {
	out := make([]string, 0, len(d.Changes)+len(d.CannotCompare)+1)
	for _, c := range d.Changes {
		out = append(out, describe(c))
	}
	if len(d.Changes) == 0 {
		out = append(out, fmt.Sprintf("Nothing the baseline recorded has changed (%d items compared).", d.Unchanged))
	}
	for _, s := range d.CannotCompare {
		out = append(out, "Cannot compare "+s+".")
	}
	return out
}

func describe(c Change) string {
	switch c.Kind {
	case KindInterfaceDown:
		return fmt.Sprintf("Interface %s was %s before the change and is %s now.", c.Subject, c.Before, c.After)
	case KindInterfaceMissing:
		return fmt.Sprintf("Interface %s (%s before the change) is not in the current read.", c.Subject, c.Before)
	case KindInterfaceUp:
		return fmt.Sprintf("Interface %s came up: %s before, %s now.", c.Subject, c.Before, c.After)
	case KindInterfaceNew:
		return fmt.Sprintf("Interface %s is new since the baseline (%s).", c.Subject, c.After)
	case KindNeighborLost:
		return fmt.Sprintf("%s (%s before the change) did not come back.", c.Subject, c.Before)
	case KindNeighborState:
		return fmt.Sprintf("%s was %s before the change and is %s now.", c.Subject, c.Before, c.After)
	case KindNeighborNew:
		return fmt.Sprintf("%s is new since the baseline (%s).", c.Subject, c.After)
	case KindPrefixes:
		return fmt.Sprintf("%s: %s before, %s now.", c.Subject, c.Before, c.After)
	case KindRoutes:
		return fmt.Sprintf("The %s held %s before the change and %s now.", c.Subject, c.Before, c.After)
	case KindOverlay:
		return fmt.Sprintf("The %s: %s before, %s now.", c.Subject, c.Before, c.After)
	case KindVersion:
		return fmt.Sprintf("The software version was %s before the change and is %s now.", c.Before, c.After)
	default:
		return fmt.Sprintf("%s: %s before, %s now.", c.Subject, c.Before, c.After)
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// clamp trims s and bounds it to n bytes on a rune boundary, dropping control
// characters (a device string is untrusted text).
func clamp(s string, n int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
