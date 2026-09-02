package protocoldiag

// statebattery.go — the SHOW-FIRST STATE BATTERY (design
// IRIS_TROUBLESHOOTING_MODEL_2026-09-02 §3.2, phase A3).
//
// The 15-issue CATALOG answers "the operator picked BGP → session down; capture
// the evidence for THAT". The BATTERY answers the question that comes first in
// NetClaw's model and therefore in ours: **never guess device state — run a show
// command first, always.** It is a small, per-area, per-dialect set of read-only
// reads an investigation takes BEFORE it has a hypothesis, so the evidence the
// model narrates is measured rather than assumed.
//
// It is a SECOND closed table, not a widening of the first. Three properties
// make that safe:
//
//   - Every template is authored data here, matched TOKEN-WISE by
//     dialectTable (commandtable.go) under batteryGrammar. Nothing is composed
//     at runtime; the SSH runner will never put a string on a wire that is not a
//     rendering of one of these templates.
//   - Every rendered form passes ValidateReadOnly, proven for BOTH the empty and
//     the fully-populated Target in TestStateBattery_EveryCommandIsReadOnly.
//     There is no `show running-config` in this table and no template that could
//     render into one.
//   - A dialect with NO authored template for a command contributes NOTHING.
//     Unlike the catalog (whose unbound vendors fall back to the Cisco dialect,
//     recorded on the Collection), the battery NEVER falls back: rendering a
//     Cisco command at a Nokia router would be a guess, and the honest answer to
//     "we have not established this platform's command" is to not run one.
//
// Dialects are internal/vendorprofile PROFILE IDS, reached through
// showparse.Dialect — one vendor vocabulary for the whole backend (CLAUDE.md
// §13). Command ids are showparse command ids, so every battery command's output
// has a parser or is honestly unparsed.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"netops/backend/internal/showparse"
	"netops/backend/internal/vendorprofile"
)

// Area is one investigative dimension of device state. It is the axis the
// caller (and, later, the `get_device_state` skill tool) selects on.
type Area string

const (
	// AreaInterfaces is interface state, error counters and transceiver DDM.
	AreaInterfaces Area = "interfaces"
	// AreaIGP is OSPF and IS-IS adjacency state.
	AreaIGP Area = "igp"
	// AreaBGP is the BGP neighbour summary.
	AreaBGP Area = "bgp"
	// AreaRoutes is the routing-table lookup for a prefix (VRF-aware).
	AreaRoutes Area = "routes"
	// AreaL2 is the ARP / MAC lookup for an address.
	AreaL2 Area = "l2"
	// AreaPlatform is CPU, memory, environment and uptime.
	AreaPlatform Area = "platform"
	// AreaLogs is the bounded device log buffer.
	AreaLogs Area = "logs"
)

// BatteryLogLines is the line bound the log-buffer reads carry where the dialect
// has a line-count keyword. It is a CONSTANT, never an operator argument: a
// caller-chosen bound is a caller-chosen cost at a production router. Where a
// dialect has no such keyword the read is bounded by MaxOutputBytes alone, which
// the per-command cap enforces regardless (§9).
const BatteryLogLines = 200

// ErrUnknownArea is returned for an area the battery does not define.
var ErrUnknownArea = errors.New("protocoldiag: unknown state-battery area")

// Areas returns every battery area in a stable, deterministic order.
func Areas() []Area {
	return []Area{AreaInterfaces, AreaIGP, AreaBGP, AreaRoutes, AreaL2, AreaPlatform, AreaLogs}
}

// ValidArea reports whether a is a defined battery area.
func ValidArea(a Area) bool {
	for _, x := range Areas() {
		if x == a {
			return true
		}
	}
	return false
}

// BatterySpec is one battery command CONCEPT: its area, its purpose, the
// per-dialect templates, and the placeholders that MUST be filled for it to
// render at all.
type BatterySpec struct {
	// ID is the showparse command id (showparse.Cmd*). It joins the rendered
	// command to the parser that reads its output, so a battery command whose
	// output nobody can parse is visible as a missing binding rather than a
	// silent raw blob.
	ID string
	// Area is the investigative dimension this command belongs to.
	Area Area
	// Purpose is the operator-facing "why we run this".
	Purpose string
	// templates is the per-dialect command text. A dialect absent from the map
	// contributes NO command (no fallback — see the file header).
	templates map[showparse.Dialect]string
	// requires lists placeholders that must be non-empty. A spec whose required
	// placeholder is empty is OMITTED from the battery rather than rendered into
	// a dangling keyword (`show mac address-table address` with no address is
	// not a valid command and must never reach a device).
	requires []string
	// vrfScoped marks a command whose lookup can be scoped to a VRF /
	// routing-instance / VPN-instance.
	vrfScoped bool
}

// Dialects returns the dialects this spec is EXPLICITLY authored for, in the
// canonical showparse order. A dialect absent from the list is honestly
// unsupported for this command.
func (s BatterySpec) Dialects() []showparse.Dialect {
	out := make([]showparse.Dialect, 0, len(s.templates))
	for _, d := range showparse.Dialects() {
		if t, ok := s.templates[d]; ok && strings.TrimSpace(t) != "" {
			out = append(out, d)
		}
	}
	return out
}

// Render returns the command text for dialect d with tgt's arguments
// substituted, and whether this spec produces a command at all for (d, tgt).
func (s BatterySpec) Render(d showparse.Dialect, tgt Target) (string, bool) {
	tmpl, ok := s.templates[d]
	if !ok || strings.TrimSpace(tmpl) == "" {
		return "", false
	}
	for _, req := range s.requires {
		if strings.TrimSpace(placeholderValue(req, tgt)) == "" {
			return "", false
		}
	}
	scope := ""
	if s.vrfScoped {
		scope = batteryVRFScope(d, tgt.VRF)
	}
	out := strings.NewReplacer(
		"{if}", tgt.Interface,
		"{peer}", tgt.Peer,
		"{prefix}", tgt.Prefix,
		"{addr}", tgt.Address,
		"{vrf-scope}", scope,
	).Replace(tmpl)
	return strings.Join(strings.Fields(out), " "), true
}

// placeholderValue resolves a required-placeholder name against a Target.
func placeholderValue(name string, tgt Target) string {
	switch name {
	case "{if}":
		return tgt.Interface
	case "{peer}":
		return tgt.Peer
	case "{prefix}":
		return tgt.Prefix
	case "{addr}":
		return tgt.Address
	case "{vrf-scope}":
		return tgt.VRF
	default:
		return ""
	}
}

// batteryVRFScope renders the dialect CLI qualifier that scopes a lookup to a
// VRF / routing-instance / VPN-instance, or "" when no VRF is set.
//
// The CONCEPT is confirmed through the vendor-profile registry (the one vendor
// vocabulary: Cisco "VRF" ≡ Juniper "routing-instance" ≡ Nokia "VPRN" ≡ Huawei
// "VPN instance"); the CLI KEYWORD is dialect-specific and authored here, the
// same split catalog.go already makes. The operator's instance name is passed
// through verbatim and case-preserved — it is their identifier, not ours to
// normalize.
func batteryVRFScope(d showparse.Dialect, vrf string) string {
	vrf = strings.TrimSpace(vrf)
	if vrf == "" {
		return ""
	}
	// Assert the concept exists in this dialect's vocabulary. The lookup is
	// documentation-in-code (as in catalog.go): it never gates the operator's
	// own identifier.
	_, _ = vendorprofile.Default().VRFDisplayTerm(vendorTokenOf(d))
	switch d {
	case showparse.DialectJunos:
		return "instance " + vrf
	case showparse.DialectNokiaSROS:
		// The SR OS templates already carry the `router` keyword
		// (`show router {vrf-scope} route-table`); the scope is the bare
		// service/instance name.
		return vrf
	case showparse.DialectHuaweiVRP:
		return "vpn-instance " + vrf
	default: // the Cisco family and Arista EOS
		return "vrf " + vrf
	}
}

// vendorTokenOf returns the vendor segment of a dialect's profile id.
func vendorTokenOf(d showparse.Dialect) string {
	v, _, _ := strings.Cut(string(d), "/")
	return v
}

// RenderedCommand is one battery command ready to run: what it is, which
// dialect it was authored for, and why it is being run.
type RenderedCommand struct {
	// SpecID is the showparse command id.
	SpecID string
	// Area is the battery area the command belongs to.
	Area Area
	// Dialect is the dialect the command was authored for (never a fallback).
	Dialect showparse.Dialect
	// Command is the rendered command text.
	Command string
	// Purpose is the operator-facing rationale.
	Purpose string
}

// StateBattery is the immutable battery: the authored specs plus the compiled
// closed table. Build it with DefaultStateBattery; it is read-only afterwards,
// so it is safe to share across goroutines.
type StateBattery struct {
	specs []BatterySpec
	table *dialectTable
}

// NewStateBattery compiles a battery from a spec set. It VALIDATES at build
// time that every authored template renders to a read-only command in both its
// empty and its fully-populated form — a battery that could emit a non-read-only
// string never becomes an object (fail closed at construction, not at a device).
func NewStateBattery(specs []BatterySpec) (*StateBattery, error) {
	cp := make([]BatterySpec, len(specs))
	copy(cp, specs)
	tbl := &dialectTable{byDialect: map[showparse.Dialect][][]string{}, grammar: batteryGrammar()}
	seen := map[showparse.Dialect]map[string]bool{}
	for _, s := range cp {
		if !ValidArea(s.Area) {
			return nil, fmt.Errorf("protocoldiag: battery spec %q has unknown area %q", s.ID, s.Area)
		}
		for d, tmpl := range s.templates {
			toks := strings.Fields(tmpl)
			if len(toks) == 0 {
				return nil, fmt.Errorf("protocoldiag: battery spec %q has an empty template for %q", s.ID, d)
			}
			if seen[d] == nil {
				seen[d] = map[string]bool{}
			}
			key := strings.Join(toks, " ")
			if !seen[d][key] {
				seen[d][key] = true
				tbl.byDialect[d] = append(tbl.byDialect[d], toks)
			}
		}
	}
	b := &StateBattery{specs: cp, table: tbl}
	// Build-time read-only proof over both target shapes.
	probes := []Target{
		{},
		{Interface: "GigabitEthernet0/0", Peer: "10.0.0.2", Prefix: "192.0.2.0/24",
			Address: "10.0.0.2", VRF: "CUST-A"},
	}
	for _, s := range cp {
		for _, d := range s.Dialects() {
			for _, tgt := range probes {
				cmd, ok := s.Render(d, tgt)
				if !ok {
					continue
				}
				if err := ValidateReadOnly(cmd); err != nil {
					return nil, fmt.Errorf("protocoldiag: battery spec %q/%q renders a non-read-only command %q: %w", s.ID, d, cmd, err)
				}
				if !tbl.Allows(d, cmd) {
					return nil, fmt.Errorf("protocoldiag: battery spec %q/%q renders %q, which its own closed table refuses", s.ID, d, cmd)
				}
			}
		}
	}
	return b, nil
}

// Specs returns every authored spec in authored order.
func (b *StateBattery) Specs() []BatterySpec {
	out := make([]BatterySpec, len(b.specs))
	copy(out, b.specs)
	return out
}

// SpecsFor returns the specs of one area in authored order.
func (b *StateBattery) SpecsFor(area Area) []BatterySpec {
	var out []BatterySpec
	for _, s := range b.specs {
		if s.Area == area {
			out = append(out, s)
		}
	}
	return out
}

// Battery returns the rendered read-only commands for (area, dialect, target),
// in authored order.
//
// It returns an EMPTY slice — never an error and never a fallback command — when
// the dialect has no authored template for any spec in the area, or when a
// spec's required argument is missing. "We have not established this platform's
// command" is honest evidence; a Cisco command rendered at a Huawei router is
// not.
//
// This is the API the forthcoming `get_device_state` skill tool calls:
//
//	dialect, ok := showparse.DialectFromPlatform(dev.Platform)
//	if !ok { /* report the device unassessed — never guess a dialect */ }
//	for _, rc := range battery.Battery(protocoldiag.AreaIGP, dialect, tgt) {
//	    raw, err := runner.Run(ctx, dev, rc.Command)   // read-only + closed table
//	    if err != nil { /* record it on that command and continue */ }
//	    red := protocoldiag.RedactOutput(raw)          // before it leaves the pkg
//	    res, _ := showparse.Parse(rc.SpecID, dialect, red)
//	    // res.Skipped ⇒ inconclusive; res.IGPNeighbors ⇒ typed evidence lines
//	}
//
// or, across a case's whole affected set in one bounded fan-out,
// BatteryCollector.RunBattery (fanout.go), which does all of the above with
// per-device isolation.
func (b *StateBattery) Battery(area Area, d showparse.Dialect, tgt Target) []RenderedCommand {
	var out []RenderedCommand
	for _, s := range b.specs {
		if s.Area != area {
			continue
		}
		cmd, ok := s.Render(d, tgt)
		if !ok {
			continue
		}
		out = append(out, RenderedCommand{
			SpecID: s.ID, Area: s.Area, Dialect: d, Command: cmd, Purpose: s.Purpose,
		})
	}
	return out
}

// Allows reports whether command is a rendering of one of the battery's
// templates for dialect d. It is the closed-table membership test the live
// runner uses; it does NOT replace ValidateReadOnly.
func (b *StateBattery) Allows(d showparse.Dialect, command string) bool {
	return b.table.Allows(d, command)
}

// Coverage reports, per dialect, how many battery specs are authored for it —
// the honest coverage figure a UI may show, with no fallback inflating it.
func (b *StateBattery) Coverage() map[showparse.Dialect]int {
	out := map[showparse.Dialect]int{}
	for _, s := range b.specs {
		for _, d := range s.Dialects() {
			out[d]++
		}
	}
	return out
}

// SpecIDs returns every distinct spec id, sorted — a deterministic enumeration
// for tests and for the parser-coverage drift check.
func (b *StateBattery) SpecIDs() []string {
	set := map[string]struct{}{}
	for _, s := range b.specs {
		set[s.ID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ── the authored battery ────────────────────────────────────────────────────

// bs builds a BatterySpec from a per-dialect template map.
func bs(id string, area Area, purpose string, templates map[showparse.Dialect]string) BatterySpec {
	return BatterySpec{ID: id, Area: area, Purpose: purpose, templates: templates}
}

// requiring returns a copy of s that only renders when every named placeholder
// is filled.
func requiring(s BatterySpec, placeholders ...string) BatterySpec {
	s.requires = append([]string(nil), placeholders...)
	return s
}

// vrfAware returns a copy of s whose {vrf-scope} placeholder is substituted.
func vrfAware(s BatterySpec) BatterySpec {
	s.vrfScoped = true
	return s
}

// DefaultStateBattery builds the shipped battery. It panics only on an authoring
// error the build-time validation catches (an unknown area, an empty template, a
// non-read-only render) — conditions a test in this package proves cannot occur,
// so the panic is a developer tripwire, never a runtime path.
func DefaultStateBattery() *StateBattery {
	b, err := NewStateBattery(defaultBatterySpecs())
	if err != nil {
		panic("protocoldiag: default state battery is invalid: " + err.Error())
	}
	return b
}

// defaultBatterySpecs is the authored table.
//
// Deliberate GAPS (a dialect absent from a spec) and why — each is a command we
// have not established for that platform, and the battery reports nothing rather
// than guessing:
//
//   - if-optics on IOS-XR, EOS and SR OS: XR's optics read is per-controller
//     rather than per-interface; EOS's transceiver sub-command placement varies
//     by train; SR OS carries its DDM inside `show port … detail`, which the
//     battery already runs as if-state.
//   - mac on IOS-XR and SR OS: both key the forwarding table on a bridge-domain
//     / service rather than on a bare address.
//   - platform-memory on NX-OS, Junos and EOS: their platform-cpu command
//     (`show system resources`, `show chassis routing-engine`) already carries
//     memory, so a second read would be a duplicate session cost.
func defaultBatterySpecs() []BatterySpec {
	const logLines = "200" // BatteryLogLines, spelled in the templates
	return []BatterySpec{
		// ── interfaces ──────────────────────────────────────────────────────
		bs(showparse.CmdInterfaceDetail, AreaInterfaces,
			"interface state, error/CRC/drop counters and flap evidence (most protocol faults are a layer below)",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show interfaces {if}",
				showparse.DialectCiscoIOSXE: "show interfaces {if}",
				showparse.DialectCiscoIOSXR: "show interfaces {if}",
				showparse.DialectCiscoNXOS:  "show interface {if}",
				showparse.DialectAristaEOS:  "show interfaces {if}",
				showparse.DialectJunos:      "show interfaces {if} extensive",
				showparse.DialectNokiaSROS:  "show port {if} detail",
				showparse.DialectHuaweiVRP:  "display interface {if}",
			}),
		bs(showparse.CmdInterfaceBrief, AreaInterfaces,
			"L3 interface summary: addressing and admin/oper state across every interface",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show ip interface brief",
				showparse.DialectCiscoIOSXE: "show ip interface brief",
				showparse.DialectCiscoIOSXR: "show ipv4 interface brief",
				showparse.DialectCiscoNXOS:  "show ip interface brief",
				showparse.DialectAristaEOS:  "show ip interface brief",
				showparse.DialectJunos:      "show interfaces terse",
				showparse.DialectNokiaSROS:  "show router interface",
				showparse.DialectHuaweiVRP:  "display ip interface brief",
			}),
		requiring(bs(showparse.CmdInterfaceOptics, AreaInterfaces,
			"transceiver digital diagnostics: Rx/Tx optical power, bias current, module temperature",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show interfaces {if} transceiver detail",
				showparse.DialectCiscoIOSXE: "show interfaces {if} transceiver detail",
				showparse.DialectCiscoNXOS:  "show interface {if} transceiver details",
				showparse.DialectJunos:      "show interfaces diagnostics optics {if}",
				showparse.DialectHuaweiVRP:  "display transceiver interface {if} verbose",
			}), "{if}"),

		// ── igp ─────────────────────────────────────────────────────────────
		bs(showparse.CmdOSPFNeighbor, AreaIGP,
			"OSPF adjacency state per neighbour (anything but FULL is the tell)",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show ip ospf neighbor",
				showparse.DialectCiscoIOSXE: "show ip ospf neighbor",
				showparse.DialectCiscoIOSXR: "show ospf neighbor",
				showparse.DialectCiscoNXOS:  "show ip ospf neighbors",
				showparse.DialectAristaEOS:  "show ip ospf neighbor",
				showparse.DialectJunos:      "show ospf neighbor",
				showparse.DialectNokiaSROS:  "show router ospf neighbor",
				showparse.DialectHuaweiVRP:  "display ospf peer brief",
			}),
		bs(showparse.CmdISISNeighbor, AreaIGP,
			"IS-IS adjacency state per neighbour (level, hold time, anything but Up)",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show isis neighbors",
				showparse.DialectCiscoIOSXE: "show isis neighbors",
				showparse.DialectCiscoIOSXR: "show isis adjacency",
				showparse.DialectCiscoNXOS:  "show isis adjacency",
				showparse.DialectAristaEOS:  "show isis neighbors",
				showparse.DialectJunos:      "show isis adjacency",
				showparse.DialectNokiaSROS:  "show router isis adjacency",
				showparse.DialectHuaweiVRP:  "display isis peer",
			}),

		// ── bgp ─────────────────────────────────────────────────────────────
		bs(showparse.CmdBGPSummary, AreaBGP,
			"BGP session state and accepted-prefix count per neighbour",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show ip bgp summary",
				showparse.DialectCiscoIOSXE: "show ip bgp summary",
				showparse.DialectCiscoIOSXR: "show bgp summary",
				showparse.DialectCiscoNXOS:  "show ip bgp summary",
				showparse.DialectAristaEOS:  "show ip bgp summary",
				showparse.DialectJunos:      "show bgp summary",
				showparse.DialectNokiaSROS:  "show router bgp summary",
				showparse.DialectHuaweiVRP:  "display bgp peer",
			}),

		// ── routes ──────────────────────────────────────────────────────────
		vrfAware(bs(showparse.CmdRoutePrefix, AreaRoutes,
			"routing-table lookup for the subject prefix, scoped to the VRF / routing-instance when one is given",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show ip route {vrf-scope} {prefix}",
				showparse.DialectCiscoIOSXE: "show ip route {vrf-scope} {prefix}",
				showparse.DialectCiscoIOSXR: "show route {vrf-scope} {prefix}",
				showparse.DialectCiscoNXOS:  "show ip route {prefix} {vrf-scope}",
				showparse.DialectAristaEOS:  "show ip route {vrf-scope} {prefix}",
				showparse.DialectJunos:      "show route {vrf-scope} {prefix}",
				showparse.DialectNokiaSROS:  "show router {vrf-scope} route-table {prefix}",
				showparse.DialectHuaweiVRP:  "display ip routing-table {vrf-scope} {prefix}",
			})),

		// ── l2 ──────────────────────────────────────────────────────────────
		bs(showparse.CmdARP, AreaL2,
			"link-layer reachability: the ARP / neighbour cache entry for the subject address",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show ip arp {addr}",
				showparse.DialectCiscoIOSXE: "show ip arp {addr}",
				showparse.DialectCiscoIOSXR: "show arp {addr}",
				showparse.DialectCiscoNXOS:  "show ip arp {addr}",
				showparse.DialectAristaEOS:  "show ip arp {addr}",
				// Junos and VRP scope the ARP table by interface or hostname,
				// not by a bare address, so the read is the whole table.
				showparse.DialectJunos:     "show arp",
				showparse.DialectNokiaSROS: "show router arp {addr}",
				showparse.DialectHuaweiVRP: "display arp",
			}),
		requiring(bs(showparse.CmdMAC, AreaL2,
			"MAC forwarding-table entry for the subject hardware address",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show mac address-table address {addr}",
				showparse.DialectCiscoIOSXE: "show mac address-table address {addr}",
				showparse.DialectCiscoNXOS:  "show mac address-table address {addr}",
				showparse.DialectAristaEOS:  "show mac address-table address {addr}",
				showparse.DialectHuaweiVRP:  "display mac-address {addr}",
			}), "{addr}"),

		// ── platform ────────────────────────────────────────────────────────
		bs(showparse.CmdPlatformCPU, AreaPlatform,
			"control-plane CPU utilization (a busy CPU explains adjacency loss that looks like a link fault)",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show processes cpu sorted",
				showparse.DialectCiscoIOSXE: "show processes cpu sorted",
				showparse.DialectCiscoIOSXR: "show processes cpu",
				showparse.DialectCiscoNXOS:  "show system resources",
				showparse.DialectAristaEOS:  "show processes top once",
				showparse.DialectJunos:      "show chassis routing-engine",
				showparse.DialectNokiaSROS:  "show system cpu",
				showparse.DialectHuaweiVRP:  "display cpu-usage",
			}),
		bs(showparse.CmdPlatformMemory, AreaPlatform,
			"control-plane memory utilization",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show processes memory sorted",
				showparse.DialectCiscoIOSXE: "show processes memory sorted",
				showparse.DialectCiscoIOSXR: "show memory summary",
				showparse.DialectNokiaSROS:  "show system memory-pools",
				showparse.DialectHuaweiVRP:  "display memory-usage",
			}),
		bs(showparse.CmdPlatformEnv, AreaPlatform,
			"environment: temperature, fan and power-supply state",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show environment all",
				showparse.DialectCiscoIOSXE: "show environment all",
				showparse.DialectCiscoIOSXR: "show environment all",
				showparse.DialectCiscoNXOS:  "show environment",
				showparse.DialectAristaEOS:  "show environment temperature",
				showparse.DialectJunos:      "show chassis environment",
				showparse.DialectNokiaSROS:  "show chassis",
				showparse.DialectHuaweiVRP:  "display device",
			}),
		bs(showparse.CmdPlatformUptime, AreaPlatform,
			"software version, uptime and last reload reason (a recent reload reframes every other symptom)",
			map[showparse.Dialect]string{
				showparse.DialectCiscoIOS:   "show version",
				showparse.DialectCiscoIOSXE: "show version",
				showparse.DialectCiscoIOSXR: "show version",
				showparse.DialectCiscoNXOS:  "show version",
				showparse.DialectAristaEOS:  "show version",
				showparse.DialectJunos:      "show system uptime",
				showparse.DialectNokiaSROS:  "show system information",
				showparse.DialectHuaweiVRP:  "display version",
			}),

		// ── logs ────────────────────────────────────────────────────────────
		bs(showparse.CmdLogs, AreaLogs,
			"recent device log buffer, bounded to the last "+logLines+" lines where the dialect has a line-count keyword",
			map[showparse.Dialect]string{
				// IOS, IOS-XE and EOS have no portable line-count keyword on
				// `show logging`; the read is bounded by MaxOutputBytes alone.
				showparse.DialectCiscoIOS:   "show logging",
				showparse.DialectCiscoIOSXE: "show logging",
				showparse.DialectAristaEOS:  "show logging",
				showparse.DialectCiscoIOSXR: "show logging last " + logLines,
				showparse.DialectCiscoNXOS:  "show logging last " + logLines,
				showparse.DialectJunos:      "show log messages | last " + logLines,
				showparse.DialectNokiaSROS:  "show log log-id 99",
				showparse.DialectHuaweiVRP:  "display logbuffer",
			}),
	}
}
