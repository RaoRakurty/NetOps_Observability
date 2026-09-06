// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package showparse is Correlix's DETERMINISTIC SHOW-OUTPUT PARSER LIBRARY —
// the in-house equivalent of Genie, scoped to the state battery the Iris
// troubleshooting model actually names (design
// IRIS_TROUBLESHOOTING_MODEL_2026-09-02 §3.2, phase A3).
//
// WHY IT EXISTS. NetClaw's load-bearing rule is "never guess device state — run
// a show command first, always", and the second half of that rule is that the
// MODEL never reads raw CLI text: every capture is parsed into typed fields
// first, so reasoning happens over `InterfaceState.CRC` and `BGPPeer.State`,
// not over a paragraph a language model may hallucinate structure into. This
// package is that parse step.
//
// THE ONE INVARIANT: A PARSER NEVER FABRICATES A FIELD.
// Every optional field is a POINTER (or an explicitly-populated slice). Absent
// means absent: a `show interfaces` capture from a platform that does not report
// a last-flap time yields LastFlap == nil, NEVER a zero time that a downstream
// rule would read as "flapped at the epoch". Output a parser does not recognize
// yields Result{Skipped: true, Reason: …} — an honest inconclusive, never a
// guessed row. This mirrors the three verify-module parsers
// (internal/verify/modules.go), whose contract is identical.
//
// SHAPE.
//   - A Library is an immutable registry of (command id, dialect) → parse
//     function, built by NewLibrary and safe to share across goroutines. There
//     is no package-level mutable state (CLAUDE.md §5); the package-level Parse
//     helper is backed by a sync.OnceValue-built Library.
//   - Command ids (Cmd*) are the SAME ids protocoldiag's state battery renders,
//     so a battery capture and its parser cannot drift apart.
//   - Dialect ids are vendorprofile PROFILE IDS ("cisco/ios_xe", "juniper/junos",
//     …). There is exactly ONE vendor vocabulary in this backend
//     (internal/vendorprofile) and this package resolves through it; a test
//     asserts every Dialect constant is a real profile in that registry.
//
// BOUNDS (§9). Input is capped at MaxInputBytes (the same ceiling
// protocoldiag.MaxOutputBytes puts on one command's capture), the number of
// lines considered is capped at maxLines, and any single line longer than
// maxLineBytes is refused for matching rather than scanned. Parsers are
// field-splitting first and regexp-light by design: there is no nested
// quantifier anywhere in this package, so adversarial input cannot trigger
// catastrophic backtracking. No parser starts a goroutine, touches the network,
// reads a file, or mutates its input.
package showparse

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"netops/backend/internal/vendorprofile"
)

// MaxInputBytes is the hard ceiling on one raw capture handed to Parse. It is
// deliberately the same number as protocoldiag.MaxOutputBytes — the collector
// refuses a bigger capture, so a bigger blob reaching a parser means something
// upstream skipped the cap and the parse is refused rather than trusted.
// (protocoldiag pins the equality with a test.)
const MaxInputBytes = 512 << 10

const (
	// maxLines bounds how many lines a parser will consider. A `show logging`
	// buffer is thousands of lines; this is generous headroom, not a target.
	maxLines = 20000
	// maxLineBytes bounds ONE line. A longer line is not scanned at all (it is
	// counted as unrecognized) — an adversarial 400 KB single line costs one
	// length check, never a scan.
	maxLineBytes = 8192
)

var (
	// ErrInputTooLarge is the size-cap refusal (§9).
	ErrInputTooLarge = errors.New("showparse: raw output exceeds the input cap")
	// ErrNoCommand is an empty command id.
	ErrNoCommand = errors.New("showparse: empty command id")
)

// Dialect is a vendor CLI dialect, identified by its internal/vendorprofile
// profile id ("<vendor>/<platform>"). Using the registry's own ids is what keeps
// this package from becoming a second vendor vocabulary.
type Dialect string

// The supported dialects. Each value is a real vendorprofile profile id;
// TestDialects_ResolveThroughVendorProfile proves it.
const (
	DialectCiscoIOS   Dialect = "cisco/ios"
	DialectCiscoIOSXE Dialect = "cisco/ios_xe"
	DialectCiscoNXOS  Dialect = "cisco/nx-os"
	DialectCiscoIOSXR Dialect = "cisco/ios_xr"
	DialectJunos      Dialect = "juniper/junos"
	DialectNokiaSROS  Dialect = "nokia/sros"
	DialectAristaEOS  Dialect = "arista/eos"
	DialectHuaweiVRP  Dialect = "huawei/vrp"
)

// Dialects returns every supported dialect in a stable, deterministic order.
func Dialects() []Dialect {
	return []Dialect{
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoNXOS, DialectCiscoIOSXR,
		DialectJunos, DialectNokiaSROS, DialectAristaEOS, DialectHuaweiVRP,
	}
}

// Command ids. These are CONCEPT ids shared with protocoldiag's state battery:
// the battery renders the dialect command for the concept, this package parses
// that concept's output for that dialect.
const (
	// CmdInterfaceDetail is the per-interface state/counter read.
	CmdInterfaceDetail = "if-state"
	// CmdInterfaceBrief is the interface/address summary read.
	CmdInterfaceBrief = "if-brief"
	// CmdInterfaceOptics is the transceiver digital-diagnostics (DDM) read.
	CmdInterfaceOptics = "if-optics"
	// CmdOSPFNeighbor is the OSPF adjacency table.
	CmdOSPFNeighbor = "ospf-neighbor"
	// CmdISISNeighbor is the IS-IS adjacency table.
	CmdISISNeighbor = "isis-neighbor"
	// CmdBGPSummary is the BGP neighbor summary.
	CmdBGPSummary = "bgp-summary"
	// CmdRoutePrefix is the routing-table lookup for one prefix.
	CmdRoutePrefix = "route-prefix"
	// CmdARP is the ARP / neighbor-cache read.
	CmdARP = "arp"
	// CmdMAC is the MAC forwarding-table read.
	CmdMAC = "mac"
	// CmdPlatformCPU is the CPU (and, where the same command carries it,
	// memory) utilization read.
	CmdPlatformCPU = "platform-cpu"
	// CmdPlatformMemory is the memory utilization read where it is a separate
	// command.
	CmdPlatformMemory = "platform-memory"
	// CmdPlatformEnv is the environment (temperature/fan/PSU) read.
	CmdPlatformEnv = "platform-env"
	// CmdPlatformUptime is the version/uptime/last-reload read.
	CmdPlatformUptime = "platform-uptime"
	// CmdLogs is the bounded device log-buffer read.
	CmdLogs = "logs"
)

// Commands returns every command id this library knows, in a stable order.
func Commands() []string {
	return []string{
		CmdInterfaceDetail, CmdInterfaceBrief, CmdInterfaceOptics,
		CmdOSPFNeighbor, CmdISISNeighbor, CmdBGPSummary, CmdRoutePrefix,
		CmdARP, CmdMAC,
		CmdPlatformCPU, CmdPlatformMemory, CmdPlatformEnv, CmdPlatformUptime,
		CmdLogs,
	}
}

// Result is one parse outcome: the typed rows a parser recognized, plus the
// honest inconclusive flag.
//
// Skipped means the parser could not recognize the output at all (wrong
// platform, truncated capture, an error banner, a format this parser was NOT
// authored against). Reason then explains why, in operator-readable words.
//
// Reason is ALSO set on a NON-skipped, deliberately-empty result — the case
// where the device answered definitively "there is nothing here" (e.g.
// "% Network not in table"). That distinction is load-bearing: "we could not
// read it" and "the device says there is none" are different evidence, and
// collapsing them would be a fabrication in the direction that matters most.
type Result struct {
	// CmdID is the command concept that was parsed.
	CmdID string
	// Dialect is the dialect the parser was selected for.
	Dialect Dialect
	// Skipped is true when nothing could be recognized (inconclusive).
	Skipped bool
	// Reason explains a Skipped result, or a recognized-but-empty one.
	Reason string

	Interfaces   []InterfaceState
	IGPNeighbors []IGPNeighbor
	BGPPeers     []BGPPeer
	Routes       []RouteEntry
	ARP          []ARPEntry
	MAC          []MACEntry
	Logs         []LogLine
	// Platform is nil unless a platform-health parser populated it.
	Platform *PlatformHealth
}

// Rows reports how many typed rows of any kind the result carries.
func (r Result) Rows() int {
	n := len(r.Interfaces) + len(r.IGPNeighbors) + len(r.BGPPeers) +
		len(r.Routes) + len(r.ARP) + len(r.MAC) + len(r.Logs)
	if r.Platform != nil {
		n++
	}
	return n
}

// parseFunc is one (command, dialect) parser. It receives the already
// size-checked, already line-split input and returns the typed rows it
// recognized. Returning an empty Result means "recognized nothing" and Parse
// turns that into the honest Skipped outcome — a parser never sets Skipped
// itself, so the fail-closed behaviour is in ONE place.
type parseFunc func(lines []string) Result

// key is the registry key.
type key struct {
	cmd     string
	dialect Dialect
}

// Library is the immutable parser registry. Build it once with NewLibrary and
// share it; it is read-only after construction, so it is safe under -race.
type Library struct {
	parsers map[key]parseFunc
}

// NewLibrary builds the parser registry. It is a pure function of authored code
// — no IO, no environment — so two Libraries are always identical.
func NewLibrary() *Library {
	l := &Library{parsers: make(map[key]parseFunc)}
	registerInterfaceParsers(l)
	registerOpticsParsers(l)
	registerIGPParsers(l)
	registerBGPParsers(l)
	registerRouteParsers(l)
	registerL2Parsers(l)
	registerPlatformParsers(l)
	registerLogParsers(l)
	return l
}

// register binds fn to (cmd, dialect...). A duplicate binding is a programming
// error and panics AT CONSTRUCTION (never at parse time) so it cannot ship: the
// registry is built by every test in this package.
func (l *Library) register(cmd string, fn parseFunc, dialects ...Dialect) {
	for _, d := range dialects {
		k := key{cmd: cmd, dialect: d}
		if _, dup := l.parsers[k]; dup {
			panic(fmt.Sprintf("showparse: duplicate parser for %s/%s", cmd, d))
		}
		l.parsers[k] = fn
	}
}

// Supports reports whether a parser exists for (cmdID, dialect).
func (l *Library) Supports(cmdID string, d Dialect) bool {
	_, ok := l.parsers[key{cmd: cmdID, dialect: d}]
	return ok
}

// Bindings returns every (command id, dialect) pair the library can parse, in a
// stable order (command order, then dialect order). It is the coverage report
// the design's "≥ 20 (command, dialect) parsers" acceptance is counted from.
func (l *Library) Bindings() [][2]string {
	var out [][2]string
	for _, c := range Commands() {
		for _, d := range Dialects() {
			if l.Supports(c, d) {
				out = append(out, [2]string{c, string(d)})
			}
		}
	}
	return out
}

// Parse parses raw output for (cmdID, dialect).
//
// It returns an error ONLY for a caller/contract violation: an empty command id
// or an over-cap input. Everything else — an unknown command, an unsupported
// dialect, unrecognizable text, a truncated capture — is a Result with
// Skipped=true and a Reason, because those are legitimate field conditions and
// an inconclusive parse is a valid, honest answer.
func (l *Library) Parse(cmdID string, d Dialect, raw string) (Result, error) {
	if strings.TrimSpace(cmdID) == "" {
		return Result{}, ErrNoCommand
	}
	res := Result{CmdID: cmdID, Dialect: d}
	if len(raw) > MaxInputBytes {
		return Result{}, fmt.Errorf("%w: %d bytes (cap %d)", ErrInputTooLarge, len(raw), MaxInputBytes)
	}
	fn, ok := l.parsers[key{cmd: cmdID, dialect: d}]
	if !ok {
		res.Skipped = true
		res.Reason = fmt.Sprintf("no parser is authored for %q on dialect %q — output left unparsed", cmdID, string(d))
		return res, nil
	}
	lines := splitLines(raw)
	if len(lines) == 0 {
		res.Skipped = true
		res.Reason = "the capture is empty"
		return res, nil
	}
	out := fn(lines)
	out.CmdID = cmdID
	out.Dialect = d
	if out.Rows() == 0 && !out.Skipped && out.Reason == "" {
		out.Skipped = true
		out.Reason = "no line of the capture matched the authored format for this dialect — reporting inconclusive rather than guessing"
	}
	return out, nil
}

// defaultLibrary is the process-wide immutable Library, built at most once. It
// is a function value, not mutable state: nothing can reassign the registry.
var defaultLibrary = sync.OnceValue(NewLibrary)

// Default returns the shared immutable Library.
func Default() *Library { return defaultLibrary() }

// Parse is the package-level convenience over Default().Parse.
func Parse(cmdID string, d Dialect, raw string) (Result, error) {
	return Default().Parse(cmdID, d, raw)
}

// DialectFromPlatform resolves a free-form platform string ("Cisco IOS-XE 17.9",
// "Juniper Junos 22.4R3", "Arista EOS 4.30.2F") onto a supported Dialect.
//
// The vendorprofile registry is the ONLY authority: its ranked
// platform_contains table resolves the text to a profile id, and this package
// answers only "do I have parsers for that id?". There is no local token map —
// the Arista/Huawei fallback that used to stand in for the two profiles that
// declared no platform_contains was deleted when those profiles gained their own
// detection strings (T9 residual, tracker 216). A gap in resolution is therefore
// a gap in internal/vendorprofile/profiles/*.json, fixed there and nowhere else.
//
// An unrecognized platform returns ("", false): the caller reports the device
// unassessed. There is NO default dialect — rendering a Cisco command at an
// unknown platform is exactly the kind of guess this package exists to refuse.
func DialectFromPlatform(platform string) (Dialect, bool) {
	if strings.TrimSpace(platform) == "" {
		return "", false
	}
	prof, ok := vendorprofile.Default().ProfileForPlatformText(platform)
	if !ok {
		return "", false
	}
	d := Dialect(prof.ID)
	for _, sup := range Dialects() {
		if sup == d {
			return d, true
		}
	}
	// The registry resolved the platform to a profile this library has no
	// dialect for (e.g. cisco/asa, nokia/srlinux). Honest miss.
	return "", false
}

// splitLines splits raw output into lines, normalizing CRLF and dropping a
// trailing empty line, bounded by maxLines. A line longer than maxLineBytes is
// replaced by the empty string: parsers then simply do not recognize it, which
// is the correct, cheap, non-backtracking answer to an adversarially long line.
func splitLines(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	if n := len(parts); n > 0 && parts[n-1] == "" {
		parts = parts[:n-1]
	}
	if len(parts) > maxLines {
		parts = parts[:maxLines]
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		if len(p) > maxLineBytes {
			out[i] = ""
			continue
		}
		out[i] = p
	}
	return out
}
