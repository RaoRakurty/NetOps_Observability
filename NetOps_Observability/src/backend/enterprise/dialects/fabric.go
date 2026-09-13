// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
// Copyright 2026 Correlix
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/Correlix-Enterprise.txt.

package dialects

import (
	"regexp"
	"strconv"
	"strings"

	"netops/backend/internal/hardening"
	"netops/backend/internal/srlpath"
)

// fabric.go — the detection bindings for the two DATA-CENTRE FABRIC
// dialects: Arista EOS and Nokia SR Linux.
//
// WHY THEY ARE THEIR OWN DIALECTS AND NOT REUSED ONES.
//
//	EOS speaks the Cisco IOS show-command grammar, which is why its CLI binding
//	is cisco-iosxe — but it does NOT speak the IOS *configuration* grammar. It
//	has no `line vty` Stanza, no `service password-encryption`, no
//	`ip http server`; its management plane is `management api http-commands` /
//	`management api gnmi` / `management ssh`, which IOS has no analogue for.
//	Binding EOS to the cisco-iosxe rules would have produced confident PASS
//	verdicts on a dozen controls by looking for lines EOS never writes — the
//	precise false-clear §5g forbids.
//
//	SR Linux is not SR OS. It shares Nokia's name and nothing else here: the
//	configuration is a flat `set / <path> <value>` rendering of a YANG tree, and
//	SR OS' `configure system management-interface …` lines do not appear in it.
//	Before this file, "Nokia SR Linux" resolved to the `nokia` (SR OS) bindings
//	and every one of those rules answered "not enabled" against a grammar the
//	device does not use.
//
// CONTROL-CATALOGUE PROVENANCE. Arista publishes a CIS Arista EOS Benchmark
// (v1.0.0 as of 2026-09-03), so the EOS-side concepts here have an industry
// catalogue behind them — but its section taxonomy could not be read from a
// published document, so internal/hardening/benchmark.go records the benchmark and cites NO section
// of it. Nokia SR Linux has no CIS benchmark and no equivalent published
// hardening standard at all. Both therefore map to NIST 800-53 controls ONLY,
// and that is a statement about the state of the industry, not an omission in
// this file. (Before 2026-09-03 the shared rules carried invented `CIS-NET-x.y`
// tags; internal/hardening/benchmark.go explains why they are gone.)
//
// WHAT IS DELIBERATELY NOT DETECTED. A default admin password: neither platform
// exposes anything in the running configuration that distinguishes a shipped
// default credential from a rotated one (both store an irreversible hash), so
// there is no rule for it — a rule that cannot observe its condition can only
// guess, and guessing here means a false clear.

// ─────────────────────────────────────────────────────────────────────────────
// Arista EOS
//
// EOS renders its management plane as IOS-style stanzas — a column-0 header
// with indented children — so Config.IOSStanzas reads it directly. What differs
// is WHICH stanzas exist and what "enabled" means inside one: an EOS management
// service block is OFF unless it carries an explicit `no shutdown`, which is
// why every probe below tests for that line rather than for the block.
// ─────────────────────────────────────────────────────────────────────────────

var (
	reEOSTelnetHeader = regexp.MustCompile(`^management telnet\b`)
	reEOSAPIHeader    = regexp.MustCompile(`^management api http-commands\b`)
	reEOSGNMIHeader   = regexp.MustCompile(`^management api gnmi\b`)
	reEOSNoShutdown   = regexp.MustCompile(`^no shutdown\b`)
	// `protocol http …` and NOT `protocol https …`: in EOS the two are separate
	// keywords and "https" does not match `http\b`.
	reEOSProtocolHTTP  = regexp.MustCompile(`^protocol http\b`)
	reEOSProtocolHTTPS = regexp.MustCompile(`^protocol https\b`)
	reEOSGRPCTransport = regexp.MustCompile(`^transport grpc\s+\S+`)
	reEOSSSLProfile    = regexp.MustCompile(`^\s*(ssl profile|transport grpc\s+\S+\s+ssl profile)\b`)
)

// eosTelnetEnabled trips when the EOS telnet server is administratively up.
// EOS ships telnet DISABLED and does not write the Stanza at all until it is
// touched, so both "no block" and "block without `no shutdown`" are the secure
// state — this reports a real assessed Pass for them, not an assumption.
func eosTelnetEnabled(c *hardening.Config) hardening.DetectResult {
	for _, st := range c.IOSStanzas(reEOSTelnetHeader) {
		if st.ChildHas(reEOSNoShutdown) {
			return hardening.DetectResult{Tripped: true, Evidence: st.Header + " / no shutdown"}
		}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "no administratively enabled `management telnet` server"}
}

// eosEAPIPlaintext trips when the eAPI (`management api http-commands`) is
// enabled AND serves the cleartext HTTP transport.
//
// The absence of a `protocol` line is a real assessed PASS, not an assumption:
// on lab leaf1, whose configuration carries `management api http-commands` with
// only `no shutdown`, `show management api http-commands` reports "HTTPS server:
// running, set to use port 443 / HTTP server: shutdown" (verified 2026-09-02).
// The cleartext listener exists only when `protocol http` is written explicitly,
// and the evidence line says which of the two cases it saw.
func eosEAPIPlaintext(c *hardening.Config) hardening.DetectResult {
	for _, st := range c.IOSStanzas(reEOSAPIHeader) {
		if !st.ChildHas(reEOSNoShutdown) {
			continue
		}
		for _, ch := range st.Children {
			if reEOSProtocolHTTP.MatchString(ch) {
				return hardening.DetectResult{Tripped: true, Evidence: st.Header + " / " + ch}
			}
		}
		if st.ChildHas(reEOSProtocolHTTPS) {
			return hardening.DetectResult{Tripped: false, Evidence: st.Header + " enabled with an explicit HTTPS transport"}
		}
		return hardening.DetectResult{Tripped: false, Evidence: st.Header + " enabled with no `protocol http` line (HTTPS default)"}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "eAPI (`management api http-commands`) not enabled"}
}

// eosGNMIPlaintext trips when a gNMI gRPC transport is configured with no TLS
// profile bound to it — telemetry and, with gNOI, device operations carried in
// cleartext across the management network.
func eosGNMIPlaintext(c *hardening.Config) hardening.DetectResult {
	for _, st := range c.IOSStanzas(reEOSGNMIHeader) {
		var transports []string
		for _, ch := range st.Children {
			if reEOSGRPCTransport.MatchString(ch) {
				transports = append(transports, ch)
			}
		}
		if len(transports) == 0 {
			continue
		}
		if st.ChildHas(reEOSSSLProfile) {
			return hardening.DetectResult{Tripped: false, Evidence: st.Header + " transports bound to an SSL profile"}
		}
		return hardening.DetectResult{Tripped: true, Evidence: st.Header + " / " + transports[0] + " (no `ssl profile` — gNMI served in cleartext)"}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "no gNMI gRPC transport configured"}
}

// eosWeakLocalSecret trips when a local user is defined with no password at all
// (`nopassword`) or with a reversible/obsolete storage type — EOS type 0 is
// cleartext and type 5 is unsalted-era MD5.
var reEOSWeakUser = regexp.MustCompile(`^username\s+\S+.*(\bnopassword\b|\bsecret\s+0\b|\bsecret\s+5\b)`)

func eosWeakLocalSecret(c *hardening.Config) hardening.DetectResult {
	if line, ok := c.FirstMatch(reEOSWeakUser); ok {
		return hardening.DetectResult{Tripped: true, Evidence: line}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "no local user with `nopassword` or a reversible secret type"}
}

// ─────────────────────────────────────────────────────────────────────────────
// Nokia SR Linux
//
// The captured configuration is a flat list of `set <path> <value>` statements,
// one per line. That is why the two multi-instance probes below (gRPC servers,
// TLS profiles) have to group lines by instance name rather than read a block:
// an instance's leaves are spread across many independent lines, and a per-line
// rule would report an instance secure because SOME other instance carried the
// TLS binding.
//
// THE PATH IS WRITTEN THREE WAYS (tracker 296). `set / system …`,
// `set /system …` and the gNMI-style `set /system/aaa/…` are the same statement,
// all legal, all observed. Every pattern here used to anchor on the literal
// `^set / system`, so a capture in either other form matched NOTHING — and a
// rule pack that matches nothing reports Pass, i.e. a CLEAN device. Both halves
// of the fix live below: the patterns are built from internal/srlpath (the one
// place the three spellings are encoded, shared with the core log catalogue),
// and srlinuxReadableConfig fails the whole dialect CLOSED when it cannot see a
// single statement it recognizes — because the next unforeseen rendering must
// produce "not evaluated", not a clean bill of health.
// ─────────────────────────────────────────────────────────────────────────────

// srlListKey is the regexp fragment for a LIST KEY inside an SR Linux path — a
// gRPC-server name, a TLS profile name, an SNMP access-group name. It is LAZY
// (`+?`) on purpose: the key is one token in the space-separated spellings, but
// in the gNMI-style form the separators around it are slashes, and a greedy
// `\S+` would swallow the following path elements with them. Lazy takes the
// shortest token that still lets the rest of the path match, which is the key
// itself in every spelling.
const srlListKey = `(\S+?)`

var (
	// `http admin-state enable` and never `https admin-state enable` — "https"
	// does not match `http\b`, in any of the three spellings.
	reSRLJSONRPCHTTP  = regexp.MustCompile(srlpath.Statement("system", "json-rpc-server") + `\b.*\bhttp` + srlpath.Sep + `admin-state` + srlpath.Sep + `enable\b`)
	reSRLJSONRPCHTTPS = regexp.MustCompile(srlpath.Statement("system", "json-rpc-server") + `\b.*\bhttps` + srlpath.Sep + `admin-state` + srlpath.Sep + `enable\b`)
	reSRLGRPCEnable   = regexp.MustCompile(srlpath.Statement("system", "grpc-server", srlListKey, "admin-state", "enable") + `\b`)
	reSRLGRPCTLS      = regexp.MustCompile(srlpath.Statement("system", "grpc-server", srlListKey) + srlpath.Sep + `(?:tls-profile` + srlpath.Sep + `\S+|default-tls-profile` + srlpath.Sep + `true)\b`)
	reSRLNoClientAuth = regexp.MustCompile(srlpath.Statement("system", "tls", "profile", srlListKey, "authenticate-client", "false") + `\b`)
	reSRLNTPServer    = regexp.MustCompile(srlpath.Statement("system", "ntp", "server") + srlpath.Sep + `\S+`)
	reSRLNTPAdmin     = regexp.MustCompile(srlpath.Statement("system", "ntp", "admin-state", "enable") + `\b`)
	reSRLCommunity    = regexp.MustCompile(srlpath.Statement("system", "snmp", "access-group", srlListKey, "community-entry") + srlpath.Sep + `(\S+)`)
	// SR Linux stores local credentials in TWO shapes, and the rule has to read
	// both. The two BUILT-IN accounts carry the leaf directly
	// (`admin-user password …`, `linuxadmin-user password …`); every account an
	// operator adds is a LIST entry (`user <name> password …`), which is two
	// tokens, not one. The old pattern allowed exactly one token between
	// `authentication` and `password`, so it only ever saw the two built-ins:
	// every configured user went unexamined while the rule still reported a
	// clean verdict over "all locally stored passwords".
	reSRLLocalPassword = regexp.MustCompile(srlpath.Statement("system", "aaa", "authentication") + srlpath.Sep +
		`(user` + srlpath.Sep + `\S+?|\S+?-user)` + srlpath.Sep + `password` + srlpath.Sep + `(\S+)`)
)

// reSRLForeignGrammar matches a configuration statement SR Linux NEVER writes:
// the unmistakable opening tokens of the other dialects we capture (IOS / EOS /
// NX-OS, Junos' slash-less `set system …`, SR OS' `configure …`) and the first
// character of a structured export. It exists only for srlinuxReadableConfig,
// which uses it to tell "a capture in an SR Linux spelling we have not seen" from
// "some other platform's configuration under an SR Linux platform label" — two
// different operator actions, both of which must produce "not evaluated".
var reSRLForeignGrammar = regexp.MustCompile(`(?i)^(?:version \d|hostname \S|interface \S|line (?:con|vty|aux)|` +
	`snmp-server |ip (?:http|ssh|domain|route|name-server) |username \S|enable (?:secret|password)|aaa new-model|` +
	`router (?:bgp|ospf|isis|eigrp)|management (?:api|telnet|ssh|security)|vlan \d|spanning-tree |` +
	`set (?:system|interfaces|protocols|snmp|security|routing-instances|groups|chassis|policy-options) \S|` +
	`/?configure |exit all|[<{])`)

// srlinuxReadableConfig is the dialect's FAIL-CLOSED boundary (hardening's
// DialectPack.Recognize, tracker 296): can the rules below read this text at all?
//
// Every rule in this dialect is a pattern over the SR Linux `set <path>` grammar.
// Handed text in a shape those patterns do not know, each one simply fails to
// match — and "no insecure line found" is the input to a PASS. That is how a
// device nothing could assess gets reported hardened. The only place to catch it
// is once, before any verdict, by asking whether the grammar is present at all.
//
// It is deliberately CONSERVATIVE, because rejecting a genuine capture would
// blind the whole dialect: ONE line that parses as a `set /<path>` statement in
// ANY of the three spellings is enough to accept the config. It rejects only
// three states, each of which is a real operational fault:
//
//   - a capture with no configuration in it at all (the transport returned
//     nothing, or only banners),
//   - a capture in which not one line is an SR Linux `set` path,
//   - a capture whose lines are mostly another platform's grammar — the
//     mislabelled-device case, where a handful of incidental `set /` lines must
//     not buy a verdict over someone else's configuration.
func srlinuxReadableConfig(c *hardening.Config) (bool, string) {
	statements, foreign, considered := 0, 0, 0
	for _, ln := range c.Lines() {
		t := strings.TrimSpace(ln)
		// Blank lines and the comment markers both grammars carry say nothing
		// about which grammar this is.
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!") {
			continue
		}
		considered++
		switch {
		case srlpath.IsStatement(t):
			statements++
		case reSRLForeignGrammar.MatchString(t):
			foreign++
		}
	}
	switch {
	case considered == 0:
		return false, "the capture carries no configuration at all"
	case statements == 0:
		return false, "not one of its " + strconv.Itoa(considered) +
			" statement(s) parses as an SR Linux `set /<path>` line, in any of the three spellings this platform writes"
	case foreign > statements:
		return false, strconv.Itoa(foreign) + " of its statements are another platform's configuration grammar, " +
			"against " + strconv.Itoa(statements) + " SR Linux `set` path(s)"
	}
	return true, ""
}

// srlJSONRPCPlaintext trips when the JSON-RPC management server serves the
// cleartext HTTP listener. SR Linux exposes HTTP and HTTPS as independent
// leaves, so an enabled HTTPS listener does NOT excuse an enabled HTTP one.
func srlJSONRPCPlaintext(c *hardening.Config) hardening.DetectResult {
	if line, ok := c.FirstMatch(reSRLJSONRPCHTTP); ok {
		return hardening.DetectResult{Tripped: true, Evidence: line}
	}
	if line, ok := c.FirstMatch(reSRLJSONRPCHTTPS); ok {
		return hardening.DetectResult{Tripped: false, Evidence: "JSON-RPC server serves HTTPS only: " + line}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "JSON-RPC server not enabled"}
}

// srlInsecureGRPC trips when any administratively enabled gRPC server instance
// (gNMI / gNOI / gNSI / gRIBI / P4RT) has no TLS profile bound — neither its own
// `tls-profile` nor `default-tls-profile true`. Instances are grouped by NAME
// because the flat form scatters one server's leaves across many lines.
func srlInsecureGRPC(c *hardening.Config) hardening.DetectResult {
	enabled := make([]string, 0, 4)
	secured := map[string]bool{}
	for _, ln := range c.Lines() {
		t := strings.TrimSpace(ln)
		if m := reSRLGRPCEnable.FindStringSubmatch(t); m != nil {
			enabled = append(enabled, m[1])
			continue
		}
		if m := reSRLGRPCTLS.FindStringSubmatch(t); m != nil {
			secured[m[1]] = true
		}
	}
	if len(enabled) == 0 {
		return hardening.DetectResult{Tripped: false, Evidence: "no gRPC server instance enabled"}
	}
	var bare []string
	for _, name := range enabled {
		if !secured[name] {
			bare = append(bare, name)
		}
	}
	if len(bare) == 0 {
		return hardening.DetectResult{Tripped: false, Evidence: "every enabled gRPC server instance binds a TLS profile"}
	}
	return hardening.DetectResult{
		Tripped:  true,
		Evidence: "gRPC server instance(s) enabled with no TLS profile: " + strings.Join(bare, ", "),
	}
}

// srlTLSNoClientAuth trips when a TLS profile accepts any client — the server
// proves its identity but never checks the caller's, so possession of the
// management address is the whole authentication story for that transport.
func srlTLSNoClientAuth(c *hardening.Config) hardening.DetectResult {
	if line, ok := c.FirstMatch(reSRLNoClientAuth); ok {
		return hardening.DetectResult{Tripped: true, Evidence: line}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "no TLS profile with `authenticate-client false`"}
}

// srlWeakLocalSecret trips when a locally stored password is NOT an SR Linux
// crypt value. Every hashed secret this OS writes begins with a `$scheme$`
// marker (`$y$` yescrypt, `$6$` sha512-crypt, `$aes1$` for reversible key
// material); a value that starts with anything else was written in the clear.
//
// It walks EVERY account rather than stopping at the first match, so the clean
// verdict can name what was actually examined. "All locally stored passwords
// carry a hash marker" is a claim about coverage, and a detector that examined
// two built-in accounts out of nine must not make it.
//
// The evidence never quotes the stored value: a cleartext credential belongs in
// a finding no more than it belongs in a log (§8).
func srlWeakLocalSecret(c *hardening.Config) hardening.DetectResult {
	examined := make([]string, 0, 4)
	weak := make([]string, 0, 2)
	for _, ln := range c.Lines() {
		m := reSRLLocalPassword.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		// The capture reads `user field-tech` or `user/field-tech` depending on
		// the spelling the device wrote; the ACCOUNT is the same either way, so
		// the evidence names it the same way too.
		account := strings.ReplaceAll(m[1], "/", " ")
		examined = append(examined, account)
		if !strings.HasPrefix(m[2], "$") {
			weak = append(weak, account)
		}
	}
	switch {
	case len(weak) > 0:
		return hardening.DetectResult{
			Tripped: true,
			Evidence: "password stored without a `$scheme$` crypt marker (written in the clear) for: " +
				strings.Join(weak, ", ") + " — of " + strconv.Itoa(len(examined)) + " local account(s) examined",
		}
	case len(examined) == 0:
		// Nothing was examined, so nothing may be claimed clean. No account
		// carries a password leaf at all, which is a statement about THIS
		// config, not about credential hygiene in general.
		return hardening.DetectResult{
			Tripped:  false,
			Evidence: "no local account carries an `aaa authentication … password` leaf: no stored password to examine",
		}
	default:
		return hardening.DetectResult{
			Tripped: false,
			Evidence: strconv.Itoa(len(examined)) + " local account(s) examined (" + strings.Join(examined, ", ") +
				"); each stored password carries a `$scheme$` hash marker",
		}
	}
}

// srlSNMPCommunity trips when any SNMP access-group carries a v1/v2c community
// entry (an unauthenticated, cleartext-on-the-wire credential).
func srlSNMPCommunity(c *hardening.Config) hardening.DetectResult {
	if line, ok := c.FirstMatch(reSRLCommunity); ok {
		return hardening.DetectResult{Tripped: true, Evidence: line}
	}
	return hardening.DetectResult{Tripped: false, Evidence: "no v1/v2c community entry configured"}
}

// srlNTPUnconfigured trips when no NTP server is configured. Unsynchronized
// time is an AUDIT control, not a convenience: every finding, log line and
// correlation window this platform emits is timestamped by the device.
func srlNTPUnconfigured(c *hardening.Config) hardening.DetectResult {
	if line, ok := c.FirstMatch(reSRLNTPServer); ok {
		if c.Has(reSRLNTPAdmin) {
			return hardening.DetectResult{Tripped: false, Evidence: line}
		}
		return hardening.DetectResult{Tripped: true, Evidence: line + " (NTP server listed but `admin-state enable` absent)"}
	}
	return hardening.DetectResult{Tripped: true, Evidence: "no `system ntp server` configured — device clock is unsynchronized"}
}
