package hardening

import (
	"regexp"
	"strings"
)

// dialect_fabric.go — the detection bindings for the two DATA-CENTRE FABRIC
// dialects: Arista EOS and Nokia SR Linux.
//
// WHY THEY ARE THEIR OWN DIALECTS AND NOT REUSED ONES.
//
//	EOS speaks the Cisco IOS show-command grammar, which is why its CLI binding
//	is cisco-iosxe — but it does NOT speak the IOS *configuration* grammar. It
//	has no `line vty` stanza, no `service password-encryption`, no
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
// published document, so benchmark.go records the benchmark and cites NO section
// of it. Nokia SR Linux has no CIS benchmark and no equivalent published
// hardening standard at all. Both therefore map to NIST 800-53 controls ONLY,
// and that is a statement about the state of the industry, not an omission in
// this file. (Before 2026-09-03 the shared rules carried invented `CIS-NET-x.y`
// tags; benchmark.go explains why they are gone.)
//
// WHAT IS DELIBERATELY NOT DETECTED. A default admin password: neither platform
// exposes anything in the running configuration that distinguishes a shipped
// default credential from a rotated one (both store an irreversible hash), so
// there is no rule for it — a rule that cannot observe its condition can only
// guess, and guessing here means a false clear.

// ─────────────────────────────────────────────────────────────────────────────
// Shared builder
// ─────────────────────────────────────────────────────────────────────────────

// notApplicable builds a detection that reports the control as structurally
// inapplicable on this platform, carrying the REASON. Use it only where the
// operating system cannot express the insecure state at all (see
// DetectResult.NotApplicable) — never as a placeholder for unwritten detection.
func notApplicable(reason string) func(*Config) DetectResult {
	return func(*Config) DetectResult {
		return DetectResult{NotApplicable: true, Evidence: reason}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Arista EOS
//
// EOS renders its management plane as IOS-style stanzas — a column-0 header
// with indented children — so Config.iosStanzas reads it directly. What differs
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
// EOS ships telnet DISABLED and does not write the stanza at all until it is
// touched, so both "no block" and "block without `no shutdown`" are the secure
// state — this reports a real assessed Pass for them, not an assumption.
func eosTelnetEnabled(c *Config) DetectResult {
	for _, st := range c.iosStanzas(reEOSTelnetHeader) {
		if st.childHas(reEOSNoShutdown) {
			return DetectResult{Tripped: true, Evidence: st.header + " / no shutdown"}
		}
	}
	return DetectResult{Tripped: false, Evidence: "no administratively enabled `management telnet` server"}
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
func eosEAPIPlaintext(c *Config) DetectResult {
	for _, st := range c.iosStanzas(reEOSAPIHeader) {
		if !st.childHas(reEOSNoShutdown) {
			continue
		}
		for _, ch := range st.children {
			if reEOSProtocolHTTP.MatchString(ch) {
				return DetectResult{Tripped: true, Evidence: st.header + " / " + ch}
			}
		}
		if st.childHas(reEOSProtocolHTTPS) {
			return DetectResult{Tripped: false, Evidence: st.header + " enabled with an explicit HTTPS transport"}
		}
		return DetectResult{Tripped: false, Evidence: st.header + " enabled with no `protocol http` line (HTTPS default)"}
	}
	return DetectResult{Tripped: false, Evidence: "eAPI (`management api http-commands`) not enabled"}
}

// eosGNMIPlaintext trips when a gNMI gRPC transport is configured with no TLS
// profile bound to it — telemetry and, with gNOI, device operations carried in
// cleartext across the management network.
func eosGNMIPlaintext(c *Config) DetectResult {
	for _, st := range c.iosStanzas(reEOSGNMIHeader) {
		var transports []string
		for _, ch := range st.children {
			if reEOSGRPCTransport.MatchString(ch) {
				transports = append(transports, ch)
			}
		}
		if len(transports) == 0 {
			continue
		}
		if st.childHas(reEOSSSLProfile) {
			return DetectResult{Tripped: false, Evidence: st.header + " transports bound to an SSL profile"}
		}
		return DetectResult{Tripped: true, Evidence: st.header + " / " + transports[0] + " (no `ssl profile` — gNMI served in cleartext)"}
	}
	return DetectResult{Tripped: false, Evidence: "no gNMI gRPC transport configured"}
}

// eosWeakLocalSecret trips when a local user is defined with no password at all
// (`nopassword`) or with a reversible/obsolete storage type — EOS type 0 is
// cleartext and type 5 is unsalted-era MD5.
var reEOSWeakUser = regexp.MustCompile(`^username\s+\S+.*(\bnopassword\b|\bsecret\s+0\b|\bsecret\s+5\b)`)

func eosWeakLocalSecret(c *Config) DetectResult {
	if line, ok := c.firstMatch(reEOSWeakUser); ok {
		return DetectResult{Tripped: true, Evidence: line}
	}
	return DetectResult{Tripped: false, Evidence: "no local user with `nopassword` or a reversible secret type"}
}

// ─────────────────────────────────────────────────────────────────────────────
// Nokia SR Linux
//
// The captured configuration is the FLAT form: one `set / <path> <value>`
// statement per line, which is why every pattern here anchors on `^set / `.
// That form is also why the two multi-instance probes below (gRPC servers, TLS
// profiles) have to group lines by instance name rather than read a block: an
// instance's leaves are spread across many independent lines, and a per-line
// rule would report an instance secure because SOME other instance carried the
// TLS binding.
// ─────────────────────────────────────────────────────────────────────────────

var (
	// `http admin-state enable` and never `https admin-state enable` — "https"
	// does not match `http\b`.
	reSRLJSONRPCHTTP  = regexp.MustCompile(`^set / system json-rpc-server\b.*\bhttp admin-state enable\b`)
	reSRLJSONRPCHTTPS = regexp.MustCompile(`^set / system json-rpc-server\b.*\bhttps admin-state enable\b`)
	reSRLGRPCEnable   = regexp.MustCompile(`^set / system grpc-server (\S+) admin-state enable\b`)
	reSRLGRPCTLS      = regexp.MustCompile(`^set / system grpc-server (\S+) (?:tls-profile\s+\S+|default-tls-profile true)\b`)
	reSRLNoClientAuth = regexp.MustCompile(`^set / system tls profile (\S+) authenticate-client false\b`)
	reSRLNTPServer    = regexp.MustCompile(`^set / system ntp server \S+`)
	reSRLNTPAdmin     = regexp.MustCompile(`^set / system ntp admin-state enable\b`)
	reSRLCommunity    = regexp.MustCompile(`^set / system snmp access-group (\S+) community-entry (\S+)`)
	reSRLWeakPassword = regexp.MustCompile(`^set / system aaa authentication \S+ password\s+[^$\s]`)
)

// srlJSONRPCPlaintext trips when the JSON-RPC management server serves the
// cleartext HTTP listener. SR Linux exposes HTTP and HTTPS as independent
// leaves, so an enabled HTTPS listener does NOT excuse an enabled HTTP one.
func srlJSONRPCPlaintext(c *Config) DetectResult {
	if line, ok := c.firstMatch(reSRLJSONRPCHTTP); ok {
		return DetectResult{Tripped: true, Evidence: line}
	}
	if line, ok := c.firstMatch(reSRLJSONRPCHTTPS); ok {
		return DetectResult{Tripped: false, Evidence: "JSON-RPC server serves HTTPS only: " + line}
	}
	return DetectResult{Tripped: false, Evidence: "JSON-RPC server not enabled"}
}

// srlInsecureGRPC trips when any administratively enabled gRPC server instance
// (gNMI / gNOI / gNSI / gRIBI / P4RT) has no TLS profile bound — neither its own
// `tls-profile` nor `default-tls-profile true`. Instances are grouped by NAME
// because the flat form scatters one server's leaves across many lines.
func srlInsecureGRPC(c *Config) DetectResult {
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
		return DetectResult{Tripped: false, Evidence: "no gRPC server instance enabled"}
	}
	var bare []string
	for _, name := range enabled {
		if !secured[name] {
			bare = append(bare, name)
		}
	}
	if len(bare) == 0 {
		return DetectResult{Tripped: false, Evidence: "every enabled gRPC server instance binds a TLS profile"}
	}
	return DetectResult{
		Tripped:  true,
		Evidence: "gRPC server instance(s) enabled with no TLS profile: " + strings.Join(bare, ", "),
	}
}

// srlTLSNoClientAuth trips when a TLS profile accepts any client — the server
// proves its identity but never checks the caller's, so possession of the
// management address is the whole authentication story for that transport.
func srlTLSNoClientAuth(c *Config) DetectResult {
	if line, ok := c.firstMatch(reSRLNoClientAuth); ok {
		return DetectResult{Tripped: true, Evidence: line}
	}
	return DetectResult{Tripped: false, Evidence: "no TLS profile with `authenticate-client false`"}
}

// srlWeakLocalSecret trips when a locally stored password is NOT an SR Linux
// crypt value. Every hashed secret this OS writes begins with a `$scheme$`
// marker (`$y$` yescrypt, `$6$` sha512-crypt, `$aes1$` for reversible key
// material); a value that starts with anything else was written in the clear.
func srlWeakLocalSecret(c *Config) DetectResult {
	if line, ok := c.firstMatch(reSRLWeakPassword); ok {
		return DetectResult{Tripped: true, Evidence: line}
	}
	return DetectResult{Tripped: false, Evidence: "all locally stored passwords carry a `$scheme$` hash marker"}
}

// srlSNMPCommunity trips when any SNMP access-group carries a v1/v2c community
// entry (an unauthenticated, cleartext-on-the-wire credential).
func srlSNMPCommunity(c *Config) DetectResult {
	if line, ok := c.firstMatch(reSRLCommunity); ok {
		return DetectResult{Tripped: true, Evidence: line}
	}
	return DetectResult{Tripped: false, Evidence: "no v1/v2c community entry configured"}
}

// srlNTPUnconfigured trips when no NTP server is configured. Unsynchronized
// time is an AUDIT control, not a convenience: every finding, log line and
// correlation window this platform emits is timestamped by the device.
func srlNTPUnconfigured(c *Config) DetectResult {
	if line, ok := c.firstMatch(reSRLNTPServer); ok {
		if c.has(reSRLNTPAdmin) {
			return DetectResult{Tripped: false, Evidence: line}
		}
		return DetectResult{Tripped: true, Evidence: line + " (NTP server listed but `admin-state enable` absent)"}
	}
	return DetectResult{Tripped: true, Evidence: "no `system ntp server` configured — device clock is unsynchronized"}
}
