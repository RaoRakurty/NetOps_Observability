package hardening

import (
	"regexp"
	"strings"

	"netops/backend/internal/secfindings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Detection helper builders.
//
// Each builder COMPILES its regexp once, at catalog-build time, and returns a
// closure that captures it. Regexps are therefore NOT package-level globals
// (§5 no-globals) — they live inside the *Catalog the constructor returns.
// ─────────────────────────────────────────────────────────────────────────────

// present builds a detection that TRIPS when any config line matches pattern
// (an insecure feature is explicitly enabled). Evidence is the offending line.
func present(pattern, absentNote string) func(*Config) DetectResult {
	re := regexp.MustCompile(pattern)
	return func(c *Config) DetectResult {
		if line, ok := c.firstMatch(re); ok {
			return DetectResult{Tripped: true, Evidence: line}
		}
		return DetectResult{Tripped: false, Evidence: absentNote}
	}
}

// absent builds a detection that TRIPS when NO config line matches pattern (a
// required hardening line is missing). Evidence is a note naming what is missing.
// The config being present-but-lacking-the-line is a real, assessed observation;
// the "config missing entirely" fail-closed case is handled in the engine.
func absent(pattern, missingNote, presentNote string) func(*Config) DetectResult {
	re := regexp.MustCompile(pattern)
	return func(c *Config) DetectResult {
		if _, ok := c.firstMatch(re); ok {
			return DetectResult{Tripped: false, Evidence: presentNote}
		}
		return DetectResult{Tripped: true, Evidence: missingNote}
	}
}

// bothPresentAbsent builds a detection that TRIPS when needleRe is present AND
// guardRe is absent — e.g. "ntp server configured but ntp authenticate missing".
func bothPresentAbsent(needle, guard, note string) func(*Config) DetectResult {
	needleRe := regexp.MustCompile(needle)
	guardRe := regexp.MustCompile(guard)
	return func(c *Config) DetectResult {
		if c.has(needleRe) && !c.has(guardRe) {
			return DetectResult{Tripped: true, Evidence: note}
		}
		return DetectResult{Tripped: false, Evidence: "guarded or not configured"}
	}
}

// ─── IOS VTY-stanza aware detections (multi-line context) ────────────────────

var (
	reIOSVTYHeader     = regexp.MustCompile(`^line vty\b`)
	reIOSTransIn       = regexp.MustCompile(`^transport input\b`)
	reIOSTransTelnet   = regexp.MustCompile(`^transport input\b.*\b(telnet|all)\b`)
	reIOSAccessClassIn = regexp.MustCompile(`^access-class\s+\S+\s+in\b`)
	// The two EXPOSURE probes below. They used to be compiled INSIDE the
	// `Enabled` closures of exposure-ssh / exposure-snmp, so every exposure
	// evaluation of every device re-parsed the same two fixed patterns —
	// regexp compilation is orders of magnitude dearer than the match it
	// enables, and these run per device per assessment (ultra-review #45,
	// tracker 208d). Same compile-once contract as the four above.
	reIOSSSHEnabled  = regexp.MustCompile(`^(ip ssh|transport input\b.*\bssh\b)`)
	reIOSSNMPEnabled = regexp.MustCompile(`^snmp-server (community|host|user|group)\b`)
)

// Note: the regexps above are compile-once matchers used by the IOS stanza and
// exposure detections below. They are unexported, immutable *regexp.Regexp
// values (regexp objects are safe for concurrent use) — matcher constants, not
// mutable program state; the no-globals rule targets shared MUTABLE state.

// iosVTYTelnet trips when any VTY line permits Telnet — either an explicit
// "transport input telnet/all", or a VTY block with NO "transport input" line at
// all (IOS default permits Telnet). SSH-only VTYs do not trip.
func iosVTYTelnet(c *Config) DetectResult {
	for _, st := range c.iosStanzas(reIOSVTYHeader) {
		if st.childHas(reIOSTransTelnet) {
			for _, ch := range st.children {
				if reIOSTransTelnet.MatchString(ch) {
					return DetectResult{Tripped: true, Evidence: st.header + " / " + ch}
				}
			}
		}
		if !st.childHas(reIOSTransIn) {
			return DetectResult{Tripped: true, Evidence: st.header + " (no `transport input` — IOS default permits Telnet)"}
		}
	}
	return DetectResult{Tripped: false, Evidence: "all VTY lines restricted to SSH"}
}

// iosVTYNoAccessClass trips when any VTY line lacks an inbound access-class ACL
// (the management plane is reachable with no source restriction).
func iosVTYNoAccessClass(c *Config) DetectResult {
	for _, st := range c.iosStanzas(reIOSVTYHeader) {
		if !st.childHas(reIOSAccessClassIn) {
			return DetectResult{Tripped: true, Evidence: st.header + " (no `access-class <acl> in`)"}
		}
	}
	return DetectResult{Tripped: false, Evidence: "all VTY lines carry an inbound access-class"}
}

// iosSNMPNoACL trips when an SNMP community is defined with NO trailing ACL token
// restricting its source. `snmp-server community NAME [RO|RW] [ACL]` — a community
// line ending at RO/RW (or the name) is unrestricted.
var reIOSSNMPCommunity = regexp.MustCompile(`^snmp-server community\s+(\S+)(?:\s+([rR][oOwW]))?(?:\s+(\S+))?\s*$`)

func iosSNMPNoACL(c *Config) DetectResult {
	for _, ln := range c.Lines() {
		t := strings.TrimSpace(ln)
		m := reIOSSNMPCommunity.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		acl := m[3]
		if acl == "" {
			return DetectResult{Tripped: true, Evidence: t + " (no source ACL)"}
		}
	}
	return DetectResult{Tripped: false, Evidence: "no unrestricted SNMP community"}
}

// iosHTTPNoACL trips when an HTTP(S) server is enabled but no `ip http
// access-class` restricts it.
var (
	reIOSHTTPServer = regexp.MustCompile(`^ip http (secure-)?server\b`)
	reIOSHTTPACL    = regexp.MustCompile(`^ip http access-class\b`)
)

func iosHTTPNoACL(c *Config) DetectResult {
	if c.has(reIOSHTTPServer) && !c.has(reIOSHTTPACL) {
		return DetectResult{Tripped: true, Evidence: "ip http server enabled with no `ip http access-class`"}
	}
	return DetectResult{Tripped: false, Evidence: "HTTP server off or ACL-restricted"}
}

// ─────────────────────────────────────────────────────────────────────────────
// The catalog. ~29 posture rules + 4 seam-aware exposure probes.
//
// Independently worded (NOT CIS PDF text — that content is non-commercially
// licensed, §5b). Cisco IOS-XE is fully bound; Arista EOS and Nokia SR Linux
// are bound across the management-plane, credential and plane controls their
// operating systems can actually express (dialect_fabric.go carries the
// detections and the reasoning); Juniper and Nokia SR OS are bound for a
// representative subset to prove the multi-vendor seam is declarative (adding a
// vendor is "add a binding"); unbound (rule, vendor) pairs report
// NotApplicable, never a false Pass.
//
// Three answers, three meanings — the distinction is the product:
//
//	Pass           we read this device's configuration and the control holds
//	NotApplicable  the concept has no realization on this platform, and the
//	               finding says WHY (DetectResult.NotApplicable), OR no binding
//	               is authored for the dialect and we say only that
//	Unknown        we could not read the configuration at all (fail closed)
// ─────────────────────────────────────────────────────────────────────────────

// DefaultCatalog builds the shipped hardening catalog fresh (no global state).
func DefaultCatalog() *Catalog {
	rules := []Rule{
		// ── Insecure management services ──────────────────────────────────────
		{
			ID: "telnet-vty-enabled", Title: "Telnet permitted on management lines",
			Concept: "cleartext-remote-mgmt", Severity: secfindings.SeverityHigh,
			Controls: []string{"AC-17", "SC-8", "CIS-NET-4.1", "PCI-2.2.4"},
			Category: CategoryMgmtService,
			Intended: "Remote management restricted to SSH; Telnet disabled on all lines.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: iosVTYTelnet,
					Remediation: "line vty 0 4\n transport input ssh\nline vty 5 15\n transport input ssh"},
				VendorJuniper: {Detect: present(`^set system services telnet\b`, "telnet service not enabled"),
					Remediation: "delete system services telnet\nset system services ssh protocol-version v2"},
				VendorNokia: {Detect: present(`(?i)\btelnet-server\b.*\b(enable|admin-state enable)\b`, "telnet-server not enabled"),
					Remediation: "configure system management-interface telnet-server admin-state disable\nconfigure system management-interface ssh-server admin-state enable"},
				VendorArista: {Detect: eosTelnetEnabled,
					Remediation: "management telnet\n   shutdown"},
				VendorSRLinux: {Detect: notApplicable(
					"SR Linux implements no telnet server anywhere in its management model — the control cannot be violated on this platform"),
					Remediation: "no action: SR Linux offers only SSH, gNMI, JSON-RPC and NETCONF for remote management"},
			},
		},
		{
			ID: "ftp-server-enabled", Title: "FTP server enabled",
			Concept: "cleartext-file-transfer", Severity: secfindings.SeverityMedium,
			Controls: []string{"SC-8", "CIS-NET-2.1"}, Category: CategoryMgmtService,
			Intended: "No cleartext FTP; use SCP/SFTP for file transfer.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^ftp-server enable\b`, "FTP server not enabled"),
					Remediation: "no ftp-server enable\nip scp server enable"},
			},
		},
		{
			ID: "tftp-server-enabled", Title: "TFTP server enabled",
			Concept: "cleartext-file-transfer", Severity: secfindings.SeverityMedium,
			Controls: []string{"SC-8", "CIS-NET-2.2"}, Category: CategoryMgmtService,
			Intended: "No unauthenticated TFTP server; use SCP/SFTP.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^tftp-server\b`, "TFTP server not enabled"),
					Remediation: "no tftp-server flash:<file>"},
			},
		},
		{
			ID: "http-server-nontls", Title: "Non-TLS HTTP management server enabled",
			Concept: "cleartext-remote-mgmt", Severity: secfindings.SeverityHigh,
			Controls: []string{"SC-8", "AC-17", "CIS-NET-3.1"}, Category: CategoryMgmtService,
			Intended: "Management web access disabled or TLS-only (ip http secure-server).",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^ip http server\b`, "non-TLS HTTP server not enabled"),
					Remediation: "no ip http server\nip http secure-server"},
				VendorJuniper: {Detect: present(`^set system services web-management http\b`, "http web-management not enabled"),
					Remediation: "delete system services web-management http\nset system services web-management https"},
				VendorArista: {Detect: eosEAPIPlaintext,
					Remediation: "management api http-commands\n   no protocol http\n   protocol https"},
				VendorSRLinux: {Detect: srlJSONRPCPlaintext,
					Remediation: "set / system json-rpc-server network-instance mgmt http admin-state disable\nset / system json-rpc-server network-instance mgmt https admin-state enable"},
			},
		},
		{
			ID: "ssh-not-v2", Title: "SSH not pinned to protocol version 2",
			Concept: "weak-remote-mgmt-crypto", Severity: secfindings.SeverityHigh,
			Controls: []string{"SC-8", "CIS-NET-4.2"}, Category: CategoryCrypto,
			Intended: "SSH forced to protocol version 2 (SSHv1 disabled).",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: absent(`^ip ssh version 2\b`,
					"`ip ssh version 2` absent — SSHv1 fallback permitted",
					"SSH pinned to version 2"),
					Remediation: "ip ssh version 2"},
				VendorArista: {Detect: notApplicable(
					"EOS implements SSHv2 only — there is no SSHv1 to fall back to and no version knob to set"),
					Remediation: "no action: EOS ships no SSHv1 implementation"},
				VendorSRLinux: {Detect: notApplicable(
					"SR Linux implements SSHv2 only — there is no SSHv1 to fall back to and no version knob to set"),
					Remediation: "no action: SR Linux ships no SSHv1 implementation"},
			},
		},
		{
			ID: "snmp-v1v2c-community", Title: "SNMP v1/v2c community strings in use",
			Concept: "weak-snmp", Severity: secfindings.SeverityHigh,
			Controls: []string{"IA-5", "SC-8", "CIS-NET-6.1"}, Category: CategoryCredential,
			Intended: "SNMPv3 authPriv only; no v1/v2c community strings.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^snmp-server community\b`, "no v1/v2c community configured"),
					Remediation: "no snmp-server community <name>\nsnmp-server group SECURE v3 priv\nsnmp-server user <u> SECURE v3 auth sha <k> priv aes 128 <k>"},
				VendorJuniper: {Detect: present(`^set snmp community\b`, "no v1/v2c community configured"),
					Remediation: "delete snmp community\nset snmp v3 usm local-engine user <u> authentication-sha ... privacy-aes128 ..."},
				VendorArista: {Detect: present(`^snmp-server community\b`, "no v1/v2c community configured"),
					Remediation: "no snmp-server community <name>\nsnmp-server group SECURE v3 priv\nsnmp-server user <u> SECURE v3 auth sha <k> priv aes <k>"},
				VendorSRLinux: {Detect: srlSNMPCommunity,
					Remediation: "delete / system snmp access-group <group> community-entry <name>\nset / system snmp access-group <group> security-level auth-priv"},
			},
		},
		{
			ID: "snmp-default-community", Title: "Default SNMP community string (public/private)",
			Concept: "default-credential", Severity: secfindings.SeverityCritical,
			Controls: []string{"IA-5", "CIS-NET-6.2", "PCI-2.1"}, Category: CategoryCredential,
			Intended: "No default community strings; SNMPv3 with unique credentials.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^snmp-server community\s+(public|private)\b`, "no default community present"),
					Remediation: "no snmp-server community public\nno snmp-server community private"},
				VendorJuniper: {Detect: present(`^set snmp community\s+(public|private)\b`, "no default community present"),
					Remediation: "delete snmp community public\ndelete snmp community private"},
				VendorArista: {Detect: present(`(?i)^snmp-server community\s+(public|private)\b`, "no default community present"),
					Remediation: "no snmp-server community public\nno snmp-server community private"},
				VendorSRLinux: {Detect: present(`(?i)^set / system snmp access-group \S+ community-entry (public|private)\b`, "no default community present"),
					Remediation: "delete / system snmp access-group <group> community-entry public"},
			},
		},
		{
			ID: "tcp-small-servers", Title: "TCP small-servers enabled",
			Concept: "legacy-small-service", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.1"}, Category: CategoryMgmtService,
			Intended: "Legacy TCP small-servers (echo/discard/chargen/daytime) disabled.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^service tcp-small-servers\b`, "tcp small-servers disabled"),
					Remediation: "no service tcp-small-servers"},
			},
		},
		{
			ID: "udp-small-servers", Title: "UDP small-servers enabled",
			Concept: "legacy-small-service", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.2"}, Category: CategoryMgmtService,
			Intended: "Legacy UDP small-servers disabled.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^service udp-small-servers\b`, "udp small-servers disabled"),
					Remediation: "no service udp-small-servers"},
			},
		},
		{
			ID: "finger-service", Title: "Finger service enabled",
			Concept: "legacy-small-service", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.3"}, Category: CategoryMgmtService,
			Intended: "Finger information service disabled.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^(ip finger|service finger)\b`, "finger disabled"),
					Remediation: "no ip finger\nno service finger"},
			},
		},
		{
			ID: "bootp-server", Title: "BOOTP server enabled",
			Concept: "legacy-small-service", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.4"}, Category: CategoryMgmtService,
			Intended: "BOOTP server disabled.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^ip bootp server\b`, "bootp server disabled"),
					Remediation: "no ip bootp server"},
			},
		},
		{
			ID: "pad-service", Title: "X.25 PAD service enabled",
			Concept: "legacy-small-service", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.5"}, Category: CategoryMgmtService,
			Intended: "PAD service disabled.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^service pad\b`, "PAD disabled"),
					Remediation: "no service pad"},
			},
		},
		{
			ID: "cdp-run-global", Title: "CDP enabled globally",
			Concept: "topology-disclosure", Severity: secfindings.SeverityLow,
			Controls: []string{"CM-7", "CIS-NET-1.6"}, Category: CategoryMgmtService,
			Intended: "CDP disabled globally or per-interface on untrusted/edge links.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^cdp run\b`, "CDP not globally enabled"),
					Remediation: "no cdp run\n! or per edge interface: no cdp enable"},
			},
		},
		// ── Access control / source restriction (seam-relevant posture) ───────
		{
			ID: "vty-no-access-class", Title: "Management lines lack an inbound access-class ACL",
			Concept: "unrestricted-mgmt-plane", Severity: secfindings.SeverityHigh,
			Controls: []string{"AC-17", "AC-4", "CIS-NET-5.1"}, Category: CategoryAccessCtrl,
			Intended: "Every VTY line restricted to the management subnet via access-class.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: iosVTYNoAccessClass,
					Remediation: "ip access-list standard MGMT-IN\n permit 10.0.0.0 0.0.0.255\nline vty 0 15\n access-class MGMT-IN in"},
			},
		},
		{
			ID: "snmp-no-source-acl", Title: "SNMP community with no source ACL",
			Concept: "unrestricted-mgmt-plane", Severity: secfindings.SeverityHigh,
			Controls: []string{"AC-4", "IA-5", "CIS-NET-6.3"}, Category: CategoryAccessCtrl,
			Intended: "SNMP access restricted to the management subnet by ACL.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: iosSNMPNoACL,
					Remediation: "ip access-list standard SNMP-IN\n permit 10.0.0.0 0.0.0.255\nsnmp-server community <name> RO SNMP-IN"},
				// EOS writes `snmp-server community <name> [ro|rw] [acl]` in the
				// same grammar IOS does, so the IOS detection reads it as-is.
				VendorArista: {Detect: iosSNMPNoACL,
					Remediation: "ip access-list standard SNMP-IN\n permit 10.0.0.0/24\nsnmp-server community <name> ro SNMP-IN"},
				VendorSRLinux: {Detect: notApplicable(
					"SR Linux binds no source ACL to a community; SNMP reachability is bounded by the network-instance the server is enabled in, which this control cannot express"),
					Remediation: "restrict SNMP by network-instance: set / system snmp network-instance mgmt admin-state enable"},
			},
		},
		{
			ID: "http-no-source-acl", Title: "HTTP management server with no access-class",
			Concept: "unrestricted-mgmt-plane", Severity: secfindings.SeverityMedium,
			Controls: []string{"AC-4", "AC-17", "CIS-NET-3.2"}, Category: CategoryAccessCtrl,
			Intended: "Web management restricted to the management subnet by access-class.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: iosHTTPNoACL,
					Remediation: "ip access-list standard MGMT-IN\n permit 10.0.0.0 0.0.0.255\nip http access-class MGMT-IN"},
			},
		},
		// ── Credential / crypto hygiene ───────────────────────────────────────
		{
			ID: "no-service-password-encryption", Title: "service password-encryption disabled",
			Concept: "cleartext-stored-credential", Severity: secfindings.SeverityMedium,
			Controls: []string{"IA-5", "CIS-NET-7.1"}, Category: CategoryCredential,
			Intended: "service password-encryption enabled so stored passwords are not cleartext.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: absent(`^service password-encryption\b`,
					"`service password-encryption` absent — passwords stored in cleartext",
					"service password-encryption enabled"),
					Remediation: "service password-encryption"},
				VendorArista: {Detect: notApplicable(
					"EOS has no global password-encryption switch: stored credentials are always hashed, and the reversible-storage question is scored by local-user-weak-secret instead"),
					Remediation: "no action: see rule local-user-weak-secret for EOS credential storage"},
				VendorSRLinux: {Detect: notApplicable(
					"SR Linux has no global password-encryption switch: stored credentials are always written as a `$scheme$` crypt value, and the storage question is scored by local-user-weak-secret instead"),
					Remediation: "no action: see rule local-user-weak-secret for SR Linux credential storage"},
			},
		},
		{
			ID: "weak-enable-password", Title: "Weak enable password instead of enable secret",
			Concept: "reversible-privileged-credential", Severity: secfindings.SeverityHigh,
			Controls: []string{"IA-5", "CIS-NET-7.2", "PCI-8.2.1"}, Category: CategoryCredential,
			Intended: "Privileged access protected by `enable secret` (irreversible hash), not `enable password`.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: present(`^enable password\b`, "no reversible enable password"),
					Remediation: "no enable password\nenable secret <strong-secret>"},
				VendorArista: {Detect: present(`^enable password\b`, "no reversible enable password"),
					Remediation: "no enable password\nenable secret sha512 <hash>"},
				VendorSRLinux: {Detect: notApplicable(
					"SR Linux has no enable/privileged-exec password: privilege is a role granted through AAA, not a second shared secret"),
					Remediation: "no action: authorize privilege through `system aaa authorization role`"},
			},
		},
		{
			ID: "no-aaa-new-model", Title: "AAA not enabled (local-only authentication)",
			Concept: "no-centralized-auth", Severity: secfindings.SeverityMedium,
			Controls: []string{"AC-2", "IA-2", "CIS-NET-8.1"}, Category: CategoryCredential,
			Intended: "AAA enabled with TACACS+/RADIUS and a local fallback.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: absent(`^aaa new-model\b`,
					"`aaa new-model` absent — device relies on local-only authentication",
					"aaa new-model enabled"),
					Remediation: "aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local"},
			},
		},
		// ── Plane hardening ───────────────────────────────────────────────────
		{
			ID: "no-central-logging", Title: "No central syslog target configured",
			Concept: "no-audit-forwarding", Severity: secfindings.SeverityMedium,
			Controls: []string{"AU-2", "AU-6", "CIS-NET-9.1"}, Category: CategoryPlane,
			Intended: "Syslog forwarded to a central collector for tamper-evident audit.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: absent(`^logging (host\s+\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
					"no `logging host` target — audit events not forwarded",
					"central logging target configured"),
					Remediation: "logging host 10.0.0.10\nlogging trap informational"},
				VendorJuniper: {Detect: absent(`^set system syslog host\b`,
					"no `system syslog host` target configured",
					"syslog host configured"),
					Remediation: "set system syslog host 10.0.0.10 any info"},
				VendorArista: {Detect: absent(`^logging host\s+\S+`,
					"no `logging host` target — audit events not forwarded",
					"central logging target configured"),
					Remediation: "logging host 10.0.0.10\nlogging trap informational"},
				VendorSRLinux: {Detect: absent(`^set / system logging remote-server \S+`,
					"no `system logging remote-server` target — audit events not forwarded",
					"central logging target configured"),
					Remediation: "set / system logging remote-server 10.0.0.10 transport udp\nset / system logging remote-server 10.0.0.10 remote-port 514"},
			},
		},
		{
			ID: "ntp-no-authentication", Title: "NTP configured without authentication",
			Concept: "unauthenticated-time", Severity: secfindings.SeverityLow,
			Controls: []string{"AU-8", "CIS-NET-9.2"}, Category: CategoryPlane,
			Intended: "NTP authenticated so time (and log timestamps) cannot be spoofed.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: bothPresentAbsent(`^ntp server\b`, `^ntp authenticate\b`,
					"NTP server configured but `ntp authenticate` missing"),
					Remediation: "ntp authenticate\nntp authentication-key 1 md5 <key>\nntp trusted-key 1\nntp server 10.0.0.20 key 1"},
				VendorArista: {Detect: bothPresentAbsent(`^ntp server\b`, `^ntp authentication-key\b`,
					"NTP server configured but no `ntp authentication-key` — time source unauthenticated"),
					Remediation: "ntp authentication-key 1 sha1 <key>\nntp trusted-key 1\nntp authenticate\nntp server 10.0.0.20 key 1"},
			},
		},
		// ── Fabric dialects: controls the IOS-centric set above cannot express ─
		//
		// These four are NOT IOS concepts wearing new bindings. Each names a
		// control that only exists once a platform has a model-driven management
		// plane (a gNMI/gRPC/JSON-RPC API with its own TLS posture) or stores
		// credentials without a global encryption switch. They are bound for
		// Arista EOS and Nokia SR Linux only; every other dialect reports
		// NotApplicable, because leaving them unbound is the honest answer for a
		// platform whose detection has not been authored.
		{
			ID: "mgmt-api-unencrypted", Title: "Model-driven management API served without TLS",
			Concept: "cleartext-remote-mgmt", Severity: secfindings.SeverityHigh,
			Controls: []string{"SC-8", "AC-17", "CIS-NET-3.3"}, Category: CategoryCrypto,
			Intended: "Every enabled gNMI/gRPC/JSON-RPC management endpoint binds a TLS profile; no cleartext transport.",
			bindings: map[Vendor]VendorBinding{
				VendorArista: {Detect: eosGNMIPlaintext,
					Remediation: "management security\n   ssl profile MGMT\n      certificate <cert> key <key>\nmanagement api gnmi\n   transport grpc default\n      ssl profile MGMT"},
				VendorSRLinux: {Detect: srlInsecureGRPC,
					Remediation: "set / system grpc-server <name> tls-profile <profile>\n! or, if the instance is not needed:\nset / system grpc-server <name> admin-state disable"},
			},
		},
		{
			ID: "tls-no-client-auth", Title: "Management TLS profile does not authenticate the client",
			Concept: "unauthenticated-mgmt-peer", Severity: secfindings.SeverityLow,
			Controls: []string{"IA-3", "SC-8", "AC-17"}, Category: CategoryCrypto,
			Intended: "Management TLS profiles require a client certificate, so possession of the management address is not by itself sufficient to connect.",
			bindings: map[Vendor]VendorBinding{
				VendorSRLinux: {Detect: srlTLSNoClientAuth,
					Remediation: "set / system tls profile <name> authenticate-client true\nset / system tls profile <name> trust-anchor <ca-pem>"},
			},
		},
		{
			ID: "local-user-weak-secret", Title: "Local account with no password or reversible storage",
			Concept: "cleartext-stored-credential", Severity: secfindings.SeverityHigh,
			Controls: []string{"IA-5", "CIS-NET-7.3", "PCI-8.2.1"}, Category: CategoryCredential,
			Intended: "Every local account stores an irreversible, salted password hash; no `nopassword` and no legacy reversible type.",
			bindings: map[Vendor]VendorBinding{
				VendorArista: {Detect: eosWeakLocalSecret,
					Remediation: "username <u> privilege 15 role network-admin secret sha512 <hash>\nno username <u> nopassword"},
				VendorSRLinux: {Detect: srlWeakLocalSecret,
					Remediation: "set / system aaa authentication <user> password <value>   ! SR Linux hashes on commit; verify the stored value carries a $scheme$ marker"},
			},
		},
		{
			ID: "no-remote-aaa", Title: "No remote AAA server group (local-only authentication)",
			Concept: "no-centralized-auth", Severity: secfindings.SeverityMedium,
			Controls: []string{"AC-2", "IA-2", "CIS-NET-8.2"}, Category: CategoryCredential,
			Intended: "Authentication delegated to a TACACS+/RADIUS server group with local credentials as the fallback, so account revocation is central.",
			bindings: map[Vendor]VendorBinding{
				VendorArista: {Detect: absent(`^aaa (?:group server (?:tacacs\+|radius)|authentication login default group)`,
					"no TACACS+/RADIUS server group — device authenticates against local accounts only",
					"remote AAA server group configured"),
					Remediation: "aaa group server tacacs+ TAC\n   server 10.0.0.30\naaa authentication login default group TAC local"},
				VendorSRLinux: {Detect: absent(`^set / system aaa server-group \S+ type (?:tacacs|radius)`,
					"no TACACS+/RADIUS server-group — device authenticates against local accounts only",
					"remote AAA server-group configured"),
					Remediation: "set / system aaa server-group TAC type tacacs\nset / system aaa authentication authentication-method [ TAC local ]"},
			},
		},
		{
			ID: "no-ntp-server", Title: "No NTP time source configured",
			Concept: "unsynchronized-time", Severity: secfindings.SeverityMedium,
			Controls: []string{"AU-8", "CIS-NET-9.3"}, Category: CategoryPlane,
			Intended: "At least one NTP server configured and enabled, so device timestamps on logs and findings are trustworthy.",
			bindings: map[Vendor]VendorBinding{
				VendorArista: {Detect: absent(`^ntp server\s+\S+`,
					"no `ntp server` configured — device clock is unsynchronized and every timestamp it stamps is unattributable",
					"NTP server configured"),
					Remediation: "ntp server 10.0.0.20 iburst\nntp source Management0"},
				VendorSRLinux: {Detect: srlNTPUnconfigured,
					Remediation: "set / system ntp admin-state enable\nset / system ntp network-instance mgmt\nset / system ntp server 10.0.0.20 iburst true"},
			},
		},
		{
			ID: "no-control-plane-protection", Title: "No control-plane protection (CoPP)",
			Concept: "control-plane-unprotected", Severity: secfindings.SeverityLow,
			Controls: []string{"SC-5", "CIS-NET-10.1"}, Category: CategoryPlane,
			Intended: "Control-plane policing/protection applied on capable platforms.",
			bindings: map[Vendor]VendorBinding{
				VendorCiscoIOSXE: {Detect: absent(`^control-plane\b`,
					"no `control-plane` policy — device CPU unprotected from control-plane floods",
					"control-plane policy present"),
					Remediation: "policy-map COPP\n class class-default\n  police 32000\ncontrol-plane\n service-policy input COPP"},
			},
		},
	}

	probes := []ExposureProbe{
		{
			ID: "exposure-telnet", Service: "telnet",
			Title:    "Telnet reachable from an untrusted seam",
			Controls: []string{"AC-17", "SC-7", "AC-4"},
			Intended: "Telnet disabled; if any cleartext mgmt exists it must not be reachable from an untrusted seam.",
			bindings: map[Vendor]ExposureBinding{
				VendorCiscoIOSXE: {
					Enabled: func(c *Config) (bool, string) {
						r := iosVTYTelnet(c)
						return r.Tripped, r.Evidence
					},
					Restricted:  func(c *Config) bool { return !iosVTYNoAccessClass(c).Tripped },
					Remediation: "line vty 0 15\n transport input ssh\n access-class MGMT-IN in",
				},
			},
		},
		{
			ID: "exposure-ssh", Service: "ssh",
			Title:    "SSH reachable from an untrusted seam with no ACL",
			Controls: []string{"AC-17", "SC-7", "AC-4"},
			Intended: "SSH restricted to the management subnet via access-class on all lines.",
			bindings: map[Vendor]ExposureBinding{
				VendorCiscoIOSXE: {
					Enabled: func(c *Config) (bool, string) {
						if line, ok := c.firstMatch(reIOSSSHEnabled); ok {
							return true, line
						}
						return false, "SSH not configured"
					},
					Restricted:  func(c *Config) bool { return !iosVTYNoAccessClass(c).Tripped },
					Remediation: "ip access-list standard MGMT-IN\n permit 10.0.0.0 0.0.0.255\nline vty 0 15\n access-class MGMT-IN in",
				},
			},
		},
		{
			ID: "exposure-snmp", Service: "snmp",
			Title:    "SNMP reachable from an untrusted seam with no ACL",
			Controls: []string{"AC-4", "SC-7", "IA-5"},
			Intended: "SNMP restricted to the management subnet by ACL and not reachable from untrusted seams.",
			bindings: map[Vendor]ExposureBinding{
				VendorCiscoIOSXE: {
					Enabled: func(c *Config) (bool, string) {
						if line, ok := c.firstMatch(reIOSSNMPEnabled); ok {
							return true, line
						}
						return false, "SNMP not configured"
					},
					Restricted:  func(c *Config) bool { return !iosSNMPNoACL(c).Tripped },
					Remediation: "ip access-list standard SNMP-IN\n permit 10.0.0.0 0.0.0.255\nsnmp-server community <name> RO SNMP-IN",
				},
			},
		},
		{
			ID: "exposure-http", Service: "http",
			Title:    "Web management reachable from an untrusted seam with no ACL",
			Controls: []string{"AC-4", "SC-7", "AC-17"},
			Intended: "Web management disabled or restricted to the management subnet by access-class.",
			bindings: map[Vendor]ExposureBinding{
				VendorCiscoIOSXE: {
					Enabled: func(c *Config) (bool, string) {
						if line, ok := c.firstMatch(reIOSHTTPServer); ok {
							return true, line
						}
						return false, "HTTP(S) server not enabled"
					},
					Restricted:  func(c *Config) bool { return !iosHTTPNoACL(c).Tripped },
					Remediation: "ip http access-class MGMT-IN\n! or disable: no ip http server / no ip http secure-server",
				},
			},
		},
	}

	return NewCatalog(rules, probes)
}
