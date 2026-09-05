// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/Correlix-Enterprise.txt.

// Package dialects carries the device-hardening DIALECTS beyond the core one.
//
// Correlix's hardening catalogue is a set of vendor-neutral CONCEPTS — "telnet
// is enabled on the management lines", "SNMP has no source ACL" — and each
// concept needs a per-platform realization: how that insecure state is written
// in the device's configuration grammar, and how it is fixed there. The
// catalogue, the engine, the benchmark provenance and the CORE dialect (Cisco
// IOS-XE) are Apache-2.0 (internal/hardening). The dialects here — Juniper
// Junos, Nokia SR OS, Arista EOS and Nokia SR Linux — are the owner's LOCKED
// `security_dialects` entitlement (Enterprise tier).
//
// HOW IT PLUGS IN. Each pack is DATA: a Vendor plus rule-id → VendorBinding.
// Nothing here can add, remove or re-word a rule, change a severity or a control
// mapping, or touch another dialect's binding — the seam (hardening.DialectPack)
// only lets a pack answer "how does THIS platform express THIS rule". The
// assembly layer passes Packs() to hardening.DefaultCatalog; core never names
// this package (licensing-gate.py check E).
//
// WHAT HAPPENS WITHOUT IT. Deleting this directory leaves a building,
// Apache-2.0 platform whose hardening engine assesses the core dialect and
// reports every other platform as NotApplicable — the same honest non-verdict
// the engine already emits for an unbound vendor. It never emits a Pass for a
// device it did not assess (§5g no false clear). Where the licence is present
// but the entitlement is not, the ENGINE's dialect gate
// (hardening.WithDialectGate, wired to the entitlement service in main.go)
// reports hardening.RuleDialectNotLicensed, which says so out loud.
package dialects

import (
	"netops/backend/internal/hardening"
)

// Packs returns every dialect this module contributes, in a stable order. It is
// the ONE symbol the assembly layer needs; a fresh slice per call, so no caller
// can mutate what another sees (§5 no shared global state).
func Packs() []hardening.DialectPack {
	return []hardening.DialectPack{junosPack(), srosPack(), eosPack(), srlinuxPack()}
}

// junosPack is the Juniper Junos dialect pack.
//
// Junos renders its configuration as a flat `set …` statement list, so every
// binding below reads a single `set` line. Junos is bound for the declarative
// subset the platform expresses in that grammar; controls it cannot express are
// left UNBOUND rather than guessed, which the engine reports as the honest
// "not assessed for this platform" non-verdict.
func junosPack() hardening.DialectPack {
	return hardening.DialectPack{Vendor: hardening.VendorJuniper, Bindings: map[string]hardening.VendorBinding{
		"http-server-nontls": {Detect: hardening.DetectPresent(`^set system services web-management http\b`, "http web-management not enabled"),
			Remediation: "delete system services web-management http\nset system services web-management https"},
		"no-central-logging": {Detect: hardening.DetectAbsent(`^set system syslog host\b`,
			"no `system syslog host` target configured",
			"syslog host configured"),
			Remediation: "set system syslog host 10.0.0.10 any info"},
		"snmp-default-community": {Detect: hardening.DetectPresent(`^set snmp community\s+(public|private)\b`, "no default community present"),
			Remediation: "delete snmp community public\ndelete snmp community private"},
		"snmp-v1v2c-community": {Detect: hardening.DetectPresent(`^set snmp community\b`, "no v1/v2c community configured"),
			Remediation: "delete snmp community\nset snmp v3 usm local-engine user <u> authentication-sha ... privacy-aes128 ..."},
		"telnet-vty-enabled": {Detect: hardening.DetectPresent(`^set system services telnet\b`, "telnet service not enabled"),
			Remediation: "delete system services telnet\nset system services ssh protocol-version v2"},
	}}
}

// srosPack is the Nokia SR OS (TiMOS) dialect pack.
//
// Nokia SR OS is the classic TiMOS configuration grammar and is NOT SR Linux
// (see the SR Linux pack below and fabric.go): the two share a vendor name and
// nothing else in this file.
func srosPack() hardening.DialectPack {
	return hardening.DialectPack{Vendor: hardening.VendorNokia, Bindings: map[string]hardening.VendorBinding{
		"telnet-vty-enabled": {Detect: hardening.DetectPresent(`(?i)\btelnet-server\b.*\b(enable|admin-state enable)\b`, "telnet-server not enabled"),
			Remediation: "configure system management-interface telnet-server admin-state disable\nconfigure system management-interface ssh-server admin-state enable"},
	}}
}

// eosPack is the Arista EOS dialect pack.
//
// EOS borrows the IOS SHOW grammar but not the IOS CONFIGURATION grammar, which
// is why it is its own dialect. Where the two genuinely agree — the SNMP
// community/ACL family — the binding REUSES the core IOS detector
// (hardening.DetectIOSSNMPNoACL) instead of re-implementing it; two copies of
// one regex family is how dialects drift apart. See fabric.go for the rest.
func eosPack() hardening.DialectPack {
	return hardening.DialectPack{Vendor: hardening.VendorArista, Bindings: map[string]hardening.VendorBinding{
		"http-server-nontls": {Detect: eosEAPIPlaintext,
			Remediation: "management api http-commands\n   no protocol http\n   protocol https"},
		"local-user-weak-secret": {Detect: eosWeakLocalSecret,
			Remediation: "username <u> privilege 15 role network-admin secret sha512 <hash>\nno username <u> nopassword"},
		"mgmt-api-unencrypted": {Detect: eosGNMIPlaintext,
			Remediation: "management security\n   ssl profile MGMT\n      certificate <cert> key <key>\nmanagement api gnmi\n   transport grpc default\n      ssl profile MGMT"},
		"no-central-logging": {Detect: hardening.DetectAbsent(`^logging host\s+\S+`,
			"no `logging host` target — audit events not forwarded",
			"central logging target configured"),
			Remediation: "logging host 10.0.0.10\nlogging trap informational"},
		"no-ntp-server": {Detect: hardening.DetectAbsent(`^ntp server\s+\S+`,
			"no `ntp server` configured — device clock is unsynchronized and every timestamp it stamps is unattributable",
			"NTP server configured"),
			Remediation: "ntp server 10.0.0.20 iburst\nntp source Management0"},
		"no-remote-aaa": {Detect: hardening.DetectAbsent(`^aaa (?:group server (?:tacacs\+|radius)|authentication login default group)`,
			"no TACACS+/RADIUS server group — device authenticates against local accounts only",
			"remote AAA server group configured"),
			Remediation: "aaa group server tacacs+ TAC\n   server 10.0.0.30\naaa authentication login default group TAC local"},
		"no-service-password-encryption": {Detect: hardening.DetectNotApplicable(
			"EOS has no global password-encryption switch: stored credentials are always hashed, and the reversible-storage question is scored by local-user-weak-secret instead"),
			Remediation: "no action: see rule local-user-weak-secret for EOS credential storage"},
		"ntp-no-authentication": {Detect: hardening.DetectBothPresentAbsent(`^ntp server\b`, `^ntp authentication-key\b`,
			"NTP server configured but no `ntp authentication-key` — time source unauthenticated"),
			Remediation: "ntp authentication-key 1 sha1 <key>\nntp trusted-key 1\nntp authenticate\nntp server 10.0.0.20 key 1"},
		"snmp-default-community": {Detect: hardening.DetectPresent(`(?i)^snmp-server community\s+(public|private)\b`, "no default community present"),
			Remediation: "no snmp-server community public\nno snmp-server community private"},
		"snmp-no-source-acl": {Detect: hardening.DetectIOSSNMPNoACL,
			Remediation: "ip access-list standard SNMP-IN\n permit 10.0.0.0/24\nsnmp-server community <name> ro SNMP-IN"},
		"snmp-v1v2c-community": {Detect: hardening.DetectPresent(`^snmp-server community\b`, "no v1/v2c community configured"),
			Remediation: "no snmp-server community <name>\nsnmp-server group SECURE v3 priv\nsnmp-server user <u> SECURE v3 auth sha <k> priv aes <k>"},
		"ssh-not-v2": {Detect: hardening.DetectNotApplicable(
			"EOS implements SSHv2 only — there is no SSHv1 to fall back to and no version knob to set"),
			Remediation: "no action: EOS ships no SSHv1 implementation"},
		"telnet-vty-enabled": {Detect: eosTelnetEnabled,
			Remediation: "management telnet\n   shutdown"},
		"weak-enable-password": {Detect: hardening.DetectPresent(`^enable password\b`, "no reversible enable password"),
			Remediation: "no enable password\nenable secret sha512 <hash>"},
	}}
}

// srlinuxPack is the Nokia SR Linux dialect pack.
//
// SR Linux is a flat `set / <path> <value>` rendering of a YANG tree. Several
// controls are structurally inexpressible on it and are bound NotApplicable with
// the reason, which is a different and more honest answer than leaving them
// unbound. See fabric.go for the detection helpers.
func srlinuxPack() hardening.DialectPack {
	return hardening.DialectPack{Vendor: hardening.VendorSRLinux, Bindings: map[string]hardening.VendorBinding{
		"http-server-nontls": {Detect: srlJSONRPCPlaintext,
			Remediation: "set / system json-rpc-server network-instance mgmt http admin-state disable\nset / system json-rpc-server network-instance mgmt https admin-state enable"},
		"local-user-weak-secret": {Detect: srlWeakLocalSecret,
			Remediation: "set / system aaa authentication <user> password <value>   ! SR Linux hashes on commit; verify the stored value carries a $scheme$ marker"},
		"mgmt-api-unencrypted": {Detect: srlInsecureGRPC,
			Remediation: "set / system grpc-server <name> tls-profile <profile>\n! or, if the instance is not needed:\nset / system grpc-server <name> admin-state disable"},
		"no-central-logging": {Detect: hardening.DetectAbsent(`^set / system logging remote-server \S+`,
			"no `system logging remote-server` target — audit events not forwarded",
			"central logging target configured"),
			Remediation: "set / system logging remote-server 10.0.0.10 transport udp\nset / system logging remote-server 10.0.0.10 remote-port 514"},
		"no-ntp-server": {Detect: srlNTPUnconfigured,
			Remediation: "set / system ntp admin-state enable\nset / system ntp network-instance mgmt\nset / system ntp server 10.0.0.20 iburst true"},
		"no-remote-aaa": {Detect: hardening.DetectAbsent(`^set / system aaa server-group \S+ type (?:tacacs|radius)`,
			"no TACACS+/RADIUS server-group — device authenticates against local accounts only",
			"remote AAA server-group configured"),
			Remediation: "set / system aaa server-group TAC type tacacs\nset / system aaa authentication authentication-method [ TAC local ]"},
		"no-service-password-encryption": {Detect: hardening.DetectNotApplicable(
			"SR Linux has no global password-encryption switch: stored credentials are always written as a `$scheme$` crypt value, and the storage question is scored by local-user-weak-secret instead"),
			Remediation: "no action: see rule local-user-weak-secret for SR Linux credential storage"},
		"snmp-default-community": {Detect: hardening.DetectPresent(`(?i)^set / system snmp access-group \S+ community-entry (public|private)\b`, "no default community present"),
			Remediation: "delete / system snmp access-group <group> community-entry public"},
		"snmp-no-source-acl": {Detect: hardening.DetectNotApplicable(
			"SR Linux binds no source ACL to a community; SNMP reachability is bounded by the network-instance the server is enabled in, which this control cannot express"),
			Remediation: "restrict SNMP by network-instance: set / system snmp network-instance mgmt admin-state enable"},
		"snmp-v1v2c-community": {Detect: srlSNMPCommunity,
			Remediation: "delete / system snmp access-group <group> community-entry <name>\nset / system snmp access-group <group> security-level auth-priv"},
		"ssh-not-v2": {Detect: hardening.DetectNotApplicable(
			"SR Linux implements SSHv2 only — there is no SSHv1 to fall back to and no version knob to set"),
			Remediation: "no action: SR Linux ships no SSHv1 implementation"},
		"telnet-vty-enabled": {Detect: hardening.DetectNotApplicable(
			"SR Linux implements no telnet server anywhere in its management model — the control cannot be violated on this platform"),
			Remediation: "no action: SR Linux offers only SSH, gNMI, JSON-RPC and NETCONF for remote management"},
		"tls-no-client-auth": {Detect: srlTLSNoClientAuth,
			Remediation: "set / system tls profile <name> authenticate-client true\nset / system tls profile <name> trust-anchor <ca-pem>"},
		"weak-enable-password": {Detect: hardening.DetectNotApplicable(
			"SR Linux has no enable/privileged-exec password: privilege is a role granted through AAA, not a second shared secret"),
			Remediation: "no action: authorize privilege through `system aaa authorization role`"},
	}}
}
