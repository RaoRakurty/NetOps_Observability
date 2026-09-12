// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"strings"
	"testing"
)

// TestRedact_StripsSecrets proves the redaction pass removes credentials/keys
// from captured output while keeping the surrounding structure, and never mutates
// the original capture.
func TestRedact_StripsSecrets(t *testing.T) {
	secrets := []string{
		"S3cr3t-BGP-Pass!",
		"myR0community",
		"0123456789abcdefMD5HASH",
		"EnableS3cret",
		"PreSharedKeyValue123",
	}
	raw := strings.Join([]string{
		"username admin password S3cr3t-BGP-Pass!",
		"enable secret 5 EnableS3cret",
		"snmp-server community myR0community RO",
		"neighbor 10.0.0.2 password S3cr3t-BGP-Pass!",
		"ip ospf message-digest-key 1 md5 0123456789abcdefMD5HASH",
		"crypto isakmp key PreSharedKeyValue123 address 10.0.0.2",
		"interface GigabitEthernet0/0",
		"  ip address 10.0.0.1 255.255.255.252",
	}, "\n")

	col := &Collection{
		DeviceID: "dev-1", Hostname: "core-01", Vendor: VendorCiscoIOSXE,
		RenderedVendor: VendorCiscoIOSXE, Protocol: ProtocolBGP,
		IssueID: "bgp-session-down", IssueTitle: "Session down",
		RulesetVersion: RulesetVersion,
		Commands: []CollectedCommand{
			{SpecID: "bgp-neighbor", Command: "show ip bgp neighbors 10.0.0.2", Output: raw},
		},
	}

	red := Redact(col)
	got := red.Commands[0].Output

	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Errorf("secret %q survived redaction:\n%s", s, got)
		}
	}
	if !strings.Contains(got, redactionMark) {
		t.Error("no redaction mark present — nothing was redacted")
	}
	// Structure preserved: the non-secret address line is intact.
	if !strings.Contains(got, "ip address 10.0.0.1 255.255.255.252") {
		t.Error("redaction destroyed non-secret content")
	}
	// Original capture is NOT mutated.
	if !strings.Contains(col.Commands[0].Output, "S3cr3t-BGP-Pass!") {
		t.Error("Redact mutated the original capture")
	}
}

// TestRedact_MultiLinePEMPrivateKeys proves a real multi-line PEM private key —
// the form keys actually take on disk and in `show` output — is fully redacted:
// no body line survives, the redaction mark is present, and the surrounding
// text (including the BEGIN/END marker lines, kept so a TAC reader sees which
// block was redacted) stays intact.
func TestRedact_MultiLinePEMPrivateKeys(t *testing.T) {
	bodies := map[string][]string{
		"RSA PRIVATE KEY":       {"MIIEpAIBAAKCAQEA7rsaBODYlinea111", "q2xRSAlineb222/+detail333=="},
		"OPENSSH PRIVATE KEY":   {"b3BlbnNzaC1rZXktdjEopenssh444", "AAAAB3NzaC1yc2Eopenssh555="},
		"ENCRYPTED PRIVATE KEY": {"MIIFHDBOBgkqhkiGencrypted666", "hkiG9w0BBQencrypted777=="},
	}
	for label, body := range bodies {
		raw := strings.Join([]string{
			"crypto key export rsa mykey pem terminal",
			"-----BEGIN " + label + "-----",
			body[0],
			body[1],
			"-----END " + label + "-----",
			"router bgp 65001",
		}, "\n")
		got := newRedactor().redactText(raw)
		for _, b := range body {
			if strings.Contains(got, b) {
				t.Errorf("%s: body line %q survived redaction:\n%s", label, b, got)
			}
		}
		if !strings.Contains(got, redactionMark) {
			t.Errorf("%s: no redaction mark present:\n%s", label, got)
		}
		if !strings.Contains(got, "-----BEGIN "+label+"-----") || !strings.Contains(got, "-----END "+label+"-----") {
			t.Errorf("%s: marker lines destroyed (reader can no longer see which block was redacted):\n%s", label, got)
		}
		if !strings.Contains(got, "crypto key export rsa mykey pem terminal") || !strings.Contains(got, "router bgp 65001") {
			t.Errorf("%s: surrounding non-secret text destroyed:\n%s", label, got)
		}
	}
}

// TestRedact_UnterminatedPEMFailsClosed proves a BEGIN with no END (truncated
// capture) redacts everything through to EOF — key material never survives a
// missing terminator.
func TestRedact_UnterminatedPEMFailsClosed(t *testing.T) {
	raw := strings.Join([]string{
		"before the block",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEpAIBAAKCAQEAtruncated888",
		"q2xtruncated999==",
		"output cut off here, no END marker",
	}, "\n")
	got := newRedactor().redactText(raw)
	for _, leak := range []string{"MIIEpAIBAAKCAQEAtruncated888", "q2xtruncated999==", "output cut off here"} {
		if strings.Contains(got, leak) {
			t.Errorf("unterminated block leaked %q (must fail closed to EOF):\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "before the block") {
		t.Errorf("text before the block destroyed:\n%s", got)
	}
	if !strings.Contains(got, redactionMark) {
		t.Errorf("no redaction mark present:\n%s", got)
	}
}

// TestRedact_CertificateBlockPreserved pins the deliberate decision that
// certificate blocks — public material that legitimately appears in
// `show crypto pki certificates` output and is often exactly what TAC needs —
// are NOT block-redacted. Only private-key-class labels are.
func TestRedact_CertificateBlockPreserved(t *testing.T) {
	certBody := "MIIDcertificatebodyAAA111"
	raw := strings.Join([]string{
		"-----BEGIN CERTIFICATE-----",
		certBody,
		"-----END CERTIFICATE-----",
	}, "\n")
	got := newRedactor().redactText(raw)
	if !strings.Contains(got, certBody) {
		t.Errorf("certificate body was redacted (certificates are public material, kept by design):\n%s", got)
	}
}

// TestRedact_SingleLinePEMStillRedacted proves the pre-existing single-line
// rule (BEGIN and END on one line) still fires.
func TestRedact_SingleLinePEMStillRedacted(t *testing.T) {
	raw := "key: -----BEGIN PRIVATE KEY-----MIIEsingleline000-----END PRIVATE KEY----- trailing"
	got := newRedactor().redactText(raw)
	if strings.Contains(got, "MIIEsingleline000") {
		t.Errorf("single-line PEM survived redaction:\n%s", got)
	}
	if !strings.Contains(got, redactionMark) {
		t.Errorf("no redaction mark present:\n%s", got)
	}
	if !strings.Contains(got, "trailing") {
		t.Errorf("text after the single-line block destroyed:\n%s", got)
	}
}

// TestRedact_MultiLinePEMWithCRLF proves CRLF line endings do not defeat the
// block scanner (marker detection is unanchored, so a trailing \r is harmless).
func TestRedact_MultiLinePEMWithCRLF(t *testing.T) {
	raw := strings.Join([]string{
		"before\r",
		"-----BEGIN EC PRIVATE KEY-----\r",
		"MHcCAQEEcrlfbody123\r",
		"-----END EC PRIVATE KEY-----\r",
		"after\r",
	}, "\n")
	got := newRedactor().redactText(raw)
	if strings.Contains(got, "MHcCAQEEcrlfbody123") {
		t.Errorf("CRLF PEM body survived redaction:\n%s", got)
	}
	if !strings.Contains(got, redactionMark) {
		t.Errorf("no redaction mark present:\n%s", got)
	}
	if !strings.Contains(got, "before\r") || !strings.Contains(got, "after\r") {
		t.Errorf("surrounding CRLF text destroyed:\n%s", got)
	}
}

// TestTACExport_RedactedAndComplete proves the TAC export is redacted, carries
// the verdict + evidence, omits the tenant id, and includes each command.
func TestTACExport_RedactedAndComplete(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()
	outputs := map[string]string{
		"bgp-summary":    "10.0.0.2 4 65002 0 0 never Idle",
		"bgp-peer-route": "% Network not in table",
		"bgp-neighbor":   "BGP neighbor is 10.0.0.2\n  neighbor 10.0.0.2 password TopSecretBGP",
	}
	col := collectFor(t, cat, ciscoDev, stdTarget, "bgp-session-down", outputs)
	res := an.Analyze(col)

	blob := TACExport(col, res)

	if strings.Contains(blob, "TopSecretBGP") {
		t.Errorf("TAC export leaked a secret:\n%s", blob)
	}
	if strings.Contains(blob, "acme") {
		t.Errorf("TAC export leaked the tenant id:\n%s", blob)
	}
	if !strings.Contains(blob, "peering address is unreachable") {
		t.Error("TAC export missing the verdict")
	}
	if !strings.Contains(blob, "show ip bgp summary") {
		t.Error("TAC export missing a captured command")
	}
	if !strings.Contains(blob, "TAC EXPORT (redacted)") {
		t.Error("TAC export missing header")
	}
}

// TestTACExport_UnmatchedHonest proves the export states the honest no-match
// message when nothing fired.
func TestTACExport_UnmatchedHonest(t *testing.T) {
	cat := DefaultCatalog()
	an := DefaultAnalyzer()
	col := collectFor(t, cat, ciscoDev, stdTarget, "bgp-wrong-path", map[string]string{
		"bgp-prefix": "  Community: 65000:100",
	})
	res := an.Analyze(col)
	blob := TACExport(col, res)
	if !strings.Contains(blob, "no known signature matched") {
		t.Errorf("unmatched export missing honest message:\n%s", blob)
	}
}

// TestRedact_RoutingProtocolSecretCanaries pins the exact secret SHAPES a
// routing-protocol capture carries. These are canaries, not examples: each line
// is one that a real `show run | section router bgp` / `show isis interface`
// capture reliably contains, and each must come back with the KNOB visible and
// the VALUE masked. A non-secret line on either side must survive untouched, so
// a failure here is unambiguous — over-redaction is as much a bug as under.
func TestRedact_RoutingProtocolSecretCanaries(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		secret string // must NOT survive
		keep   string // must survive (the knob, so TAC still sees which one)
	}{
		{"bgp neighbor type-7 password",
			" neighbor 10.0.0.1 password 7 094F471A1A0A", "094F471A1A0A", "password"},
		{"bgp neighbor cleartext password",
			" neighbor 10.0.0.1 password S3cr3tPeerPass", "S3cr3tPeerPass", "neighbor 10.0.0.1"},
		{"ospf interface authentication-key",
			" ip ospf authentication-key 7 110A1016141D", "110A1016141D", "authentication-key"},
		{"junos authentication-key",
			"    authentication-key \"$9$abcDEF123\"; ## SECRET-DATA", "$9$abcDEF123", "authentication-key"},
		{"isis key-chain key-string",
			"  key-string 7 05080F1C2243", "05080F1C2243", "key-string"},
		{"isis md5 key",
			" isis authentication key-chain md5 IsIsMd5Secret", "IsIsMd5Secret", "md5"},
		{"snmp community",
			"snmp-server community Str1ctlyPr1vate RO", "Str1ctlyPr1vate", "snmp-server community"},
	}
	untouched := []string{
		" router bgp 65001",
		"  neighbor 10.0.0.1 remote-as 65002",
		"  neighbor 10.0.0.1 send-community both",
		" ip ospf network point-to-point",
		"  MTU is 1500 bytes",
	}

	var lines []string
	for _, c := range cases {
		lines = append(lines, c.line)
	}
	lines = append(lines, untouched...)
	raw := strings.Join(lines, "\n")

	col := &Collection{
		DeviceID: "dev-1", Hostname: "core-01", Vendor: VendorCiscoIOSXE,
		RenderedVendor: VendorCiscoIOSXE, Protocol: ProtocolBGP,
		IssueID: "bgp-session-down", IssueTitle: "Session down",
		RulesetVersion: RulesetVersion,
		Commands: []CollectedCommand{
			{SpecID: "bgp-neighbor", Command: "show ip bgp neighbors 10.0.0.1", Output: raw},
		},
	}
	got := Redact(col).Commands[0].Output

	for _, c := range cases {
		if strings.Contains(got, c.secret) {
			t.Errorf("%s: secret %q survived redaction:\n%s", c.name, c.secret, got)
		}
		if !strings.Contains(got, c.keep) {
			t.Errorf("%s: knob %q was destroyed — TAC can no longer see which setting it was", c.name, c.keep)
		}
	}
	for _, u := range untouched {
		if !strings.Contains(got, u) {
			t.Errorf("non-secret line %q was altered by redaction:\n%s", u, got)
		}
	}
	// The original capture is untouched — the caller keeps the raw evidence for
	// its own in-tenant use.
	if !strings.Contains(col.Commands[0].Output, "094F471A1A0A") {
		t.Error("Redact mutated the original capture")
	}
}

// TestTACExport_UnknownDialectIsNotClaimedAsAVendor is the D-2 half of the
// 2026-09-03 live run that lands in THIS package: an SR Linux spine's bundle
// carried the header `Vendor : Nokia SR OS` over `Platform : nokia SR Linux`,
// and attributed real SR Linux output to `$ show router isis adjacency` — a
// command that box cannot parse. A bundle handed to a vendor TAC must never
// name an operating system the device is not running.
//
// With no authored srlinux CLI dialect the platform now resolves to
// VendorUnknown, so the header states the fallback instead of a vendor.
func TestTACExport_UnknownDialectIsNotClaimedAsAVendor(t *testing.T) {
	srl := Device{ID: "spine1", Hostname: "spine1", Platform: "nokia SR Linux", TenantID: "acme"}
	if got := srl.Vendor(); got != VendorUnknown {
		t.Fatalf("precondition: SR Linux must have no authored dialect, got %q", got)
	}
	col := collectFor(t, DefaultCatalog(), srl, Target{}, "isis-adjacency-down", map[string]string{
		"isis-neighbors": "| ethernet-1/1.0 | 0100.0000.0011 | L2 | 10.0.1.1 | :: | up | 30 |",
	})
	blob := TACExport(col, DefaultAnalyzer().Analyze(col))

	if strings.Contains(blob, "Nokia SR OS") {
		t.Fatalf("the export names an operating system this device is not running:\n%s", blob)
	}
	if !strings.Contains(blob, "Platform    : nokia SR Linux") {
		t.Errorf("the export must state the platform it actually captured from:\n%s", blob)
	}
	// It must say WHY the commands look the way they do — a TAC engineer reading
	// `show ip ...` against an SR Linux box needs to know we fell back.
	for _, want := range []string{"no authored CLI dialect", "fallback", "may not be valid here"} {
		if !strings.Contains(blob, want) {
			t.Errorf("the header does not disclose the dialect fallback (%q missing):\n%s", want, blob)
		}
	}

	// Control: a device WITH an authored dialect keeps the plain, unqualified
	// header — the disclosure must not become noise on every export.
	plain := TACExport(
		collectFor(t, DefaultCatalog(), ciscoDev, stdTarget, "isis-adjacency-down", nil),
		AnalyzeResult{Unmatched: "n/a"},
	)
	if strings.Contains(plain, "no authored CLI dialect") {
		t.Errorf("a known dialect must not carry the fallback disclosure:\n%s", plain)
	}
	if !strings.Contains(plain, "Vendor      : "+DisplayVendor(VendorCiscoIOSXE)+"\n") {
		t.Errorf("a known dialect must render its own name plainly:\n%s", plain)
	}
}
