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
