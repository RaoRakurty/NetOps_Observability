// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"strings"
	"testing"
)

// canaries are the exact secret VALUES the redaction suite hunts for. If any of
// them survives into a redacted body, a device credential just reached an
// operator's browser (and, through the SPA, a log or a screenshot).
const (
	canaryEnableSecret = "S3cr3tEnablePw!"
	canaryCommunity    = "R0-C0mmun1ty-Pr1v"
	canaryJunosPW      = "$6$abcdefgh$JunosHashCanary"
	canaryPSK          = "PreSharedKeyCanary123"
	canaryTacacsKey    = "TacacsKeyCanary"
	canaryUserPW       = "UserPasswordCanary"
)

func TestVendorFromPlatform(t *testing.T) {
	cases := map[string]Vendor{
		"Cisco IOS-XE 17.9":     VendorCisco,
		"cisco nx-os 9.3":       VendorCisco,
		"Arista EOS 4.30":       VendorArista,
		"Juniper Junos 21.4":    VendorJuniper,
		"Huawei VRP V800":       VendorHuawei,
		"Nokia SR OS 22.10":     VendorNokia,
		"":                      VendorUnknown,
		"SomeVendor MagicOS 1":  VendorUnknown,
		"arista cisco-like eos": VendorArista, // arista wins its own dialect
	}
	for platform, want := range cases {
		if got := VendorFromPlatform(platform); got != want {
			t.Errorf("VendorFromPlatform(%q) = %q, want %q", platform, got, want)
		}
	}
}

// TestCaptureCommandTableIsClosed: an unbound platform must be REFUSED, never
// probed with a guessed command at a device prompt.
func TestCaptureCommandTableIsClosed(t *testing.T) {
	if _, ok := CaptureCommand(VendorUnknown); ok {
		t.Fatal("VendorUnknown must have no capture command")
	}
	for _, v := range []Vendor{VendorCisco, VendorArista, VendorJuniper, VendorHuawei, VendorNokia} {
		cmd, ok := CaptureCommand(v)
		if !ok || cmd == "" {
			t.Fatalf("vendor %q has no capture command", v)
		}
		lower := strings.ToLower(cmd)
		if !strings.HasPrefix(lower, "show ") && !strings.HasPrefix(lower, "display ") &&
			!strings.HasPrefix(lower, "admin display") {
			t.Errorf("vendor %q command %q is not a read-only show/display verb", v, cmd)
		}
	}
}

// TestNormalizeStripsVolatileLinesDeterministically is the content-addressing
// contract: two captures of the SAME configuration a minute apart differ only in
// their volatile headers and MUST hash identically.
func TestNormalizeStripsVolatileLinesDeterministically(t *testing.T) {
	first := "Building configuration...\r\n" +
		"Current configuration : 4231 bytes\r\n" +
		"! Last configuration change at 10:00:00 UTC Mon Aug 25 2026\r\n" +
		"! NVRAM config last updated at 09:59:00 UTC Mon Aug 25 2026\r\n" +
		"hostname edge-01\r\n" +
		"ntp clock-period 17179869\r\n" +
		"interface Gi0/0\r\n" +
		" ip address 10.0.0.1 255.255.255.0   \r\n" +
		"!\r\n"
	second := "Building configuration...\n" +
		"Current configuration : 4235 bytes\n" +
		"! Last configuration change at 10:31:14 UTC Mon Aug 25 2026\n" +
		"! NVRAM config last updated at 10:30:02 UTC Mon Aug 25 2026\n" +
		"hostname edge-01\n" +
		"ntp clock-period 17179999\n" +
		"interface Gi0/0\n" +
		" ip address 10.0.0.1 255.255.255.0\n" +
		"!\n\n\n"

	a, b := Normalize(VendorCisco, first), Normalize(VendorCisco, second)
	if a != b {
		t.Fatalf("normalization is not stable across volatile headers:\n%q\n%q", a, b)
	}
	if SHA256Hex(a) != SHA256Hex(b) {
		t.Fatal("normalized configs hash differently")
	}
	for _, banned := range []string{"Building configuration", "Current configuration",
		"Last configuration change", "NVRAM config last updated", "ntp clock-period"} {
		if strings.Contains(a, banned) {
			t.Errorf("volatile line %q survived normalization", banned)
		}
	}
	// Idempotent: normalizing a normalized config changes nothing.
	if Normalize(VendorCisco, a) != a {
		t.Error("Normalize is not idempotent")
	}
	// A REAL change must still change the hash — the failure mode that matters.
	changed := strings.Replace(a, "10.0.0.1", "10.0.0.2", 1)
	if SHA256Hex(changed) == SHA256Hex(a) {
		t.Fatal("a real configuration change did not change the content address")
	}
}

func TestNormalizePerVendorVolatileRules(t *testing.T) {
	cases := []struct {
		vendor Vendor
		raw    string
		gone   string
		kept   string
	}{
		{VendorArista, "! Time: Mon Aug 25 10:00:00 2026\nhostname sw1\n", "Time:", "hostname sw1"},
		{VendorJuniper, "## Last commit: 2026-08-25 10:00:00 UTC\nset system host-name r1\n", "Last commit", "host-name r1"},
		{VendorHuawei, "!Last configuration was updated at 2026-08-25\nsysname r1\n", "Last configuration was updated", "sysname r1"},
		{VendorNokia, "# Generated THU AUG 25 10:00:00 2026 UTC\nconfigure system name \"r1\"\n", "Generated", "system name"},
	}
	for _, tc := range cases {
		got := Normalize(tc.vendor, tc.raw)
		if strings.Contains(got, tc.gone) {
			t.Errorf("%s: volatile %q survived: %q", tc.vendor, tc.gone, got)
		}
		if !strings.Contains(got, tc.kept) {
			t.Errorf("%s: configuration line %q was dropped: %q", tc.vendor, tc.kept, got)
		}
	}
}

// TestNormalizeKeepsConfigurationIntent guards the OTHER direction: a
// normalization rule that ate real configuration would silently hide changes.
func TestNormalizeKeepsConfigurationIntent(t *testing.T) {
	raw := "ntp server 10.1.1.1\n" + // NOT ntp clock-period
		"snmp-server host 10.2.2.2 version 2c public\n" +
		"! this is an operator comment\n" +
		"boot system flash:image.bin\n"
	got := Normalize(VendorCisco, raw)
	for _, want := range []string{"ntp server 10.1.1.1", "snmp-server host", "operator comment", "boot system"} {
		if !strings.Contains(got, want) {
			t.Errorf("normalization dropped real configuration %q", want)
		}
	}
}

// TestRedactionCanariesCisco drives the documented Cisco/Arista secret rules.
func TestRedactionCanariesCisco(t *testing.T) {
	cfg := strings.Join([]string{
		"enable secret 5 " + canaryEnableSecret,
		"username admin privilege 15 secret 9 " + canaryUserPW,
		"snmp-server community " + canaryCommunity + " RO",
		"snmp-server host 10.2.2.2 version 2c " + canaryCommunity,
		"tacacs-server host 10.3.3.3 key 7 " + canaryTacacsKey,
		"crypto isakmp key " + canaryPSK + " address 10.4.4.4",
		"line vty 0 4",
		" password 7 " + canaryUserPW,
		"interface Gi0/0",
		" ip address 10.0.0.1 255.255.255.0",
	}, "\n")

	got := Redact(VendorCisco, cfg)
	for _, canary := range []string{canaryEnableSecret, canaryCommunity, canaryTacacsKey, canaryPSK, canaryUserPW} {
		if strings.Contains(got, canary) {
			t.Errorf("SECRET LEAK: %q survived redaction:\n%s", canary, got)
		}
	}
	if !strings.Contains(got, Mask) {
		t.Fatal("nothing was masked at all")
	}
	// Non-secret configuration must survive: a redactor that eats the config is
	// as useless as one that leaks.
	for _, keep := range []string{"enable secret", "snmp-server community", "interface Gi0/0", "10.0.0.1"} {
		if !strings.Contains(got, keep) {
			t.Errorf("redaction destroyed non-secret content %q:\n%s", keep, got)
		}
	}
	// Idempotent.
	if Redact(VendorCisco, got) != got {
		t.Error("Redact is not idempotent")
	}
}

// TestRedactionCanariesJunos drives the documented Junos rules.
func TestRedactionCanariesJunos(t *testing.T) {
	cfg := strings.Join([]string{
		`set system root-authentication encrypted-password "` + canaryJunosPW + `"`,
		`set system login user ops authentication encrypted-password "` + canaryJunosPW + `"`,
		`set security ike policy P1 pre-shared-key ascii-text "` + canaryPSK + `"`,
		`set system radius-server 10.1.1.1 secret "` + canaryTacacsKey + `"`,
		`set snmp community ` + canaryCommunity + ` authorization read-only`,
		`set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24`,
	}, "\n")

	got := Redact(VendorJuniper, cfg)
	for _, canary := range []string{canaryJunosPW, canaryPSK, canaryTacacsKey, canaryCommunity} {
		if strings.Contains(got, canary) {
			t.Errorf("SECRET LEAK: %q survived redaction:\n%s", canary, got)
		}
	}
	if !strings.Contains(got, "10.0.0.1/24") {
		t.Errorf("redaction destroyed non-secret content:\n%s", got)
	}
}

// TestRedactionMasksInlineKeyMaterial covers the multi-line PEM/hex blob path no
// single-line rule can see.
func TestRedactionMasksInlineKeyMaterial(t *testing.T) {
	cfg := "crypto pki certificate chain TP\n" +
		" certificate self-signed 01\n" +
		"  30820229308201 92A0030201020202 0130 0D06092A864886F70D01010505003031\n" +
		"  quit\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEAxCanaryPrivateKeyMaterial\n" +
		"-----END RSA PRIVATE KEY-----\n"
	got := Redact(VendorCisco, cfg)
	if strings.Contains(got, "CanaryPrivateKeyMaterial") {
		t.Errorf("SECRET LEAK: PEM body survived:\n%s", got)
	}
	if strings.Contains(got, "30820229308201") {
		t.Errorf("SECRET LEAK: inline hex certificate body survived:\n%s", got)
	}
}

// TestSecretAndVolatileRuleListsAreDocumented pins the rule NAMES so a silent
// deletion (or a rename that drops a rule) fails the build rather than quietly
// widening what reaches an operator.
func TestSecretAndVolatileRuleListsAreDocumented(t *testing.T) {
	wantSecret := map[Vendor][]string{
		VendorCisco: {"pre-shared-key", "key-string", "shared-secret", "auth-priv-token",
			"enable-secret", "username-secret", "snmp-community", "snmp-host-community",
			"aaa-server-key", "keychain-key", "isakmp-key", "line-password",
			"bgp-neighbor-pass", "ospf-md5-key", "ppp-password", "wpa-psk", "ftp-password"},
		VendorJuniper: {"pre-shared-key", "key-string", "shared-secret", "auth-priv-token",
			"junos-encrypted-pw", "junos-plain-text-pw", "junos-auth-key", "junos-secret",
			"junos-ssh-key", "junos-snmp-community"},
	}
	for v, want := range wantSecret {
		got := SecretRuleNames(v)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s secret rules changed:\n got %v\nwant %v", v, got, want)
		}
	}
	if names := VolatileRuleNames(VendorCisco); len(names) != 8 {
		t.Errorf("cisco volatile rule list changed: %v", names)
	}
	if names := VolatileRuleNames(VendorUnknown); len(names) != len(volatileCommon) {
		t.Errorf("unknown vendor must apply only the common volatile rules: %v", names)
	}
}

func TestValidSHA(t *testing.T) {
	good := SHA256Hex("hello")
	if !validSHA(good) {
		t.Fatalf("valid sha rejected: %q", good)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("A", 64),
		"../../etc/passwd", good + "x"} {
		if validSHA(bad) {
			t.Errorf("invalid version id accepted: %q", bad)
		}
	}
}
