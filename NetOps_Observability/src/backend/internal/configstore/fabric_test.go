// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"context"
	"os"
	"strings"
	"testing"
)

// fabric_test.go — capture, normalization and redaction for the two data-centre
// fabric dialects, driven by REAL device output.
//
// FIXTURE PROVENANCE. Both files under testdata/ are excerpts of real captures
// taken on 2026-09-02 over the same single, non-interactive, read-only SSH exec
// the gateway performs:
//
//	arista_leaf1_excerpt.txt    leaf1  172.40.40.21  cEOSLab 4.36.0.1F
//	                            `show running-config`
//	srlinux_spine1_excerpt.txt  spine1 172.40.40.11  SR Linux v26.3.2
//	                            `info from running flat`
//
// They are excerpts of the secret-bearing and header regions on purpose: those
// are the parts this package reasons about. Every secret VALUE is replaced and
// its SHAPE preserved (SR Linux crypt values keep their `$scheme$` marker, the
// EOS user secret keeps `sha512 $6$…`, key bodies and the community name are
// fixed placeholders), so the redaction rules below are still exercised against
// the real grammar. No credential from these devices is in this repository.

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// TestFabricPlatformsResolveToTheirCaptureFamily — the resolution bug this work
// fixed. "Nokia SR Linux" contains "nokia", so before the srlinux dialect was
// declared the nokia family claimed it and an SR Linux box would have been sent
// SR OS' `admin display-config`: a command that does not exist on that OS.
func TestFabricPlatformsResolveToTheirCaptureFamily(t *testing.T) {
	cases := []struct {
		platform string
		vendor   Vendor
		cmd      string
	}{
		{"Nokia SR Linux 26.3", VendorSRLinux, "info from running flat"},
		{"srlinux", VendorSRLinux, "info from running flat"},
		{"Nokia SR OS 22.10", VendorNokia, "admin display-config"},
		{"TiMOS-B-22.10", VendorNokia, "admin display-config"},
		{"Arista EOS 4.36", VendorArista, "show running-config"},
		{"cEOS", VendorArista, "show running-config"},
	}
	for _, c := range cases {
		got := VendorFromPlatform(c.platform)
		if got != c.vendor {
			t.Errorf("VendorFromPlatform(%q) = %q, want %q", c.platform, got, c.vendor)
			continue
		}
		cmd, ok := CaptureCommand(got)
		if !ok || cmd != c.cmd {
			t.Errorf("CaptureCommand(%q) = %q ok=%v, want %q", got, cmd, ok, c.cmd)
		}
	}
}

// TestFabricNormalizationIsStableAndDropsOnlyHeaders — normalization is the
// content-addressing contract: the same capture must hash to the same version,
// and only clock/banner lines may be dropped.
func TestFabricNormalizationIsStableAndDropsOnlyHeaders(t *testing.T) {
	eos := loadFixture(t, "arista_leaf1_excerpt.txt")
	n1, n2 := Normalize(VendorArista, eos), Normalize(VendorArista, eos)
	if SHA256Hex(n1) != SHA256Hex(n2) {
		t.Error("EOS normalization is not deterministic")
	}
	// The two headers EOS stamps are volatile and must be gone…
	for _, gone := range []string{"! Command: show running-config", "! device: leaf1"} {
		if strings.Contains(n1, gone) {
			t.Errorf("EOS volatile header survived normalization: %q", gone)
		}
	}
	// …and nothing else may be.
	for _, kept := range []string{"no aaa root", "username admin privilege 15", "management api http-commands", "snmp-server community"} {
		if !strings.Contains(n1, kept) {
			t.Errorf("EOS configuration line was dropped by normalization: %q", kept)
		}
	}

	srl := loadFixture(t, "srlinux_spine1_excerpt.txt")
	m1, m2 := Normalize(VendorSRLinux, srl), Normalize(VendorSRLinux, srl)
	if SHA256Hex(m1) != SHA256Hex(m2) {
		t.Error("SR Linux normalization is not deterministic")
	}
	// SR Linux declares NO volatile rules, so its capture must survive intact
	// line for line (bar the trailing-blank trim normalization always does).
	if got, want := len(strings.Split(strings.TrimRight(m1, "\n"), "\n")),
		len(strings.Split(strings.TrimRight(strings.ReplaceAll(srl, "\r\n", "\n"), "\n"), "\n")); got != want {
		t.Errorf("SR Linux normalization dropped lines: %d → %d (the dialect declares no volatile rules)", want, got)
	}
}

// TestSRLinuxRedactionMasksEverySecretShape drives each SR Linux secret grammar
// through Redact and asserts the VALUE is gone while the statement that carries
// it survives — an operator must still be able to read the diff.
func TestSRLinuxRedactionMasksEverySecretShape(t *testing.T) {
	// Realistic (fabricated) values in the exact shapes the device writes.
	raw := strings.Join([]string{
		`set / system aaa authentication linuxadmin-user password $y$j9T$Nabcdefghijklmnop$5WQpwXtkvoh8uSopqRZ`,
		`set / system aaa authentication admin-user ssh-key [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuZe59aRGJKf" ]`,
		`set / system snmp access-group G community-entry RO community $aes1$ATdhzzQkkJ4uI28=$LLoMgqck5b0ZLKNT`,
		`set / system snmp access-group G security-entry m authentication password $aes1$ATVj6gXtM0otw28=$9Gnua`,
		`set / system tls profile clab-profile key $aes1$ATS1Z+HiFtyO/m8=$ly6Edrri86uVfd29auuVIY59JmyHoEu40jI`,
		`set / system tls profile clab-profile certificate "-----BEGIN CERTIFICATE-----`,
		`MIID7jCCAtagAwIBAgICBnowDQYJKoZIhvcNAQELBQAwXDELMAkGA1UEBhMCVVMx`,
		`-----END CERTIFICATE-----`,
		`set / system tls profile clab-profile authenticate-client false`,
		``,
	}, "\n")
	out := Redact(VendorSRLinux, raw)

	// Every secret VALUE is gone.
	for _, secret := range []string{
		"$y$j9T$Nabcdefghijklmnop$5WQpwXtkvoh8uSopqRZ",
		"AAAAC3NzaC1lZDI1NTE5AAAAICuZe59aRGJKf",
		"$aes1$ATdhzzQkkJ4uI28=$LLoMgqck5b0ZLKNT",
		"$aes1$ATVj6gXtM0otw28=$9Gnua",
		"$aes1$ATS1Z+HiFtyO/m8=$ly6Edrri86uVfd29auuVIY59JmyHoEu40jI",
		"MIID7jCCAtagAwIBAgICBnowDQYJKoZIhvcNAQELBQAwXDELMAkGA1UEBhMCVVMx",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("secret survived redaction: %q\n%s", secret, out)
		}
	}
	// The STATEMENTS survive, so a redacted diff is still readable.
	for _, kept := range []string{
		"set / system aaa authentication linuxadmin-user password",
		"set / system snmp access-group G community-entry RO community",
		"set / system tls profile clab-profile key",
		"set / system tls profile clab-profile authenticate-client false",
		"-----BEGIN CERTIFICATE-----",
	} {
		if !strings.Contains(out, kept) {
			t.Errorf("redaction ate a configuration statement: %q\n%s", kept, out)
		}
	}
	// Redaction is idempotent.
	if again := Redact(VendorSRLinux, out); again != out {
		t.Error("Redact is not idempotent on SR Linux text")
	}
}

// TestFabricFixturesCarryNoUnmaskedSecretMaterial is the belt-and-braces check
// on the CHECKED-IN fixtures themselves: whatever the rules do, no crypt value,
// key body or PEM body may sit in the repository.
func TestFabricFixturesCarryNoUnmaskedSecretMaterial(t *testing.T) {
	for _, f := range []string{"srlinux_spine1_excerpt.txt", "arista_leaf1_excerpt.txt"} {
		body := loadFixture(t, f)
		for _, line := range strings.Split(body, "\n") {
			for _, marker := range []string{"$y$", "$6$", "$aes1$", "ssh-ed25519 ", "ssh-rsa "} {
				i := strings.Index(line, marker)
				if i < 0 {
					continue
				}
				rest := line[i+len(marker):]
				if !strings.HasPrefix(rest, "REDACTED") {
					t.Errorf("%s: unmasked secret material after %q: %q", f, marker, line)
				}
			}
		}
	}
}

// TestSecretRuleNamesForSRLinuxArePinned — the rule list is the contract; a
// silent deletion here publishes a device credential.
func TestSecretRuleNamesForSRLinuxArePinned(t *testing.T) {
	want := []string{
		"pre-shared-key", "key-string", "shared-secret", "auth-priv-token",
		"srl-crypt-value", "srl-password", "srl-community", "srl-secret-key", "srl-ssh-key",
	}
	got := SecretRuleNames(VendorSRLinux)
	if len(got) != len(want) {
		t.Fatalf("SR Linux secret rules = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SR Linux secret rule %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestCLIRefusalIsNeverStoredAsAVersion — the silent-corruption guard.
//
// EOS answers `show running-config` from a privilege-1 session with a
// diagnostic on stdout and a ZERO exit status. Without this check the capture
// would succeed, the refusal text would be hashed as a new configuration
// version, the device would report drift, and the sealed artifact an operator
// restores from would be one line of error text.
func TestCLIRefusalIsNeverStoredAsAVersion(t *testing.T) {
	for _, refusal := range []string{
		"% Invalid input (privileged mode required) at line 1\n",
		"% Authorization denied\n",
		"Error: Path not valid\n",
		"unknown command.\n",
	} {
		if line, ok := looksLikeCLIRefusal(refusal); !ok {
			t.Errorf("refusal not recognized: %q", refusal)
		} else if line == "" {
			t.Errorf("refusal recognized with no evidence line: %q", refusal)
		}
	}
	// A real configuration is never mistaken for a refusal — including one whose
	// BODY contains a percent sign, which banners and descriptions do.
	for _, cfg := range []string{
		"no aaa root\nbanner motd 100% authorized users only\n",
		"set / system banner login-banner \"90% capacity\"\n",
		"hostname r1\n",
	} {
		if line, ok := looksLikeCLIRefusal(cfg); ok {
			t.Errorf("configuration misread as a refusal (%q): %q", line, cfg)
		}
	}
}

// TestCaptureRefusesADeviceThatRefusedTheCommand runs the guard through the
// real capture path: the gateway succeeds, the device refused, and NO version
// is stored.
func TestCaptureRefusesADeviceThatRefusedTheCommand(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Arista EOS 4.36")
	f.gw.set("d1", "% Invalid input (privileged mode required) at line 1\n")

	if _, err := f.mgr.Capture(context.Background(), dev, "acme", "test"); err == nil {
		t.Fatal("capture stored a CLI refusal as a configuration version")
	} else if !strings.Contains(err.Error(), "refused the capture command") {
		t.Errorf("error does not name the refusal: %v", err)
	}
	if _, ok, lerr := f.store.Latest(context.Background(), "acme", false, "d1"); lerr != nil || ok {
		t.Errorf("a version was stored for a refused capture (ok=%v err=%v)", ok, lerr)
	}
	// The failure is OBSERVABLE (§10): it is recorded, not swallowed.
	if len(f.failures) == 0 {
		t.Error("the refused capture was not recorded as a failure")
	}
}
