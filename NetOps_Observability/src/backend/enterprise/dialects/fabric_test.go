// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/Correlix-Enterprise.txt.

package dialects

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/hardening"
	"netops/backend/internal/secfindings"
)

// findingFor returns the finding for a given RawRuleID (the core engine test has
// its own copy; this package must not reach into another package's test file).
func findingFor(fs []secfindings.Finding, ruleID string) (secfindings.Finding, bool) {
	for _, f := range fs {
		if f.RawRuleID == ruleID {
			return f, true
		}
	}
	return secfindings.Finding{}, false
}

// fixedClock pins the engine's clock so a finding's timestamps are deterministic
// (the core engine test has its own copy; this package must not reach into it).
func fixedClock() func() time.Time {
	t := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// dialect_fabric_test.go — the Arista EOS / Nokia SR Linux bindings, scored
// against the configurations the LAB DEVICES actually returned.
//
// FIXTURE PROVENANCE. Both files under testdata/ are real captures taken on
// 2026-09-02 over the same single, non-interactive, read-only SSH exec the
// capture gateway uses:
//
//	arista_leaf1_running.txt   leaf1  172.40.40.21  cEOSLab 4.36.0.1F
//	                           `show running-config` (privileged exec)
//	srlinux_spine1_running.txt spine1 172.40.40.11  SR Linux v26.3.2, 7220 IXR-D3L
//	                           `info from running flat`
//
// They are REDACTED, and redacted in the one way that keeps them useful as test
// input: every secret VALUE is replaced while its SHAPE is preserved, because
// several rules here read the shape. SR Linux crypt values keep their scheme
// marker (`$y$REDACTED`, `$aes1$REDACTED`) so local-user-weak-secret still sees
// a hashed password rather than a cleartext one; the EOS user secret keeps
// `sha512 $6$…` for the same reason; authorized SSH public-key bodies, the SNMP
// community name, the SNMPv3 auth/priv keys and the TLS certificate body are
// replaced with fixed placeholders. No credential from these devices is in this
// repository.
//
// The EOS fixture's `! Command: show running-config at line 2` header is
// verbatim: reaching privileged exec during verification took a two-line
// `enable` prelude. It is stripped by the eos-command volatile rule before the
// capture is ever hashed, and the hardening engine does not read it.

const (
	platformEOS     = "Arista EOS 4.36"
	platformSRLinux = "Nokia SR Linux 26.3"
)

func loadFabricFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// evaluateFixture runs the shipped catalog over one fixture with no seam model
// (exposure probes therefore report Unknown/NotApplicable and are not what this
// file is about).
func evaluateFixture(t *testing.T, platform, raw string) []secfindings.Finding {
	t.Helper()
	dev := hardening.Device{ID: "d1", Hostname: "lab", Platform: platform, TenantID: "acme"}
	eng := hardening.NewEngine(hardening.DefaultCatalog(Packs()...), hardening.MemConfigSource{"d1": raw}, hardening.MemSeamResolver{}, hardening.WithClock(fixedClock()))
	fs, err := eng.Evaluate(context.Background(), dev)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return fs
}

// statusOf returns one rule's status, failing the test if the rule produced no
// finding at all (which would mean the catalog silently lost it).
func statusOf(t *testing.T, fs []secfindings.Finding, ruleID string) secfindings.StatusID {
	t.Helper()
	f, ok := findingFor(fs, ruleID)
	if !ok {
		t.Fatalf("no finding for rule %q", ruleID)
	}
	return f.StatusID
}

// ─────────────────────────────────────────────────────────────────────────────
// Dialect selection
// ─────────────────────────────────────────────────────────────────────────────

// TestFabricPlatformsResolveToTheirOwnDialect is the regression this whole file
// exists for: before it, "Arista EOS" resolved to NO dialect (every rule
// NotApplicable) and "Nokia SR Linux" resolved to the SR OS dialect, whose
// detections read a configuration grammar SR Linux does not write.
func TestFabricPlatformsResolveToTheirOwnDialect(t *testing.T) {
	cases := []struct {
		platform string
		want     hardening.Vendor
		display  string
	}{
		{platformEOS, hardening.VendorArista, "Arista EOS"},
		{"arista", hardening.VendorArista, "Arista EOS"},
		{"ceos", hardening.VendorArista, "Arista EOS"},
		{platformSRLinux, hardening.VendorSRLinux, "Nokia SR Linux"},
		{"srlinux", hardening.VendorSRLinux, "Nokia SR Linux"},
		{"Nokia SR OS 22", hardening.VendorNokia, "Nokia SR OS"},
	}
	for _, c := range cases {
		if got := hardening.VendorFromPlatform(c.platform); got != c.want {
			t.Errorf("VendorFromPlatform(%q) = %q, want %q", c.platform, got, c.want)
		}
		if got := hardening.DisplayVendor(c.want); got != c.display {
			t.Errorf("DisplayVendor(%q) = %q, want %q", c.want, got, c.display)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// As-found verdicts on the real captures
// ─────────────────────────────────────────────────────────────────────────────

// TestAristaLeafAsFoundVerdicts pins every verdict the shipped catalog reaches
// on leaf1's real configuration. Each row is a claim about the DEVICE, so a
// change to any of them is a change to what we tell an operator about it.
func TestAristaLeafAsFoundVerdicts(t *testing.T) {
	fs := evaluateFixture(t, platformEOS, loadFabricFixture(t, "arista_leaf1_running.txt"))
	want := map[string]secfindings.StatusID{
		// FAIL — real, reproducible findings on leaf1.
		"snmp-v1v2c-community": secfindings.StatusFail, // snmp-server community … ro
		"snmp-no-source-acl":   secfindings.StatusFail, // …with no trailing ACL token
		"mgmt-api-unencrypted": secfindings.StatusFail, // management api gnmi / transport grpc default, no ssl profile
		"no-remote-aaa":        secfindings.StatusFail, // `no aaa root` only; no TACACS+/RADIUS group
		"no-ntp-server":        secfindings.StatusFail, // no `ntp server` line at all

		// PASS — assessed and clean.
		"telnet-vty-enabled":     secfindings.StatusPass, // no `management telnet` block
		"http-server-nontls":     secfindings.StatusPass, // eAPI up, no `protocol http`
		"snmp-default-community": secfindings.StatusPass, // community is not public/private
		"no-central-logging":     secfindings.StatusPass, // logging host 10.70.245.122
		"weak-enable-password":   secfindings.StatusPass, // no `enable password`
		"local-user-weak-secret": secfindings.StatusPass, // secret sha512
		"ntp-no-authentication":  secfindings.StatusPass, // no NTP server → nothing unauthenticated

		// NOT APPLICABLE with a stated reason — the concept has no EOS form.
		"ssh-not-v2":                     secfindings.StatusNotApplicable,
		"no-service-password-encryption": secfindings.StatusNotApplicable,
	}
	for rule, status := range want {
		if got := statusOf(t, fs, rule); got != status {
			t.Errorf("EOS rule %q = %s, want %s", rule, got, status)
		}
	}

	// NOT EMITTED AT ALL: rules with no EOS binding (IOS-only legacy services
	// and IOS-grammar access-control checks). They are not EOS controls, so
	// they are not EOS verdicts either — before 2026-09-03 each of these
	// produced a per-device NotApplicable that rendered OUR coverage gap as a
	// statement about the device. Listed so authoring an EOS binding has to
	// move the row up into `want`.
	for _, rule := range []string{
		"ftp-server-enabled", "tftp-server-enabled", "tcp-small-servers", "udp-small-servers",
		"finger-service", "bootp-server", "pad-service", "cdp-run-global",
		"vty-no-access-class", "http-no-source-acl", "no-aaa-new-model",
		"no-control-plane-protection",
		// tls-no-client-auth is SR Linux-only: EOS binds its TLS client
		// authentication elsewhere and we have authored no detection for it.
		"tls-no-client-auth",
	} {
		if f, ok := findingFor(fs, rule); ok {
			t.Errorf("EOS emitted unbound rule %q (%s) — a rule with no binding is not this platform's control",
				rule, f.StatusID)
		}
	}

	// leaf1's whole emitted set is its control set and nothing else.
	got := map[string]bool{}
	for _, f := range fs {
		got[f.RawRuleID] = true
	}
	if len(got) != len(want) {
		t.Errorf("EOS emitted %d checks (%v), want exactly the %d bound ones", len(got), got, len(want))
	}
}

// TestSRLinuxSpineAsFoundVerdicts does the same for spine1.
func TestSRLinuxSpineAsFoundVerdicts(t *testing.T) {
	fs := evaluateFixture(t, platformSRLinux, loadFabricFixture(t, "srlinux_spine1_running.txt"))
	want := map[string]secfindings.StatusID{
		// FAIL — real, reproducible findings on spine1.
		"http-server-nontls":   secfindings.StatusFail, // json-rpc-server … http admin-state enable
		"mgmt-api-unencrypted": secfindings.StatusFail, // grpc-server insecure-mgmt / eda-insecure-mgmt, no TLS profile
		"tls-no-client-auth":   secfindings.StatusFail, // tls profile clab-profile authenticate-client false
		"snmp-v1v2c-community": secfindings.StatusFail, // SNMPv2-RO-Community community-entry
		"no-remote-aaa":        secfindings.StatusFail, // authentication-method [ local ]
		"no-ntp-server":        secfindings.StatusFail, // no system ntp server

		// PASS — assessed and clean.
		"snmp-default-community": secfindings.StatusPass, // community is not public/private
		"no-central-logging":     secfindings.StatusPass, // logging remote-server 10.70.245.122
		"local-user-weak-secret": secfindings.StatusPass, // every password carries a $scheme$ marker

		// NOT APPLICABLE with a stated reason.
		"telnet-vty-enabled":             secfindings.StatusNotApplicable,
		"ssh-not-v2":                     secfindings.StatusNotApplicable,
		"no-service-password-encryption": secfindings.StatusNotApplicable,
		"weak-enable-password":           secfindings.StatusNotApplicable,
		"snmp-no-source-acl":             secfindings.StatusNotApplicable,
	}
	for rule, status := range want {
		if got := statusOf(t, fs, rule); got != status {
			t.Errorf("SR Linux rule %q = %s, want %s", rule, got, status)
		}
	}

	// The scan's WHOLE emitted set is spine1's control set — nothing more. The
	// lab defect of 2026-09-03 emitted 32 checks per spine (the entire catalog,
	// Cisco IOS rules included); the correct answer is these 14.
	got := map[string]secfindings.StatusID{}
	for _, f := range fs {
		got[f.RawRuleID] = f.StatusID
	}
	if len(got) != len(want) {
		t.Errorf("SR Linux emitted %d checks, want exactly the %d bound ones; emitted=%v", len(got), len(want), got)
	}
	for rule := range got {
		if _, ok := want[rule]; !ok {
			t.Errorf("SR Linux emitted %q, which has no srlinux binding", rule)
		}
	}

	// The FAIL list a lab scan of spine1 must produce, asserted as a SET so a
	// rule that stops firing is caught as loudly as one that starts.
	wantFail := []string{
		"http-server-nontls", "mgmt-api-unencrypted", "tls-no-client-auth",
		"snmp-v1v2c-community", "no-remote-aaa", "no-ntp-server",
	}
	fails := []string{}
	for rule, st := range got {
		if st == secfindings.StatusFail {
			fails = append(fails, rule)
		}
	}
	sort.Strings(fails)
	sorted := append([]string(nil), wantFail...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(fails, sorted) {
		t.Errorf("spine1 FAIL set = %v, want %v", fails, sorted)
	}
}

// TestFabricNotApplicableCarriesItsReason — a NotApplicable that says only
// "not assessed for this platform" is indistinguishable from a coverage gap.
// Where a binding declares the control structurally inapplicable it MUST say
// why, and the reason must name the platform's actual behaviour.
func TestFabricNotApplicableCarriesItsReason(t *testing.T) {
	srl := evaluateFixture(t, platformSRLinux, loadFabricFixture(t, "srlinux_spine1_running.txt"))
	eos := evaluateFixture(t, platformEOS, loadFabricFixture(t, "arista_leaf1_running.txt"))

	cases := []struct {
		fs       []secfindings.Finding
		rule     string
		contains string
	}{
		{srl, "telnet-vty-enabled", "no telnet server"},
		{srl, "ssh-not-v2", "SSHv2 only"},
		{srl, "snmp-no-source-acl", "network-instance"},
		{srl, "weak-enable-password", "no enable/privileged-exec password"},
		{eos, "ssh-not-v2", "SSHv2 only"},
		{eos, "no-service-password-encryption", "no global password-encryption switch"},
	}
	for _, c := range cases {
		f, ok := findingFor(c.fs, c.rule)
		if !ok {
			t.Fatalf("no finding for %q", c.rule)
		}
		if f.StatusID != secfindings.StatusNotApplicable {
			t.Errorf("%s: status = %s, want NotApplicable", c.rule, f.StatusID)
			continue
		}
		if !strings.Contains(f.Detail, c.contains) {
			t.Errorf("%s: detail %q does not explain why (want it to mention %q)", c.rule, f.Detail, c.contains)
		}
		// A structural NotApplicable is NOT the generic unbound-vendor answer.
		if strings.Contains(f.Detail, "no detection binding") {
			t.Errorf("%s: reported as an unbound vendor, not as structurally inapplicable", c.rule)
		}
	}
}

// TestFabricUnknownWhenConfigUnavailable — the fail-closed leg. No config on
// file means every fabric rule is Unknown, never a Pass.
func TestFabricUnknownWhenConfigUnavailable(t *testing.T) {
	for _, platform := range []string{platformEOS, platformSRLinux} {
		dev := hardening.Device{ID: "d1", Hostname: "lab", Platform: platform, TenantID: "acme"}
		eng := hardening.NewEngine(hardening.DefaultCatalog(Packs()...), hardening.MemConfigSource{}, hardening.MemSeamResolver{}, hardening.WithClock(fixedClock()))
		fs, err := eng.Evaluate(context.Background(), dev)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		for _, rule := range []string{"mgmt-api-unencrypted", "no-ntp-server", "no-remote-aaa", "local-user-weak-secret", "telnet-vty-enabled"} {
			if got := statusOf(t, fs, rule); got != secfindings.StatusUnknown {
				t.Errorf("%s / %s = %s, want Unknown (fail-closed)", platform, rule, got)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The other side of every FAIL: a hardened configuration must Pass
//
// An as-found corpus proves the rules FIRE. These prove they STOP firing when
// the control is actually satisfied — without which a rule that trips on
// everything would look correct above.
// ─────────────────────────────────────────────────────────────────────────────

const cfgEOSHardened = `! Command: show running-config
! device: leaf9 (cEOSLab, EOS-4.36.0.1F)
!
management telnet
   shutdown
!
username ops privilege 15 role network-admin secret sha512 $6$REDACTED
!
management api http-commands
   no shutdown
   protocol https
!
management security
   ssl profile MGMT
      certificate leaf.crt key leaf.key
!
management api gnmi
   transport grpc default
      ssl profile MGMT
!
aaa group server tacacs+ TAC
   server 10.0.0.30
aaa authentication login default group TAC local
!
logging host 10.0.0.10
!
ntp authentication-key 1 sha1 keykeykey
ntp trusted-key 1
ntp authenticate
ntp server 10.0.0.20 key 1
!
ip access-list standard SNMP-IN
   permit 10.0.0.0/24
snmp-server community lab-only ro SNMP-IN
!
end
`

const cfgSRLinuxHardened = `set / system json-rpc-server admin-state enable
set / system json-rpc-server network-instance mgmt https admin-state enable
set / system json-rpc-server network-instance mgmt https tls-profile mgmt-profile
set / system aaa authentication authentication-method [ tacacs local ]
set / system aaa authentication admin-user password $y$REDACTED
set / system aaa server-group TAC type tacacs
set / system logging remote-server 10.0.0.10 transport udp
set / system ntp admin-state enable
set / system ntp network-instance mgmt
set / system ntp server 10.0.0.20 iburst true
set / system snmp access-group SNMPv3-Group security-level auth-priv
set / system snmp network-instance mgmt admin-state enable
set / system tls profile mgmt-profile authenticate-client true
set / system grpc-server mgmt admin-state enable
set / system grpc-server mgmt tls-profile mgmt-profile
set / system grpc-server eda-mgmt admin-state enable
set / system grpc-server eda-mgmt default-tls-profile true
`

// TestFabricHardenedConfigsPass is the negative control for every FAIL pinned
// above: the same rules, a configuration that satisfies them, all Pass.
func TestFabricHardenedConfigsPass(t *testing.T) {
	eos := evaluateFixture(t, platformEOS, cfgEOSHardened)
	for _, rule := range []string{
		"telnet-vty-enabled", "http-server-nontls", "mgmt-api-unencrypted",
		"no-remote-aaa", "no-ntp-server", "ntp-no-authentication",
		"snmp-no-source-acl", "snmp-default-community", "no-central-logging",
		"local-user-weak-secret", "weak-enable-password",
	} {
		if got := statusOf(t, eos, rule); got != secfindings.StatusPass {
			t.Errorf("hardened EOS rule %q = %s, want Pass", rule, got)
		}
	}

	srl := evaluateFixture(t, platformSRLinux, cfgSRLinuxHardened)
	for _, rule := range []string{
		"http-server-nontls", "mgmt-api-unencrypted", "tls-no-client-auth",
		"snmp-v1v2c-community", "snmp-default-community", "no-remote-aaa",
		"no-ntp-server", "no-central-logging", "local-user-weak-secret",
	} {
		if got := statusOf(t, srl, rule); got != secfindings.StatusPass {
			t.Errorf("hardened SR Linux rule %q = %s, want Pass", rule, got)
		}
	}
}

// TestFabricDetectionsAreNotFooledByNearMisses pins the string-level traps each
// dialect sets, one assertion per trap. These are the mistakes a plain
// substring rule makes on these two platforms.
func TestFabricDetectionsAreNotFooledByNearMisses(t *testing.T) {
	// `https` must not read as `http`.
	httpsOnly := hardening.NewConfig(hardening.VendorSRLinux, "set / system json-rpc-server network-instance mgmt https admin-state enable\n")
	if r := srlJSONRPCPlaintext(httpsOnly); r.Tripped {
		t.Errorf("srlJSONRPCPlaintext tripped on an HTTPS-only listener: %q", r.Evidence)
	}
	eosHTTPS := hardening.NewConfig(hardening.VendorArista, "management api http-commands\n   no shutdown\n   protocol https\n")
	if r := eosEAPIPlaintext(eosHTTPS); r.Tripped {
		t.Errorf("eosEAPIPlaintext tripped on `protocol https`: %q", r.Evidence)
	}

	// An EOS management block that exists but is shut down is not "enabled".
	eosTelnetShut := hardening.NewConfig(hardening.VendorArista, "management telnet\n   shutdown\n")
	if r := eosTelnetEnabled(eosTelnetShut); r.Tripped {
		t.Errorf("eosTelnetEnabled tripped on a shut-down telnet server: %q", r.Evidence)
	}

	// SR Linux gRPC instances are scored INDIVIDUALLY: one secured instance
	// must not clear a second, bare one.
	mixed := hardening.NewConfig(hardening.VendorSRLinux, strings.Join([]string{
		"set / system grpc-server mgmt admin-state enable",
		"set / system grpc-server mgmt tls-profile p1",
		"set / system grpc-server insecure-mgmt admin-state enable",
		"",
	}, "\n"))
	r := srlInsecureGRPC(mixed)
	if !r.Tripped {
		t.Fatal("srlInsecureGRPC did not trip on a bare instance beside a secured one")
	}
	if !strings.Contains(r.Evidence, "insecure-mgmt") || strings.Contains(r.Evidence, "mgmt,") {
		t.Errorf("evidence should name only the bare instance, got %q", r.Evidence)
	}

	// A redacted-but-hashed password must not read as cleartext: the crypt
	// marker is what the rule keys on, and it survives redaction by design.
	hashed := hardening.NewConfig(hardening.VendorSRLinux, "set / system aaa authentication admin-user password $y$REDACTED\n")
	if r := srlWeakLocalSecret(hashed); r.Tripped {
		t.Errorf("srlWeakLocalSecret tripped on a hashed password: %q", r.Evidence)
	}
	clear := hardening.NewConfig(hardening.VendorSRLinux, "set / system aaa authentication admin-user password NokiaSrl1\n")
	if r := srlWeakLocalSecret(clear); !r.Tripped {
		t.Error("srlWeakLocalSecret did not trip on a cleartext password")
	}
}
