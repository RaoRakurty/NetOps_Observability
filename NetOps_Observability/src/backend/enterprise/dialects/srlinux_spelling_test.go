// SPDX-License-Identifier: LicenseRef-Correlix-Enterprise
// Copyright 2026 Correlix
//
// COMMERCIAL ADD-ON MODULE. This package implements the `security_dialects`
// entitlement (Enterprise tier) and is NOT Apache-2.0 core. See the LICENSE
// notice file in this directory, ../../../../LICENSING.md, and
// LICENSES/LicenseRef-Correlix-Enterprise.txt.

package dialects

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/hardening"
)

// srlinux_spelling_test.go — tracker 296.
//
// SR Linux writes the SAME configuration path in three spellings, all of them
// legal and all of them observed (internal/threatlane's catalogue carries the
// same three, with the provenance of each):
//
//	set / system aaa authentication user bob …   the `info … flat` / commit form
//	set /system aaa authentication user bob …    the commit-audit line captured
//	                                            on the lab, 2026-09-03
//	set /system/aaa/authentication/user/bob …    the gNMI-style path form
//
// Every SR Linux hardening rule anchored on the FIRST spelling only. The form
// the configstore feeds the engine today IS that first one, so the rules matched
// — but a capture arriving in either other form matched NOTHING, and a rule pack
// that recognizes no line in the config it was handed used to report the device
// CLEAN. A silent fail-open on a security control is worse than no control.

// srlStmt is one SR Linux configuration statement as a PATH plus its value, so
// this test renders the three spellings of the same statement mechanically
// rather than hand-copying three config blocks that could drift apart.
type srlStmt struct {
	path  []string
	value string
}

// render writes the statement in one of the three spellings:
//
//	lead="/ ", sep=" "  → set / system ntp admin-state enable
//	lead="/",  sep=" "  → set /system ntp admin-state enable
//	lead="/",  sep="/"  → set /system/ntp/admin-state enable
func (s srlStmt) render(lead, sep string) string {
	line := "set " + lead + strings.Join(s.path, sep)
	if s.value != "" {
		line += " " + s.value
	}
	return line
}

// srlNonCompliant is ONE non-compliant SR Linux device expressed as paths. The
// statements are the shapes the lab spine capture and the synthetic list-user
// fixture carry (fabric_test.go holds their provenance); what is new here is
// only that the same device can be rendered three ways.
var srlNonCompliant = []srlStmt{
	// cleartext JSON-RPC listener → http-server-nontls
	{[]string{"system", "json-rpc-server", "network-instance", "mgmt", "http", "admin-state"}, "enable"},
	// a gRPC server instance with no TLS profile → mgmt-api-unencrypted
	{[]string{"system", "grpc-server", "insecure-mgmt", "admin-state"}, "enable"},
	// a TLS profile that authenticates nobody → tls-no-client-auth
	{[]string{"system", "tls", "profile", "clab-profile", "authenticate-client"}, "false"},
	// a v1/v2c community, and a DEFAULT one → snmp-v1v2c-community + snmp-default-community
	{[]string{"system", "snmp", "access-group", "SNMPv2-RO", "community-entry", "public"}, ""},
	// a configured LIST user whose stored password carries no `$scheme$` marker
	// → local-user-weak-secret
	{[]string{"system", "aaa", "authentication", "user", "field-tech", "password"}, "PlaintextPlaceholder1"},
	// local-only authentication → no-remote-aaa
	{[]string{"system", "aaa", "authentication", "authentication-method"}, "[ local ]"},
	// …and no `logging remote-server` and no `ntp server` at all →
	// no-central-logging, no-ntp-server
}

func renderSRLConfig(stmts []srlStmt, lead, sep string) string {
	var b strings.Builder
	for _, s := range stmts {
		b.WriteString(s.render(lead, sep))
		b.WriteString("\n")
	}
	return b.String()
}

// srlSpellings is the three documented renderings, in the order the catalogue
// documents them.
var srlSpellings = []struct {
	name string
	lead string
	sep  string
}{
	{"flat `set / system` (the form configstore feeds today)", "/ ", " "},
	{"commit-audit `set /system`", "/", " "},
	{"gNMI-style `set /system/aaa/...`", "/", "/"},
}

// TestSRLinuxAllThreeSpellingsScoreIdentically is the tracker-296 regression:
// the same non-compliant device, rendered in each documented spelling, must
// produce the same verdicts. Before the fix, spellings 2 and 3 matched no rule
// at all and the device came back clean.
func TestSRLinuxAllThreeSpellingsScoreIdentically(t *testing.T) {
	verdicts := make([]map[string]string, 0, len(srlSpellings))
	for _, sp := range srlSpellings {
		fs := evaluateFixture(t, platformSRLinux, renderSRLConfig(srlNonCompliant, sp.lead, sp.sep))
		got := map[string]string{}
		for _, f := range fs {
			got[f.RawRuleID] = f.StatusID.String()
		}
		verdicts = append(verdicts, got)
	}

	// The canonical spelling must FAIL exactly the controls this device violates
	// — without this the test would also pass if all three spellings were
	// uniformly blind.
	wantFail := []string{
		"http-server-nontls", "local-user-weak-secret", "mgmt-api-unencrypted",
		"no-central-logging", "no-ntp-server", "no-remote-aaa",
		"snmp-default-community", "snmp-v1v2c-community", "tls-no-client-auth",
	}
	fails := []string{}
	for id, st := range verdicts[0] {
		if st == "Fail" {
			fails = append(fails, id)
		}
	}
	sort.Strings(fails)
	if !reflect.DeepEqual(fails, wantFail) {
		t.Fatalf("canonical spelling FAIL set = %v, want %v", fails, wantFail)
	}

	for i := 1; i < len(verdicts); i++ {
		if !reflect.DeepEqual(verdicts[i], verdicts[0]) {
			t.Errorf("%s scored differently from the canonical spelling:\n got  %v\n want %v",
				srlSpellings[i].name, verdicts[i], verdicts[0])
		}
	}
}

// TestSRLinuxUnreadableConfigIsUnassessedNotClean is the fail-closed half of
// tracker 296, and it is the half that matters even after every rule learns all
// three spellings: whatever a FOURTH form turns out to look like, a rule pack
// that recognizes NO line in the text it was handed must report the device
// UNASSESSED with a reason. Reporting Pass for controls nothing looked at is a
// false clear — the §5g rule the rest of this engine already follows.
func TestSRLinuxUnreadableConfigIsUnassessedNotClean(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"another dialect's grammar (an EOS capture mislabelled SR Linux)",
			loadFabricFixture(t, "arista_leaf1_running.txt")},
		{"a structured export no SR Linux rule can read",
			"{\n  \"srl_nokia-system:system\": {\n    \"ntp\": {\"admin-state\": \"disable\"}\n  }\n}\n"},
		{"an empty capture (the transport returned nothing)", "\n\n"},
	}
	for _, c := range cases {
		fs := evaluateFixture(t, platformSRLinux, c.raw)
		if len(fs) == 0 {
			t.Errorf("%s: no findings at all — an empty result set reads as a clean device", c.name)
			continue
		}
		reasoned := false
		for _, f := range fs {
			if f.StatusID.String() == "Pass" || f.StatusID.String() == "Fail" {
				t.Errorf("%s: rule %q returned a real verdict (%s) from a config no SR Linux rule can read: %q",
					c.name, f.RawRuleID, f.StatusID, f.Observed)
			}
			if strings.Contains(f.Detail, "does not parse as") || strings.Contains(f.Detail, "not assessed") {
				reasoned = true
			}
		}
		if !reasoned {
			t.Errorf("%s: no finding says WHY nothing was assessed", c.name)
		}
	}
}

// TestSRLinuxReadableConfigAcceptsRealCapturesAndRejectsForeignOnes tests the
// boundary check DIRECTLY, including the reason it gives. The reason is not
// decoration: it is what an operator reads instead of a verdict, so it has to
// name which of the three faults occurred.
func TestSRLinuxReadableConfigAcceptsRealCapturesAndRejectsForeignOnes(t *testing.T) {
	// ACCEPTED: both real SR Linux fixtures, and all three spellings of the
	// synthetic device. Rejecting a genuine capture would blind the dialect
	// completely, which is why this half comes first.
	accepted := map[string]string{
		"the lab spine capture":       loadFabricFixture(t, "srlinux_spine1_running.txt"),
		"the synthetic list-user set": loadFabricFixture(t, "srlinux_listusers_synthetic.txt"),
		"a hardened config":           cfgSRLinuxHardened,
	}
	for _, sp := range srlSpellings {
		accepted["the synthetic device in "+sp.name] = renderSRLConfig(srlNonCompliant, sp.lead, sp.sep)
	}
	for name, raw := range accepted {
		if ok, reason := srlinuxReadableConfig(hardening.NewConfig(hardening.VendorSRLinux, raw)); !ok {
			t.Errorf("%s was rejected as unreadable (%s) — a genuine capture must be assessed", name, reason)
		}
	}

	// REJECTED, each with the reason that fits the fault.
	rejected := []struct {
		name   string
		raw    string
		reason string
	}{
		{"an EOS capture under an SR Linux platform label",
			loadFabricFixture(t, "arista_leaf1_running.txt"),
			"parses as an SR Linux `set /<path>` line"},
		{"a structured export",
			"{\n  \"srl_nokia-system:system\": {\n    \"ntp\": {\"admin-state\": \"disable\"}\n  }\n}\n",
			"parses as an SR Linux `set /<path>` line"},
		{"an empty capture", "\n\n", "no configuration at all"},
		{"a comment-only capture", "! nothing here\n# nor here\n", "no configuration at all"},
		{"an IOS config carrying one incidental SR Linux line",
			strings.Join([]string{
				"hostname edge-01",
				"ip http server",
				"snmp-server community public RO",
				"line vty 0 4",
				"username ops privilege 15",
				"router bgp 65001",
				"set / system ntp admin-state enable",
				"",
			}, "\n"),
			"another platform's configuration grammar"},
	}
	for _, c := range rejected {
		ok, reason := srlinuxReadableConfig(hardening.NewConfig(hardening.VendorSRLinux, c.raw))
		if ok {
			t.Errorf("%s was accepted as readable SR Linux configuration", c.name)
			continue
		}
		if !strings.Contains(reason, c.reason) {
			t.Errorf("%s: reason = %q, want it to mention %q", c.name, reason, c.reason)
		}
	}
}

// TestNoSRLinuxRuleIsTypedAgainstOneSpelling is the guard that keeps the fix
// from decaying. The defect was not a wrong regex, it was a HABIT: typing
// `^set / system …` out by hand, which reads correct and is dead on two thirds of
// this platform's renderings. Every SR Linux pattern must come from
// internal/srlpath, which is the only place the three spellings are encoded.
func TestNoSRLinuxRuleIsTypedAgainstOneSpelling(t *testing.T) {
	for _, name := range []string{"fabric.go", "packs.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // prose may quote the old anchor; patterns may not use it
			}
			if strings.Contains(line, "^set /") {
				t.Errorf("%s:%d anchors a pattern on ONE SR Linux spelling — build it from srlpath.Statement/Path instead:\n\t%s",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestSRLinuxMultiInstanceGroupingSurvivesEverySpelling pins the subtle half of
// the pattern rewrite. Two rules GROUP lines by a list key — gRPC server
// instances by name, accounts by account — and in the gNMI-style spelling the
// separators around that key are slashes, so a pattern that captured greedily
// would take `mgmt/admin-state` as the instance name. Two lines about ONE
// instance would then land under two different keys, and a secured instance
// would stop clearing itself (or, worse, clear a bare one).
func TestSRLinuxMultiInstanceGroupingSurvivesEverySpelling(t *testing.T) {
	for _, sp := range srlSpellings {
		mixed := renderSRLConfig([]srlStmt{
			{[]string{"system", "grpc-server", "mgmt", "admin-state"}, "enable"},
			{[]string{"system", "grpc-server", "mgmt", "tls-profile"}, "p1"},
			{[]string{"system", "grpc-server", "insecure-mgmt", "admin-state"}, "enable"},
		}, sp.lead, sp.sep)
		r := srlInsecureGRPC(hardening.NewConfig(hardening.VendorSRLinux, mixed))
		if !r.Tripped {
			t.Errorf("%s: the bare gRPC instance was not detected: %q", sp.name, r.Evidence)
			continue
		}
		// The evidence must name the bare instance and ONLY the bare instance —
		// by its own name, not by a path fragment.
		if !strings.Contains(r.Evidence, "insecure-mgmt") || strings.Contains(r.Evidence, "admin-state") {
			t.Errorf("%s: evidence must name the bare instance by name, got %q", sp.name, r.Evidence)
		}
		if strings.Contains(r.Evidence, "mgmt,") {
			t.Errorf("%s: the TLS-bound instance was reported as bare: %q", sp.name, r.Evidence)
		}

		// The same for accounts: the finding names the account the same way
		// whichever spelling the device wrote, and never quotes the secret.
		users := renderSRLConfig([]srlStmt{
			{[]string{"system", "aaa", "authentication", "admin-user", "password"}, "$y$REDACTED"},
			{[]string{"system", "aaa", "authentication", "user", "field-tech", "password"}, "PlaintextPlaceholder1"},
		}, sp.lead, sp.sep)
		ur := srlWeakLocalSecret(hardening.NewConfig(hardening.VendorSRLinux, users))
		if !ur.Tripped {
			t.Errorf("%s: the cleartext list user was not detected: %q", sp.name, ur.Evidence)
			continue
		}
		for _, want := range []string{"user field-tech", "2 local account(s) examined"} {
			if !strings.Contains(ur.Evidence, want) {
				t.Errorf("%s: evidence %q is missing %q", sp.name, ur.Evidence, want)
			}
		}
		if strings.Contains(ur.Evidence, "PlaintextPlaceholder1") {
			t.Errorf("%s: evidence quoted the stored secret: %q", sp.name, ur.Evidence)
		}
	}
}
