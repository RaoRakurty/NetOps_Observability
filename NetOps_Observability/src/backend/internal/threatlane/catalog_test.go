// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package threatlane

import (
	"testing"
	"time"

	"netops/backend/internal/secfindings"
)

// firedLogRules returns the set of device-log rule IDs that trip for ev.
func firedLogRules(cat *Catalog, ev LogEvent) map[string]DetectResult {
	out := map[string]DetectResult{}
	for _, r := range cat.LogRules() {
		if res := r.Detect(ev); res.Tripped {
			out[r.ID] = res
		}
	}
	return out
}

// A weekday, mid-morning — inside the default business window.
var inHours = time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) // Wed 10:00
// A weekend, small hours — outside the window.
var offHrs = time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC) // Sat 02:00

func TestDeviceLogRules_TripAndTechnique(t *testing.T) {
	cat := DefaultCatalog()
	cases := []struct {
		name      string
		ev        LogEvent
		wantRule  string
		technique string
	}{
		{"logging disabled", LogEvent{Mnemonic: "SYS-6-LOGGINGHOST_STARTSTOP", Message: "no logging host 10.1.1.9"}, "log-logging-disabled", "T1562.001"},
		{"log cleared", LogEvent{Mnemonic: "SYS-5-CLEAR", Message: "clear logging by admin"}, "log-buffer-cleared", "T1070"},
		{"offhours config change", LogEvent{Mnemonic: "SYS-5-CONFIG_I", Message: "Configured from console by op", Time: offHrs}, "log-offhours-config-change", "T1059.008"},
		{"new local user", LogEvent{Mnemonic: "PARSER-5-CFGLOG_LOGGEDCMD", Message: "username svcbackdoor password 7 070C285F"}, "log-new-local-user", "T1136.001"},
		{"privilege escalation", LogEvent{Mnemonic: "PARSER-5-CFGLOG_LOGGEDCMD", Message: "aaa attribute privilege 15 for guest"}, "log-privilege-escalation", "T1098"},
		{"gre tunnel", LogEvent{Mnemonic: "LINK-3-UPDOWN", Message: "interface Tunnel0 created, tunnel mode gre ip"}, "log-gre-tunnel", "T1572"},
		{"aaa tampering", LogEvent{Mnemonic: "PARSER-5-CFGLOG_LOGGEDCMD", Message: "aaa authentication login default none"}, "log-aaa-tampering", "T1556"},
		{"boot image change", LogEvent{Mnemonic: "PARSER-5-CFGLOG_LOGGEDCMD", Message: "boot system flash bootflash:rogue.bin"}, "log-boot-image-change", "T1601"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedLogRules(cat, tc.ev)
			if _, ok := fired[tc.wantRule]; !ok {
				t.Fatalf("rule %s did not fire for %+v (fired: %v)", tc.wantRule, tc.ev, keys(fired))
			}
			// Assert the fired rule carries the expected technique + a remediation.
			for _, r := range cat.LogRules() {
				if r.ID != tc.wantRule {
					continue
				}
				if r.Technique != tc.technique {
					t.Errorf("rule %s technique=%q want %q", r.ID, r.Technique, tc.technique)
				}
				if r.Remediation == "" {
					t.Errorf("rule %s has no remediation", r.ID)
				}
				if !severityOK(r.Severity) {
					t.Errorf("rule %s severity %q invalid", r.ID, r.Severity)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-DIALECT COVERAGE (tracker D-02).
//
// The catalog's rules were IOS/NX-OS-phrased only, so on the reference lab —
// Nokia SR Linux — every one of the eight log-* rules was structurally silent.
// The 2026-09-03 security-ops run proved it: two syslog lines describing the
// SAME real event were injected at spine1, the IOS-phrased one fired two rules
// and the SR Linux-phrased one fired NONE
// (docs/qa/scenarios/security-ops-2026-09-03.md §1).
//
// This table is the guard against that regressing, in three columns per rule:
//   srlinux  — the SR Linux phrasing that MUST now fire (was the whole defect);
//   legacy   — the Cisco/EOS fixture that must STILL fire (no regression);
//   nearMiss — an ORDINARY-OPERATION line, in the new dialect, that must NOT
//              fire. Widening a rule into a substring match that trips on
//              healthy configuration would trade a silent lane for a noisy one.
// ─────────────────────────────────────────────────────────────────────────────

// The two lines below are REAL captures, quoted verbatim from the 2026-09-03
// security-ops run (docs/qa/scenarios/security-ops-2026-09-03.md §1, injected to
// UDP 514 with HOSTNAME=spine1 and indexed at 04:04:56Z). Password material is
// truncated exactly as the scenario doc truncates it — a fixture never carries a
// full credential (§8).
const (
	// Line A — IOS/NX-OS phrasing. It fired log-new-local-user and
	// log-privilege-escalation on the live run and must keep doing so.
	qaLineAIOS = `%SEC-5-CONFIG: username backdoor privilege 15 secret 5 $1$Qa9L$LabDrillOnly`
	// Line B — the SR Linux native phrasing of the SAME event. It fired NOTHING
	// on the live run. That is D-02.
	qaLineBSRLinux = `User 'admin' committed candidate: set /system aaa authentication user backdoor password $y$j9T$`
)

func TestDeviceLogRules_DialectCoverage(t *testing.T) {
	cat := DefaultCatalog()
	cases := []struct {
		rule     string
		srlinux  string // SR Linux phrasing — MUST fire
		legacy   string // Cisco/EOS phrasing — must still fire
		nearMiss string // ordinary SR Linux operation — must NOT fire
	}{
		{
			rule:    "log-logging-disabled",
			srlinux: "User 'op' committed candidate: delete /system logging remote-server 10.1.1.9",
			legacy:  "no logging host 10.1.1.9",
			// Configuring a remote server is the OPPOSITE act, and dropping
			// console logging is hardening — neither is a tamper.
			nearMiss: "User 'op' committed candidate: set / system logging remote-server 10.1.1.9 remote-port 514",
		},
		{
			rule:     "log-buffer-cleared",
			srlinux:  "tools system logging buffer messages clear",
			legacy:   "clear logging by admin",
			nearMiss: "User 'op' committed candidate: set /system logging buffer messages subsystem aaa priority informational",
		},
		{
			rule:    "log-new-local-user",
			srlinux: qaLineBSRLinux,
			legacy:  qaLineAIOS,
			// An SSH key, not a password, and no new credential material.
			nearMiss: "User 'op' committed candidate: set /system aaa authentication user bob ssh-key [ ssh-rsa AAAAB3 ]",
		},
		{
			rule:    "log-privilege-escalation",
			srlinux: "User 'op' committed candidate: set /system aaa authorization role netops superuser true",
			legacy:  "aaa attribute privilege 15 for guest",
			// Granting an ORDINARY role is routine operation.
			nearMiss: "User 'op' committed candidate: set /system aaa authentication user bob role [ ops ]",
		},
		{
			rule:    "log-gre-tunnel",
			srlinux: "User 'op' committed candidate: set / tunnel-interface gre1 encapsulation gre",
			legacy:  "interface Tunnel0 created, tunnel mode gre ip",
			// EVPN-VXLAN fabric configuration — what the lab spines actually run.
			// This is the false positive the GRE anchor exists to prevent.
			nearMiss: "User 'op' committed candidate: set / tunnel-interface vxlan1 vxlan-interface 1 type bridged",
		},
		{
			rule:    "log-aaa-tampering",
			srlinux: "User 'op' committed candidate: delete /system aaa authentication authentication-method",
			legacy:  "aaa authentication login default none",
			// REMOVING a rogue account is remediation, not tampering, and it sits
			// under the same /system/aaa/authentication prefix.
			nearMiss: "User 'op' committed candidate: delete /system aaa authentication user backdoor",
		},
		{
			rule:     "log-boot-image-change",
			srlinux:  "tools system deploy-image srlinux-26.3.2.bin",
			legacy:   "boot system flash bootflash:rogue.bin",
			nearMiss: "User 'op' committed candidate: set /system boot autoboot admin-state disable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			if _, ok := firedLogRules(cat, LogEvent{Message: tc.srlinux})[tc.rule]; !ok {
				t.Errorf("SR Linux phrasing did not fire %s (D-02 regression): %q", tc.rule, tc.srlinux)
			}
			if _, ok := firedLogRules(cat, LogEvent{Message: tc.legacy})[tc.rule]; !ok {
				t.Errorf("Cisco/EOS phrasing no longer fires %s (regression): %q", tc.rule, tc.legacy)
			}
			if fired := firedLogRules(cat, LogEvent{Message: tc.nearMiss}); len(fired) != 0 {
				t.Errorf("near-miss line tripped %v — ordinary operation must stay silent: %q", keys(fired), tc.nearMiss)
			}
		})
	}
}

// TestOffHoursRule_SRLinuxCommit — the eighth rule. Its dialect axis is time, so
// it needs its own case: SR Linux announces a change ONLY by committing a
// candidate, and an in-hours commit must stay silent exactly as an in-hours
// `Configured from console` does.
func TestOffHoursRule_SRLinuxCommit(t *testing.T) {
	cat := DefaultCatalog()
	const commit = "User 'admin' committed candidate: set / system name host-name spine1"
	if _, ok := firedLogRules(cat, LogEvent{Message: commit, Time: offHrs})["log-offhours-config-change"]; !ok {
		t.Errorf("off-hours SR Linux commit did not fire log-offhours-config-change: %q", commit)
	}
	if fired := firedLogRules(cat, LogEvent{Message: commit, Time: inHours}); len(fired) != 0 {
		t.Errorf("in-hours SR Linux commit tripped %v, want silence", keys(fired))
	}
	// A device-generated line that merely mentions the word "commit" is not a
	// commit announcement.
	const chatter = "gnmi client requested commit confirmed timeout of 30 seconds"
	if fired := firedLogRules(cat, LogEvent{Message: chatter, Time: offHrs}); len(fired) != 0 {
		t.Errorf("non-commit chatter tripped %v, want silence: %q", keys(fired), chatter)
	}
}

// TestQAScenarioLinesBothFire pins the exact defect D-02 measured: line A fired
// two rules, line B fired none. Both lines describe the SAME real-world event —
// a rogue local account created on spine1 — so both must now be detected.
func TestQAScenarioLinesBothFire(t *testing.T) {
	cat := DefaultCatalog()
	firedA := firedLogRules(cat, LogEvent{Mnemonic: "SEC-5-CONFIG", Message: qaLineAIOS})
	for _, want := range []string{"log-new-local-user", "log-privilege-escalation"} {
		if _, ok := firedA[want]; !ok {
			t.Errorf("line A (IOS) no longer fires %s; fired %v", want, keys(firedA))
		}
	}
	firedB := firedLogRules(cat, LogEvent{Message: qaLineBSRLinux})
	if _, ok := firedB["log-new-local-user"]; !ok {
		t.Fatalf("line B (SR Linux) still fires nothing for the account creation — D-02 is NOT fixed; fired %v", keys(firedB))
	}
	// Line B carries no privilege/role grant, so — unlike line A — it must NOT
	// claim one. Honest coverage, not maximal coverage.
	if _, ok := firedB["log-privilege-escalation"]; ok {
		t.Error("line B claimed a privilege escalation it does not describe")
	}
}

func TestDeviceLogRules_NoFalsePositives(t *testing.T) {
	cat := DefaultCatalog()
	benign := []LogEvent{
		{Mnemonic: "LINK-3-UPDOWN", Message: "Interface GigabitEthernet0/1, changed state to up"},
		{Mnemonic: "SYS-5-CONFIG_I", Message: "Configured from console by op", Time: inHours}, // in-hours change: not off-hours
		{Mnemonic: "OSPF-5-ADJCHG", Message: "Process 1, Nbr 10.0.0.2 on Gi0/1 from LOADING to FULL"},
		{Mnemonic: "SEC-6-IPACCESSLOGP", Message: "list 101 permitted tcp 10.0.0.5 -> 10.0.0.9 (443)"},
		{Mnemonic: "SYS-5-HARDEN", Message: "no logging console"}, // hardening best-practice, NOT a tamper
	}
	for _, ev := range benign {
		if fired := firedLogRules(cat, ev); len(fired) != 0 {
			t.Errorf("benign event tripped %v: %+v", keys(fired), ev)
		}
	}
}

func TestOffHoursRule_WindowBoundary(t *testing.T) {
	cat := DefaultCatalog()
	change := func(ts time.Time) LogEvent {
		return LogEvent{Mnemonic: "SYS-5-CONFIG_I", Message: "Configured from console by op", Time: ts}
	}
	if fired := firedLogRules(cat, change(inHours)); len(fired) != 0 {
		t.Errorf("in-hours config change must not trip, got %v", keys(fired))
	}
	if _, ok := firedLogRules(cat, change(offHrs))["log-offhours-config-change"]; !ok {
		t.Error("off-hours config change must trip")
	}
	// A zero event time must NOT trip (cannot prove off-hours → no false positive).
	if _, ok := firedLogRules(cat, change(time.Time{}))["log-offhours-config-change"]; ok {
		t.Error("zero-time config change must not trip the off-hours rule")
	}
}

func TestCatalog_SelfConsistency(t *testing.T) {
	cat := DefaultCatalog()
	if cat.Len() < 4 {
		t.Fatalf("catalog too small: %d", cat.Len())
	}
	seen := map[string]bool{}
	check := func(id, tech, sev string, verdict secfindings.StatusID, rem string) {
		if id == "" || seen[id] {
			t.Errorf("rule id empty or duplicate: %q", id)
		}
		seen[id] = true
		if tech == "" {
			t.Errorf("rule %s has no MITRE technique", id)
		}
		if !severityOK(sev) {
			t.Errorf("rule %s severity %q invalid", id, sev)
		}
		if verdict != secfindings.StatusFail && verdict != secfindings.StatusWarning {
			t.Errorf("rule %s verdict %v is not Fail/Warning", id, verdict)
		}
		if rem == "" {
			t.Errorf("rule %s has no remediation", id)
		}
	}
	for _, r := range cat.LogRules() {
		check(r.ID, r.Technique, r.Severity, r.Verdict, r.Remediation)
	}
	for _, r := range cat.PairRules() {
		check(r.ID, r.Technique, r.Severity, r.Verdict, r.Remediation)
	}
	for _, r := range cat.SourceRules() {
		check(r.ID, r.Technique, r.Severity, r.Verdict, r.Remediation)
	}
	techs := cat.sortedTechniques()
	t.Logf("catalog: %d rules, %d MITRE techniques: %v", cat.Len(), len(techs), techs)
}

func keys(m map[string]DetectResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRealSRLinuxLabLogsStaySilent is the noise half of the D-02 fix. Extending
// eight rules onto a new dialect is only half a win: if the new clauses trip on
// what the platform emits all day, a silent lane becomes a noisy one and the
// operator learns to ignore it.
//
// Every line below is a REAL, verbatim SR Linux message read out of the lab's
// own syslog index (netops-syslog-t_d3d5…-2026.09.03, spine1/spine2, appname +
// body as indexed) on 2026-09-03. None of them describes a security event, so
// none may fire a rule. The `sr_cli` parse-error line is deliberately included:
// it is the device's reply to the SR OS commands the wrong CLI dialect sent it
// (tracker D-2), it enumerates SR Linux's real top-level tokens — including
// `system`, `tunnel` and `tunnel-interface` — and it came back through syslog as
// "evidence", so it is precisely the line most likely to trip a careless path
// regexp.
func TestRealSRLinuxLabLogsStaySilent(t *testing.T) {
	cat := DefaultCatalog()
	real := []struct{ appname, body string }{
		{"sr_grpc_server", `debug|5290|5290|2539845|TR||W: common    grpc_server_instance.cc:1965 BuildAndStartServer  Unable to retrieve TLS profile 'EDA'`},
		{"sr_license_mgr", `debug|4353|4353|08496|TR||E: licensemgr license_mgr.cc:581     CheckLicenseExpiration  no default license file nor configured license instances, posting license expiry`},
		{"sr_xdp_cpm", `debug|4666|5038|08559|TR||W: csim_pd   csim_platform.cc:2623   UpdateLicenseValidity  No valid license, limiting packet rate to 10000pps`},
		{"sr_aaa_mgr", `aaa|4260|4927|00047|EV|sessionOpened|N: Opened session 221 for user admin from host 10.70.245.122 in network-instance mgmt`},
		{"sr_aaa_mgr", `aaa|4260|4927|00048|EV|userAuthenticationSucceeded|N: User admin on session 221 successfully authenticated from host 10.70.245.122 in network-instance mgmt`},
		{"sr_aaa_mgr", `aaa|4260|4929|00050|EV|sessionClosed|N: Closed session 221 for user admin from host 10.70.245.122 in network-instance mgmt`},
		{"sr_cli", `debug|390596|390596|00001|TR||I: common    |admin|0| Started a new CLI session`},
		{"sr_cli", `debug|390596|390596|00002|TR||I: common    |admin|219| Established connection to AAA server`},
		{"sr_cli", `debug|390596|390596|00003|TR||I: common    |admin|219| Parsing error: Unknown token 'router'. Options are ['#', '/', '>', '>>', 'acl', 'arpnd', 'interface', 'lag', 'network-instance', 'platform', 'qos', 'system', 'tunnel', 'tunnel-interface', 'version', '|']`},
		{"sr_cli", `debug|390596|390596|00004|TR||I: common    |admin|219| Closing the CLI session. Reason quit was requested`},
	}
	for _, ln := range real {
		// SR Linux carries no Cisco-style mnemonic, so Mnemonic is empty exactly
		// as internal/seclane leaves it for this platform.
		ev := LogEvent{Platform: "nokia SR Linux", Message: ln.body, Time: offHrs}
		if fired := firedLogRules(cat, ev); len(fired) != 0 {
			t.Errorf("real %s line tripped %v: %q", ln.appname, keys(fired), ln.body)
		}
	}
}
