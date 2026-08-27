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
