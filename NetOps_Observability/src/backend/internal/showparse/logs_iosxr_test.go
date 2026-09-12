// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// logs_iosxr_test.go — the IOS-XR four-part syslog tag.
//
// XR's documented message format is "%<category>-<group>-<severity>-<message
// code>", one part longer than the IOS "%FACILITY-SEVERITY-MNEMONIC" the shared
// parser was written for. A three-way split reads "LINK" as the severity, which
// is not a number, so every line in an XR log buffer was dropped without a note
// — a whole dialect's log evidence silently absent.

import "testing"

// ciscoXRLogging is a real-shaped IOS-XR `show logging` buffer: XR's own line
// prefix, its " : " separator before the message, and four-part tags.
const ciscoXRLogging = `Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)
Log Buffer (16384 bytes):

RP/0/RSP0/CPU0:Sep  2 09:58:12.345 UTC: ifmgr[257]: %PKT_INFRA-LINK-3-UPDOWN : Interface GigabitEthernet0/0/0/1, changed state to Down
RP/0/RSP0/CPU0:Sep  2 09:58:12.350 UTC: ifmgr[257]: %PKT_INFRA-LINEPROTO-5-UPDOWN : Line protocol on Interface GigabitEthernet0/0/0/1, changed state to Down
RP/0/RSP0/CPU0:Sep  2 09:58:13.001 UTC: bgp[1046]: %ROUTING-BGP-5-ADJCHANGE : neighbor 10.0.0.2 Down - BGP Notification sent
`

func TestParseCiscoSyslog_IOSXRFourPartTag(t *testing.T) {
	res := mustParse(t, CmdLogs, DialectCiscoIOSXR, ciscoXRLogging)
	if len(res.Logs) != 3 {
		t.Fatalf("got %d lines, want 3 — an XR log buffer must not be silently dropped", len(res.Logs))
	}

	// The sub-group is kept, so a link down and a line-protocol down remain
	// distinguishable in Facility.
	wantStrP(t, "Facility", res.Logs[0].Facility, "PKT_INFRA-LINK")
	wantIntP(t, "Severity", res.Logs[0].Severity, 3)
	wantStrP(t, "Mnemonic", res.Logs[0].Mnemonic, "UPDOWN")
	if got := res.Logs[0].Message; got != "Interface GigabitEthernet0/0/0/1, changed state to Down" {
		t.Errorf("Message = %q", got)
	}

	wantStrP(t, "Facility", res.Logs[1].Facility, "PKT_INFRA-LINEPROTO")
	wantIntP(t, "Severity", res.Logs[1].Severity, 5)
	wantStrP(t, "Mnemonic", res.Logs[1].Mnemonic, "UPDOWN")

	wantStrP(t, "Facility", res.Logs[2].Facility, "ROUTING-BGP")
	wantIntP(t, "Severity", res.Logs[2].Severity, 5)
	wantStrP(t, "Mnemonic", res.Logs[2].Mnemonic, "ADJCHANGE")
}

// TestParseCiscoSyslog_ThreePartTagUnchanged is the no-regression half: the IOS
// buffer must parse byte-for-byte as it did before the four-part shape existed,
// including under the XR dialect (the parser is shared).
func TestParseCiscoSyslog_ThreePartTagUnchanged(t *testing.T) {
	res := mustParse(t, CmdLogs, DialectCiscoIOS, ciscoLogging)
	if len(res.Logs) != 3 {
		t.Fatalf("got %d lines, want 3", len(res.Logs))
	}
	wantStrP(t, "Facility", res.Logs[0].Facility, "OSPF")
	wantIntP(t, "Severity", res.Logs[0].Severity, 5)
	wantStrP(t, "Mnemonic", res.Logs[0].Mnemonic, "ADJCHG")
	wantStrP(t, "Timestamp", res.Logs[0].Timestamp, "Sep  2 09:58:12.345")
	wantStrP(t, "Facility", res.Logs[1].Facility, "LINK")
	wantIntP(t, "Severity", res.Logs[1].Severity, 3)
	wantStrP(t, "Mnemonic", res.Logs[1].Mnemonic, "UPDOWN")
	wantStrP(t, "Facility", res.Logs[2].Facility, "LINEPROTO")
	wantIntP(t, "Severity", res.Logs[2].Severity, 5)
	wantStrP(t, "Mnemonic", res.Logs[2].Mnemonic, "UPDOWN")
}

// TestSplitCiscoSyslogTag_Precedence locks the ordering rule down directly: the
// three-way split wins whenever its middle token is a severity, so a THREE-part
// tag carrying a dash inside its mnemonic keeps the whole mnemonic instead of
// being re-read as an XR four-part tag.
func TestSplitCiscoSyslogTag_Precedence(t *testing.T) {
	cases := []struct {
		tag      string
		facility string
		sev      int64
		mnemonic string
		ok       bool
	}{
		{"LINK-3-UPDOWN", "LINK", 3, "UPDOWN", true},
		// Three parts with a dashed mnemonic: unchanged, NOT re-split.
		{"OSPF-5-ADJCHG-EXTRA", "OSPF", 5, "ADJCHG-EXTRA", true},
		{"PKT_INFRA-LINK-3-UPDOWN", "PKT_INFRA-LINK", 3, "UPDOWN", true},
		// Four parts whose third token is not a severity stays dropped.
		{"A-B-C-D", "", 0, "", false},
		// Severity out of the 0-7 syslog range is dropped in both shapes.
		{"LINK-9-UPDOWN", "", 0, "", false},
		{"PKT_INFRA-LINK-9-UPDOWN", "", 0, "", false},
		// Empty components are dropped.
		{"PKT_INFRA-LINK-3-", "", 0, "", false},
		{"-3-UPDOWN", "", 0, "", false},
		{"NOSEVERITY", "", 0, "", false},
	}
	for _, tc := range cases {
		fac, sev, mn, ok := splitCiscoSyslogTag(tc.tag)
		if ok != tc.ok || fac != tc.facility || sev != tc.sev || mn != tc.mnemonic {
			t.Errorf("splitCiscoSyslogTag(%q) = (%q,%d,%q,%v), want (%q,%d,%q,%v)",
				tc.tag, fac, sev, mn, ok, tc.facility, tc.sev, tc.mnemonic, tc.ok)
		}
	}
}
