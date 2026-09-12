// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// learning_test.go — the properties the learning backlog must not lose.
//
// The list is short and every item is something an operator would be misled by
// if it broke:
//   1. a command a parser READ is not a gap, and a command that ERRORED is not
//      one either — the backlog is about recognition, not connectivity;
//   2. the three gap kinds are three different work items and stay distinct;
//   3. a secret in unrecognised output never reaches the record;
//   4. the record is bounded, and says so when a ceiling cut it;
//   5. a collection with no gaps is still filed — "fully recognised" is the
//      denominator, and dropping it makes the backlog a list with no scale.

import (
	"strings"
	"testing"
	"time"

	"netops/backend/internal/showparse"
)

func learnTime() time.Time { return time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC) }

// iosXEBGPSummary is real-shaped IOS-XE output the library parses.
const iosXEBGPSummary = `BGP router identifier 10.0.0.1, local AS number 65001
Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65002    1204    1198       17    0    0 02:14:33            42
`

func TestObserveCaptureSeparatesRecognitionFromCollection(t *testing.T) {
	capt := &Capture{
		TenantID: "acme", IncidentID: "inc-1", DeviceID: "d1",
		Hostname: "leaf1", Platform: "Cisco IOS-XE 17.9", Dialect: "cisco-iosxe",
		ClassID: "bgp-session",
		Commands: []CollectedCommand{
			// read by a parser → not a gap
			{Intent: "bgp.summary", Command: "show ip bgp summary", Output: iosXEBGPSummary, Bytes: len(iosXEBGPSummary)},
			// errored → not a gap: nothing was read, so nothing failed to be read
			{Intent: "ospf.neighbors", Command: "show ip ospf neighbor", Err: "connection reset"},
			// empty output → not a gap for the same reason
			{Intent: "arp.table", Command: "show ip arp", Output: "   \n"},
			// no parser is authored for this concept at all
			{Intent: "ospf.database", Command: "show ip ospf database", Output: "OSPF Router with ID (10.0.0.1)", Bytes: 30},
			// a parser exists for the concept but cannot read this text
			{Intent: "interface.detail", Command: "show interfaces Gi1", Output: "%% Invalid input detected at '^' marker.", Bytes: 39},
		},
	}
	rec := ObserveCapture(capt, "lr-1", learnTime())

	if rec.TenantID != "acme" || rec.IncidentID != "inc-1" || rec.Dialect != "cisco-iosxe" {
		t.Fatalf("record did not carry its subject: %+v", rec)
	}
	if rec.Commands != 5 {
		t.Fatalf("commands = %d, want 5", rec.Commands)
	}
	if rec.Recognised != 1 {
		t.Fatalf("recognised = %d, want 1 (the BGP summary)", rec.Recognised)
	}
	byIntent := map[string]Gap{}
	for _, g := range rec.Gaps {
		byIntent[g.Intent] = g
	}
	if len(rec.Gaps) != 2 {
		t.Fatalf("gaps = %d (%v), want 2 — an errored or empty command is not a recognition gap", len(rec.Gaps), byIntent)
	}
	if g := byIntent["ospf.database"]; g.Kind != GapNoParser {
		t.Fatalf("ospf.database kind = %q, want %q", g.Kind, GapNoParser)
	}
	if g := byIntent["interface.detail"]; g.Kind != GapUnparsed {
		t.Fatalf("interface.detail kind = %q, want %q", g.Kind, GapUnparsed)
	} else if strings.TrimSpace(g.Reason) == "" {
		t.Fatal("an unparsed gap must carry the parser's reason — 'it did not work' is not a work item")
	}
	if _, bad := byIntent["bgp.summary"]; bad {
		t.Fatal("a command a parser READ was recorded as a gap")
	}
	if _, bad := byIntent["ospf.neighbors"]; bad {
		t.Fatal("a command that ERRORED was recorded as a recognition gap")
	}
}

func TestObserveCaptureUnknownPlatformIsADialectGapNotAParserGap(t *testing.T) {
	capt := &Capture{
		TenantID: "acme", IncidentID: "inc-2", Platform: "Nokia SR Linux 24.3", Dialect: "nokia-srlinux",
		Commands: []CollectedCommand{
			{Intent: "bgp.summary", Command: "show network-instance default protocols bgp neighbor", Output: "peer 10.0.0.2 established", Bytes: 25},
		},
	}
	rec := ObserveCapture(capt, "lr-2", learnTime())
	if len(rec.Gaps) != 1 || rec.Gaps[0].Kind != GapNoDialect {
		t.Fatalf("gaps = %+v, want one no_dialect gap — a bound concept on an unauthored platform is a DIALECT gap, "+
			"and calling it no_parser would send someone to write a parser that already exists", rec.Gaps)
	}
}

func TestObserveCaptureRedactsTheExcerpt(t *testing.T) {
	secret := "Building configuration...\nsnmp-server community s3cr3t-community RO\nusername admin password 0 hunter2\n"
	capt := &Capture{
		TenantID: "acme", IncidentID: "inc-3", Platform: "Cisco IOS-XE 17.9", Dialect: "cisco-iosxe",
		Commands: []CollectedCommand{
			{Intent: "config.running", Command: "show running-config", Output: secret, Bytes: len(secret)},
		},
	}
	rec := ObserveCapture(capt, "lr-3", learnTime())
	if len(rec.Gaps) != 1 {
		t.Fatalf("gaps = %d, want 1", len(rec.Gaps))
	}
	ex := rec.Gaps[0].Excerpt
	for _, leak := range []string{"s3cr3t-community", "hunter2"} {
		if strings.Contains(ex, leak) {
			t.Fatalf("the excerpt leaked %q — everything stored is redacted, twice:\n%s", leak, ex)
		}
	}
	if !strings.Contains(ex, "Building configuration") {
		t.Fatalf("redaction removed the whole excerpt; the work item needs the shape of the output:\n%s", ex)
	}
}

func TestObserveCaptureIsBoundedAndSaysSo(t *testing.T) {
	cmds := make([]CollectedCommand, 0, MaxGapsPerRecord+5)
	for i := 0; i < MaxGapsPerRecord+5; i++ {
		cmds = append(cmds, CollectedCommand{
			Intent: "ospf.database", Command: "show ip ospf database " + itoaTAC(i),
			Output: strings.Repeat("x", 8<<10), Bytes: 8 << 10,
		})
	}
	rec := ObserveCapture(&Capture{TenantID: "acme", Platform: "Cisco IOS-XE 17.9", Commands: cmds}, "lr-4", learnTime())
	if len(rec.Gaps) != MaxGapsPerRecord {
		t.Fatalf("gaps = %d, want the ceiling %d", len(rec.Gaps), MaxGapsPerRecord)
	}
	if !rec.Truncated {
		t.Fatal("a record cut by the ceiling must say so; a partial record that reads as complete is the silent-failure shape")
	}
	for _, g := range rec.Gaps {
		if len(g.Excerpt) > maxExcerptBytes {
			t.Fatalf("excerpt is %d bytes, over the %d ceiling", len(g.Excerpt), maxExcerptBytes)
		}
		if g.Bytes != 8<<10 {
			t.Fatalf("Bytes = %d — the FULL size must survive the excerpt, or a clipped answer reads as a tiny one", g.Bytes)
		}
	}
}

func TestObserveCaptureFilesAFullyRecognisedCollection(t *testing.T) {
	rec := ObserveCapture(&Capture{
		TenantID: "acme", IncidentID: "inc-5", Platform: "Cisco IOS-XE 17.9", Dialect: "cisco-iosxe",
		Commands: []CollectedCommand{{Intent: "bgp.summary", Command: "show ip bgp summary", Output: iosXEBGPSummary}},
	}, "lr-5", learnTime())
	if rec.ID == "" || rec.Commands != 1 || rec.Recognised != 1 {
		t.Fatalf("a fully recognised collection must still produce a record: %+v", rec)
	}
	if len(rec.Gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", rec.Gaps)
	}
	if got := rec.GapCounts(); got[GapNoParser] != 0 || got[GapUnparsed] != 0 || got[GapNoDialect] != 0 {
		t.Fatalf("GapCounts = %v, want every kind present and zero", got)
	}
}

func TestObserveCaptureNilIsTheZeroRecord(t *testing.T) {
	if rec := ObserveCapture(nil, "lr-6", learnTime()); rec.ID != "" || len(rec.Gaps) != 0 {
		t.Fatalf("a collection that did not happen must not invent a backlog entry: %+v", rec)
	}
}

func TestEveryBoundIntentResolvesToAKnownParser(t *testing.T) {
	known := map[string]bool{}
	for _, c := range showparse.Commands() {
		known[c] = true
	}
	for intent, cmd := range intentParsers {
		if !known[cmd] {
			t.Errorf("intent %q binds parser concept %q, which internal/showparse does not have — "+
				"a binding to a parser that does not exist would report a gap as recognised", intent, cmd)
		}
		if !intentRE.MatchString(intent) {
			t.Errorf("intent %q is not an intent id", intent)
		}
	}
}
