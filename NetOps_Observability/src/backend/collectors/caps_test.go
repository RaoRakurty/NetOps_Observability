// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"strings"
	"testing"
)

// caps_test.go — the bound on untrusted device strings (audit PIPE-MED-8/9/11).
//
// Every test here asserts the SAME two-part contract, because a cap that mangles
// ordinary data is as much a defect as no cap at all:
//
//	1. a hostile / oversize / high-cardinality input is BOUNDED, and
//	2. a NORMAL value passes through completely unchanged.

// ---- the string primitives -------------------------------------------------

func TestSanitizeLabelBoundsHostileInputAndPreservesNormalOnes(t *testing.T) {
	normal := []string{
		"GigabitEthernet0/0/1",
		"WAN-to-AWS Circuit ID 7Y-XYZ",
		"core-sw-01.dc1",
		"ISR4331/K9",
		"",
	}
	for _, s := range normal {
		if got := sanitizeLabel(s); got != s {
			t.Errorf("sanitizeLabel(%q) = %q — a legitimate label must pass through unchanged", s, got)
		}
	}

	// A device (or an attacker forging one) sends 64 KB in an ifAlias. Unbounded,
	// this becomes a 64 KB VictoriaMetrics LABEL VALUE on every interface series.
	hostile := strings.Repeat("A", 64*1024)
	got := sanitizeLabel(hostile)
	if len([]rune(got)) != maxLabelChars {
		t.Fatalf("sanitizeLabel(64KB) kept %d runes, want the %d-rune cap",
			len([]rune(got)), maxLabelChars)
	}

	// Control characters corrupt a Prometheus exposition line and a log record.
	if got := sanitizeLabel("Gi0/0\r\n\tup\x00down"); got != "Gi0/0 up down" {
		t.Errorf("sanitizeLabel did not scrub control chars: %q", got)
	}

	// Idempotent: capping an already-capped value must be a no-op, or a replayed
	// value would drift on every pass.
	once := sanitizeLabel(hostile)
	if twice := sanitizeLabel(once); twice != once {
		t.Error("sanitizeLabel is not idempotent")
	}
}

func TestSanitizeTextIsLooserThanLabelButStillBounded(t *testing.T) {
	// A real Cisco sysDescr is ~200-400 chars and must survive intact.
	descr := "Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), " +
		"Version 16.09.04, RELEASE SOFTWARE (fc2) Technical Support: http://www.cisco.com/techsupport " +
		"Copyright (c) 1986-2019 by Cisco Systems, Inc. Compiled Thu 22-Aug-19 18:09 by mcpre"
	if len(descr) <= maxLabelChars {
		t.Fatalf("test fixture is too short to prove the point (%d chars)", len(descr))
	}
	if got := sanitizeText(descr); got != descr {
		t.Errorf("sanitizeText mangled a legitimate sysDescr:\n got %q\nwant %q", got, descr)
	}
	if got := sanitizeText(strings.Repeat("B", 1<<16)); len([]rune(got)) != maxTextChars {
		t.Errorf("sanitizeText(64KB) kept %d runes, want %d", len([]rune(got)), maxTextChars)
	}
}

func TestClampRunesNeverSplitsAMultiByteCharacter(t *testing.T) {
	// A torn UTF-8 sequence is exactly what an OpenSearch mapping rejects, so the
	// bound is on runes, not bytes.
	s := strings.Repeat("é", 200) // 2 bytes each
	got := clampRunes(s, 10)
	if got != strings.Repeat("é", 10) {
		t.Fatalf("clampRunes cut mid-codepoint: %q", got)
	}
	if !isValidUTF8(got) {
		t.Fatal("clampRunes produced invalid UTF-8")
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

// ---- the trap path ---------------------------------------------------------

// buildTrapWithNVarbinds forges an SNMPv2c trap carrying n extra varbinds beyond
// the mandatory sysUpTime.0/snmpTrapOID.0 pair — the shape of the ~10k-varbind
// packet that fits in one 65 KB UDP datagram.
func buildTrapWithNVarbinds(n int, payload []byte) []byte {
	sysUpTime := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	snmpTrapOIDArcs := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	linkDown := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	ifIndex := []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2}

	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	vbs := vb(sysUpTime, berTLV(0x43, []byte{0, 1, 0, 0}))
	vbs = append(vbs, vb(snmpTrapOIDArcs, berOID(linkDown))...)
	for i := 0; i < n; i++ {
		if payload != nil {
			vbs = append(vbs, vb(ifIndex, berTLV(0x04, payload))...)
		} else {
			vbs = append(vbs, vb(ifIndex, berInt(i))...)
		}
	}
	pduBody := berInt(42)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berTLV(0x30, vbs)...)
	msg := berInt(1)
	msg = append(msg, berTLV(0x04, []byte("public"))...)
	msg = append(msg, berTLV(0xA7, pduBody)...)
	return berTLV(0x30, msg)
}

func TestTrapVarbindCountIsBoundedAndTheDropIsRecorded(t *testing.T) {
	const sent = 5000
	ev, err := decodeTrap(buildTrapWithNVarbinds(sent, nil), "10.0.0.9", nil)
	if err != nil {
		t.Fatalf("decodeTrap: %v", err)
	}
	if len(ev.Varbinds) > maxTrapVarbinds {
		t.Fatalf("kept %d varbinds, want at most the %d cap", len(ev.Varbinds), maxTrapVarbinds)
	}
	// The bound must be OBSERVABLE — a truncated trap that looks complete is the
	// silent-failure defect the guards exist for (CLAUDE.md §10).
	if !ev.Truncated {
		t.Error("a truncated trap did not set Truncated — the cut is invisible to the operator")
	}
	if ev.VarbindsDropped == 0 {
		t.Error("VarbindsDropped is 0 after dropping thousands of varbinds")
	}
	if got, want := ev.VarbindsDropped+len(ev.Varbinds), sent; got != want {
		// snmpTrapOID.0 is consumed into TrapOID, sysUpTime.0 stays a varbind.
		if got != want+1 {
			t.Errorf("kept+dropped = %d, want %d (the count must be honest)", got, want)
		}
	}
	if len(ev.Message) > maxTrapMessageChars {
		t.Errorf("ev.Message is %d chars, want at most %d", len(ev.Message), maxTrapMessageChars)
	}
	if ev.TrapName != "linkDown" {
		t.Errorf("truncation broke normal decoding: TrapName = %q", ev.TrapName)
	}
}

func TestTrapVarbindValueLengthIsBounded(t *testing.T) {
	// One 60 KB non-printable OCTET STRING: valStr hex-doubles it to ~120 KB,
	// which finalizeTrap then concatenated into ev.Message verbatim.
	payload := make([]byte, 60*1024)
	for i := range payload {
		payload[i] = 0xFF // non-printable → the hex branch
	}
	ev, err := decodeTrap(buildTrapWithNVarbinds(1, payload), "10.0.0.9", nil)
	if err != nil {
		t.Fatalf("decodeTrap: %v", err)
	}
	for _, vb := range ev.Varbinds {
		if len([]rune(vb.Value)) > maxVarbindValueChars+2 { // +2 for the "0x" prefix
			t.Fatalf("varbind value is %d chars, want at most %d",
				len([]rune(vb.Value)), maxVarbindValueChars+2)
		}
	}
	if len([]rune(ev.Message)) > maxTrapMessageChars {
		t.Fatalf("ev.Message is %d runes, want at most %d", len([]rune(ev.Message)), maxTrapMessageChars)
	}
}

func TestOrdinaryTrapIsUntouchedByTheCaps(t *testing.T) {
	ev, err := decodeTrap(buildV2cTrap("public"), "10.0.0.9", nil)
	if err != nil {
		t.Fatalf("decodeTrap: %v", err)
	}
	if ev.Truncated || ev.VarbindsDropped != 0 {
		t.Errorf("a 3-varbind trap was marked truncated (%v/%d) — the cap is firing on normal data",
			ev.Truncated, ev.VarbindsDropped)
	}
	if ev.TrapName != "linkDown" {
		t.Errorf("TrapName = %q, want linkDown", ev.TrapName)
	}
	if !strings.Contains(ev.Message, "linkDown") {
		t.Errorf("Message lost its content: %q", ev.Message)
	}
}

func TestClampOIDCutsAtAnArcBoundary(t *testing.T) {
	// A normal OID is untouched.
	const real = "1.3.6.1.6.3.1.1.5.3"
	if got := clampOID(real); got != real {
		t.Errorf("clampOID(%q) = %q", real, got)
	}
	// A hostile OID with hundreds of arcs is cut, and never mid-arc: a partial
	// arc would silently RENAME the object.
	long := "1.3.6.1.4.1.9" + strings.Repeat(".12345", 200)
	got := clampOID(long)
	if len(got) > maxTrapOIDChars {
		t.Fatalf("clampOID left %d chars, want at most %d", len(got), maxTrapOIDChars)
	}
	if strings.HasSuffix(got, ".") {
		t.Fatalf("clampOID left a trailing dot: %q", got)
	}
	for _, arc := range strings.Split(got, ".") {
		if arc == "" {
			t.Fatalf("clampOID produced an empty arc: %q", got)
		}
	}
	if !strings.HasPrefix(long, got) {
		t.Fatalf("clampOID(%q…) = %q is not a prefix of the input", long[:40], got)
	}
}

// ---- the SNMP value decoder ------------------------------------------------

func TestBerValStrIsBoundedForEveryCaller(t *testing.T) {
	// berVal.str() feeds CDP/LLDP neighbour names, ifName/ifDescr and
	// sysName/sysDescr. Capping at the decoder is what makes a NEW caller inherit
	// the bound instead of having to remember it.
	v := berVal{tag: 0x04, raw: []byte(strings.Repeat("x", 64*1024))}
	if got := v.str(); len([]rune(got)) != maxTextChars {
		t.Fatalf("berVal.str() returned %d runes for a 64KB OCTET STRING, want %d",
			len([]rune(got)), maxTextChars)
	}
	normal := berVal{tag: 0x04, raw: []byte("Ethernet1/1")}
	if got := normal.str(); got != "Ethernet1/1" {
		t.Errorf("berVal.str() mangled a normal value: %q", got)
	}
}
