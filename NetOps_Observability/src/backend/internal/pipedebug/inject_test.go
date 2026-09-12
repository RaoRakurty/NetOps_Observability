// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

func TestValidDeviceKeyIsAClosedGrammar(t *testing.T) {
	for _, ok := range []string{"spine1", "core-rtr-01", "edge_1.lab", "10.0.0.1", "fe80::1"} {
		if err := ValidDeviceKey(ok); err != nil {
			t.Errorf("ValidDeviceKey(%q) rejected a legal device: %v", ok, err)
		}
	}
	// A space or newline in a device key would let a caller forge extra
	// structure inside the syslog frame it is written into.
	for _, bad := range []string{"", "  ", "spine 1", "spine1\nfake line", "a<b>", strings.Repeat("x", 200)} {
		if err := ValidDeviceKey(bad); err == nil {
			t.Errorf("ValidDeviceKey(%q) accepted an injectable device key", bad)
		}
	}
}

func TestSyslogFrameIsRFC5424AndCarriesBothTags(t *testing.T) {
	m := "01j9abcdefghjkmnpqrstvwxyz"
	frame := BuildSyslogFrame(m, "spine1", time.Date(2026, 9, 4, 11, 5, 6, 0, time.UTC))
	if !strings.HasPrefix(frame, "<134>1 2026-09-04T11:05:06.000000Z spine1 correlix-debug - - - ") {
		t.Errorf("frame header is not the RFC5424 shape: %q", frame)
	}
	if !strings.Contains(frame, MarkerTag(m)) {
		t.Error("the frame carries no marker")
	}
	if !strings.Contains(frame, SyntheticTag) {
		t.Error("the frame is not tagged synthetic — it would be indistinguishable from device traffic in the UI")
	}
	if strings.Count(frame, "\n") != 0 {
		t.Error("the frame contains a newline, which would split it into two syslog records")
	}
}

// The trap PDU must be well-formed BER, and its trap OID must NOT be a real
// notification: a probe that decodes as coldStart or linkDown would be reasoned
// about by the correlation engine as if it were a real event.
func TestTrapPDUIsWellFormedAndUsesTheExperimentalArc(t *testing.T) {
	m := "01j9abcdefghjkmnpqrstvwxyz"
	pdu, err := BuildTrapPDU(m, "spine1", "public", time.Date(2026, 9, 4, 11, 5, 6, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildTrapPDU: %v", err)
	}
	// Structural check: the outer value must parse as a SEQUENCE covering the
	// whole buffer (a bad length octet would leave trailing bytes).
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(pdu, &outer)
	if err != nil {
		t.Fatalf("the PDU is not decodable BER: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes after the outer SEQUENCE — the length encoding is wrong", len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		t.Errorf("outer value is not a SEQUENCE: class=%d tag=%d", outer.Class, outer.Tag)
	}
	// version (v2c == 1) and the community are the first two members.
	var version int
	body, err := asn1.Unmarshal(outer.Bytes, &version)
	if err != nil || version != 1 {
		t.Fatalf("version field: %v (%v) — v2c must encode as 1", version, err)
	}
	var community []byte
	if _, err := asn1.Unmarshal(body, &community); err != nil || string(community) != "public" {
		t.Fatalf("community field: %q (%v)", community, err)
	}
	text := string(pdu)
	if !strings.Contains(text, MarkerTag(m)) || !strings.Contains(text, SyntheticTag) {
		t.Error("the trap carries no marker/synthetic varbind")
	}
	// 1.3.6.1.3 = the IANA EXPERIMENTAL arc, encoded 0x2b 0x06 0x01 0x03.
	if !strings.Contains(text, "\x2b\x06\x01\x03") {
		t.Error("the trap OID is not under the experimental arc — a probe must not decode as a real notification")
	}
	if strings.Contains(text, "\x2b\x06\x01\x06\x03\x01\x01\x05") {
		t.Error("the trap OID is under the SNMPv2-MIB generic-trap subtree (coldStart/linkDown live there)")
	}
}

func TestTrapPDURefusesAMalformedDeviceOrMarker(t *testing.T) {
	now := time.Now()
	if _, err := BuildTrapPDU("01j9abcdefghjkmnpqrstvwxyz", "bad device", "", now); err == nil {
		t.Error("an injectable device key reached the PDU encoder")
	}
	if _, err := BuildTrapPDU("nope", "spine1", "", now); err == nil {
		t.Error("a malformed marker reached the PDU encoder")
	}
}

func TestMarkerPayloadIsIdenticalForEveryKind(t *testing.T) {
	m := "01j9abcdefghjkmnpqrstvwxyz"
	frame := BuildSyslogFrame(m, "spine1", time.Now())
	pdu, err := BuildTrapPDU(m, "spine1", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload := MarkerPayload(m)
	if !strings.Contains(frame, payload) || !strings.Contains(string(pdu), payload) {
		t.Error("the two kinds carry different marker payloads — one grep must find a probe in any store")
	}
}

func TestSendUDPRefusesAnEmptyTarget(t *testing.T) {
	if err := SendUDP("", []byte("x"), time.Second); err == nil {
		t.Error("SendUDP accepted an empty target — it would have to guess a host")
	}
}
