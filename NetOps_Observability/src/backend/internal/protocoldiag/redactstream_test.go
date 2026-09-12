// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// redactstream_test.go — the streaming redactor, and the safety proof for the
// prefilter that makes it fast enough to run over a support bundle.
//
// Two properties are load-bearing here and both are asserted rather than
// reasoned about:
//
//  1. The stream produces EXACTLY what the buffered pass produces. Two redactors
//     that could disagree would be worse than one, because the disagreement
//     would show up as a secret in a bundle nobody re-checked.
//  2. The prefilter cannot miss a rule. It is a performance shortcut over
//     customer secrets, so it gets a structural test (every rule's pattern still
//     contains the literals its anchors claim) as well as a behavioural one.

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// redactCorpus is the shared input for the equivalence tests: real-looking
// device output with every class of secret the rules cover, at awkward offsets.
var redactCorpus = []string{
	"Building configuration...",
	"hostname core1",
	"username admin privilege 15 password 7 070C285F4D06",
	"enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
	"snmp-server community pub1ic-str1ng ro",
	" ip ospf message-digest-key 1 md5 7 104D000A0618",
	"  authentication-key \"$9$abcdEF\"",
	" key-string 7 02050D480809",
	"crypto isakmp key MyPreSharedKey address 198.51.100.7",
	" keyring key 0 anotherSecret",
	"crypto ikev2 profile PROF pre-shared-key localSecret remote",
	"-----BEGIN RSA PRIVATE KEY-----",
	"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qNQyR2dPUxJ8ZAsxLJZ5Z5Z5Z5",
	"c3RyaW5nIHdpdGggbm8gc2VjcmV0IGluIGl0IGF0IGFsbCBqdXN0IGJhc2U2NA==",
	"-----END RSA PRIVATE KEY-----",
	"interface GigabitEthernet0/0/0",
	" description transit to isp-a",
	"  ip address 203.0.113.1 255.255.255.252",
	"Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State",
	"192.0.2.1       4 65001    9123    9110      142    0    0 03:14:07        7",
	"-----BEGIN CERTIFICATE-----",
	"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ",
	"-----END CERTIFICATE-----",
	"PSK: -----BEGIN OPENSSH PRIVATE KEY-----AAAA-----END OPENSSH PRIVATE KEY-----",
	"",
	"Total output drops: 0",
}

// TestRedactingWriterMatchesTheBufferedPassExactly is property (1).
func TestRedactingWriterMatchesTheBufferedPassExactly(t *testing.T) {
	text := strings.Join(redactCorpus, "\n")
	want := RedactOutput(text)

	// Chunk sizes chosen to split lines, split the PEM markers, and land
	// exactly on newline boundaries — the three ways a streaming scanner breaks.
	for _, chunk := range []int{1, 2, 3, 7, 13, 64, 512, 100000} {
		var got bytes.Buffer
		w := NewRedactingWriter(&got)
		for i := 0; i < len(text); i += chunk {
			end := i + chunk
			if end > len(text) {
				end = len(text)
			}
			if _, err := io.WriteString(w, text[i:end]); err != nil {
				t.Fatalf("chunk %d: write: %v", chunk, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("chunk %d: close: %v", chunk, err)
		}
		if got.String() != want {
			t.Fatalf("chunk %d: the streamed redaction differs from the buffered one\n got: %q\nwant: %q",
				chunk, got.String(), want)
		}
		if w.Written() != int64(got.Len()) {
			t.Fatalf("chunk %d: Written() says %d, %d bytes were written", chunk, w.Written(), got.Len())
		}
	}
}

// TestRedactingWriterDropsAPEMBodyAcrossChunks is the case a naive line scanner
// gets wrong: the key body arrives in pieces and none of it may survive.
func TestRedactingWriterDropsAPEMBodyAcrossChunks(t *testing.T) {
	const body = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn"
	text := "hostname core1\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n" + body + "\n-----END RSA PRIVATE KEY-----\ninterface Gi0/0\n"
	var got bytes.Buffer
	w := NewRedactingWriter(&got)
	for i := 0; i < len(text); i += 5 {
		end := i + 5
		if end > len(text) {
			end = len(text)
		}
		if _, err := io.WriteString(w, text[i:end]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if strings.Contains(got.String(), body) {
		t.Fatalf("the private-key body survived the stream:\n%s", got.String())
	}
	for _, keep := range []string{"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", redactionMark, "interface Gi0/0"} {
		if !strings.Contains(got.String(), keep) {
			t.Fatalf("the stream lost %q:\n%s", keep, got.String())
		}
	}
}

// TestRedactingWriterRefusesAfterClose — a closed writer is closed.
func TestRedactingWriterRefusesAfterClose(t *testing.T) {
	var got bytes.Buffer
	w := NewRedactingWriter(&got)
	if _, err := io.WriteString(w, "hostname core1"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := io.WriteString(w, "snmp-server community leaked ro"); err == nil {
		t.Fatal("a write after Close must be refused, not silently appended")
	}
	if strings.Contains(got.String(), "leaked") {
		t.Fatal("a post-Close write reached the underlying writer")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

// TestRedactingWriterFlushesAnUnterminatedLine — output with no trailing
// newline still gets redacted.
func TestRedactingWriterFlushesAnUnterminatedLine(t *testing.T) {
	var got bytes.Buffer
	w := NewRedactingWriter(&got)
	if _, err := io.WriteString(w, "snmp-server community trailing-secret ro"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if strings.Contains(got.String(), "trailing-secret") {
		t.Fatalf("a trailing partial line escaped redaction: %q", got.String())
	}
	if !strings.Contains(got.String(), redactionMark) {
		t.Fatalf("the trailing line was not redacted: %q", got.String())
	}
}

// TestPrefilterCannotMissARule is property (2), structurally: every anchor a
// rule declares must still be present in the rule's own pattern. An edit that
// removes the literal — the only way the shortcut could become wrong — fails
// here rather than in a customer's bundle.
func TestPrefilterCannotMissARule(t *testing.T) {
	r := newRedactor()
	if len(r.rules) == 0 {
		t.Fatal("no rules")
	}
	for i, rule := range r.rules {
		if len(rule.anchors) == 0 {
			t.Fatalf("rule %d declares no anchors, so the prefilter could skip it", i)
		}
		pattern := rule.re.String()
		for _, a := range rule.anchors {
			if !strings.Contains(strings.ToLower(pattern), a) {
				t.Fatalf("rule %d declares anchor %q, which its pattern %q no longer contains",
					i, a, pattern)
			}
		}
		if !r.prefilterHit(rule.anchors[0]) {
			t.Fatalf("rule %d's anchor %q does not reach the prefilter", i, rule.anchors[0])
		}
	}
}

// TestPrefilterAgreesWithTheUnfilteredRules is property (2), behaviourally: for
// the whole corpus, the shortcut and the full rule loop produce the same line.
func TestPrefilterAgreesWithTheUnfilteredRules(t *testing.T) {
	r := newRedactor()
	unfiltered := func(line string) string {
		for _, rule := range r.rules {
			line = rule.re.ReplaceAllString(line, rule.repl)
		}
		return line
	}
	cases := append([]string(nil), redactCorpus...)
	// Case variants and leading noise, because the prefilter is
	// case-insensitive and unanchored and must stay both.
	for _, l := range redactCorpus {
		cases = append(cases, strings.ToUpper(l), "  \t"+l, l+"   ", "! "+l)
	}
	for _, line := range cases {
		if got, want := r.redactLine(line), unfiltered(line); got != want {
			t.Fatalf("prefilter changed the outcome for %q:\n got: %q\nwant: %q", line, got, want)
		}
	}
}
