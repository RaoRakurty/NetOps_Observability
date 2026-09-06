// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bytes"
	"testing"
)

// snmpv3_priv_test.go locks the SNMPv3 USM privacy round-trip. The cipher modes
// here (AES-128-CFB per RFC 3826, DES-CBC per RFC 3414) are protocol-mandated and
// flagged "weak" by gosec/staticcheck — suppressed with citations at each site in
// snmpv3.go. This test guards that the suppressed code stays CORRECT: whatever we
// encrypt for an agent we can decrypt back, so a future refactor can't silently
// break interop.

func newPrivTestSession() *v3Session {
	s := &v3Session{boots: 7, etime: 42, privKeyL: make([]byte, 16)}
	for i := range s.privKeyL {
		s.privKeyL[i] = byte(i*7 + 3) // deterministic, non-zero key material
	}
	return s
}

func TestSNMPv3PrivRoundTrip(t *testing.T) {
	salt8 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, proto := range []string{"AES", "DES"} {
		t.Run(proto, func(t *testing.T) {
			s := newPrivTestSession()
			creds := snmpCreds{PrivProto: proto}
			plain := []byte("the quick brown fox jumps over the lazy SNMP agent")

			ct, params, err := s.encrypt(creds, plain, salt8)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if bytes.HasPrefix(ct, plain) {
				t.Fatal("ciphertext must not start with the plaintext (encryption did nothing)")
			}

			got, err := s.decrypt(creds, ct, params)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			// DES-CBC pads to an 8-byte boundary, so the recovered text may carry
			// trailing pad bytes; the plaintext must be a prefix either way.
			if !bytes.HasPrefix(got, plain) {
				t.Fatalf("round-trip mismatch:\n got=%q\nwant prefix=%q", got, plain)
			}
		})
	}
}

// TestSNMPv3PrivWrongKeyGarbles confirms a different priv key does not recover the
// plaintext (no shared secret ⇒ no plaintext). Unauthenticated modes can't detect
// tampering, but a wrong key must still not decrypt to the original.
func TestSNMPv3PrivWrongKeyGarbles(t *testing.T) {
	salt8 := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	s := newPrivTestSession()
	plain := []byte("sensitive scoped PDU contents here")
	ct, params, err := s.encrypt(snmpCreds{PrivProto: "AES"}, plain, salt8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	other := newPrivTestSession()
	for i := range other.privKeyL {
		other.privKeyL[i] ^= 0xFF // a completely different key
	}
	got, err := other.decrypt(snmpCreds{PrivProto: "AES"}, ct, params)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if bytes.Equal(got, plain) {
		t.Fatal("a wrong priv key must not recover the plaintext")
	}
}
