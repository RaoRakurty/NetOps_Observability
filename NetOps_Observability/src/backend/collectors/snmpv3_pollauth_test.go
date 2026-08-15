package collectors

import (
	"bytes"
	"testing"
)

// snmpv3_pollauth_test.go — SNMPv3 poll-response authentication (SR poll-HMAC).
//
// parseScoped used to adopt the packet's engineID/boots/etime and decrypt, all
// from an UNVERIFIED datagram. A forged UDP response could therefore move the
// session's trusted engine clock and feed CFB-malleable "sample" bytes to the
// caller. These tests build a REAL authenticated response with the production
// message builder, prove it is accepted, then tamper it and prove every tamper
// is rejected with NO trusted-state mutation.
//
// SNMP-1/5/6/7 (authPriv accept, ciphertext-tamper reject, authNoPriv accept,
// authNoPriv HMAC reject); SNMP-3/4 (forged sysUpTime / engine state not
// trusted); SNMP-8 (noAuthNoPriv unchanged). SNMP-9 (trap regression) is the
// existing snmptrap_test.go, unchanged.

// authSession returns a session whose keys are localized to engineID, plus the
// creds to mint/verify with. Mirrors discoverV3's localization.
func authSession(t *testing.T, level, authProto, privProto string) (*v3Session, snmpCreds) {
	t.Helper()
	eid := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef}
	creds := snmpCreds{
		Version: 3, User: "monitor", Level: level,
		AuthProto: authProto, AuthKey: "authpassword123",
		PrivProto: privProto, PrivKey: "privpassword123",
	}
	newHash, _ := authHash(authProto)
	s := &v3Session{creds: creds, engineID: eid, boots: 11, etime: 2222, msgID: 5}
	s.authKeyL = localizeKey(newHash, creds.AuthKey, eid)
	if creds.wantsPriv() {
		s.privKeyL = localizeKey(newHash, creds.PrivKey, eid)
	}
	return s, creds
}

// mintResponse builds an authenticated (and, for authPriv, encrypted) v3 message
// carrying `scoped` as its payload, exactly as an agent would.
func mintResponse(t *testing.T, s *v3Session, creds snmpCreds, scoped []byte) []byte {
	t.Helper()
	if creds.wantsPriv() {
		salt := []byte{9, 9, 9, 9, 8, 8, 8, 8}
		ct, params, err := s.encrypt(creds, scoped, salt)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return buildV3Message(s.msgID, creds, s, ct, params)
	}
	return buildV3Message(s.msgID, creds, s, scoped, nil)
}

func sampleScoped(s *v3Session) []byte {
	// A minimal well-formed scopedPDU is enough — parseScoped's job is to
	// authenticate and (if priv) decrypt; varbind parsing is downstream.
	return buildScopedPDU(s.engineID, "", buildPDU(0xA2, 1, berTLV(0x30, nil)))
}

// SNMP-1: a valid authPriv response is accepted and decrypts back to the PDU.
func TestPollAuthPrivValidAccepted(t *testing.T) {
	s, creds := authSession(t, "authPriv", "SHA256", "AES")
	scoped := sampleScoped(s)
	pkt := mintResponse(t, s, creds, scoped)

	// Fresh receiver session, same creds/engine (as after discovery).
	rx, _ := authSession(t, "authPriv", "SHA256", "AES")
	before := snapshotCounters()
	out, err := rx.parseScoped(pkt)
	if err != nil {
		t.Fatalf("valid authPriv response rejected: %v", err)
	}
	if !bytes.Equal(out, scoped) {
		t.Fatalf("decrypted scopedPDU mismatch:\n got=%x\nwant=%x", out, scoped)
	}
	assertNoAuthFailure(t, before)
}

// SNMP-6: a valid authNoPriv response is accepted.
func TestPollAuthNoPrivValidAccepted(t *testing.T) {
	s, creds := authSession(t, "authNoPriv", "SHA", "")
	scoped := sampleScoped(s)
	pkt := mintResponse(t, s, creds, scoped)

	rx, _ := authSession(t, "authNoPriv", "SHA", "")
	out, err := rx.parseScoped(pkt)
	if err != nil {
		t.Fatalf("valid authNoPriv response rejected: %v", err)
	}
	if !bytes.Equal(out, scoped) {
		t.Fatalf("scopedPDU mismatch under authNoPriv")
	}
}

// SNMP-2/7: a corrupted HMAC is rejected, and NO engine state is adopted.
func TestPollBadHMACRejectedNoStateMutation(t *testing.T) {
	for _, level := range []string{"authNoPriv", "authPriv"} {
		t.Run(level, func(t *testing.T) {
			priv := ""
			if level == "authPriv" {
				priv = "AES"
			}
			s, creds := authSession(t, level, "SHA256", priv)
			pkt := mintResponse(t, s, creds, sampleScoped(s))

			// Flip a bit inside the authParams region by corrupting a late byte of
			// the message body (the MAC covers the whole message).
			tampered := append([]byte(nil), pkt...)
			tampered[len(tampered)/2] ^= 0x01

			rx, _ := authSession(t, level, "SHA256", priv)
			rx.engineID = []byte("ESTABLISHED")
			rx.boots, rx.etime = 11, 2222
			before := snapshotCounters()

			if _, err := rx.parseScoped(tampered); err == nil {
				t.Fatal("tampered response was ACCEPTED — HMAC not enforced")
			}
			// The forged packet carried a different engineID; it must not have
			// been adopted.
			if string(rx.engineID) != "ESTABLISHED" {
				t.Fatalf("engine state mutated from an unauthenticated packet: %x", rx.engineID)
			}
			after := snapshotCounters()
			if after.auth <= before.auth {
				t.Fatal("auth-failure counter did not advance")
			}
		})
	}
}

// SNMP-3/4: a FORGED response (attacker has no auth key) with a chosen sysUpTime
// and engine identity is rejected, so ProbeSNMP / the credential sentinel are
// not fooled and engine state is not trusted.
func TestPollForgedResponseRejected(t *testing.T) {
	// Receiver expects auth; the attacker mints with the WRONG key.
	rx, _ := authSession(t, "authPriv", "SHA256", "AES")
	rx.engineID = []byte("TRUSTED-ENGINE")

	attacker, acreds := authSession(t, "authPriv", "SHA256", "AES")
	attacker.authKeyL = bytes.Repeat([]byte{0xAB}, len(attacker.authKeyL)) // key the receiver does not share
	attacker.engineID = []byte{0x80, 0x00, 0x00, 0x00, 0x66, 0x61, 0x6b, 0x65}
	attacker.boots, attacker.etime = 99999, 123456 // forged clock
	forged := mintResponse(t, attacker, acreds, sampleScoped(attacker))

	if _, err := rx.parseScoped(forged); err == nil {
		t.Fatal("forged response accepted — a spoofer could drive sysUpTime/ProbeSNMP")
	}
	if string(rx.engineID) != "TRUSTED-ENGINE" {
		t.Fatalf("forged engine identity was trusted: %x", rx.engineID)
	}
}

// SNMP-5: under authPriv, modifying the CIPHERTEXT fails authentication — the
// response is rejected before decryption is trusted (decryption returning bytes
// is not authenticity).
func TestPollCiphertextTamperRejected(t *testing.T) {
	s, creds := authSession(t, "authPriv", "SHA256", "AES")
	pkt := mintResponse(t, s, creds, sampleScoped(s))

	// Corrupt a byte near the end (inside the encrypted scopedPDU octet string).
	tampered := append([]byte(nil), pkt...)
	tampered[len(tampered)-3] ^= 0xFF

	rx, _ := authSession(t, "authPriv", "SHA256", "AES")
	if _, err := rx.parseScoped(tampered); err == nil {
		t.Fatal("ciphertext tamper accepted — HMAC must reject before decryption is trusted")
	}
}

// SNMP-8: an explicit noAuthNoPriv session has no HMAC by design and its
// behavior is unchanged — parseScoped returns the payload without an auth gate.
func TestPollNoAuthNoPrivUnchanged(t *testing.T) {
	s := &v3Session{
		creds:    snmpCreds{Version: 3, User: "monitor", Level: "noAuthNoPriv"},
		engineID: []byte{0x80, 0x00, 0x00, 0x01}, boots: 1, etime: 1, msgID: 2,
	}
	scoped := sampleScoped(s)
	pkt := buildV3Message(s.msgID, s.creds, s, scoped, nil)
	out, err := s.parseScoped(pkt)
	if err != nil {
		t.Fatalf("noAuthNoPriv parse failed: %v", err)
	}
	if !bytes.Equal(out, scoped) {
		t.Fatal("noAuthNoPriv payload changed")
	}
}

// counters helper --------------------------------------------------------------

type ctr struct{ auth, decrypt, timeliness int64 }

func snapshotCounters() ctr {
	a, d, tl := SNMPv3PollSecurityCounters()
	return ctr{a, d, tl}
}

func assertNoAuthFailure(t *testing.T, before ctr) {
	t.Helper()
	if after := snapshotCounters(); after.auth != before.auth {
		t.Fatalf("auth-failure counter advanced on a VALID response: %d → %d", before.auth, after.auth)
	}
}
