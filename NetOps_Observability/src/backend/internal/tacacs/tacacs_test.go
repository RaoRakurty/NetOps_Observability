// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tacacs

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TACACS+ test suite.
//
// The protocol PRIMITIVES (pad/obfuscation, header, START body, config) are
// implemented and tested here and pass today. The full PAP HANDSHAKE tests run
// against a real mock TACACS+ server (mockTacacsServer below) but are SKIPPED
// until TACACS.Authenticate is built — un-skip them as the implementation lands.
// They are the executable acceptance spec for that build.

// ---- config -----------------------------------------------------------------

func TestTACACSDisabledAuthIsNoop(t *testing.T) {
	c := &Client{enabled: false}
	ok, err := c.Authenticate("u", "p")
	if ok || err != nil {
		t.Errorf("disabled Authenticate should be (false,nil), got (%v,%v)", ok, err)
	}
}

// ---- protocol primitives (pass today) ---------------------------------------

// The obfuscation pad is its own inverse: XOR-ing twice with the same pad
// recovers the plaintext. This is the core of RFC 8907 body confidentiality.
func TestTACACSObfuscationRoundTrip(t *testing.T) {
	secret := "shared-secret"
	var sid uint32 = 0xDEADBEEF
	orig := []byte("\x01\x01\x02\x01username...password")
	body := append([]byte(nil), orig...)

	tacacsObfuscate(secret, sid, tacVersion, 1, body) // obfuscate
	if bytes.Equal(body, orig) {
		t.Fatal("obfuscation did not change the body")
	}
	tacacsObfuscate(secret, sid, tacVersion, 1, body) // de-obfuscate
	if !bytes.Equal(body, orig) {
		t.Fatal("round-trip failed: de-obfuscated body != original")
	}
}

// A different secret/session must produce a different pad (no fixed keystream).
func TestTACACSPadVariesByInputs(t *testing.T) {
	a := tacacsPad("secretA", 1, tacVersion, 1, 32)
	b := tacacsPad("secretB", 1, tacVersion, 1, 32)
	c := tacacsPad("secretA", 2, tacVersion, 1, 32)
	if bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Error("pad must vary by secret and session id")
	}
	if len(a) != 32 {
		t.Errorf("pad length = %d, want 32", len(a))
	}
}

func TestTACACSHeaderEncoding(t *testing.T) {
	h := tacacsHeader(tacTypeAuthen, 1, 0, 0x01020304, 40)
	if h[0] != tacVersion || h[1] != tacTypeAuthen || h[2] != 1 {
		t.Errorf("header prefix wrong: %x", h[:4])
	}
	if binary.BigEndian.Uint32(h[4:8]) != 0x01020304 {
		t.Error("session id mis-encoded")
	}
	if binary.BigEndian.Uint32(h[8:12]) != 40 {
		t.Error("body length mis-encoded")
	}
}

func TestTACACSAuthenStartPAPLayout(t *testing.T) {
	b := authenStartPAP("alice", "pw123")
	if b[0] != tacAuthenActionLogin || b[2] != tacAuthenTypePAP {
		t.Errorf("PAP start action/type wrong: %x", b[:4])
	}
	if b[4] != byte(len("alice")) || b[7] != byte(len("pw123")) {
		t.Errorf("PAP field lengths wrong: user=%d data=%d", b[4], b[7])
	}
	if !bytes.Contains(b, []byte("alice")) || !bytes.Contains(b, []byte("pw123")) {
		t.Error("PAP body should carry username + password")
	}
}

// ---- full handshake (SKIPPED — build-next acceptance spec) -------------------

// mockTacacsServer is a minimal TACACS+ server for tests: it reads a START
// packet, de-obfuscates the PAP body with the shared secret, and replies PASS if
// (user,password) matches `validUser`/`validPass`, else FAIL. It is already
// correct so the client build can be validated immediately by un-skipping the
// tests below.
func mockTacacsServer(t *testing.T, secret, validUser, validPass string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 12)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(hdr[4:8])
		blen := int(binary.BigEndian.Uint32(hdr[8:12]))
		body := make([]byte, blen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		if hdr[3]&tacFlagUnencrypted == 0 {
			tacacsObfuscate(secret, sid, hdr[0], hdr[2], body) // de-obfuscate
		}
		// Parse the PAP START fields.
		ul, pl := int(body[4]), int(body[7])
		off := 8
		user := string(body[off : off+ul])
		off += ul + int(body[5]) + int(body[6])
		pass := string(body[off : off+pl])

		status := byte(tacStatusFail)
		if user == validUser && pass == validPass {
			status = tacStatusPass
		}
		reply := []byte{status, 0x00, 0x00, 0x00, 0x00, 0x00} // status + flags + server_msg_len(2) + data_len(2)
		tacacsObfuscate(secret, sid, hdr[0], hdr[2]+1, reply)
		conn.Write(tacacsHeader(tacTypeAuthen, hdr[2]+1, 0, sid, len(reply)))
		conn.Write(reply)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestTACACSAuthenticatePAPSuccess(t *testing.T) {
	addr, stop := mockTacacsServer(t, "topsecret", "noc-admin", "Cisco123")
	defer stop()
	c := &Client{addr: addr, secret: "topsecret", enabled: true, timeout: 3 * time.Second}
	ok, err := c.Authenticate("noc-admin", "Cisco123")
	if err != nil || !ok {
		t.Fatalf("expected PASS, got ok=%v err=%v", ok, err)
	}
}

func TestTACACSAuthenticatePAPFailure(t *testing.T) {
	addr, stop := mockTacacsServer(t, "topsecret", "noc-admin", "Cisco123")
	defer stop()
	c := &Client{addr: addr, secret: "topsecret", enabled: true, timeout: 3 * time.Second}
	ok, err := c.Authenticate("noc-admin", "wrong-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("wrong password must FAIL")
	}
}

// Empty credentials are rejected before any network I/O.
func TestTACACSAuthenticateRejectsEmptyCreds(t *testing.T) {
	c := &Client{addr: "127.0.0.1:1", secret: "x", enabled: true, timeout: time.Second}
	if ok, err := c.Authenticate("", "p"); ok || err == nil {
		t.Errorf("empty username: got ok=%v err=%v", ok, err)
	}
	if ok, err := c.Authenticate("u", ""); ok || err == nil {
		t.Errorf("empty password: got ok=%v err=%v", ok, err)
	}
}

// The AUTHEN START PAP body must survive obfuscate -> de-obfuscate and parse
// back into the original username/password fields (the keystream is keyed by
// secret/session/version/seq, so the server can recover it).
func TestTACACSStartBodyObfuscateRoundTrip(t *testing.T) {
	const secret = "topsecret"
	const user, pass = "noc-admin", "Cisco123"
	var sid uint32 = 0x12345678
	body := authenStartPAP(user, pass)
	orig := append([]byte(nil), body...)

	tacacsObfuscate(secret, sid, tacACSPAPVersion, 1, body)
	if bytes.Equal(body, orig) {
		t.Fatal("obfuscation did not change the START body")
	}
	tacacsObfuscate(secret, sid, tacACSPAPVersion, 1, body)
	if !bytes.Equal(body, orig) {
		t.Fatal("round-trip failed: de-obfuscated body != original")
	}

	// Parse the recovered PAP fields the way a server would.
	ul, pl := int(body[4]), int(body[7])
	off := 8
	gotUser := string(body[off : off+ul])
	off += ul + int(body[5]) + int(body[6])
	gotPass := string(body[off : off+pl])
	if gotUser != user || gotPass != pass {
		t.Errorf("recovered (%q,%q), want (%q,%q)", gotUser, gotPass, user, pass)
	}
}
