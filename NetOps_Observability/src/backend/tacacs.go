package main

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"time"
)

// tacacs.go — TACACS+ authentication module (RFC 8907).
//
// STATUS: SCAFFOLD. The wire primitives below (body obfuscation pad, header
// marshalling, config) are implemented and unit-tested; the START/REPLY
// handshake in Authenticate is the "build next" step (see the design notes and
// the skipped handshake tests in tacacs_test.go that already drive it against a
// mock TACACS+ server).
//
// Why TACACS+ (vs the existing local/LDAP/SAML/OIDC paths): network operators
// commonly centralize device-admin AAA on TACACS+ (Cisco ISE, etc.). Adding it
// lets NetOps authenticate operators against the same server that fronts their
// routers/switches. It stays stdlib-only — TACACS+ is plain TCP with an MD5
// body-obfuscation scheme we implement here.
//
// Design (build-next):
//   - Transport: TCP to TACACS_HOST:TACACS_PORT (default 49), TACACS_TIMEOUT.
//   - We use the PAP authentication type (authen_type=2): the START packet
//     carries the username (user field) and password (data field) in one round
//     trip; the server replies PASS(1) or FAIL(2). (ASCII login is a multi-packet
//     GETUSER/GETPASS exchange — PAP is sufficient for a web login form.)
//   - Every body is XOR-obfuscated with a pseudo-pad derived from the shared
//     secret (tacacsPad below). The header travels in clear.
//   - On PASS, the caller (handleLogin) JIT-provisions the user via
//     users.UpsertFederated(..., source="tacacs", ...) and issues a native
//     session — identical to the SSO broker-and-reissue model, so RBAC/tenancy
//     are unchanged downstream.
//
// Config: TACACS_ENABLED=true, TACACS_HOST, TACACS_PORT (49), TACACS_SECRET,
// TACACS_TIMEOUT (5s), TACACS_DEFAULT_ROLE (read-only), TACACS_DEFAULT_TENANT.

var errTACACSNotImplemented = errors.New("tacacs: PAP handshake not yet implemented (scaffold)")

// TACACS+ packet constants (RFC 8907 §4).
const (
	tacVersionMajor = 0xc        // major version 12 (0xc)
	tacVersionMinor = 0x0        // minor 0 = ASCII/PAP/CHAP authentication
	tacVersion      = (tacVersionMajor << 4) | tacVersionMinor

	tacTypeAuthen = 0x01 // packet type: authentication

	tacAuthenActionLogin = 0x01
	tacAuthenTypePAP     = 0x02
	tacAuthenSvcLogin    = 0x01
	tacPrivLvlUser       = 0x01

	tacStatusPass = 0x01
	tacStatusFail = 0x02

	tacFlagUnencrypted = 0x01 // set when body is NOT obfuscated (test/dev only)
)

// TACACS is the TACACS+ authentication client.
type TACACS struct {
	addr        string
	secret      string
	timeout     time.Duration
	enabled     bool
	defaultRole string
	tenant      string
}

func newTACACS() *TACACS {
	t := &TACACS{
		addr:        envOr("TACACS_HOST", "") + ":" + envOr("TACACS_PORT", "49"),
		secret:      os.Getenv("TACACS_SECRET"),
		timeout:     durEnv("TACACS_TIMEOUT", 5*time.Second),
		enabled:     os.Getenv("TACACS_ENABLED") == "true" && os.Getenv("TACACS_HOST") != "",
		defaultRole: envOr("TACACS_DEFAULT_ROLE", RoleReadOnly),
		tenant:      os.Getenv("TACACS_DEFAULT_TENANT"),
	}
	return t
}

func (t *TACACS) Enabled() bool { return t != nil && t.enabled }

// Host returns the configured server address (for status/diagnostics).
func (t *TACACS) Host() string { return strings.TrimSuffix(t.addr, ":") }

// tacacsPad builds the MD5-chained pseudo-pad used to obfuscate a TACACS+ body
// (RFC 8907 §4.5). The pad is the concatenation of MD5 hashes:
//
//	hash_1 = MD5(session_id . secret . version . seq_no)
//	hash_n = MD5(session_id . secret . version . seq_no . hash_{n-1})
//
// truncated to bodyLen. XOR-ing a body with this pad obfuscates it; XOR-ing the
// obfuscated body with the same pad recovers it (the operation is its own
// inverse) — which is exactly what the round-trip test asserts.
func tacacsPad(secret string, sessionID uint32, version, seqNo byte, bodyLen int) []byte {
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)
	seed := func(prev []byte) []byte {
		h := md5.New()
		h.Write(sid[:])
		h.Write([]byte(secret))
		h.Write([]byte{version})
		h.Write([]byte{seqNo})
		if prev != nil {
			h.Write(prev)
		}
		return h.Sum(nil)
	}
	pad := make([]byte, 0, bodyLen+md5.Size)
	var prev []byte
	for len(pad) < bodyLen {
		prev = seed(prev)
		pad = append(pad, prev...)
	}
	return pad[:bodyLen]
}

// tacacsObfuscate XORs body in place with the pad (encrypt == decrypt).
func tacacsObfuscate(secret string, sessionID uint32, version, seqNo byte, body []byte) {
	pad := tacacsPad(secret, sessionID, version, seqNo, len(body))
	for i := range body {
		body[i] ^= pad[i]
	}
}

// tacacsHeader marshals the 12-byte TACACS+ packet header (RFC 8907 §4.1).
func tacacsHeader(pktType, seqNo, flags byte, sessionID uint32, bodyLen int) []byte {
	h := make([]byte, 12)
	h[0] = tacVersion
	h[1] = pktType
	h[2] = seqNo
	h[3] = flags
	binary.BigEndian.PutUint32(h[4:8], sessionID)
	binary.BigEndian.PutUint32(h[8:12], uint32(bodyLen))
	return h
}

// authenStartPAP marshals an AUTHEN START body for PAP (RFC 8907 §5.1):
// action, priv_lvl, authen_type, authen_service, then the length-prefixed
// user / port / rem_addr / data(=password) fields.
func authenStartPAP(user, password string) []byte {
	port, rem := "netops", "netops-api"
	b := []byte{
		tacAuthenActionLogin,
		tacPrivLvlUser,
		tacAuthenTypePAP,
		tacAuthenSvcLogin,
		byte(len(user)),
		byte(len(port)),
		byte(len(rem)),
		byte(len(password)),
	}
	b = append(b, []byte(user)...)
	b = append(b, []byte(port)...)
	b = append(b, []byte(rem)...)
	b = append(b, []byte(password)...)
	return b
}

// Authenticate performs a PAP login against the TACACS+ server and reports
// whether the credentials are valid.
//
// BUILD-NEXT: open TCP to t.addr (t.timeout), write
// tacacsHeader(tacTypeAuthen, seq=1, flags=0, sessionID, len(body)) followed by
// tacacsObfuscate(...authenStartPAP(user,password)...); read the 12-byte reply
// header, read+deobfuscate the REPLY body, and return body[0]==tacStatusPass.
// The skipped tests in tacacs_test.go already drive this against a mock server —
// un-skip them as the implementation lands.
func (t *TACACS) Authenticate(username, password string) (bool, error) {
	if !t.Enabled() {
		return false, nil
	}
	return false, errTACACSNotImplemented
}
