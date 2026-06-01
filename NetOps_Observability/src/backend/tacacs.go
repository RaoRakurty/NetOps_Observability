package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// tacacs.go — TACACS+ authentication module (RFC 8907), stdlib-only.
//
// Why TACACS+ (vs the existing local/LDAP/SAML/OIDC paths): network operators
// commonly centralize device-admin AAA on TACACS+ (Cisco ISE, etc.). Adding it
// lets NetOps authenticate operators against the same server that fronts their
// routers/switches. It stays stdlib-only — TACACS+ is plain TCP with an MD5
// body-obfuscation scheme we implement here.
//
// Design (implemented):
//   - Transport: TCP to host:port (default 49) with a per-call deadline.
//   - PAP authentication type (authen_type=2): the START packet carries the
//     username (user field) and password (data field) in one round trip; the
//     server replies PASS(1) or FAIL(2). (ASCII login is a multi-packet
//     GETUSER/GETPASS exchange — PAP is sufficient for a web login form.)
//   - Every body is XOR-obfuscated with a pseudo-pad derived from the shared
//     secret (tacacsPad below). The header travels in clear.
//   - On PASS, handleTACACSLogin JIT-provisions the user via
//     users.UpsertFederated(..., source="tacacs", ...) and issues a native
//     session — identical to the SSO broker-and-reissue model, so RBAC/tenancy
//     are unchanged downstream.
//
// Configuration is resolved at runtime from the kv-backed tacacsConfigStore
// (admin UI), falling back to env (TACACS_ENABLED/HOST/PORT/SECRET/TIMEOUT/
// DEFAULT_ROLE/DEFAULT_TENANT) until an operator saves — see auth_config.go.

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

	// AUTHEN REPLY status codes (RFC 8907 §5.2).
	tacStatusPass    = 0x01
	tacStatusFail    = 0x02
	tacStatusGetData = 0x03
	tacStatusGetUser = 0x04
	tacStatusGetPass = 0x05
	tacStatusRestart = 0x06
	tacStatusError   = 0x07
	tacStatusFollow  = 0x21

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

// tacacsHeader marshals the 12-byte TACACS+ packet header (RFC 8907 §4.1) using
// the default version byte (minor 0). Retained for the primitives/tests.
func tacacsHeader(pktType, seqNo, flags byte, sessionID uint32, bodyLen int) []byte {
	return tacacsHeaderVer(tacVersion, pktType, seqNo, flags, sessionID, bodyLen)
}

// tacacsHeaderVer marshals the 12-byte header with an explicit version byte
// (PAP/CHAP START requires minor version 1, i.e. 0xc1).
func tacacsHeaderVer(version, pktType, seqNo, flags byte, sessionID uint32, bodyLen int) []byte {
	h := make([]byte, 12)
	h[0] = version
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

// tacACSPAPVersion is the version byte for PAP authentication: major 0xc, minor
// 1 (RFC 8907 §4.1 — minor version 1 is REQUIRED for PAP/CHAP/MS-CHAP START).
const tacACSPAPVersion = (tacVersionMajor << 4) | 0x1 // 0xc1

// tacacsSessionID returns a cryptographically-random 32-bit session id.
func tacacsSessionID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal-grade; fall back to a time-derived id so
		// we never emit a fixed/zero session id (which would weaken the pad).
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// Authenticate performs a single-round-trip PAP login (RFC 8907 §5.1/§5.2)
// against the TACACS+ server and reports whether the credentials are valid.
//
// Returns (true,nil) on AUTHEN REPLY status PASS, (false,nil) on FAIL, and
// (false,err) on protocol/IO errors. A multi-packet exchange (GETUSER/GETPASS/
// GETDATA) is not expected for PAP and is treated as a protocol error.
func (t *TACACS) Authenticate(username, password string) (bool, error) {
	if !t.Enabled() {
		return false, nil
	}
	if username == "" || password == "" {
		return false, errors.New("tacacs: username and password required")
	}

	conn, err := net.DialTimeout("tcp", t.addr, t.timeout)
	if err != nil {
		return false, fmt.Errorf("tacacs dial: %w", err)
	}
	defer conn.Close()
	if t.timeout > 0 {
		deadline := time.Now().Add(t.timeout)
		_ = conn.SetDeadline(deadline)
	}

	const version = tacACSPAPVersion
	const seqNo = byte(1) // START is always seq_no 1
	sessionID := tacacsSessionID()

	// Build + (optionally) obfuscate the AUTHEN START body.
	body := authenStartPAP(username, password)
	var flags byte
	if t.secret == "" {
		// No shared secret → send unencrypted (test/dev only). The flag tells
		// the server the body is in the clear.
		flags = tacFlagUnencrypted
	} else {
		tacacsObfuscate(t.secret, sessionID, version, seqNo, body)
	}

	// Frame: 12-byte clear header followed by the (obfuscated) body.
	hdr := tacacsHeaderVer(version, tacTypeAuthen, seqNo, flags, sessionID, len(body))
	if _, err := conn.Write(append(hdr, body...)); err != nil {
		return false, fmt.Errorf("tacacs write: %w", err)
	}

	// Read the 12-byte reply header.
	rhdr := make([]byte, 12)
	if _, err := io.ReadFull(conn, rhdr); err != nil {
		return false, fmt.Errorf("tacacs read header: %w", err)
	}
	if rhdr[1] != tacTypeAuthen {
		return false, fmt.Errorf("tacacs: unexpected reply type 0x%02x", rhdr[1])
	}
	rSeq := rhdr[2]
	rFlags := rhdr[3]
	rSession := binary.BigEndian.Uint32(rhdr[4:8])
	rLen := int(binary.BigEndian.Uint32(rhdr[8:12]))
	if rSession != sessionID {
		return false, errors.New("tacacs: reply session id mismatch")
	}
	if rLen < 6 || rLen > 1<<16 { // REPLY is status+flags+2*len(2) + msg/data
		return false, fmt.Errorf("tacacs: bad reply body length %d", rLen)
	}

	// Read and (if obfuscated) de-obfuscate the REPLY body. The obfuscation pad
	// is keyed by (session_id, secret, version, seq_no). The version is fixed for
	// the whole session, so we key it with the version WE sent (RFC 8907 §4.1:
	// all packets in a session share one version); the seq_no is the reply's.
	rbody := make([]byte, rLen)
	if _, err := io.ReadFull(conn, rbody); err != nil {
		return false, fmt.Errorf("tacacs read body: %w", err)
	}
	if rFlags&tacFlagUnencrypted == 0 && t.secret != "" {
		tacacsObfuscate(t.secret, rSession, version, rSeq, rbody)
	}

	// AUTHEN REPLY: status(1) flags(1) server_msg_len(2) data_len(2) ...
	switch rbody[0] {
	case tacStatusPass:
		return true, nil
	case tacStatusFail:
		return false, nil
	case tacStatusError:
		return false, errors.New("tacacs: server reported ERROR")
	case tacStatusGetData, tacStatusGetUser, tacStatusGetPass:
		// PAP carries the password in the START packet; a CONTINUE request means
		// the server isn't doing PAP as expected.
		return false, fmt.Errorf("tacacs: server requested more data (status 0x%02x); PAP single-packet expected", rbody[0])
	case tacStatusRestart:
		return false, errors.New("tacacs: server requested RESTART")
	case tacStatusFollow:
		return false, errors.New("tacacs: server returned FOLLOW (redirect not supported)")
	default:
		return false, fmt.Errorf("tacacs: unknown reply status 0x%02x", rbody[0])
	}
}

// handleTACACSLogin (public) authenticates {username,password} against the
// configured TACACS+ server via PAP, JIT-provisions a local user, and issues the
// same access + refresh session as handleLogin. TACACS+ has no group model, so
// the user always gets t.defaultRole.
func (s *server) handleTACACSLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	t := s.tacacs.effective().client()
	if !t.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("tacacs authentication not configured"))
		return
	}
	ok, err := t.Authenticate(req.Username, req.Password)
	if err != nil {
		logInfo("auth", "tacacs login error", map[string]any{"user": req.Username, "reason": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("tacacs authentication unavailable"))
		return
	}
	if !ok {
		logInfo("auth", "tacacs login failed", map[string]any{"user": req.Username})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	user, err := s.users.UpsertFederated(req.Username, "", req.Username, t.defaultRole, "tacacs", t.tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	ttl := accessTokenTTL()
	tok, err := signJWT(jwtClaims{
		Sub:    user.Username,
		Role:   user.Role,
		Tenant: user.TenantID,
		Iat:    time.Now().Unix(),
		Exp:    time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	refresh, err := s.refresh.Issue(user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.users.TouchLogin(user.Username)
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role, "src": "tacacs"})
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: refresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}
