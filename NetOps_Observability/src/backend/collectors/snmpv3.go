package collectors

// SNMPv3's User-based Security Model (USM) fixes its crypto on the wire: RFC 3414
// defines DES-CBC privacy and HMAC-MD5-96 / HMAC-SHA-96 authentication; RFC 3826
// adds AES-128 in CFB-128 mode. These primitives are weak by modern standards but
// are MANDATED by the protocol — substituting AEAD/SHA-2 would make us unable to
// speak to any real SNMP agent. The gosec "weak crypto" warnings below (G50x/G40x)
// and the staticcheck CFB deprecation are therefore suppressed with an RFC citation
// at each site, not "fixed". The privacy round-trip is locked by snmpv3_priv_test.go.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- RFC 3414 DES-CBC privacy; protocol-mandated, not a free cipher choice
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- RFC 3414 HMAC-MD5-96 authentication; protocol-mandated
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 3414 HMAC-SHA-96 authentication; protocol-mandated
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"strings"
)

// snmpv3.go — SNMPv3 USM (User-based Security Model, RFC 3414/3826/7860)
// implemented in pure stdlib so the backend stays dependency-free.
//
// Flow per exchange:
//   1. Engine discovery — a reportable, unauthenticated request with an empty
//      engineID; the agent replies with a Report carrying its authoritative
//      engineID + engineBoots + engineTime.
//   2. Key localization — password -> Ku (expand to 1MB, hash) -> Kul =
//      hash(Ku || engineID || Ku).
//   3. Build the v3 message; for authPriv encrypt the scopedPDU (AES-CFB or
//      DES-CBC) then HMAC the whole message (truncated) into authParameters.
//
// Auth protocols: MD5, SHA1 (12-byte MAC), SHA-256 (24), SHA-384 (32),
// SHA-512 (48). Priv: AES-128-CFB, DES-CBC. Levels: noAuthNoPriv, authNoPriv,
// authPriv.

// snmpCreds carries everything the engine needs to talk to one agent — either
// a v2c community or a full v3 USM identity.
type snmpCreds struct {
	Version   int // 2 = v2c, 3 = v3
	Community string

	User      string // securityName
	Level     string // noAuthNoPriv | authNoPriv | authPriv
	AuthProto string // MD5 | SHA | SHA224 | SHA256 | SHA384 | SHA512
	AuthKey   string // auth password (plain; localized per-engine at runtime)
	PrivProto string // DES | AES | AES128 | AES192 | AES256
	PrivKey   string // privacy password
	Context   string // contextName (usually "")
}

// v2c wraps a community string as v2c creds (the legacy default path).
func v2c(community string) snmpCreds { return snmpCreds{Version: 2, Community: community} }

func (c snmpCreds) isV3() bool { return c.Version == 3 }
func (c snmpCreds) wantsAuth() bool {
	return c.isV3() && (c.Level == "authNoPriv" || c.Level == "authPriv") && c.AuthKey != ""
}
func (c snmpCreds) wantsPriv() bool {
	return c.isV3() && c.Level == "authPriv" && c.PrivKey != ""
}

// ---- hashing / protocol selection -----------------------------------------

// authHash returns the hash constructor and truncated-MAC length (RFC 3414 §6,
// RFC 7860 §4.2) for an auth protocol name.
func authHash(proto string) (func() hash.Hash, int) {
	switch strings.ToUpper(strings.TrimSpace(proto)) {
	case "MD5", "USMHMACMD5", "HMAC-MD5":
		return md5.New, 12
	case "SHA", "SHA1", "SHA-1", "USMHMACSHA":
		return sha1.New, 12
	case "SHA224", "SHA-224":
		return sha256.New224, 16
	case "SHA256", "SHA-256":
		return sha256.New, 24
	case "SHA384", "SHA-384":
		return sha512.New384, 32
	case "SHA512", "SHA-512":
		return sha512.New, 48
	default:
		return sha1.New, 12
	}
}

// localizeKey turns a password into an engine-localized key (RFC 3414 A.2).
func localizeKey(newHash func() hash.Hash, password string, engineID []byte) []byte {
	if password == "" {
		return nil
	}
	h := newHash()
	pw := []byte(password)
	// Expand the password to exactly 1,048,576 bytes and hash it -> Ku.
	const total = 1 << 20
	buf := make([]byte, 0, len(pw)*64)
	for len(buf) < 64 {
		buf = append(buf, pw...)
	}
	written := 0
	for written < total {
		n := total - written
		if n > len(buf) {
			n = len(buf)
		}
		h.Write(buf[:n])
		written += n
	}
	ku := h.Sum(nil)
	// Kul = hash(Ku || engineID || Ku).
	h.Reset()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// ---- v3 message assembly ---------------------------------------------------

func berOctet(b []byte) []byte { return berTLV(0x04, b) }

// buildScopedPDU = SEQUENCE { contextEngineID, contextName, PDU }.
func buildScopedPDU(engineID []byte, ctxName string, pdu []byte) []byte {
	body := berOctet(engineID)
	body = append(body, berOctet([]byte(ctxName))...)
	body = append(body, pdu...)
	return berTLV(0x30, body)
}

// buildPDU = <tag> { request-id, error-status, error-index, varbinds }.
func buildPDU(pduTag byte, reqID int, varbinds []byte) []byte {
	body := berInt(reqID)
	body = append(body, berInt(0)...)
	body = append(body, berInt(0)...)
	body = append(body, varbinds...)
	return berTLV(pduTag, body)
}

func oneNullVarbind(oid []int) []byte {
	return berTLV(0x30, berTLV(0x30, append(berOID(oid), berTLV(0x05, nil)...)))
}

// usmSecurityParams builds the msgSecurityParameters OCTET STRING and returns
// it plus the absolute offset of the authParameters content within it (so the
// caller can splice in the MAC after serializing the whole message).
func usmSecurityParams(engineID []byte, boots, etime int, user string, macLen int, privParams []byte) (octet []byte, authOffsetInOctet int) {
	authPlaceholder := make([]byte, macLen)
	body := berOctet(engineID)
	body = append(body, berInt(boots)...)
	body = append(body, berInt(etime)...)
	body = append(body, berOctet([]byte(user))...)
	authFieldStart := len(body) // start of the authParams TLV within body
	body = append(body, berOctet(authPlaceholder)...)
	body = append(body, berOctet(privParams)...)
	usmSeq := berTLV(0x30, body)
	// Offset within usmSeq = len(usmSeq header) + authFieldStart + len(authParams TLV header).
	seqHdr := len(usmSeq) - len(body)
	authTLVHdr := len(berOctet(authPlaceholder)) - macLen // 0x04 + length byte(s)
	authOffsetInSeq := seqHdr + authFieldStart + authTLVHdr
	octet = berOctet(usmSeq)
	octHdr := len(octet) - len(usmSeq)
	return octet, octHdr + authOffsetInSeq
}

// msgFlags byte: bit0 auth, bit1 priv, bit2 reportable.
func msgFlags(auth, priv, reportable bool) byte {
	var f byte
	if auth {
		f |= 0x01
	}
	if priv {
		f |= 0x02
	}
	if reportable {
		f |= 0x04
	}
	return f
}

// buildV3Message assembles a full SNMPv3 message. When auth is set the returned
// bytes already carry the spliced-in HMAC.
func buildV3Message(msgID int, creds snmpCreds, sess *v3Session, scopedOrCipher []byte, privParams []byte) []byte {
	auth := creds.wantsAuth()
	priv := creds.wantsPriv()
	macLen := 0
	if auth {
		_, macLen = authHash(creds.AuthProto)
	}

	global := berInt(msgID)
	global = append(global, berInt(65507)...)
	global = append(global, berOctet([]byte{msgFlags(auth, priv, true)})...)
	global = append(global, berInt(3)...) // USM security model
	globalSeq := berTLV(0x30, global)

	secOctet, authOff := usmSecurityParams(sess.engineID, sess.boots, sess.etime, creds.User, macLen, privParams)

	var msgData []byte
	if priv {
		msgData = berOctet(scopedOrCipher) // encrypted scopedPDU wrapped as OCTET STRING
	} else {
		msgData = scopedOrCipher // plaintext scopedPDU
	}

	body := berInt(3) // msgVersion = 3
	body = append(body, globalSeq...)
	secStart := len(body)
	body = append(body, secOctet...)
	body = append(body, msgData...)
	msg := berTLV(0x30, body)

	if auth {
		// Absolute offset of authParams content within the final message.
		msgHdr := len(msg) - len(body)
		absAuth := msgHdr + secStart + authOff
		newHash, _ := authHash(creds.AuthProto)
		mac := hmac.New(newHash, sess.authKeyL)
		mac.Write(msg) // authParams region is currently zeros
		sum := mac.Sum(nil)[:macLen]
		copy(msg[absAuth:absAuth+macLen], sum)
	}
	return msg
}

// ---- privacy (AES-CFB / DES-CBC) -------------------------------------------

// privCipher returns (ciphertext, privParams-salt) for the scopedPDU.
func (s *v3Session) encrypt(creds snmpCreds, scoped []byte, salt8 []byte) ([]byte, []byte, error) {
	proto := strings.ToUpper(strings.TrimSpace(creds.PrivProto))
	switch {
	case strings.HasPrefix(proto, "AES"):
		key := s.privKeyL
		if len(key) < 16 {
			return nil, nil, fmt.Errorf("snmpv3: priv key too short for AES")
		}
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, nil, err
		}
		iv := make([]byte, 16)
		// IV = engineBoots(4) || engineTime(4) || salt(8) per RFC 3826 §3.1 — a
		// constructed, unique IV, NOT a zero/hardcoded nonce (so G407 is a false
		// positive here).
		binary.BigEndian.PutUint32(iv[0:4], uint32(s.boots)) // #nosec G115 -- SNMP engineBoots/engineTime are RFC 3414 0..2^31-1, fit uint32
		binary.BigEndian.PutUint32(iv[4:8], uint32(s.etime)) // #nosec G115 -- SNMP engineBoots/engineTime are RFC 3414 0..2^31-1, fit uint32
		copy(iv[8:16], salt8)
		out := make([]byte, len(scoped))
		// #nosec G407 -- IV constructed above per RFC 3826, not zeroed
		//lint:ignore SA1019 SNMPv3 USM mandates AES-CFB (RFC 3826); no AEAD mode interoperates
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, scoped) //nolint:staticcheck // SA1019: SNMPv3 USM mandates AES-CFB (RFC 3826); no AEAD interops
		return out, salt8, nil
	case strings.HasPrefix(proto, "DES"):
		key := s.privKeyL
		if len(key) < 16 {
			return nil, nil, fmt.Errorf("snmpv3: priv key too short for DES")
		}
		block, err := des.NewCipher(key[:8]) // #nosec G405 -- RFC 3414 DES-CBC privacy; protocol-mandated
		if err != nil {
			return nil, nil, err
		}
		// salt = engineBoots(4) || 4 random bytes; IV = preIV XOR salt.
		salt := make([]byte, 8)
		binary.BigEndian.PutUint32(salt[0:4], uint32(s.boots)) // #nosec G115 -- SNMP engineBoots/engineTime are RFC 3414 0..2^31-1, fit uint32
		copy(salt[4:8], salt8[4:8])
		preIV := key[8:16]
		iv := make([]byte, 8)
		for i := 0; i < 8; i++ {
			iv[i] = preIV[i] ^ salt[i]
		}
		// pad to 8-byte multiple
		pad := (8 - len(scoped)%8) % 8
		pt := append(append([]byte(nil), scoped...), make([]byte, pad)...)
		out := make([]byte, len(pt))
		// #nosec G407 -- IV = preIV XOR salt (constructed above per RFC 3414), not zeroed
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, pt)
		return out, salt, nil
	default:
		return nil, nil, fmt.Errorf("snmpv3: unknown priv protocol %q", creds.PrivProto)
	}
}

func (s *v3Session) decrypt(creds snmpCreds, cipherText, privParams []byte) ([]byte, error) {
	proto := strings.ToUpper(strings.TrimSpace(creds.PrivProto))
	switch {
	case strings.HasPrefix(proto, "AES"):
		block, err := aes.NewCipher(s.privKeyL[:16])
		if err != nil {
			return nil, err
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:4], uint32(s.boots)) // #nosec G115 -- SNMP engineBoots/engineTime are RFC 3414 0..2^31-1, fit uint32
		binary.BigEndian.PutUint32(iv[4:8], uint32(s.etime)) // #nosec G115 -- SNMP engineBoots/engineTime are RFC 3414 0..2^31-1, fit uint32
		copy(iv[8:16], privParams)
		out := make([]byte, len(cipherText))
		// #nosec G407 -- IV reconstructed from engineBoots/time + privParams per RFC 3826
		//lint:ignore SA1019 SNMPv3 USM mandates AES-CFB (RFC 3826); no AEAD mode interoperates
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, cipherText) //nolint:staticcheck // SA1019: SNMPv3 USM mandates AES-CFB (RFC 3826)
		return out, nil
	case strings.HasPrefix(proto, "DES"):
		block, err := des.NewCipher(s.privKeyL[:8]) // #nosec G405 -- RFC 3414 DES-CBC privacy; protocol-mandated
		if err != nil {
			return nil, err
		}
		preIV := s.privKeyL[8:16]
		iv := make([]byte, 8)
		for i := 0; i < 8 && i < len(privParams); i++ {
			iv[i] = preIV[i] ^ privParams[i]
		}
		if len(cipherText)%8 != 0 {
			return nil, fmt.Errorf("snmpv3: DES ciphertext not block-aligned")
		}
		out := make([]byte, len(cipherText))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, cipherText)
		return out, nil
	default:
		return nil, fmt.Errorf("snmpv3: unknown priv protocol %q", creds.PrivProto)
	}
}

// ---- session: discovery + exchange -----------------------------------------

type v3Session struct {
	creds        snmpCreds
	engineID     []byte
	boots, etime int
	authKeyL     []byte
	privKeyL     []byte
	msgID        int
}

// discoverV3 performs engine-ID discovery over conn and localizes the keys.
func discoverV3(conn net.Conn, creds snmpCreds) (*v3Session, error) {
	s := &v3Session{creds: creds, msgID: 1}
	// Probe message: reportable, no auth/priv, empty engineID/user.
	probe := snmpCreds{Version: 3, Level: "noAuthNoPriv", User: ""}
	scoped := buildScopedPDU(nil, "", buildPDU(0xA0, 1, berTLV(0x30, nil)))
	msg := buildV3Message(1, probe, s, scoped, nil)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	eid, boots, etime, _, err := parseV3SecurityParams(buf[:n])
	if err != nil {
		return nil, err
	}
	if len(eid) == 0 {
		return nil, fmt.Errorf("snmpv3: discovery returned empty engineID")
	}
	s.engineID, s.boots, s.etime = eid, boots, etime
	if creds.wantsAuth() {
		newHash, _ := authHash(creds.AuthProto)
		s.authKeyL = localizeKey(newHash, creds.AuthKey, eid)
		if creds.wantsPriv() {
			// Priv key is localized with the AUTH hash (RFC 3414).
			s.privKeyL = localizeKey(newHash, creds.PrivKey, eid)
		}
	}
	return s, nil
}

// exchange sends one authenticated/encrypted request and returns the first
// varbind of the reply.
func (s *v3Session) exchange(conn net.Conn, pduTag byte, oid []int, reqID int) (valTag byte, val []byte, retOID []int, err error) {
	s.msgID++
	scoped := buildScopedPDU(s.engineID, s.creds.Context, buildPDU(pduTag, reqID, oneNullVarbind(oid)))

	var payload, privParams []byte
	if s.creds.wantsPriv() {
		salt := make([]byte, 8)
		if _, e := rand.Read(salt); e != nil {
			return 0, nil, nil, e
		}
		payload, privParams, err = s.encrypt(s.creds, scoped, salt)
		if err != nil {
			return 0, nil, nil, err
		}
	} else {
		payload = scoped
	}
	msg := buildV3Message(s.msgID, s.creds, s, payload, privParams)
	if _, err = conn.Write(msg); err != nil {
		return 0, nil, nil, err
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, nil, nil, err
	}
	scopedResp, err := s.parseScoped(buf[:n])
	if err != nil {
		return 0, nil, nil, err
	}
	return varbindFromScoped(scopedResp)
}

// parseScoped extracts (and decrypts if needed) the scopedPDU from a response.
func (s *v3Session) parseScoped(pkt []byte) ([]byte, error) {
	eid, boots, etime, privParams, err := parseV3SecurityParams(pkt)
	if err != nil {
		return nil, err
	}
	// Track the agent's clock so subsequent auth stays in the time window.
	if len(eid) > 0 {
		s.engineID, s.boots, s.etime = eid, boots, etime
	}
	priv, msgData, err := v3MsgData(pkt)
	if err != nil {
		return nil, err
	}
	if priv {
		return s.decrypt(s.creds, msgData, privParams)
	}
	return msgData, nil
}

// ---- v3 response parsing ---------------------------------------------------

// parseV3SecurityParams returns engineID, boots, time, privParams from a v3 msg.
func parseV3SecurityParams(pkt []byte) (engineID []byte, boots, etime int, privParams []byte, err error) {
	_, body, _, err := readTLV(pkt) // outer SEQUENCE
	if err != nil {
		return
	}
	_, _, rest, err := readTLV(body) // msgVersion
	if err != nil {
		return
	}
	_, _, rest, err = readTLV(rest) // msgGlobalData
	if err != nil {
		return
	}
	_, secOctet, _, err := readTLV(rest) // msgSecurityParameters (OCTET STRING)
	if err != nil {
		return
	}
	_, usm, _, err := readTLV(secOctet) // USM SEQUENCE
	if err != nil {
		return
	}
	_, engineID, u, err := readTLV(usm) // engineID
	if err != nil {
		return
	}
	_, bootsB, u, err := readTLV(u) // boots
	if err != nil {
		return
	}
	_, timeB, u, err := readTLV(u) // time
	if err != nil {
		return
	}
	_, _, u, err = readTLV(u) // userName
	if err != nil {
		return
	}
	_, _, u, err = readTLV(u) // authParams
	if err != nil {
		return
	}
	_, privParams, _, err = readTLV(u) // privParams
	if err != nil {
		return
	}
	boots = int(decodeUint(bootsB)) // #nosec G115 -- engineBoots parsed from a 32-bit wire field
	etime = int(decodeUint(timeB))  // #nosec G115 -- engineTime parsed from a 32-bit wire field
	return engineID, boots, etime, privParams, nil
}

// v3MsgData returns whether msgData is encrypted (priv flag) and the raw
// msgData bytes (ciphertext if priv, else the scopedPDU SEQUENCE).
func v3MsgData(pkt []byte) (priv bool, data []byte, err error) {
	_, body, _, err := readTLV(pkt)
	if err != nil {
		return
	}
	_, _, rest, err := readTLV(body) // version
	if err != nil {
		return
	}
	_, global, rest, err := readTLV(rest) // msgGlobalData
	if err != nil {
		return
	}
	_, _, rest, err = readTLV(rest) // msgSecurityParameters
	if err != nil {
		return
	}
	// msgData is next.
	tag, payload, _, err := readTLV(rest)
	if err != nil {
		return
	}
	// flags byte sits in globalData: msgID, msgMaxSize, msgFlags(OCTET), model.
	_, _, g, e := readTLV(global)
	if e == nil {
		_, _, g, e = readTLV(g)
	}
	if e == nil {
		var flags []byte
		if _, flags, _, e = readTLV(g); e == nil && len(flags) > 0 {
			priv = flags[0]&0x02 != 0
		}
	}
	if priv {
		return true, payload, nil // OCTET STRING content = ciphertext
	}
	// plaintext: hand the parser the full scopedPDU TLV (tag+length+content)
	return false, berTLV(tag, payload), nil
}

// reportReason decodes a Report PDU's first varbind OID into a usmStats reason
// (RFC 3414 §5). Best-effort; returns the raw OID if unrecognized.
func reportReason(pdu []byte) string {
	_, _, p, err := readTLV(pdu) // request-id
	if err == nil {
		_, _, p, err = readTLV(p) // error-status
	}
	if err == nil {
		_, _, p, err = readTLV(p) // error-index
	}
	if err != nil {
		return "unparseable"
	}
	_, vblist, _, err := readTLV(p)
	if err != nil {
		return "unparseable"
	}
	_, vb, _, err := readTLV(vblist)
	if err != nil {
		return "unparseable"
	}
	_, ocontent, _, err := readTLV(vb)
	if err != nil {
		return "unparseable"
	}
	oid := decodeOID(ocontent)
	names := map[int]string{
		1: "unsupportedSecLevel", 2: "notInTimeWindow", 3: "unknownUserName",
		4: "unknownEngineID", 5: "wrongDigest (bad auth password)", 6: "decryptionError (bad priv password)",
	}
	// usmStats OIDs are 1.3.6.1.6.3.15.1.1.<n>.0
	if len(oid) >= 2 {
		if n, ok := names[oid[len(oid)-2]]; ok {
			return n
		}
	}
	return oidSuffix(oid, nil)
}

// varbindFromScoped reads the first varbind of a scopedPDU
// (SEQUENCE { ctxEngineID, ctxName, PDU }).
func varbindFromScoped(scoped []byte) (valTag byte, val []byte, oid []int, err error) {
	_, body, _, err := readTLV(scoped) // scopedPDU SEQUENCE
	if err != nil {
		return
	}
	_, _, rest, err := readTLV(body) // contextEngineID
	if err != nil {
		return
	}
	_, _, rest, err = readTLV(rest) // contextName
	if err != nil {
		return
	}
	pduTag, pdu, _, err := readTLV(rest) // PDU
	if err != nil {
		return
	}
	if pduTag == 0xA8 { // Report PDU — USM rejected us (unknown user, wrong digest, …)
		return 0, nil, nil, fmt.Errorf("snmpv3: agent returned Report (%s)", reportReason(pdu))
	}
	_, _, p, err := readTLV(pdu) // request-id
	if err != nil {
		return
	}
	_, _, p, err = readTLV(p) // error-status
	if err != nil {
		return
	}
	_, _, p, err = readTLV(p) // error-index
	if err != nil {
		return
	}
	_, vblist, _, err := readTLV(p) // varbind list
	if err != nil {
		return
	}
	_, vb, _, err := readTLV(vblist) // first varbind
	if err != nil {
		return
	}
	otag, ocontent, vrest, err := readTLV(vb) // OID
	if err != nil {
		return
	}
	if otag != 0x06 {
		return 0, nil, nil, fmt.Errorf("snmpv3: varbind missing OID")
	}
	oid = decodeOID(ocontent)
	valTag, val, _, err = readTLV(vrest)
	return valTag, val, oid, err
}

// ---- v3-aware get / walk (used by snmpGet / snmpWalkColumn) ----------------

func snmpGetV3(ctx context.Context, addr string, creds snmpCreds, oid []int) (berVal, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return berVal{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl) // best-effort: a failed deadline set surfaces as a read/write error
	}
	sess, err := discoverV3(c, creds)
	if err != nil {
		return berVal{}, err
	}
	valTag, val, _, err := sess.exchange(c, 0xA0, oid, 1)
	if err != nil {
		return berVal{}, err
	}
	if valTag == tagNoSuchObject || valTag == tagNoSuchInstance || valTag == tagEndOfMibView {
		return berVal{}, fmt.Errorf("snmp: no such object")
	}
	return berVal{tag: valTag, raw: append([]byte(nil), val...)}, nil
}

func snmpWalkColumnV3(ctx context.Context, addr string, creds snmpCreds, col []int) (map[string]berVal, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl) // best-effort: a failed deadline set surfaces as a read/write error
	}
	sess, err := discoverV3(c, creds)
	if err != nil {
		return nil, err
	}
	out := make(map[string]berVal)
	cur := col
	for iter := 0; iter < 4096; iter++ {
		valTag, val, oid, err := sess.exchange(c, 0xA1, cur, iter+2)
		if err != nil {
			return out, err
		}
		if valTag == tagEndOfMibView || valTag == tagNoSuchObject || valTag == tagNoSuchInstance {
			break
		}
		if !oidUnder(oid, col) {
			break
		}
		out[oidSuffix(oid, col)] = berVal{tag: valTag, raw: append([]byte(nil), val...)}
		cur = oid
	}
	return out, nil
}
