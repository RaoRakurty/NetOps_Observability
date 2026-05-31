package collectors

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// TestLocalizeKeyRFC3414 checks key localization against the canonical RFC 3414
// Appendix A.3 test vectors (password "maplesyrup", engineID 00..02). This
// pins both the MD5 and SHA auth-protocol key derivations.
func TestLocalizeKeyRFC3414(t *testing.T) {
	eid, _ := hex.DecodeString("000000000000000000000002")
	md5Kul := hex.EncodeToString(localizeKey(md5.New, "maplesyrup", eid))
	if md5Kul != "526f5eed9fcce26f8964c2930787d82b" {
		t.Errorf("MD5 localized key = %s, want 526f5eed9fcce26f8964c2930787d82b", md5Kul)
	}
	shaKul := hex.EncodeToString(localizeKey(sha1.New, "maplesyrup", eid))
	if shaKul != "6695febc9288e36282235fc7151f128497b38f3f" {
		t.Errorf("SHA localized key = %s, want 6695febc9288e36282235fc7151f128497b38f3f", shaKul)
	}
}

// TestPrivRoundTrip encrypts then decrypts a scopedPDU for each privacy
// protocol — proving AES-128-CFB and DES-CBC both round-trip cleanly.
func TestPrivRoundTrip(t *testing.T) {
	scoped := buildScopedPDU([]byte("engine-id-01"), "",
		buildPDU(0xA0, 7, oneNullVarbind([]int{1, 3, 6, 1, 2, 1, 1, 3, 0})))

	for _, proto := range []string{"AES128", "DES"} {
		sess := &v3Session{
			engineID: []byte("engine-id-01"), boots: 3, etime: 12345,
			// 20-byte localized priv key (AES uses [:16], DES uses [:8]+[8:16])
			privKeyL: []byte("0123456789abcdef0123"),
		}
		creds := snmpCreds{Version: 3, Level: "authPriv", PrivProto: proto, PrivKey: "x"}
		salt := []byte("salt8byt")
		ct, params, err := sess.encrypt(creds, scoped, salt)
		if err != nil {
			t.Fatalf("%s encrypt: %v", proto, err)
		}
		if bytes.Equal(ct, scoped) {
			t.Errorf("%s: ciphertext equals plaintext", proto)
		}
		pt, err := sess.decrypt(creds, ct, params)
		if err != nil {
			t.Fatalf("%s decrypt: %v", proto, err)
		}
		// DES pads to an 8-byte boundary; compare the original length only.
		if !bytes.Equal(pt[:len(scoped)], scoped) {
			t.Errorf("%s: round-trip mismatch", proto)
		}
	}
}

// TestMsgFlags pins the auth/priv/reportable flag byte across security levels.
func TestMsgFlags(t *testing.T) {
	cases := []struct {
		auth, priv bool
		want       byte
	}{
		{false, false, 0x04}, // noAuthNoPriv (+reportable)
		{true, false, 0x05},  // authNoPriv
		{true, true, 0x07},   // authPriv
	}
	for _, c := range cases {
		if got := msgFlags(c.auth, c.priv, true); got != c.want {
			t.Errorf("msgFlags(%v,%v) = 0x%02x, want 0x%02x", c.auth, c.priv, got, c.want)
		}
	}
}

// TestCredsLevels checks the security-level predicates that gate auth/priv.
func TestCredsLevels(t *testing.T) {
	noauth := snmpCreds{Version: 3, Level: "noAuthNoPriv"}
	if noauth.wantsAuth() || noauth.wantsPriv() {
		t.Error("noAuthNoPriv must not want auth or priv")
	}
	authonly := snmpCreds{Version: 3, Level: "authNoPriv", AuthKey: "k"}
	if !authonly.wantsAuth() || authonly.wantsPriv() {
		t.Error("authNoPriv must want auth, not priv")
	}
	full := snmpCreds{Version: 3, Level: "authPriv", AuthKey: "k", PrivKey: "p"}
	if !full.wantsAuth() || !full.wantsPriv() {
		t.Error("authPriv must want both auth and priv")
	}
	if v2c("public").isV3() {
		t.Error("v2c creds must not be v3")
	}
}
