package collectors

import (
	"crypto/rand"
	"testing"
)

// buildV2cTrap constructs a minimal SNMPv2c trap: sysUpTime.0 + snmpTrapOID.0
// (= linkDown) + one extra varbind (ifIndex=2). Reuses the package BER encoders.
func buildV2cTrap(community string) []byte {
	sysUpTime := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	linkDown := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	ifIndex := []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 2}

	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	timeticks := berTLV(0x43, []byte{0x00, 0x01, 0x00, 0x00}) // TimeTicks
	vbs := vb(sysUpTime, timeticks)
	vbs = append(vbs, vb(snmpTrapOID, berOID(linkDown))...)
	vbs = append(vbs, vb(ifIndex, berInt(2))...)
	varbinds := berTLV(0x30, vbs)

	pduBody := berInt(42) // request-id
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, varbinds...)
	pdu := berTLV(0xA7, pduBody) // SNMPv2-Trap-PDU

	msg := berInt(1) // version v2c
	msg = append(msg, berTLV(0x04, []byte(community))...)
	msg = append(msg, pdu...)
	return berTLV(0x30, msg)
}

func TestDecodeV2cTrap(t *testing.T) {
	pkt := buildV2cTrap("public")
	ev, err := decodeTrap(pkt, "10.0.0.9", nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Version != "v2c" {
		t.Errorf("version = %q, want v2c", ev.Version)
	}
	if ev.Community != "public" {
		t.Errorf("community = %q", ev.Community)
	}
	if ev.TrapOID != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap oid = %q", ev.TrapOID)
	}
	if ev.TrapName != "linkDown" || ev.Severity != "warning" {
		t.Errorf("name/sev = %q/%q, want linkDown/warning", ev.TrapName, ev.Severity)
	}
	// snmpTrapOID.0 is consumed into TrapOID; sysUpTime.0 + ifIndex remain.
	if len(ev.Varbinds) != 2 {
		t.Fatalf("varbinds = %+v, want 2 (sysUpTime, ifIndex)", ev.Varbinds)
	}
	if ev.Varbinds[1].OID != "1.3.6.1.2.1.2.2.1.1.2" || ev.Varbinds[1].Value != "2" {
		t.Errorf("last varbind = %+v, want ifIndex=2", ev.Varbinds[1])
	}
	if ev.Host != "10.0.0.9" {
		t.Errorf("host = %q", ev.Host)
	}
}

func TestDecodeV1Trap(t *testing.T) {
	enterprise := []int{1, 3, 6, 1, 4, 1, 9}
	pduBody := berOID(enterprise)
	pduBody = append(pduBody, berTLV(0x40, []byte{10, 0, 0, 7})...)            // agent-addr IpAddress
	pduBody = append(pduBody, berInt(2)...)                                    // generic = linkDown
	pduBody = append(pduBody, berInt(0)...)                                    // specific
	pduBody = append(pduBody, berTLV(0x43, []byte{0x00, 0x00, 0x01, 0x00})...) // timestamp
	pduBody = append(pduBody, berTLV(0x30, nil)...)                            // empty varbinds
	pdu := berTLV(0xA4, pduBody)

	msg := berInt(0) // version v1
	msg = append(msg, berTLV(0x04, []byte("public"))...)
	msg = append(msg, pdu...)
	pkt := berTLV(0x30, msg)

	ev, err := decodeTrap(pkt, "10.0.0.7", nil)
	if err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	if ev.Version != "v1" || ev.TrapName != "linkDown" {
		t.Errorf("v1 trap = %+v", ev)
	}
}

// TestV3AuthPrivRoundTrip builds an authPriv v3 trap with the package's own USM
// engine, then verifies the receiver authenticates + decrypts it back. Locks the
// inbound USM path (verifyV3Auth + decrypt) against the outbound one (encrypt).
func TestV3AuthPrivRoundTrip(t *testing.T) {
	creds := snmpCreds{
		Version: 3, User: "trapuser", Level: "authPriv",
		AuthProto: "SHA", AuthKey: "authpassword123",
		PrivProto: "AES", PrivKey: "privpassword123",
	}
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x01, 0xde, 0xad, 0xbe, 0xef}
	boots, etime := 7, 1234

	// Localize keys to the engine (same as the receiver will).
	newHash, _ := authHash(creds.AuthProto)
	sess := &v3Session{creds: creds, engineID: engineID, boots: boots, etime: etime}
	sess.authKeyL = localizeKey(newHash, creds.AuthKey, engineID)
	sess.privKeyL = localizeKey(newHash, creds.PrivKey, engineID)

	// Inner trap PDU (v2-style) inside a scopedPDU.
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	coldStart := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	varbinds := berTLV(0x30, vb(snmpTrapOID, berOID(coldStart)))
	pdu := buildPDU(0xA7, 1, varbinds)
	scoped := buildScopedPDU(engineID, "", pdu)

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	cipher, privParams, err := sess.encrypt(creds, scoped, salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pkt := buildV3Message(99, creds, sess, cipher, privParams)

	// The receiver resolves source IP → these creds.
	resolve := func(ip string) (Target, bool) {
		return Target{ID: "core-rtr", Address: "10.0.0.5", SNMPVersion: 3,
			V3User: creds.User, V3Level: creds.Level,
			V3AuthProto: creds.AuthProto, V3AuthKey: creds.AuthKey,
			V3PrivProto: creds.PrivProto, V3PrivKey: creds.PrivKey}, true
	}
	ev, err := decodeTrap(pkt, "10.0.0.5", resolve)
	if err != nil {
		t.Fatalf("decode v3: %v", err)
	}
	if !ev.Authenticated {
		t.Error("v3 trap not marked authenticated")
	}
	if ev.Version != "v3" || ev.User != "trapuser" {
		t.Errorf("v3 envelope = version %q user %q", ev.Version, ev.User)
	}
	if ev.TrapOID != "1.3.6.1.6.3.1.1.5.1" || ev.TrapName != "coldStart" {
		t.Errorf("v3 trap oid/name = %q/%q", ev.TrapOID, ev.TrapName)
	}
	if ev.Device != "core-rtr" {
		t.Errorf("device = %q, want core-rtr", ev.Device)
	}

	// Tamper one byte of the ciphertext region → auth must now fail.
	bad := append([]byte(nil), pkt...)
	bad[len(bad)-1] ^= 0xff
	if _, err := decodeTrap(bad, "10.0.0.5", resolve); err == nil {
		t.Error("tampered v3 trap should fail auth verification")
	}
}

// ── G2 — trap device attribution (NAT-surviving entity canonicalization) ──────
// resolve must FAIL-CLOSED on an ambiguous (shared) trap source: a NAT gateway
// fronting many devices must never be guessed to one of them, or one device's
// trap would masquerade as another's evidence (false cross-device independence).
func TestTrapResolveAmbiguityGuard(t *testing.T) {
	cases := []struct {
		name    string
		targets []Target
		ip      string
		wantID  string
		wantOK  bool
	}{
		{"unique source resolves", []Target{{ID: "leaf1", Address: "10.0.0.5:161"}}, "10.0.0.5", "leaf1", true},
		{"unknown source is honest miss", []Target{{ID: "leaf1", Address: "10.0.0.5"}}, "192.0.2.120", "", false},
		{"shared NAT source fails closed", []Target{
			{ID: "leaf1", Address: "192.0.2.120:16001"},
			{ID: "leaf2", Address: "192.0.2.120:16002"},
		}, "192.0.2.120", "", false},
		{"same device twice still resolves", []Target{
			{ID: "leaf1", Address: "10.0.0.5:161"},
			{ID: "leaf1", Address: "10.0.0.5:161"},
		}, "10.0.0.5", "leaf1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.targets
			r := &trapReceiver{targets: func() []Target { return ts }}
			got, ok := r.resolve(tc.ip)
			if ok != tc.wantOK || got.ID != tc.wantID {
				t.Errorf("resolve(%q) = (%q,%v), want (%q,%v)", tc.ip, got.ID, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestTrapAttributeDevice(t *testing.T) {
	ts := []Target{
		{ID: "leaf1", Address: "10.0.0.5:161", Community: "nocpub"},
		{ID: "spine1", Address: "10.0.0.9:161", Community: "nocpub"},
	}
	// A NAT gateway fronting both devices — neither leaf1 nor spine1 polls FROM it.
	nat := []Target{
		{ID: "leaf1", Address: "192.0.2.120:16001", Community: "nocpub"},
		{ID: "spine1", Address: "192.0.2.120:16002", Community: "nocpub"},
	}
	sysName := func(name string) []TrapVarbind {
		return []TrapVarbind{{OID: "1.3.6.1.2.1.1.5.0", Name: "sysName", Value: name}}
	}
	// M4: the PDU rescue paths only claim an identity the trap can PROVE
	// (community match for v1/v2c, verified HMAC for v3), so the events below
	// carry the version + community the wire event would.
	v2c := func(community string, vbs []TrapVarbind) *TrapEvent {
		return &TrapEvent{Version: "v2c", Community: community, Varbinds: vbs}
	}

	cases := []struct {
		name       string
		targets    []Target
		ev         *TrapEvent
		srcIP      string
		wantDevice string
		wantStatus string
	}{
		// (source-IP attribution is decodeTrap's job — see TestTrapResolveAmbiguityGuard
		// + TestV3AuthPrivRoundTrip; attributeDevice only RESCUES identity from the PDU.)
		{"already attributed is left untouched", ts, &TrapEvent{Device: "leaf1"}, "10.0.0.5", "leaf1", "inventory_matched"},
		{"sysName recovers identity behind NAT", nat, v2c("nocpub", sysName("spine1")), "192.0.2.120", "spine1", "inventory_matched"},
		{"v1 agent-addr recovers identity behind NAT", nat, &TrapEvent{Version: "v1", Community: "nocpub", agentAddr: "10.0.0.5"}, "192.0.2.120", "", "inventory_missing"}, // agent-addr not in NAT inventory
		{"v1 agent-addr resolves when in inventory", ts, &TrapEvent{Version: "v1", Community: "nocpub", agentAddr: "10.0.0.9"}, "172.16.0.1", "spine1", "inventory_matched"},
		{"sysName wins over a shared source", nat, v2c("nocpub", sysName("leaf1")), "192.0.2.120", "leaf1", "inventory_matched"},
		{"unknown NAT source stays an honest unknown", nat, &TrapEvent{}, "192.0.2.120", "", "inventory_missing"},
		{"unmatched sysName falls through to unknown", ts, v2c("nocpub", sysName("ghost")), "192.0.2.120", "", "inventory_missing"},
		// M4 regressions: a forged sysName without the device's community must
		// NOT be attributed — before the gate, ANY host that could reach :162
		// could file evidence under a real device with a guessed hostname.
		{"M4: forged sysName with wrong community refused", nat, v2c("wrong", sysName("spine1")), "203.0.113.9", "", "inventory_missing"},
		{"M4: forged sysName with no community refused", nat, &TrapEvent{Version: "v2c", Varbinds: sysName("spine1")}, "203.0.113.9", "", "inventory_missing"},
		{"M4: v1 agent-addr with wrong community refused", ts, &TrapEvent{Version: "v1", Community: "wrong", agentAddr: "10.0.0.9"}, "172.16.0.1", "", "inventory_missing"},
		{"M4: unauthenticated v3 sysName refused", nat, &TrapEvent{Version: "v3", Varbinds: sysName("spine1")}, "203.0.113.9", "", "inventory_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgs := tc.targets
			r := &trapReceiver{targets: func() []Target { return tgs }}
			r.attributeDevice(tc.ev, tc.srcIP)
			if tc.ev.Device != tc.wantDevice {
				t.Errorf("Device = %q, want %q", tc.ev.Device, tc.wantDevice)
			}
			if tc.ev.EnrichmentStatus != tc.wantStatus {
				t.Errorf("EnrichmentStatus = %q, want %q", tc.ev.EnrichmentStatus, tc.wantStatus)
			}
		})
	}
}
