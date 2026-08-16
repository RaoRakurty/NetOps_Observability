package collectors

// snmptrap_forgery_test.go — M4: forged trap identity.
//
// The receiver stored the v1/v2c community "for audit" but never compared it,
// and attributeDevice rescued an unresolved source by sysName alone — so any
// host that could reach :162 could file evidence under a real inventory device
// by guessing its hostname (or spoofing its IP), feeding forged evidence into
// events/correlation/RCA under that device's (tenant's) identity. These tests
// lock the gates: source-IP attribution requires the device's community
// (constant-time compare), the sysName/agent-addr rescues require the trap to
// PROVE the claimed identity, and a v3 device configured for an authenticated
// level is never accepted cleartext just because its key material is missing.

import (
	"strings"
	"testing"
)

// buildV2cSysNameTrap is buildV2cTrap plus a sysName.0 varbind — the forgery
// vehicle: identity claimed from PDU CONTENT, which the sender fully controls.
func buildV2cSysNameTrap(community, sysName string) []byte {
	sysUpTime := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	linkDown := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	sysNameOID := []int{1, 3, 6, 1, 2, 1, 1, 5, 0}

	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	vbs := vb(sysUpTime, berTLV(0x43, []byte{0x00, 0x01, 0x00, 0x00}))
	vbs = append(vbs, vb(snmpTrapOID, berOID(linkDown))...)
	vbs = append(vbs, vb(sysNameOID, berTLV(0x04, []byte(sysName)))...)
	varbinds := berTLV(0x30, vbs)

	pduBody := berInt(42)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, varbinds...)
	pdu := berTLV(0xA7, pduBody)

	msg := berInt(1)
	msg = append(msg, berTLV(0x04, []byte(community))...)
	msg = append(msg, pdu...)
	return berTLV(0x30, msg)
}

// TestM4SourceAttributionRequiresCommunity: a v2c trap from a known device's
// own source IP is only attributed when it carries that device's community.
func TestM4SourceAttributionRequiresCommunity(t *testing.T) {
	tg := Target{ID: "leaf1", Address: "10.0.0.5:161", Community: "s3cret"}
	resolve := func(ip string) (Target, bool) {
		if ip == "10.0.0.5" {
			return tg, true
		}
		return Target{}, false
	}

	// Wrong community (spoofed source, guessed community): decoded as evidence,
	// but the inventory identity is refused.
	ev, err := decodeTrap(buildV2cTrap("public"), "10.0.0.5", resolve)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "" {
		t.Fatalf("mismatched community was attributed to %q — spoofable identity", ev.Device)
	}

	// Correct community: attribution stands (the poller-style resolution).
	ev, err = decodeTrap(buildV2cTrap("s3cret"), "10.0.0.5", resolve)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "leaf1" {
		t.Fatalf("matching community not attributed (Device=%q)", ev.Device)
	}
}

// TestM4ForgedSysNameTrapNotAttributed is the finding's headline: a forged v2c
// trap carrying a victim's sysName, sent from an UNKNOWN source with a wrong
// (or default) community, must NOT be attributed to the inventory device —
// while a genuine NAT-fronted device presenting the right community still is.
func TestM4ForgedSysNameTrapNotAttributed(t *testing.T) {
	targets := func() []Target {
		return []Target{{ID: "spine1", Address: "10.0.0.9:161", Community: "s3cret"}}
	}
	r := &trapReceiver{targets: targets}

	// Forgery: unknown source, victim's sysName, guessed community.
	ev, err := r.decodePacket(buildV2cSysNameTrap("public", "spine1"), "203.0.113.50")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "" || ev.EnrichmentStatus != "inventory_missing" {
		t.Fatalf("forged sysName trap attributed to %q (status %q) — identity forgery",
			ev.Device, ev.EnrichmentStatus)
	}

	// Genuine NAT case: same unknown source, but the device's real community —
	// the NAT-surviving rescue must keep working.
	ev, err = r.decodePacket(buildV2cSysNameTrap("s3cret", "spine1"), "203.0.113.50")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "spine1" || ev.EnrichmentStatus != "inventory_matched" {
		t.Fatalf("genuine NAT-fronted trap lost attribution (Device=%q status=%q)",
			ev.Device, ev.EnrichmentStatus)
	}
}

// TestM4V3AuthConfiguredNeverAcceptedCleartext: a device the operator
// configured for authPriv/authNoPriv whose key material is missing must REFUSE
// a cleartext v3 trap, not silently downgrade to the noAuthNoPriv path.
func TestM4V3AuthConfiguredNeverAcceptedCleartext(t *testing.T) {
	// Cleartext (noAuthNoPriv-flagged) v3 trap, built with the package's own
	// message builder — exactly what a forger would send.
	eid := []byte{0x80, 0x00, 0x1f, 0x88, 0x02, 0xde, 0xad, 0xbe, 0xef}
	clear := snmpCreds{Version: 3, Level: "noAuthNoPriv", User: "forger"}
	sess := &v3Session{creds: clear, engineID: eid, boots: 1, etime: 1}
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	coldStart := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	vb := berTLV(0x30, berTLV(0x30, append(berOID(snmpTrapOID), berOID(coldStart)...)))
	scoped := buildScopedPDU(eid, "", buildPDU(0xA7, 1, vb))
	pkt := buildV3Message(1, clear, sess, scoped, nil)

	// Device is configured authPriv but its key never made it to the target
	// (cred-store miss, rotation gap) — refusal, not downgrade.
	tg := Target{ID: "fw1", Address: "10.0.0.7:161", SNMPVersion: 3, V3User: "ops", V3Level: "authPriv"}
	resolve := func(ip string) (Target, bool) {
		if ip == "10.0.0.7" {
			return tg, true
		}
		return Target{}, false
	}
	if _, err := decodeTrap(pkt, "10.0.0.7", resolve); err == nil {
		t.Fatal("cleartext v3 trap accepted for an authPriv-configured device — forgeable downgrade")
	} else if !strings.Contains(err.Error(), "refusing unauthenticated") {
		t.Fatalf("unexpected refusal: %v", err)
	}

	// Unknown sender stays decodable (evidence under its source host) —
	// unchanged behavior for genuinely unconfigured/foreign devices.
	ev, err := decodeTrap(pkt, "192.0.2.99", resolve)
	if err != nil {
		t.Fatalf("cleartext v3 trap from an unknown sender should still decode: %v", err)
	}
	if ev.Device != "" {
		t.Fatalf("unknown v3 sender attributed to %q", ev.Device)
	}
}

// TestM4SysNameRescueMatchesStoredName: the sysName rescue must compare the
// trap's sysName varbind against the device's STORED name, not only the derived
// inventory id. Scan devices are keyed ScanDeviceID(sysName, addr) — sanitized,
// lowercased, address-hash-suffixed — so a device named "core-sw#1" has an id
// like "core-sw-1-9f3a2b" that can NEVER equal-fold the real sysName the trap
// carries. Before the Name compare, every legitimately-authenticated NAT-fronted
// trap from a scan device was left inventory_missing.
func TestM4SysNameRescueMatchesStoredName(t *testing.T) {
	targets := func() []Target {
		return []Target{{
			ID:        "core-sw-1-9f3a2b", // ScanDeviceID-style: sanitized + addr hash
			Name:      "core-sw#1",        // the device's real sysName
			Address:   "10.0.0.7:161",
			Community: "s3cret",
		}}
	}
	r := &trapReceiver{targets: targets}

	// Genuine NAT-fronted trap: unresolved source, real sysName, RIGHT community.
	ev, err := r.decodePacket(buildV2cSysNameTrap("s3cret", "core-sw#1"), "203.0.113.60")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "core-sw-1-9f3a2b" || ev.EnrichmentStatus != "inventory_matched" {
		t.Fatalf("authenticated trap with stored sysName not attributed (Device=%q status=%q)",
			ev.Device, ev.EnrichmentStatus)
	}

	// M4 gate preserved: same sysName, WRONG community — still refused.
	ev, err = r.decodePacket(buildV2cSysNameTrap("public", "core-sw#1"), "203.0.113.60")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Device != "" || ev.EnrichmentStatus != "inventory_missing" {
		t.Fatalf("forged trap with stored sysName attributed to %q (status %q) — M4 gate lost",
			ev.Device, ev.EnrichmentStatus)
	}
}
