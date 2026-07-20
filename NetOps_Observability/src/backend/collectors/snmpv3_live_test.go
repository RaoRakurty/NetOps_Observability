package collectors

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveV3 exercises the SNMPv3 USM engine against the real clos-lab fabric.
// Gated by SNMP_LIVE=1 so it never runs in offline CI.
//
//	SNMP_LIVE=1 go test ./collectors/ -run TestLiveV3 -v
func TestLiveV3(t *testing.T) {
	if os.Getenv("SNMP_LIVE") == "" {
		t.Skip("set SNMP_LIVE=1 to run against the live fabric")
	}
	cases := []struct {
		name, addr                            string
		user, auth, authpw, priv, privpw, lvl string
	}{
		{"arista-leaf1", "172.40.40.21:161", "arista-monitor", "SHA", "AristaAuth2024!", "AES", "AristaPriv2024!", "authPriv"},
		{"cisco-lansw1", "172.40.40.51:161", "cisco-monitor", "SHA", "CiscoAuth2024!", "AES", "CiscoPriv2024!", "authPriv"},
		{"fortinet-dmz", "172.40.40.41:161", "fortinet-monitor", "SHA", "FortinetAuth2024!", "AES", "FortinetPriv2024!", "authPriv"},
		{"nokia-spine1", "172.40.40.11:161", "srl-monitor", "SHA", "SrlAuth2024!", "AES", "SrlPriv2024!", "authPriv"},
	}
	for _, c := range cases {
		creds := snmpCreds{Version: 3, User: c.user, Level: c.lvl, AuthProto: c.auth, AuthKey: c.authpw, PrivProto: c.priv, PrivKey: c.privpw}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		v, err := snmpGetV3(ctx, c.addr, creds, sysObjectIDOID)
		cancel()
		if err != nil {
			t.Errorf("%-14s GET failed: %v", c.name, err)
			continue
		}
		t.Logf("%-14s OK sysObjectID=%v (tag 0x%02x)", c.name, decodeOID(v.raw), v.tag)
	}
}
