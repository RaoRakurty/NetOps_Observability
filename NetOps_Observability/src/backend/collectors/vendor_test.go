package collectors

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEnterpriseOf(t *testing.T) {
	// 1.3.6.1.4.1.9.1.222 (a Cisco sysObjectID) -> enterprise 9
	if ent, ok := enterpriseOf([]int{1, 3, 6, 1, 4, 1, 9, 1, 222}); !ok || ent != 9 {
		t.Errorf("cisco: ent=%d ok=%v want 9,true", ent, ok)
	}
	// Juniper 2636
	if ent, ok := enterpriseOf([]int{1, 3, 6, 1, 4, 1, 2636, 1, 1, 1, 2, 57}); !ok || ent != 2636 {
		t.Errorf("juniper: ent=%d ok=%v want 2636,true", ent, ok)
	}
	// Not under the enterprise arc
	if _, ok := enterpriseOf([]int{1, 3, 6, 1, 2, 1, 1, 1}); ok {
		t.Error("non-enterprise OID should not match")
	}
}

func TestVendorFromDescr(t *testing.T) {
	cases := map[string]string{
		"Cisco IOS Software, C3560 Software":       "cisco",
		"Juniper Networks, Inc. mx240 JUNOS 21.4":  "juniper",
		"Arista Networks EOS version 4.30":         "arista",
		"FortiGate-100F v7.2.5":                    "fortinet",
		"Palo Alto Networks PA-3260 series PAN-OS": "paloalto",
		"Nokia 7750 SR TiMOS-B-22.10":              "nokia",
		"Linux fw01 5.15.0":                        "linux",
		"Some unknown widget":                      "",
	}
	for descr, want := range cases {
		if got := vendorFromDescr(descr); got != want {
			t.Errorf("vendorFromDescr(%q)=%q want %q", descr, got, want)
		}
	}
}

// TestDetectVendor drives DetectVendor against a UDP server that answers the
// sysObjectID GET with a Cisco enterprise OID and the sysDescr GET with text.
func TestDetectVendor(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// OID value content bytes (strip the tag+len that berOID prepends).
	oidContent := func(arcs []int) []byte {
		b := berOID(arcs)
		return b[2:]
	}
	go func() {
		buf := make([]byte, 4096)
		hits := 0
		for {
			_, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var resp []byte
			if hits == 0 {
				resp = snmpResponse(sysObjectIDOID, 0x06, oidContent([]int{1, 3, 6, 1, 4, 1, 9, 1, 222}), 1)
			} else {
				resp = snmpResponse(sysDescrOID, 0x04, []byte("Cisco IOS Software"), 2)
			}
			hits++
			_, _ = conn.WriteTo(resp, peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	vendor, descr := DetectVendor(ctx, conn.LocalAddr().String(), "public")
	if vendor != "cisco" {
		t.Errorf("vendor=%q want cisco", vendor)
	}
	if descr != "Cisco IOS Software" {
		t.Errorf("descr=%q", descr)
	}
}
