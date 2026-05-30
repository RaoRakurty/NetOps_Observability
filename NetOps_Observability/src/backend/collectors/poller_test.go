package collectors

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// The SNMP v2c GET for sysUpTimeInstance is a fixed, well-known byte string
// (community "public", request-id 1). Pin it so BER-encoding regressions are
// caught — a malformed packet would silently never get a reply from a device.
func TestBuildSNMPGet(t *testing.T) {
	got := buildSNMPGet("public", sysUpTimeOID, 1)
	want := []byte{
		0x30, 0x26, // SEQUENCE, len 38
		0x02, 0x01, 0x01, // version = 1 (v2c)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community
		0xA0, 0x19, // GetRequest PDU, len 25
		0x02, 0x01, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
		0x30, 0x0e, // varbind list, len 14
		0x30, 0x0c, // varbind, len 12
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, // OID 1.3.6.1.2.1.1.3.0
		0x05, 0x00, // NULL
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SNMP GET mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestBase128(t *testing.T) {
	cases := map[int][]byte{
		0:    {0x00},
		127:  {0x7f},
		128:  {0x81, 0x00},
		2055: {0x90, 0x07},
	}
	for in, want := range cases {
		if got := base128(in); !bytes.Equal(got, want) {
			t.Errorf("base128(%d)=%x want %x", in, got, want)
		}
	}
}

// tcpProbe should succeed against a live listener and fail against a dead port.
func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tcpProbe(ctx, ln.Addr().String(), Target{}); err != nil {
		t.Errorf("probe of live listener failed: %v", err)
	}

	// A port nobody is listening on should error promptly.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := tcpProbe(ctx2, "127.0.0.1:1", Target{}); err == nil {
		t.Errorf("probe of dead port unexpectedly succeeded")
	}
}

// byProtocol must hand each collector only its own devices, treat a blank
// preferred protocol as SNMP, and match case-insensitively.
func TestByProtocol(t *testing.T) {
	all := func() []Target {
		return []Target{
			{ID: "a", Protocol: "snmp"},
			{ID: "b", Protocol: "gnmi"},
			{ID: "c", Protocol: "NETCONF"}, // case-insensitive
			{ID: "d", Protocol: ""},        // defaults to snmp
		}
	}
	cases := map[string][]string{
		"snmp":    {"a", "d"},
		"gnmi":    {"b"},
		"netconf": {"c"},
	}
	for proto, want := range cases {
		got := byProtocol(all, proto)()
		if len(got) != len(want) {
			t.Errorf("byProtocol(%q): got %d targets, want %d", proto, len(got), len(want))
			continue
		}
		for i, id := range want {
			if got[i].ID != id {
				t.Errorf("byProtocol(%q)[%d]=%q want %q", proto, i, got[i].ID, id)
			}
		}
	}

	if byProtocol(nil, "snmp") != nil {
		t.Error("byProtocol(nil,...) should return nil")
	}
}

func TestWithPort(t *testing.T) {
	if got := withPort("10.0.0.1", 161); got != "10.0.0.1:161" {
		t.Errorf("withPort no-port: got %q", got)
	}
	if got := withPort("10.0.0.1:830", 161); got != "10.0.0.1:830" {
		t.Errorf("withPort existing-port: got %q", got)
	}
}
