package collectors

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"testing"
	"time"
)

// snmpResponse builds a v2c GetResponse with a single varbind, reusing the BER
// encoders from poller.go. It's the inverse of firstVarbind, so the decoder is
// tested against the encoder (round-trip).
func snmpResponse(oid []int, valTag byte, val []byte, reqID int) []byte {
	vb := berTLV(0x30, append(berOID(oid), berTLV(valTag, val)...))
	vbs := berTLV(0x30, vb)
	body := berInt(reqID)
	body = append(body, berInt(0)...) // error-status
	body = append(body, berInt(0)...) // error-index
	body = append(body, vbs...)
	pdu := berTLV(0xA2, body) // GetResponse
	msg := berInt(1)
	msg = append(msg, berTLV(0x04, []byte("public"))...)
	msg = append(msg, pdu...)
	return berTLV(0x30, msg)
}

// GetNext must be byte-identical to Get except for the PDU tag (0xA1 vs 0xA0).
// This also guards the buildSNMPRequest refactor.
func TestBuildSNMPGetNext(t *testing.T) {
	get := buildSNMPGet("public", sysUpTimeOID, 1)
	next := buildSNMPGetNext("public", sysUpTimeOID, 1)
	if len(get) != len(next) {
		t.Fatalf("get/next length differ: %d vs %d", len(get), len(next))
	}
	diffs := 0
	var at int
	for i := range get {
		if get[i] != next[i] {
			diffs++
			at = i
		}
	}
	if diffs != 1 || get[at] != 0xA0 || next[at] != 0xA1 {
		t.Fatalf("expected exactly one diff (0xA0->0xA1), got %d (at %d: %#x->%#x)",
			diffs, at, get[at], next[at])
	}
}

func TestReadTLV(t *testing.T) {
	// short form: INTEGER 1
	tag, content, rest, err := readTLV([]byte{0x02, 0x01, 0x01, 0xFF})
	if err != nil || tag != 0x02 || !bytes.Equal(content, []byte{0x01}) || !bytes.Equal(rest, []byte{0xFF}) {
		t.Fatalf("short form: tag=%#x content=%x rest=%x err=%v", tag, content, rest, err)
	}
	// long form: OCTET STRING of 130 bytes -> length encoded as 0x81 0x82
	body := bytes.Repeat([]byte{0xAB}, 130)
	pkt := append([]byte{0x04, 0x81, 0x82}, body...)
	tag, content, _, err = readTLV(pkt)
	if err != nil || tag != 0x04 || len(content) != 130 {
		t.Fatalf("long form: tag=%#x len=%d err=%v", tag, len(content), err)
	}
	// truncated
	if _, _, _, err := readTLV([]byte{0x04, 0x05, 0x01}); err == nil {
		t.Fatal("expected error on truncated content")
	}
}

func TestDecodeOID(t *testing.T) {
	got := decodeOID([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x08})
	want := []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8} // ifOperStatus
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeOID=%v want %v", got, want)
	}
	// multi-byte arc: 1.3.6.1.4.1.9999  (9999 = 0xCE 0x0F base128)
	got = decodeOID([]byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xCE, 0x0F})
	want = []int{1, 3, 6, 1, 4, 1, 9999}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeOID multibyte=%v want %v", got, want)
	}
}

func TestDecodeValues(t *testing.T) {
	if v := decodeInt([]byte{0x01}); v != 1 {
		t.Errorf("decodeInt(1)=%d", v)
	}
	if v := decodeInt([]byte{0xFF}); v != -1 {
		t.Errorf("decodeInt(-1)=%d", v)
	}
	if v := decodeUint([]byte{0x01, 0x00}); v != 256 {
		t.Errorf("decodeUint(256)=%d", v)
	}
	if s := decodeIP([]byte{10, 20, 0, 1}); s != "10.20.0.1" {
		t.Errorf("decodeIP=%q", s)
	}
	if s := decodeIP([]byte{1, 2, 3}); s != "" {
		t.Errorf("decodeIP(bad len)=%q want empty", s)
	}
}

func TestFirstVarbind(t *testing.T) {
	oid := append(append([]int{}, oidIfOper...), 7) // ifOperStatus.7
	pkt := snmpResponse(oid, 0x02, []byte{0x01}, 42)
	gotOID, valTag, val, err := firstVarbind(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotOID, oid) {
		t.Errorf("oid=%v want %v", gotOID, oid)
	}
	if valTag != 0x02 || !bytes.Equal(val, []byte{0x01}) {
		t.Errorf("value tag=%#x val=%x", valTag, val)
	}
}

func TestOidHelpers(t *testing.T) {
	col := oidIfOper
	under := append(append([]int{}, col...), 12)
	if !oidUnder(under, col) {
		t.Error("oidUnder should be true for a row under the column")
	}
	if oidUnder(col, col) {
		t.Error("oidUnder should be false for the column itself")
	}
	if oidUnder(oidIfType, col) {
		t.Error("oidUnder should be false for a sibling column")
	}
	if s := oidSuffix(append(append([]int{}, col...), 3, 4), col); s != "3.4" {
		t.Errorf("oidSuffix=%q want 3.4", s)
	}
}

func TestIsTunnelIface(t *testing.T) {
	cases := []struct {
		f    iface
		ep   bool
		want bool
	}{
		{iface{name: "Tunnel0"}, false, true},
		{iface{name: "GigabitEthernet0/0"}, false, false},
		{iface{ifType: ifTypeTunnel, name: "ge-0/0/0.0"}, false, true},
		{iface{name: "ge-0/0/0"}, true, true}, // TUNNEL-MIB says it's a tunnel
		{iface{descr: "vti1"}, false, true},
		{iface{name: "lo0"}, false, false},
	}
	for i, c := range cases {
		if got := isTunnelIface(&c.f, c.ep); got != c.want {
			t.Errorf("case %d (%+v ep=%v): got %v want %v", i, c.f, c.ep, got, c.want)
		}
	}
}

func TestTunnelType(t *testing.T) {
	if got := tunnelType(&iface{name: "gre1"}, nil); got != "gre" {
		t.Errorf("gre name=%q", got)
	}
	if got := tunnelType(&iface{name: "Tunnel100"}, &endpoint{encaps: 3}); got != "gre" {
		t.Errorf("encaps gre=%q", got)
	}
	if got := tunnelType(&iface{descr: "ipsec-vti"}, nil); got != "ipsec" {
		t.Errorf("ipsec=%q", got)
	}
	if got := tunnelType(&iface{name: "Tunnel0"}, nil); got != "tunnel" {
		t.Errorf("default=%q", got)
	}
}

// TestSnmpWalkColumn drives the GetNext loop against a local UDP server that
// returns two rows then endOfMibView — verifying the walk records both rows,
// stops on the exception, and keys by the trailing OID index.
func TestSnmpWalkColumn(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	col := oidIfOper
	row1 := append(append([]int{}, col...), 1)
	row2 := append(append([]int{}, col...), 2)
	go func() {
		buf := make([]byte, 4096)
		hits := 0
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			var resp []byte
			switch hits {
			case 0:
				resp = snmpResponse(row1, 0x02, []byte{0x01}, 1) // up(1)
			case 1:
				resp = snmpResponse(row2, 0x02, []byte{0x02}, 2) // down(2)
			default:
				resp = snmpResponse(row2, tagEndOfMibView, nil, 3)
			}
			hits++
			_, _ = conn.WriteTo(resp, peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := snmpWalkColumn(ctx, conn.LocalAddr().String(), v2c("public"), col)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %v", len(got), got)
	}
	if got["1"].int() != 1 || got["2"].int() != 2 {
		t.Errorf("row values: 1=%d 2=%d want 1,2", got["1"].int(), got["2"].int())
	}
}
