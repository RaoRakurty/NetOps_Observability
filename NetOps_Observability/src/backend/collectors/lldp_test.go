package collectors

import "testing"

// The composite remote-table index is "timeMark.localPortNum.remIndex"; we must
// pull the MIDDLE arc to map a neighbour to its local port. Getting this wrong
// silently attaches every neighbour to the wrong port (or none).
func TestLLDPLocalPortNum(t *testing.T) {
	cases := map[string]string{
		"0.7.1":        "7",
		"1234567.10.3": "10",
		"0.1.1":        "1",
		"7":            "", // malformed: missing arcs
		"7.1":          "", // malformed: only two arcs
		"":             "",
	}
	for suffix, want := range cases {
		if got := lldpLocalPortNum(suffix); got != want {
			t.Errorf("lldpLocalPortNum(%q) = %q, want %q", suffix, got, want)
		}
	}
}

// Chassis/Port IDs render by subtype, and CRUCIALLY the chassis and port subtype
// enums differ: subtype 5 = networkAddress for a chassis but interfaceName for a
// port. Mixing them renders "Ethernet1" as hex (or a MAC as mojibake).
func TestLLDPRenderChassisAndPort(t *testing.T) {
	macRaw := berVal{raw: []byte{0x0c, 0x00, 0x84, 0x2b, 0x3c, 0x00}}

	// chassis macAddress = subtype 4
	if got := lldpRenderChassis(macRaw, berVal{raw: []byte{4}}); got != "0c:00:84:2b:3c:00" {
		t.Errorf("chassis mac = %q", got)
	}
	// chassis networkAddress = subtype 5 → dotted IPv4 (family octet + addr)
	if got := lldpRenderChassis(berVal{raw: []byte{1, 10, 0, 0, 5}}, berVal{raw: []byte{5}}); got != "10.0.0.5" {
		t.Errorf("chassis networkAddress = %q, want 10.0.0.5", got)
	}
	// chassis local = subtype 7 → the hostname string (common on cEOS/SR Linux)
	if got := lldpRenderChassis(berVal{raw: []byte("spine1")}, berVal{raw: []byte{7}}); got != "spine1" {
		t.Errorf("chassis local = %q, want spine1", got)
	}

	// port macAddress = subtype 3 (NOT 4)
	if got := lldpRenderPort(macRaw, berVal{raw: []byte{3}}); got != "0c:00:84:2b:3c:00" {
		t.Errorf("port mac = %q", got)
	}
	// port interfaceName = subtype 5 → the string (this is the chassis/port clash)
	if got := lldpRenderPort(berVal{raw: []byte("Ethernet1")}, berVal{raw: []byte{5}}); got != "Ethernet1" {
		t.Errorf("port ifName = %q, want Ethernet1", got)
	}
	// port local = subtype 7 → the string
	if got := lldpRenderPort(berVal{raw: []byte("ge-0/0/1")}, berVal{raw: []byte{7}}); got != "ge-0/0/1" {
		t.Errorf("port local = %q", got)
	}
	// empty → empty
	if got := lldpRenderChassis(berVal{}, berVal{raw: []byte{4}}); got != "" {
		t.Errorf("empty chassis = %q, want empty", got)
	}
}

func TestIsPrintableASCII(t *testing.T) {
	if !isPrintableASCII([]byte("Ethernet1/1")) {
		t.Error("Ethernet1/1 should be printable")
	}
	if isPrintableASCII([]byte{0x0c, 0x00, 0x84}) {
		t.Error("MAC bytes should not be printable")
	}
	if isPrintableASCII(nil) {
		t.Error("empty should not be printable")
	}
}
