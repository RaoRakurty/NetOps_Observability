package collectors

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// oncePoller is the poll-cycle seam both discovery collectors expose in-package.
type oncePoller interface {
	Collector
	pollOnce(ctx context.Context)
}

// Characterization of the CDP/LLDP poll-cycle harness (#147 T4): the two
// collectors must report identical cycle semantics — a collector with no
// targets is healthy-and-idle; a device that ANSWERS but has no neighbours
// counts as answered (healthy) yet not reachable; a device whose walk fails
// makes the cycle unhealthy and surfaces the partial-blackout error.
func TestNeighborPollCycleHarness(t *testing.T) {
	// A local "agent" that answers every request with endOfMibView: the device
	// answers fine but reports no neighbours.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			_, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(snmpResponse([]int{1, 3, 6, 1}, tagEndOfMibView, nil, 1), peer)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, mk := range map[string]func(TargetFunc) Collector{"cdp": NewCDP, "lldp": NewLLDP} {
		t.Run(name+"/no targets is healthy-and-idle", func(t *testing.T) {
			c := mk(func() []Target { return nil }).(oncePoller)
			c.pollOnce(ctx)
			st := c.Status()
			if !st.Healthy || st.Targets != 0 || st.Reachable != 0 || st.LastError != "" {
				t.Fatalf("empty cycle status: %+v", st)
			}
			if st.LastTick.IsZero() {
				t.Fatal("LastTick must be stamped by the cycle")
			}
		})
		t.Run(name+"/answered with no neighbours is healthy", func(t *testing.T) {
			tg := Target{ID: "dev1", Address: conn.LocalAddr().String()}
			c := mk(func() []Target { return []Target{tg} }).(oncePoller)
			c.pollOnce(ctx)
			st := c.Status()
			if !st.Healthy || st.Targets != 1 || st.LastError != "" {
				t.Fatalf("answered-empty cycle status: %+v", st)
			}
			if st.Reachable != 0 {
				t.Fatalf("no neighbours must not count as reachable: %+v", st)
			}
		})
		t.Run(name+"/failed walk degrades the cycle", func(t *testing.T) {
			tg := Target{ID: "dev1", Address: "bad host"} // invalid name: dial fails fast
			c := mk(func() []Target { return []Target{tg} }).(oncePoller)
			c.pollOnce(ctx)
			st := c.Status()
			if st.Healthy {
				t.Fatalf("a full blackout must be unhealthy: %+v", st)
			}
			if !strings.Contains(st.LastError, "1/1 targets did not answer") {
				t.Fatalf("cycle error not surfaced: %+v", st)
			}
		})
	}
}

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
