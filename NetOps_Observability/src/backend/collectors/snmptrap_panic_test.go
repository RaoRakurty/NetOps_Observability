package collectors

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// snmptrap_panic_test.go — the trap listener takes UNAUTHENTICATED UDP and walks
// it with hand-rolled BER offset arithmetic. A panic there is remote, pre-auth
// termination of the whole API process, so the contract is: one poisoned packet
// costs that packet and nothing else. A panic in any case below fails the test
// by killing it.

func testTrapReceiver(targets TargetFunc) *trapReceiver {
	return &trapReceiver{
		addr:    "127.0.0.1:0",
		sinkURL: "http://127.0.0.1:1/",
		targets: targets,
		events:  make(chan *TrapEvent, 8),
		status:  Status{Name: "snmptrap", Kind: "trap", Healthy: true},
	}
}

func TestDecodePacketSurvivesMalformedTraps(t *testing.T) {
	valid := buildV2cTrap("public")
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"single byte", []byte{0x30}},
		{"sequence with no content", []byte{0x30, 0x00}},
		{"length longer than packet", []byte{0x30, 0x7f, 0x02, 0x01, 0x01}},
		{"long-form length past end", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02}},
		{"long-form length zero octets", []byte{0x30, 0x80, 0x02, 0x01, 0x01}},
		{"not a sequence", []byte{0x04, 0x02, 0x41, 0x42}},
		{"version only", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{"v3 claim, no security params", []byte{0x30, 0x03, 0x02, 0x01, 0x03}},
		{"all 0xff", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"all zeroes", make([]byte, 64)},
		{"valid packet", valid},
	}
	r := testTrapReceiver(func() []Target { return nil })
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := r.decodePacket(tc.pkt, "192.0.2.10")
			if err == nil && ev == nil {
				t.Fatal("decodePacket returned neither an event nor an error")
			}
			if err != nil && strings.Contains(err.Error(), "panicked") {
				t.Fatalf("decoder panicked: %v", err)
			}
		})
	}
}

// Every truncation and every single-byte mutation of a well-formed trap: the
// shapes a real attacker (or a lossy network) produces.
func TestDecodePacketSurvivesTruncationAndMutation(t *testing.T) {
	valid := buildV2cTrap("public")
	r := testTrapReceiver(func() []Target { return []Target{{ID: "core", Address: "192.0.2.10"}} })

	for i := 0; i <= len(valid); i++ {
		if _, err := r.decodePacket(valid[:i], "192.0.2.10"); err != nil && strings.Contains(err.Error(), "panicked") {
			t.Fatalf("decoder panicked on truncation at %d: %v", i, err)
		}
	}

	// Deterministic seed: a failure here must be reproducible.
	rng := rand.New(rand.NewPCG(1, 2))
	for n := 0; n < 2000; n++ {
		mutated := append([]byte(nil), valid...)
		for f := 0; f < 3; f++ {
			mutated[rng.IntN(len(mutated))] = byte(rng.IntN(256))
		}
		if _, err := r.decodePacket(mutated, "192.0.2.10"); err != nil && strings.Contains(err.Error(), "panicked") {
			t.Fatalf("decoder panicked on mutation %d: %v\npacket: %x", n, err, mutated)
		}
	}
}

// The guard itself: when something under the decoder DOES panic, the receiver
// must convert it into a per-packet error and keep listening — not die.
func TestDecodePacketConvertsPanicToError(t *testing.T) {
	boom := true
	r := testTrapReceiver(func() []Target {
		if boom {
			panic("simulated decoder fault")
		}
		return []Target{{ID: "core", Address: "192.0.2.10"}}
	})

	ev, err := r.decodePacket(buildV2cTrap("public"), "192.0.2.10")
	if err == nil {
		t.Fatal("expected an error from the panicking decode path")
	}
	if ev != nil {
		t.Fatal("no event may escape a panicking decode")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("error should name the panic: %v", err)
	}

	// …and the receiver is still fully usable afterwards.
	boom = false
	ev, err = r.decodePacket(buildV2cTrap("public"), "192.0.2.10")
	if err != nil {
		t.Fatalf("receiver unusable after a panicking packet: %v", err)
	}
	if ev.TrapName != "linkDown" || ev.Device != "core" {
		t.Fatalf("post-panic decode wrong: %+v", ev)
	}
}
