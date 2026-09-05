package protocoldiag

import (
	"context"
	"testing"
)

// TestValidateBoundedProbeAccepts — the shapes the owner's 2026-09-05 rule
// admits: one ping or traceroute per vendor spelling, every parameter inside
// the bound, with a destination.
func TestValidateBoundedProbeAccepts(t *testing.T) {
	for _, cmd := range []string{
		// Cisco IOS / IOS-XE / NX-OS
		"ping 192.0.2.1",
		"ping 192.0.2.1 repeat 5",
		"ping 192.0.2.1 repeat 5 size 1500 df-bit",
		"ping 192.0.2.1 vrf management",
		"ping 192.0.2.1 source-interface Loopback0",
		"traceroute 192.0.2.1",
		"traceroute 192.0.2.1 ttl 30 probe 3",
		// Arista EOS
		"ping 2001:db8::1 repeat 3 timeout 2",
		"ping6 2001:db8::1 repeat 2",
		// Junos
		"ping 192.0.2.1 count 5 do-not-fragment size 1400",
		"traceroute 192.0.2.1 no-resolve",
		// Nokia SR OS / SR Linux
		"ping 192.0.2.1 count 5 size 1400",
		"ping network-instance default 192.0.2.1 -c 2",
		// Huawei VRP
		"ping -c 5 -s 1400 192.0.2.1",
		"ping vpn-instance RED 192.0.2.1",
		// FortiOS
		"execute ping 192.0.2.1",
		"execute ping service.fortiguard.net",
		"execute traceroute 192.0.2.1",
		// PAN-OS
		"ping count 5 host 192.0.2.1",
		"traceroute host 192.0.2.1",
		// Unrendered templates (the loader validates these shapes too).
		"ping {peer}",
		"traceroute {prefix}",
		"ping {peer} size 1500 df-bit",
	} {
		if !IsProbeCommand(cmd) {
			t.Errorf("IsProbeCommand(%q) = false, want true", cmd)
		}
		if err := ValidateBoundedProbe(cmd); err != nil {
			t.Errorf("ValidateBoundedProbe(%q) = %v, want nil", cmd, err)
		}
	}
}

// TestValidateBoundedProbeRefuses — a probe is admitted as a QUESTION, never as
// a packet generator, and never without a destination.
func TestValidateBoundedProbeRefuses(t *testing.T) {
	for _, cmd := range []string{
		// No destination: a bare ping opens an interactive dialog on IOS.
		"ping",
		"ping count 5",
		"traceroute",
		"execute ping",
		// Over the bounds.
		"ping 192.0.2.1 repeat 100",
		"ping 192.0.2.1 count 1000",
		"ping 192.0.2.1 size 18000",
		"ping 192.0.2.1 timeout 600",
		"traceroute 192.0.2.1 ttl 255",
		"traceroute 192.0.2.1 probe 30",
		"ping 192.0.2.1 repeat 0",
		// Packet generators.
		"ping 192.0.2.1 flood",
		"ping -f 192.0.2.1",
		"ping 192.0.2.1 sweep 100 2000 1",
		"ping 192.0.2.1 count 5 rapid",
		"ping 192.0.2.1 pattern 0xdeadbeef",
		"ping 192.0.2.1 interval 0",
		"ping 192.0.2.1 -i 0",
		// Not a probe at all.
		"show ip route",
		"reload",
		"ping-options size 9000",
		// Structure.
		"ping 192.0.2.1; reload",
		"ping 192.0.2.1 | include ttl",
		"ping $(hostname)",
		"ping 192.0.2.1 > /tmp/x",
		// A number with no keyword: which parameter it is cannot be told.
		"ping 192.0.2.1 100",
		// A keyword with no value.
		"ping 192.0.2.1 count",
		"ping 192.0.2.1 vrf",
	} {
		if err := ValidateBoundedProbe(cmd); err == nil {
			t.Errorf("ValidateBoundedProbe(%q) = nil, want a refusal", cmd)
		}
	}
}

// TestProbeIsNotAReadOnlyShow keeps the two grammars separate: admitting a probe
// must never have widened ValidateReadOnly, which is what every other caller in
// this package relies on.
func TestProbeIsNotAReadOnlyShow(t *testing.T) {
	for _, cmd := range []string{"ping 192.0.2.1", "traceroute 192.0.2.1", "execute ping 192.0.2.1"} {
		if err := ValidateReadOnly(cmd); err == nil {
			t.Errorf("ValidateReadOnly(%q) = nil; the read-only grammar must not admit a probe", cmd)
		}
	}
	if IsProbeCommand("show ip route") {
		t.Error("a show was mistaken for a probe")
	}
}

// TestProbeBoundsAreTheDocumentedOnes pins the numbers the owner's rule names,
// so widening one is a deliberate, visible edit.
func TestProbeBoundsAreTheDocumentedOnes(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"count", MaxProbeCount, 5},
		{"size", MaxProbeSize, 1500},
		{"timeout", MaxProbeTimeoutSeconds, 5},
		{"hops", MaxProbeHops, 30},
		{"probes", MaxProbeProbes, 3},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s bound is %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestSSHRunnerAdmitsOnlyAGatedProbe proves the widening at the runner does not
// widen what a caller can run: the closed table still has to contain it. A gate
// that authored no probe template refuses one; a gate that did, admits it.
func TestSSHRunnerAdmitsOnlyAGatedProbe(t *testing.T) {
	dev := Device{ID: "d1", Hostname: "core-01", Platform: "Cisco IOS-XE 17.9", Address: "192.0.2.9"}
	gw := probeGateway{}

	noProbes, err := NewSSHGatedRunner(probeTestGate{}, gw)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if _, err := noProbes.Run(context.Background(), dev, "ping 192.0.2.1"); err == nil {
		t.Fatal("a runner whose table has no probe template ran one")
	}

	withProbe, err := NewSSHGatedRunner(probeTestGate{allow: "ping 192.0.2.1"}, gw)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if _, err := withProbe.Run(context.Background(), dev, "ping 192.0.2.1"); err != nil {
		t.Fatalf("a gated, in-bounds probe was refused: %v", err)
	}
	// Even a gate that allows it cannot get an out-of-bounds probe through: the
	// shape check runs first.
	flood, err := NewSSHGatedRunner(probeTestGate{allow: "ping 192.0.2.1 flood"}, gw)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if _, err := flood.Run(context.Background(), dev, "ping 192.0.2.1 flood"); err == nil {
		t.Fatal("a flood was admitted because its gate allowed it")
	}
}

// probeTestGate allows exactly one command string and nothing else.
type probeTestGate struct{ allow string }

func (g probeTestGate) Allows(_ Device, command string) bool {
	return g.allow != "" && command == g.allow
}
func (g probeTestGate) Name() string { return "probe test gate" }

// probeGateway is an in-memory Gateway: it never opens a socket.
type probeGateway struct{}

func (probeGateway) Run(_ context.Context, _ Device, command string, _ int64) (string, error) {
	return "ran: " + command, nil
}
