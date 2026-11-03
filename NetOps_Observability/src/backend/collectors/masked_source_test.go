// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"errors"
	"strings"
	"testing"
)

// A container on the compose bridge (gateway 172.18.0.1), as the kernel prints it.
const bridgeRoutes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"

func routes(s string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(s), nil }
}

func TestDefaultGatewaysReadsTheBridgeGateway(t *testing.T) {
	gws := defaultGateways([]byte(bridgeRoutes))
	if len(gws) != 1 || gws[0].String() != "172.18.0.1" {
		t.Fatalf("gateways = %v, want [172.18.0.1]", gws)
	}
}

func TestDefaultGatewaysSkipsNonDefaultAndMalformedRows(t *testing.T) {
	raw := "header\n" +
		"eth0\t000012AC\t010012AC\t0003\n" + // not a default route
		"eth0\t00000000\t00000000\t0001\n" + // default, no RTF_GATEWAY
		"eth0\t00000000\tZZZZ\t0003\n" + // bad hex
		"eth0\t00000000\n" + // short
		"eth1\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" // a second default
	gws := defaultGateways([]byte(raw))
	if len(gws) != 1 || gws[0].String() != "192.168.1.1" {
		t.Fatalf("gateways = %v, want only the well-formed default 192.168.1.1", gws)
	}
}

func TestTheDetectorFlagsOnlyTheGateway(t *testing.T) {
	d, note := newMaskedSourceDetector("docker-bridge", routes(bridgeRoutes))
	if note != "" {
		t.Fatalf("unexpected note %q", note)
	}
	for src, want := range map[string]bool{
		"172.18.0.1":        true,
		"::ffff:172.18.0.1": true, // IPv4-mapped: the same gateway
		" 172.18.0.1 ":      true,
		"192.168.200.33":    false, // a real sender
		"172.18.0.21":       false, // another container is not the gateway
		"":                  false,
		"not-an-ip":         false,
	} {
		if got := d.masked(src); got != want {
			t.Errorf("masked(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestTheDetectorIsOffUnlessTheDeploymentSaysDockerBridge(t *testing.T) {
	for _, mode := range []string{"", "off", "host", "DOCKER-BRIDGE"} {
		d, note := newMaskedSourceDetector(mode, routes(bridgeRoutes))
		if d.masked("172.18.0.1") || note != "" {
			t.Errorf("mode %q: masked=%v note=%q — on host networking the gateway is a real router",
				mode, d.masked("172.18.0.1"), note)
		}
	}
}

func TestTheDetectorSaysWhyItIsOff(t *testing.T) {
	d, note := newMaskedSourceDetector("docker-bridge", func() ([]byte, error) { return nil, errors.New("eperm") })
	if d.masked("172.18.0.1") || !strings.Contains(note, "cannot read the routing table") {
		t.Fatalf("unreadable table: masked=%v note=%q", d.masked("172.18.0.1"), note)
	}
	d, note = newMaskedSourceDetector("docker-bridge", routes("Iface\tDestination\tGateway\n"))
	if d.masked("172.18.0.1") || !strings.Contains(note, "no default gateway") {
		t.Fatalf("no default route: masked=%v note=%q", d.masked("172.18.0.1"), note)
	}
}

func TestTheZeroDetectorDetectsNothing(t *testing.T) {
	var d maskedSourceDetector
	if d.masked("172.18.0.1") {
		t.Fatal("the zero value must detect nothing")
	}
}

func TestMaskedTrapErrorNamesTheRemedy(t *testing.T) {
	msg := maskedTrapError(3)
	for _, want := range []string{"3 trap(s)", "bridge gateway", "host==container", "ingest-sender-address-masked.md"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

func FuzzDefaultGateways(f *testing.F) {
	f.Add([]byte(bridgeRoutes))
	f.Add([]byte("x\n\t00000000\t\t\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, gw := range defaultGateways(raw) {
			if gw.To4() == nil || gw.IsUnspecified() {
				t.Fatalf("parser returned a non-IPv4 or unspecified gateway %v", gw)
			}
		}
	})
}

func TestTheReceiverStampsAMaskedTrapAndSaysSo(t *testing.T) {
	d, _ := newMaskedSourceDetector("docker-bridge", routes(bridgeRoutes))
	r := &trapReceiver{masks: d, status: Status{Name: "snmptrap"}}

	masked := &TrapEvent{Host: "172.18.0.1"}
	r.recordDecoded(masked, "172.18.0.1")
	if !masked.SourceMasked || !strings.Contains(r.Status().LastError, "1 trap(s)") {
		t.Fatalf("masked trap: stamped=%v status=%q", masked.SourceMasked, r.Status().LastError)
	}

	genuine := &TrapEvent{Host: "192.168.200.33"}
	r.recordDecoded(genuine, "192.168.200.33")
	if genuine.SourceMasked || r.Status().LastError != "" {
		t.Fatalf("real sender: stamped=%v status=%q — a real trap clears the note", genuine.SourceMasked, r.Status().LastError)
	}
	if r.Status().Reachable != 2 {
		t.Fatalf("decoded = %d, want 2", r.Status().Reachable)
	}
}

func TestTheReceiverWithoutDetectionNeverStamps(t *testing.T) {
	r := &trapReceiver{status: Status{Name: "snmptrap"}}
	ev := &TrapEvent{}
	r.recordDecoded(ev, "172.18.0.1")
	if ev.SourceMasked {
		t.Fatal("detection off must never stamp")
	}
}
