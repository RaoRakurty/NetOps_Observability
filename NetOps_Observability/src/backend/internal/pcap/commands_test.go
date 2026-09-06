// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"errors"
	"strings"
	"testing"
)

// commands_test.go — the rendering half of the injection boundary. The grammar
// proves the input is clean; these tests prove the TEMPLATES cannot be made to
// carry a caller construct even so, on every supported platform.

const testCaptureID = "0123456789abcdef0123456789abcdef"

func testRequest(iface, filter string) CommandRequest {
	return CommandRequest{
		Interface: iface, File: captureFileName(testCaptureID), Name: captureName(testCaptureID),
		DurationSec: 30, MaxPackets: 100, MaxBytes: MaxBytes, Filter: filter,
	}
}

func TestCommandTableRendersEverySupportedPlatform(t *testing.T) {
	table := NewProfileCommandTable()
	for _, tc := range []struct {
		platform string
		wantKey  string
		needle   string
	}{
		{"cisco IOS-XE", "cisco_iosxe", "monitor capture"},
		{"cisco NX-OS", "cisco_nxos", "ethanalyzer"},
		{"juniper JUNOS", "juniper_junos", "monitor traffic"},
		{"arista EOS", "arista_eos", "tcpdump"},
	} {
		key, _, ok := table.Supports(tc.platform)
		if !ok || key != tc.wantKey {
			t.Fatalf("Supports(%q) = (%q, %v), want %q", tc.platform, key, ok, tc.wantKey)
		}
		set, err := table.For(tc.platform, testRequest("Ethernet1/1", ""))
		if err != nil {
			t.Fatalf("For(%q) = %v", tc.platform, err)
		}
		if len(set.Start) == 0 {
			t.Fatalf("%s rendered no start command", tc.platform)
		}
		if !strings.Contains(strings.Join(set.Start, " "), tc.needle) {
			t.Fatalf("%s start commands %v do not use %q", tc.platform, set.Start, tc.needle)
		}
		if set.RemotePath == "" {
			t.Fatalf("%s declared no remote path", tc.platform)
		}
		if len(set.Cleanup) == 0 {
			t.Fatalf("%s declared NO cleanup — a capture point could be left on a production interface", tc.platform)
		}
	}
}

func TestCommandTableRefusesUnknownPlatform(t *testing.T) {
	table := NewProfileCommandTable()
	if _, _, ok := table.Supports("acme-networks SomeOS"); ok {
		t.Fatal("an unknown platform reported as supported — a guessed command would reach a live device")
	}
	if _, err := table.For("acme-networks SomeOS", testRequest("eth0", "")); err == nil {
		t.Fatal("For() rendered a command for an unknown platform")
	}
}

// shellMeta are the bytes that mean something to a shell or a device CLI. Not
// one of them may appear in ANY rendered command beyond the constants the
// templates themselves contain.
var shellMeta = []string{";", "|", "&", "$", "`", "\n", "\r", ">", "<", "\\", "*", "?", "#", "{", "}", "[", "]", "!"}

func TestRenderedCommandsNeverCarryUnescapedUserInput(t *testing.T) {
	table := NewProfileCommandTable()
	// Every filter here is one the GRAMMAR accepts, rendered on every platform
	// that claims filter support. The assertion is that the resulting command
	// line contains no shell-meaningful byte at all.
	filters := []string{"", "host 10.1.2.3", "tcp and port 22", "(tcp and port 80) or udp", "net 10.0.0.0/8 and not port 22"}
	ifaces := []string{"Ethernet1/1", "ge-0/0/0.100", "GigabitEthernet0/0/1", "xe-0/0/0:1"}
	for _, platform := range PlatformKeys() {
		_, supportsFilter, _ := table.Supports(platform)
		for _, f := range filters {
			if f != "" && !supportsFilter {
				// The platform must REFUSE, not silently widen the capture.
				if _, err := table.For(platform, testRequest("Ethernet1/1", f)); err == nil {
					t.Errorf("%s accepted a filter it cannot express — the capture would silently be wider than asked", platform)
				}
				continue
			}
			for _, iface := range ifaces {
				set, err := table.For(platform, testRequest(iface, f))
				if err != nil {
					t.Fatalf("For(%s, %q, %q) = %v", platform, iface, f, err)
				}
				cmds := append(append(append([]string{}, set.Start...), set.Stop...), set.Cleanup...)
				cmds = append(cmds, set.RemotePath)
				for _, cmd := range cmds {
					for _, meta := range shellMeta {
						if strings.Contains(cmd, meta) {
							t.Errorf("%s rendered a command containing %q with iface=%q filter=%q: %s",
								platform, meta, iface, f, cmd)
						}
					}
				}
			}
		}
	}
}

// TestRenderedCommandsRejectUnvalidatedInputAtTheTable is the defence-in-depth
// assertion: even a caller that BYPASSES the manager and reaches a table
// directly cannot get a hostile value rendered.
func TestRenderedCommandsRejectUnvalidatedInputAtTheTable(t *testing.T) {
	table := NewProfileCommandTable()
	for _, iface := range []string{"eth0; reboot", "eth0 && id", "eth0`id`", "eth0$(id)", "eth0\nreload"} {
		if _, err := table.For("cisco_nxos", testRequest(iface, "")); err == nil {
			t.Errorf("INJECTION ACCEPTED at the table: interface %q rendered", iface)
		}
	}
	for _, f := range injectionCanaries {
		req := testRequest("Ethernet1/1", f)
		if _, err := table.For("cisco_nxos", req); err == nil {
			t.Errorf("INJECTION ACCEPTED at the table: filter %q rendered", f)
		}
	}
	// A file name that was not minted by this package is refused: it becomes an
	// on-device path.
	bad := testRequest("Ethernet1/1", "")
	bad.File = "../../etc/passwd"
	if _, err := table.For("cisco_nxos", bad); err == nil {
		t.Fatal("INJECTION ACCEPTED at the table: an unminted capture file name rendered")
	}
}

func TestIOSXERefusesAFilterItCannotExpress(t *testing.T) {
	table := NewProfileCommandTable()
	key, supports, ok := table.Supports("cisco IOS-XE")
	if !ok || key != "cisco_iosxe" {
		t.Fatalf("Supports(cisco IOS-XE) = (%q, %v, %v)", key, supports, ok)
	}
	if supports {
		t.Fatal("IOS-XE Embedded Packet Capture has no pcap-filter syntax; claiming support would silently widen captures")
	}
	if _, err := table.For("cisco IOS-XE", testRequest("GigabitEthernet0/0/1", "host 10.1.2.3")); !errors.Is(err, ErrFilterUnsupported) {
		t.Fatalf("For(IOS-XE, filtered) = %v, want ErrFilterUnsupported", err)
	}
}

func TestRenderedCommandsCarryTheBounds(t *testing.T) {
	table := NewProfileCommandTable()
	req := testRequest("Ethernet1/1", "")
	req.MaxPackets = 77
	req.DurationSec = 11
	set, err := table.For("cisco_nxos", req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(set.Start[0], "limit-captured-frames 77") {
		t.Fatalf("the packet bound is not in the rendered command: %q", set.Start[0])
	}
	// A caller that reaches the table with an out-of-range bound gets it CLAMPED
	// at the table too (the manager refuses first, but the table is the second
	// line and must never render an unbounded capture).
	req.MaxPackets = MaxPackets * 100
	req.DurationSec = 100000
	set, err = table.For("arista_eos", req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(set.Start[0], "100000") {
		t.Fatalf("an out-of-range duration reached the rendered command: %q", set.Start[0])
	}
	if !strings.Contains(set.Start[0], "-c 10000") {
		t.Fatalf("the packet bound was not clamped to MaxPackets: %q", set.Start[0])
	}
}
