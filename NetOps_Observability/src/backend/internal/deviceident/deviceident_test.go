// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package deviceident

// deviceident_test.go — the per-vendor extraction, against the SHIPPED profile
// data.
//
// These tests deliberately use the real registry rather than a hand-built one:
// the thing most likely to break is not this Go code but the authored patterns,
// and a fixture that is the real command's real output is the only way to find
// that out before a device does (the same reasoning
// internal/osprobe/sources_test.go records).

import (
	"strings"
	"testing"

	"netops/backend/internal/vendorprofile"
)

// bind resolves a platform and the authored binding for one command, failing the
// test when the shipped data does not carry them — a profile edit that drops a
// binding must fail HERE, naming the row, not somewhere downstream.
func bind(t *testing.T, platform, command string) (vendorprofile.Profile, vendorprofile.IdentityCommand) {
	t.Helper()
	reg := vendorprofile.Default()
	p, probe, ok := reg.IdentityProbeForPlatformID(platform)
	if !ok {
		t.Fatalf("no identity probe for platform %q", platform)
	}
	c, ok := BindCommand(probe, command)
	if !ok {
		t.Fatalf("platform %q binds no identity patterns to %q", platform, command)
	}
	return p, c
}

func extract(t *testing.T, platform, command, output string) Identity {
	t.Helper()
	p, c := bind(t, platform, command)
	got, err := NewExtractor(vendorprofile.Default()).FromOutput(p.ID, c, command, output)
	if err != nil {
		t.Fatalf("FromOutput(%s, %q): %v", platform, command, err)
	}
	return got
}

// TestPerVendorExtraction is the coverage table: one row per (platform,
// command) binding the registry ships, asserting the EXACT serial and model the
// fixture's device printed.
func TestPerVendorExtraction(t *testing.T) {
	cases := []struct {
		name       string
		platform   string
		command    string
		output     string
		wantSerial string
		wantModel  string
	}{
		{"cisco/ios_xe show version", "cisco/ios_xe", "show version", showVersionIOSXE,
			"FOC2130Z0RD", "C9300-48P"},
		{"cisco/ios_xe show inventory", "cisco/ios_xe", "show inventory", showInventoryIOSXE,
			"FOC2130Z0RD", "C9300-48P"},
		{"cisco/ios show version", "cisco/ios", "show version", showVersionIOS,
			"FTX1840ALBS", "ISR4331/K9"},
		{"cisco/nx-os show version", "cisco/nx-os", "show version", showVersionNXOS,
			"FDO21120U5D", "C93180YC-FX3"},
		{"cisco/ios_xr show inventory", "cisco/ios_xr", "show inventory", showInventoryIOSXR,
			"FOX1441GPWM", "ASR-9006-AC-V2"},
		{"arista/eos show version", "arista/eos", "show version", showVersionEOS,
			"JPE19141ABC", "DCS-7050SX3-48YC8-F"},
		{"juniper/junos show chassis hardware", "juniper/junos", "show chassis hardware", showChassisHardwareJunos,
			"JN123456AB", ""},
		{"juniper/junos show version", "juniper/junos", "show version", showVersionJunos,
			"", "mx204"},
		{"nokia/srlinux show version", "nokia/srlinux", "show version", showVersionSRLinux,
			"Sim Serial No.", "7220 IXR-D3L"},
		{"nokia/sros show chassis", "nokia/sros", "show chassis", showChassisSROS,
			"NS1234C5678", "7750 SR-12"},
		{"paloalto/pan-os show system info", "paloalto/pan-os", "show system info", showSystemInfoPANOS,
			"001801000123", "PA-3220"},
		{"fortinet/fortios get system status", "fortinet/fortios", "get system status", getSystemStatusFortiOS,
			"FG100FTK20000123", "FortiGate-100F"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extract(t, tc.platform, tc.command, tc.output)
			if got.Serial != tc.wantSerial {
				t.Errorf("serial = %q, want %q", got.Serial, tc.wantSerial)
			}
			if got.Model != tc.wantModel {
				t.Errorf("model = %q, want %q", got.Model, tc.wantModel)
			}
			if got.Serial != "" && got.SerialCommand != tc.command {
				t.Errorf("serial_command = %q, want %q", got.SerialCommand, tc.command)
			}
			if got.Model != "" && got.ModelCommand != tc.command {
				t.Errorf("model_command = %q, want %q", got.ModelCommand, tc.command)
			}
			if !got.Empty() && got.ProfileID != tc.platform {
				t.Errorf("profile_id = %q, want %q", got.ProfileID, tc.platform)
			}
		})
	}
}

// TestCiscoInventoryReadsTheChassisNotTheFirstAccessory — `show inventory` lists
// every FRU. The chassis is the FIRST entry and the one the row is about; a
// pattern that matched the power supply's serial would put an accessory's
// identity on the device.
func TestCiscoInventoryReadsTheChassisNotTheFirstAccessory(t *testing.T) {
	got := extract(t, "cisco/ios_xe", "show inventory", showInventoryIOSXE)
	if got.Serial != "FOC2130Z0RD" || got.Model != "C9300-48P" {
		t.Fatalf("got (%q, %q), want the CHASSIS entry (FOC2130Z0RD, C9300-48P)", got.Serial, got.Model)
	}
	if strings.Contains(got.Serial, "LIT") || strings.Contains(got.Model, "PWR") {
		t.Fatalf("read the power supply's inventory row: %+v", got)
	}
}

// TestNXOSModelIsNotTheBIOSOrTheImage — the NX-OS Software block carries two
// version lines and an image path; none of them is a chassis model.
func TestNXOSModelIsNotTheBIOSOrTheImage(t *testing.T) {
	got := extract(t, "cisco/nx-os", "show version", showVersionNXOS)
	if got.Model != "C93180YC-FX3" {
		t.Fatalf("model = %q, want the Hardware block's chassis", got.Model)
	}
}

// TestFortiOSModelIsNotTheFirmware — the FortiOS Version line carries the model
// and the firmware in one string. Capturing the firmware as the model would put
// `v7.2.5,build1517,230606` in the inventory's model column.
func TestFortiOSModelIsNotTheFirmware(t *testing.T) {
	got := extract(t, "fortinet/fortios", "get system status", getSystemStatusFortiOS)
	if got.Model != "FortiGate-100F" {
		t.Fatalf("model = %q, want FortiGate-100F", got.Model)
	}
	if strings.Contains(got.Model, "build") || strings.HasPrefix(got.Model, "v") {
		t.Fatalf("captured the firmware as the model: %q", got.Model)
	}
}

// ── the invariant: never fabricate ──────────────────────────────────────────

// TestUnparseableOutputLeavesTheIdentityUnset is THE test this feature has to
// pass. Output a parser does not recognize — a rejected command, a truncated
// capture, a block of labels with no values, another platform's output entirely
// — must yield an EMPTY Identity, never a token lifted off a line that happened
// to look right.
func TestUnparseableOutputLeavesTheIdentityUnset(t *testing.T) {
	platforms := []struct{ platform, command string }{
		{"cisco/ios_xe", "show version"},
		{"cisco/ios_xe", "show inventory"},
		{"cisco/ios", "show version"},
		{"cisco/nx-os", "show version"},
		{"cisco/ios_xr", "show inventory"},
		{"arista/eos", "show version"},
		{"juniper/junos", "show version"},
		{"juniper/junos", "show chassis hardware"},
		{"nokia/srlinux", "show version"},
		{"nokia/sros", "show chassis"},
		{"paloalto/pan-os", "show system info"},
		{"fortinet/fortios", "get system status"},
	}
	outputs := []struct{ name, text string }{
		{"garbage", garbageOutput},
		{"truncated", truncatedIOSXE},
		{"labels with no values", labelsWithNoValues},
		{"empty", ""},
		{"whitespace", "\n\n   \n\t\n"},
	}
	for _, p := range platforms {
		for _, o := range outputs {
			got := extract(t, p.platform, p.command, o.text)
			if !got.Empty() {
				t.Errorf("%s / %s on %s: invented %+v — unrecognized output must leave the identity UNSET",
					p.platform, p.command, o.name, got)
			}
		}
	}
}

// TestAnotherPlatformsOutputIsNotRead — the platforms whose labels are close
// enough to collide. Reading a Junos chassis table with the Nokia patterns (or
// the reverse) must produce nothing, not a plausible-looking wrong answer.
func TestAnotherPlatformsOutputIsNotRead(t *testing.T) {
	cases := []struct{ platform, command, output, name string }{
		{"nokia/srlinux", "show version", showVersionEOS, "EOS banner through SR Linux patterns"},
		{"arista/eos", "show version", showVersionSRLinux, "SR Linux banner through EOS patterns"},
		{"paloalto/pan-os", "show system info", getSystemStatusFortiOS, "FortiOS status through PAN-OS patterns"},
		{"cisco/ios_xr", "show inventory", showChassisHardwareJunos, "Junos chassis table through Cisco inventory patterns"},
	}
	for _, tc := range cases {
		got := extract(t, tc.platform, tc.command, tc.output)
		if !got.Empty() {
			t.Errorf("%s: read %+v out of another platform's output", tc.name, got)
		}
	}
}

// TestOversizedOutputIsRefusedNotScanned — §9. A blob over the cap means
// something upstream skipped its own bound; it is refused with an error rather
// than scanned or silently truncated.
func TestOversizedOutputIsRefusedNotScanned(t *testing.T) {
	p, c := bind(t, "arista/eos", "show version")
	big := strings.Repeat("x", MaxOutputBytes+1)
	if _, err := NewExtractor(vendorprofile.Default()).FromOutput(p.ID, c, "show version", big); err == nil {
		t.Fatal("an output over the cap was accepted")
	}
}

// TestOverlongValueIsRefusedNotTruncated — half a serial is not a serial.
func TestOverlongValueIsRefusedNotTruncated(t *testing.T) {
	long := "Serial number: " + strings.Repeat("A", MaxSerialBytes+1) + "\n"
	got := extract(t, "arista/eos", "show version", "Arista DCS-7050SX3-48YC8-F\n"+long)
	if got.Serial != "" {
		t.Fatalf("serial = %q, want it refused for length", got.Serial)
	}
	if got.Model != "DCS-7050SX3-48YC8-F" {
		t.Fatalf("model = %q — a refused serial must not suppress the model", got.Model)
	}
}

// ── the capture-side seam ───────────────────────────────────────────────────

// TestFromCaptureWalksAFinishedCollection — the seam a TAC collection is walked
// through: (command, output, platform) triples in, one identity out.
func TestFromCaptureWalksAFinishedCollection(t *testing.T) {
	got := FromCapture([]CapturedCommand{
		{Command: "show interfaces status", Output: "Port  Name  Status", Platform: "cisco-iosxe"},
		{Command: "show version", Output: showVersionIOSXE, Platform: "cisco-iosxe"},
		{Command: "show inventory", Output: showInventoryIOSXE, Platform: "cisco-iosxe"},
	})
	if got.Serial != "FOC2130Z0RD" || got.Model != "C9300-48P" {
		t.Fatalf("got (%q, %q), want (FOC2130Z0RD, C9300-48P)", got.Serial, got.Model)
	}
	if got.SerialCommand != "show version" {
		t.Errorf("serial_command = %q, want the FIRST capture that answered", got.SerialCommand)
	}
	if got.ProfileID != "cisco/ios_xe" {
		t.Errorf("profile_id = %q, want cisco/ios_xe", got.ProfileID)
	}
}

// TestFromCaptureAcceptsThePlanIdSpellings — a collection labels itself with the
// TAC plan id ("cisco-iosxe"), the canonical profile id ("cisco/ios_xe") or a
// free-form label; all three name the same platform and none may be read with
// another platform's patterns. The IOS-XR case is the one that matters: a
// SUBSTRING table would resolve "cisco-iosxr" onto cisco/ios (which owns the
// bare token "cisco") and read an IOS-XR capture with IOS patterns.
func TestFromCaptureAcceptsThePlanIdSpellings(t *testing.T) {
	for _, platform := range []string{"cisco-iosxe", "cisco/ios_xe", "cisco_ios_xe", "Cisco IOS-XE 17.9"} {
		got := FromCapture([]CapturedCommand{{Command: "show version", Output: showVersionIOSXE, Platform: platform}})
		if got.Serial != "FOC2130Z0RD" {
			t.Errorf("platform %q: serial = %q, want FOC2130Z0RD", platform, got.Serial)
		}
	}
	xr := FromCapture([]CapturedCommand{{Command: "show inventory", Output: showInventoryIOSXR, Platform: "cisco-iosxr"}})
	if xr.ProfileID != "cisco/ios_xr" {
		t.Fatalf("cisco-iosxr resolved to %q, want cisco/ios_xr", xr.ProfileID)
	}
	if xr.Serial != "FOX1441GPWM" {
		t.Errorf("serial = %q, want FOX1441GPWM", xr.Serial)
	}
}

// TestFromCaptureIgnoresWhatItCannotGround — an unknown platform, an unbound
// command and a bound command whose output is unrecognized each contribute
// NOTHING. A collection that teaches the platform nothing must leave the row
// alone rather than filling it with the nearest match.
func TestFromCaptureIgnoresWhatItCannotGround(t *testing.T) {
	cases := []struct {
		name string
		cmds []CapturedCommand
	}{
		{"unknown platform", []CapturedCommand{
			{Command: "show version", Output: showVersionIOSXE, Platform: "acme-netos"}}},
		{"no platform at all", []CapturedCommand{
			{Command: "show version", Output: showVersionIOSXE, Platform: ""}}},
		{"unbound command", []CapturedCommand{
			{Command: "show running-config", Output: showVersionIOSXE, Platform: "cisco-iosxe"}}},
		{"bound command, unrecognized output", []CapturedCommand{
			{Command: "show version", Output: garbageOutput, Platform: "cisco-iosxe"}}},
		{"platform with no identity probe", []CapturedCommand{
			{Command: "display version", Output: showVersionIOSXE, Platform: "huawei-vrp"}}},
		{"nothing collected", nil},
	}
	for _, tc := range cases {
		if got := FromCapture(tc.cmds); !got.Empty() {
			t.Errorf("%s: invented %+v", tc.name, got)
		}
	}
}

// TestFromCaptureBindsALongerFormOfAnAuthoredCommand — a collection taken with
// `show chassis hardware detail` is still the output the `show chassis hardware`
// binding reads; the reverse is NOT true, because a profile that authored the
// longer form is stating that the shorter one prints something else.
func TestFromCaptureBindsALongerFormOfAnAuthoredCommand(t *testing.T) {
	got := FromCapture([]CapturedCommand{
		{Command: "show chassis hardware detail", Output: showChassisHardwareJunos, Platform: "juniper-junos"},
	})
	if got.Serial != "JN123456AB" {
		t.Fatalf("serial = %q, want the longer command form to bind", got.Serial)
	}
	reg := vendorprofile.Default()
	_, probe, ok := reg.IdentityProbeForPlatformID("juniper/junos")
	if !ok {
		t.Fatal("juniper/junos declares no identity probe")
	}
	if _, bound := BindCommand(probe, "show chassis"); bound {
		t.Error("a SHORTER command bound an authored longer one — that is a different command's output")
	}
}

// TestFromCaptureIsBounded — §9: a collection larger than the cap is truncated
// to the cap rather than walked whole.
func TestFromCaptureIsBounded(t *testing.T) {
	cmds := make([]CapturedCommand, 0, MaxCommands+10)
	for i := 0; i < MaxCommands+10; i++ {
		cmds = append(cmds, CapturedCommand{Command: "show clock", Output: "10:00:00", Platform: "cisco-iosxe"})
	}
	// The answer is at the very end, past the cap: it must NOT be reached.
	cmds = append(cmds, CapturedCommand{Command: "show version", Output: showVersionIOSXE, Platform: "cisco-iosxe"})
	if got := FromCapture(cmds); !got.Empty() {
		t.Fatalf("walked past the %d-command cap: %+v", MaxCommands, got)
	}
}

// TestNilSeamResolvesNothing — an extractor with no registry is the honest state
// of a deployment that wired none; it must not fall back to a global one.
func TestNilSeamResolvesNothing(t *testing.T) {
	e := NewExtractor(nil)
	if got := e.FromCapture([]CapturedCommand{
		{Command: "show version", Output: showVersionIOSXE, Platform: "cisco-iosxe"},
	}); !got.Empty() {
		t.Fatalf("a nil seam produced %+v", got)
	}
	if _, _, ok := e.ForDevice("cisco", "Cisco IOS-XE 17.9"); ok {
		t.Error("a nil seam claimed a device probe")
	}
}
