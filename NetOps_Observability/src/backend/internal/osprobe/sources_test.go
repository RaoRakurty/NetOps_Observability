package osprobe

// sources_test.go — the three rungs against the SHIPPED profile data.
//
// These tests deliberately use the real registry rather than a hand-built one:
// the thing most likely to break is not this Go code but the authored patterns,
// and a fixture that is a real device's real `show version` output is the only
// way to find that out before a device does.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"netops/backend/internal/vendorprofile"
)

// ─── realistic `show version` fixtures ───────────────────────────────────────

// showVersionSRLinux — Nokia SR Linux 26.3.2 on a 7220 IXR-D3L, the shape the
// reference lab's spines print. Note what is NOT in it: the `SRLinux-v` prefix
// the vendor's os_version_pattern is anchored on. That absence is the entire
// reason version_render exists.
const showVersionSRLinux = `--------------------------------------------------------------------------------
Hostname             : spine1
Chassis Type         : 7220 IXR-D3L
Part Number          : Sim Part No.
Serial Number        : Sim Serial No.
System HW MAC Address: 1A:9E:02:FF:00:00
OS                   : SR Linux
Software Version     : v26.3.2
Build Number         : 426-g2b38957bbca
Architecture         : x86_64
Last Booted          : 2026-09-02T09:14:31.000Z
Total Memory         : 20463034 kB
Free Memory          : 12103391 kB
--------------------------------------------------------------------------------`

// showVersionIOSXE — a Catalyst 9300 running IOS-XE 17.09.04a. Two version
// lines: the platform banner and the packaged IOS version. Only the first is the
// OS version an advisory feed keys on.
const showVersionIOSXE = `Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Thu 12-Oct-23 22:02 by mcpre

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.9.1r[FC1], RELEASE SOFTWARE (P)

switch uptime is 41 weeks, 2 days, 6 hours, 11 minutes
System returned to ROM by Reload Command
System image file is "flash:cat9k_iosxe.17.09.04a.SPA.bin"

cisco C9300-48P (X86) processor with 1343803K/6147K bytes of memory.`

// showVersionNXOS — a Nexus 9000 running 10.3(4a). The Software block carries
// BIOS and NXOS versions side by side; anchoring on the word "version" alone
// would read the BIOS one.
const showVersionNXOS = `Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Copyright (C) 2002-2024, Cisco and/or its affiliates.

Software
  BIOS: version 05.47
  NXOS: version 10.3(4a)
  BIOS compile time:  09/11/2023
  NXOS image file is: bootflash:///nxos64-cs.10.3.4a.M.bin
  NXOS compile time:  2/9/2024 12:00:00 [02/09/2024 20:33:36]

Hardware
  cisco Nexus9000 C93180YC-FX3 Chassis`

// showVersionEOS — an Arista 7050SX3 running EOS 4.32.0F. `Software image
// version` is the OS version; `Internal build version` is a build id and must
// not be what is captured.
const showVersionEOS = `Arista DCS-7050SX3-48YC8-F
Hardware version: 11.03
Serial number: JPE19141ABC
Hardware MAC address: 2899.3a11.2233
System MAC address: 2899.3a11.2233

Software image version: 4.32.0F
Architecture: x86_64
Internal build version: 4.32.0F-36993274.4320F
Internal build ID: 6a0b1c2d-3e4f-5061-7283-94a5b6c7d8e9

Uptime: 31 weeks, 4 days, 2 hours and 9 minutes
Total memory: 8127708 kB
Free memory: 5241016 kB`

// showVersionJunos — an MX204 running a Junos service release. The hyphen in
// 21.4R3-S5.4 is part of the version, which is why the Junos pattern's capture
// class keeps it where the Arista and SR Linux ones drop it.
const showVersionJunos = `Hostname: mx-edge-1
Model: mx204
Junos: 21.4R3-S5.4
JUNOS OS Kernel 64-bit  [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS OS runtime [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS Routing Engine 64-bit [20230419.5b1b0eb_builder_stable_12-214ab]
JUNOS py extensions [20230419.5b1b0eb_builder_stable_12-214ab]`

// fakeRunner is the injected SSH gateway: it records what was asked and returns
// the fixture. No test in this package opens a socket.
type fakeRunner struct {
	out      string
	err      error
	commands []string
}

func (f *fakeRunner) Run(_ context.Context, _ Target, command string) (string, error) {
	f.commands = append(f.commands, command)
	return f.out, f.err
}

// fakeGetter is the injected gNMI Get client.
type fakeGetter struct {
	values map[string]string
	err    error
	paths  []string
}

func (f *fakeGetter) Get(_ context.Context, _ Target, path string) (string, error) {
	f.paths = append(f.paths, path)
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[path]
	if !ok {
		return "", errors.New("path not found")
	}
	return v, nil
}

// TestSSHRungParsesEveryAuthoredVendor is the per-vendor parser proof. Each case
// is a real device's real banner, and the assertion is not merely "a version was
// found" — it is that the stored string ROUND TRIPS back through the vendor's
// own os_version_pattern to the version the banner named. That is the property
// that makes the device assessable, and it is the one that was missing.
func TestSSHRungParsesEveryAuthoredVendor(t *testing.T) {
	reg := vendorprofile.Default()
	cases := []struct {
		name        string
		vendor      string
		osText      string
		output      string
		wantStored  string
		wantVersion string
		wantProduct string
		wantCommand string
	}{
		{
			name:   "Nokia SR Linux — the reference lab's spines",
			vendor: "nokia", osText: "SR Linux", output: showVersionSRLinux,
			wantStored: "SRLinux-v26.3.2", wantVersion: "26.3.2", wantProduct: "srlinux",
			wantCommand: "show version",
		},
		{
			name: "Cisco IOS-XE", vendor: "cisco", osText: "Cisco IOS-XE 17.9", output: showVersionIOSXE,
			wantStored: "Version 17.09.04a", wantVersion: "17.09.04a", wantProduct: "ios_xe",
			wantCommand: "show version",
		},
		{
			name: "Cisco NX-OS", vendor: "cisco", osText: "Cisco NX-OS", output: showVersionNXOS,
			wantStored: "Version 10.3(4a)", wantVersion: "10.3(4a)", wantProduct: "nx-os",
			wantCommand: "show version",
		},
		{
			name: "Arista EOS", vendor: "arista", osText: "Arista EOS", output: showVersionEOS,
			wantStored: "version 4.32.0F", wantVersion: "4.32.0F", wantProduct: "eos",
			wantCommand: "show version",
		},
		{
			name: "Juniper Junos", vendor: "juniper", osText: "Juniper Junos", output: showVersionJunos,
			wantStored: "JUNOS 21.4R3-S5.4", wantVersion: "21.4R3-S5.4", wantProduct: "junos",
			wantCommand: "show version",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{out: tc.output}
			src := NewSSHSource(runner, reg)
			got, err := src.Probe(context.Background(), Target{DeviceID: "d1", Vendor: tc.vendor, OSText: tc.osText})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if got != tc.wantStored {
				t.Fatalf("stored %q, want %q", got, tc.wantStored)
			}
			if len(runner.commands) != 1 || runner.commands[0] != tc.wantCommand {
				t.Fatalf("ran %v, want exactly one %q", runner.commands, tc.wantCommand)
			}
			// The round trip: what lands on the row must be readable by the
			// SAME parser that reads a sysDescr, or the device is assessable in
			// name only.
			id, ok := reg.ResolveOS(tc.vendor, tc.osText+" "+got)
			if !ok {
				t.Fatalf("vendor %q could not resolve OS from the stored value", tc.vendor)
			}
			if id.Version != tc.wantVersion {
				t.Errorf("stored value read back as version %q, want %q", id.Version, tc.wantVersion)
			}
			if id.Product != tc.wantProduct {
				t.Errorf("stored value read back as product %q, want %q", id.Product, tc.wantProduct)
			}
		})
	}
}

// TestSSHRungCapturesTheOSVersionNotANeighbouringOne — the near-miss cases each
// pattern was written to avoid. A parser that grabs the BIOS version or an
// internal build id would report a device on software it is not running, which
// is worse than reporting it unassessed.
func TestSSHRungCapturesTheOSVersionNotANeighbouringOne(t *testing.T) {
	reg := vendorprofile.Default()
	cases := []struct{ name, vendor, osText, output, notWant string }{
		{"NX-OS must not read the BIOS version", "cisco", "Cisco NX-OS", showVersionNXOS, "Version 05.47"},
		{"EOS must not read the internal build version", "arista", "Arista EOS", showVersionEOS, "version 4.32.0F-36993274.4320F"},
		{"IOS-XE must not read the ROMMON bootstrap version", "cisco", "Cisco IOS-XE", showVersionIOSXE, "Version 17.9.1r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := NewSSHSource(&fakeRunner{out: tc.output}, reg)
			got, err := src.Probe(context.Background(), Target{Vendor: tc.vendor, OSText: tc.osText})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if got == tc.notWant {
				t.Errorf("captured the neighbouring version %q", got)
			}
		})
	}
}

// TestSSHRungIsHonestWhenTheDeviceAnswersWithoutAVersion — a device that
// answers something unparseable is NOT an error and NOT a version.
func TestSSHRungIsHonestWhenTheDeviceAnswersWithoutAVersion(t *testing.T) {
	src := NewSSHSource(&fakeRunner{out: "Parsing error: Unknown token 'version'\n"}, vendorprofile.Default())
	got, err := src.Probe(context.Background(), Target{Vendor: "nokia", OSText: "SR Linux"})
	if err != nil {
		t.Fatalf("an unparseable answer is not an error: %v", err)
	}
	if got != "" {
		t.Errorf("invented %q out of an error message", got)
	}
}

// TestSSHRungReportsUnconfiguredRatherThanGuessing — a platform with no authored
// probe, and a deployment with no gateway, must both be UNAVAILABLE, never an
// improvised command at a live device.
func TestSSHRungReportsUnconfiguredRatherThanGuessing(t *testing.T) {
	reg := vendorprofile.Default()
	runner := &fakeRunner{out: showVersionSRLinux}

	// A vendor with no os_version_probe block anywhere.
	src := NewSSHSource(runner, reg)
	if _, err := src.Probe(context.Background(), Target{Vendor: "mikrotik", OSText: "RouterOS"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("unauthored platform: err = %v, want ErrNotConfigured", err)
	}
	// A platform of an AUTHORED vendor that is itself unauthored (SR OS).
	if _, err := src.Probe(context.Background(), Target{Vendor: "nokia", OSText: "Nokia SR OS"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("unauthored platform of an authored vendor: err = %v, want ErrNotConfigured", err)
	}
	if len(runner.commands) != 0 {
		t.Errorf("a command was run at a device with no authored probe: %v", runner.commands)
	}
	// No gateway at all.
	if _, err := NewSSHSource(nil, reg).Probe(context.Background(), Target{Vendor: "nokia", OSText: "SR Linux"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no gateway: err = %v, want ErrNotConfigured", err)
	}
}

// TestSSHRungWillNotCrossVendors — the label names one vendor, the row's
// DETECTED vendor is another.
//
// The sysDescr route is vendor-scoped by construction (ResolveOS is asked about
// one vendor), so the leak this guards is the platform-TEXT backstop: "Nokia SR
// Linux" resolves to nokia/srlinux on the label alone. A row whose vendor is
// cisco must not be handed that profile, or the ladder would run one vendor's
// command at another vendor's device. Cisco is the vendor used here precisely
// because its os_parse declares no unconditional default, so this case actually
// reaches the backstop instead of stopping at the sysDescr route.
func TestSSHRungWillNotCrossVendors(t *testing.T) {
	runner := &fakeRunner{out: showVersionSRLinux}
	src := NewSSHSource(runner, vendorprofile.Default())
	if _, err := src.Probe(context.Background(), Target{Vendor: "cisco", OSText: "Nokia SR Linux"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured for a label that belongs to another vendor", err)
	}
	if len(runner.commands) != 0 {
		t.Errorf("a command was run across a vendor boundary: %v", runner.commands)
	}
}

// TestSSHRungRefusesACommandWithChainingMetacharacters — the closed-command
// property, tested at the shape check rather than through the data (the loader
// already refuses such data; this proves the second, defensive gate).
func TestSSHRungRefusesACommandWithChainingMetacharacters(t *testing.T) {
	profiles := fakeProfiles{
		profile: vendorprofile.Profile{ID: "test/evil", Capture: vendorprofile.Capture{ShowVersionCmd: "show version; reload"}},
		probe:   vendorprofile.OSVersionProbe{CLIVersionPattern: `(\d+)`, VersionRender: "Version {version}"},
		ok:      true,
	}
	runner := &fakeRunner{out: "1"}
	_, err := NewSSHSource(runner, profiles).Probe(context.Background(), Target{Vendor: "test", OSText: "evil"})
	if err == nil {
		t.Fatal("a chained command was accepted")
	}
	if len(runner.commands) != 0 {
		t.Errorf("the refused command reached the gateway anyway: %v", runner.commands)
	}
}

// fakeProfiles is a hand-built vendor-knowledge seam for the cases the shipped
// data (correctly) refuses to contain.
type fakeProfiles struct {
	profile vendorprofile.Profile
	probe   vendorprofile.OSVersionProbe
	ok      bool
}

func (f fakeProfiles) OSVersionProbeForDevice(string, string) (vendorprofile.Profile, vendorprofile.OSVersionProbe, bool) {
	return f.profile, f.probe, f.ok
}

// ─── the gNMI rung ───────────────────────────────────────────────────────────

// TestGNMIRungReadsTheSoftwareVersionLeaf — the leaf value SR Linux serves,
// through the shipped paths and the shipped pattern.
func TestGNMIRungReadsTheSoftwareVersionLeaf(t *testing.T) {
	getter := &fakeGetter{values: map[string]string{
		"/platform/control[slot=A]/software-version": `{"srl_nokia-platform:software-version":"v26.3.2-426-g2b38957bbca"}`,
	}}
	src := NewGNMISource(getter, vendorprofile.Default())
	got, err := src.Probe(context.Background(), Target{Vendor: "nokia", OSText: "SR Linux"})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got != "SRLinux-v26.3.2" {
		t.Fatalf("stored %q, want %q — the build suffix must not reach a CVE range comparison", got, "SRLinux-v26.3.2")
	}
	id, ok := vendorprofile.Default().ResolveOS("nokia", "SR Linux "+got)
	if !ok || id.Version != "26.3.2" || id.Product != "srlinux" {
		t.Errorf("stored value read back as %+v, want product srlinux version 26.3.2", id)
	}
}

// TestGNMIRungFallsThroughToTheNextPath — a chassis that does not publish the
// first path must not end the probe.
func TestGNMIRungFallsThroughToTheNextPath(t *testing.T) {
	getter := &fakeGetter{values: map[string]string{
		"/system/information/version": "v26.3.2-426-g2b38957bbca",
	}}
	src := NewGNMISource(getter, vendorprofile.Default())
	got, err := src.Probe(context.Background(), Target{Vendor: "nokia", OSText: "SR Linux"})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got != "SRLinux-v26.3.2" {
		t.Errorf("stored %q, want the second path's answer", got)
	}
	if len(getter.paths) != 2 {
		t.Errorf("tried %v, want both authored paths in order", getter.paths)
	}
}

// TestGNMIRungReadsOpenConfigPlatforms — the same rung, the OpenConfig shape.
func TestGNMIRungReadsOpenConfigPlatforms(t *testing.T) {
	cases := []struct{ name, vendor, osText, path, value, want string }{
		{"Arista EOS", "arista", "Arista EOS", "/system/state/software-version", `{"software-version":"4.32.0F"}`, "version 4.32.0F"},
		{"Juniper Junos", "juniper", "Juniper Junos", "/system/state/software-version", `"21.4R3-S5.4"`, "JUNOS 21.4R3-S5.4"},
		{"Cisco IOS-XE", "cisco", "Cisco IOS-XE 17.9", "/system/state/software-version", "17.09.04a", "Version 17.09.04a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := NewGNMISource(&fakeGetter{values: map[string]string{tc.path: tc.value}}, vendorprofile.Default())
			got, err := src.Probe(context.Background(), Target{Vendor: tc.vendor, OSText: tc.osText})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if got != tc.want {
				t.Errorf("stored %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGNMIRungReportsTheFailureItSaw — every path failing must surface the
// first error, not decay into a silent "no version" (§10).
func TestGNMIRungReportsTheFailureItSaw(t *testing.T) {
	src := NewGNMISource(&fakeGetter{err: errors.New("rpc error: code = Unavailable")}, vendorprofile.Default())
	_, err := src.Probe(context.Background(), Target{Vendor: "nokia", OSText: "SR Linux"})
	if err == nil {
		t.Fatal("a transport failure was reported as a benign empty answer")
	}
	if !strings.Contains(err.Error(), "Unavailable") {
		t.Errorf("err = %v, want it to carry what the transport said", err)
	}
}

// TestGNMIRungReportsUnconfiguredWithNoClient — the deployment state Correlix is
// actually in today: the paths are authored, no Get client is wired, and the
// ladder must say so rather than claiming the capability.
func TestGNMIRungReportsUnconfiguredWithNoClient(t *testing.T) {
	if _, err := NewGNMISource(nil, vendorprofile.Default()).Probe(context.Background(),
		Target{Vendor: "nokia", OSText: "SR Linux"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
}

// ─── the SNMP rung ───────────────────────────────────────────────────────────

// TestSNMPRungReturnsTheSysDescrVerbatim — the top rung needs no profile data,
// which is exactly why it leads.
func TestSNMPRungReturnsTheSysDescrVerbatim(t *testing.T) {
	const descr = "SRLinux-v26.3.2-426-g2b38957bbca 7220 IXR-D3L Copyright (c) 2000-2026 Nokia."
	src := NewSNMPSource(func(context.Context, string) (string, string) { return "nokia", descr })
	got, err := src.Probe(context.Background(), Target{Address: "172.40.40.11"})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got != descr {
		t.Errorf("got %q, want the sysDescr verbatim", got)
	}
}

// TestSNMPRungIsUnavailableWithoutAnAddressOrAReader.
func TestSNMPRungIsUnavailableWithoutAnAddressOrAReader(t *testing.T) {
	src := NewSNMPSource(func(context.Context, string) (string, string) { return "", "" })
	if _, err := src.Probe(context.Background(), Target{}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no address: err = %v, want ErrNotConfigured", err)
	}
	if _, err := NewSNMPSource(nil).Probe(context.Background(), Target{Address: "10.0.0.1"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no reader: err = %v, want ErrNotConfigured", err)
	}
}

// TestSNMPRungTreatsAnUnreachableDeviceAsNoVersion — a timed-out SNMP get and a
// device with no agent look identical at this layer, and both mean "no version",
// never an invented one. This is the lab's actual SNMP state.
func TestSNMPRungTreatsAnUnreachableDeviceAsNoVersion(t *testing.T) {
	src := NewSNMPSource(func(context.Context, string) (string, string) { return "", "" })
	got, err := src.Probe(context.Background(), Target{Address: "172.40.40.11"})
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want an empty non-error answer", got, err)
	}
}
