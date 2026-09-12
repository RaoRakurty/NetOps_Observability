// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

// os_version_probe_test.go — the OS-VERSION SOURCE LADDER's profile contract.
//
// The registry's job here is to make one class of defect impossible: a platform
// declaring a probe whose reading it cannot then read back. The loader proves
// the round trip at build time; these tests prove the loader actually does, pin
// the rows the ladder consumes, and pin the resolution rule that keeps one
// vendor's command away from another vendor's device.

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestShippedOSVersionProbesRoundTrip is the property the whole design rests on:
// for every authored probe, rendering a version produces a string the VENDOR's
// own os_version_pattern reads back as that same version. Without it a probe
// writes a value nothing downstream can parse and the device stays unassessed
// with the answer sitting in its row.
func TestShippedOSVersionProbesRoundTrip(t *testing.T) {
	reg := Default()
	// Per-platform REAL versions, on top of the universal "9.9.9" every profile
	// is checked with. They are platform-specific because the character classes
	// legitimately differ: a Junos service release carries a hyphen the SR Linux
	// pattern deliberately drops, and an NX-OS maintenance suffix carries
	// parentheses only the Cisco vendor pattern accepts.
	realVersions := map[string][]string{
		"nokia/srlinux": {"26.3.2"},
		"cisco/ios_xe":  {"17.09.04a"},
		"cisco/nx-os":   {"10.3(4a)"},
		"arista/eos":    {"4.32.0F"},
		"juniper/junos": {"21.4R3-S5.4"},
	}
	authored := 0
	for _, p := range reg.Profiles() {
		if !p.OSVersionProbe.Declared() {
			continue
		}
		authored++
		versions := append([]string{"9.9.9"}, realVersions[p.ID]...)
		if len(versions) == 1 {
			t.Errorf("%s declares a probe but this test has no real version for it — add one rather than leaving the platform covered only by the synthetic token", p.ID)
		}
		for _, version := range versions {
			rendered := p.OSVersionProbe.Render(version)
			if rendered == "" {
				t.Errorf("%s: version_render produced nothing for %q", p.ID, version)
				continue
			}
			id, ok := reg.ResolveOS(p.Vendor, p.DisplayName+" "+rendered)
			if !ok {
				t.Errorf("%s: vendor %q cannot resolve %q", p.ID, p.Vendor, rendered)
				continue
			}
			if id.Version != version {
				t.Errorf("%s: rendered %q reads back as version %q, want %q",
					p.ID, rendered, id.Version, version)
			}
			if id.Product != p.Platform {
				t.Errorf("%s: rendered %q reads back as product %q, want %q",
					p.ID, rendered, id.Product, p.Platform)
			}
		}
	}
	if authored == 0 {
		t.Fatal("no profile declares an os_version_probe — the ladder has no data and this test is vacuous")
	}
	t.Logf("round-tripped %d authored os_version_probe blocks", authored)
}

// TestOSVersionProbeRowsArePinned binds the ladder's consumers to the DATA that
// moved into the registry, so a silent edit to a path or a command shows up as a
// failing test rather than as a device that stops answering.
func TestOSVersionProbeRowsArePinned(t *testing.T) {
	reg := Default()
	want := map[string]struct {
		gnmiPaths []string
		render    string
		command   string
	}{
		"nokia/srlinux": {
			gnmiPaths: []string{"/platform/control[slot=A]/software-version", "/system/information/version"},
			render:    "SRLinux-v{version}", command: "show version",
		},
		"cisco/ios_xe": {gnmiPaths: []string{"/system/state/software-version"}, render: "Version {version}", command: "show version"},
		"cisco/nx-os":  {gnmiPaths: []string{"/system/state/software-version"}, render: "Version {version}", command: "show version"},
		"arista/eos": {
			gnmiPaths: []string{"/system/state/software-version", "/components/component[name=Chassis]/state/software-version"},
			render:    "version {version}", command: "show version",
		},
		"juniper/junos": {gnmiPaths: []string{"/system/state/software-version"}, render: "JUNOS {version}", command: "show version"},
	}
	for id, w := range want {
		p, ok := reg.Lookup(id)
		if !ok {
			t.Errorf("profile %s is gone", id)
			continue
		}
		got := p.OSVersionProbe
		if strings.Join(got.GNMIPaths, "|") != strings.Join(w.gnmiPaths, "|") {
			t.Errorf("%s: gnmi_paths = %v, want %v", id, got.GNMIPaths, w.gnmiPaths)
		}
		if got.VersionRender != w.render {
			t.Errorf("%s: version_render = %q, want %q", id, got.VersionRender, w.render)
		}
		if p.Capture.ShowVersionCmd != w.command {
			t.Errorf("%s: capture.show_version_cmd = %q, want %q", id, p.Capture.ShowVersionCmd, w.command)
		}
		if !got.HasGNMI() || !got.HasCLI() {
			t.Errorf("%s: declares an incomplete probe (gnmi=%v cli=%v)", id, got.HasGNMI(), got.HasCLI())
		}
	}
}

// TestOSVersionProbeForDeviceIsVendorBounded — the resolution rule. The lab's
// row (vendor nokia, os "SR Linux") must resolve; the same label on another
// vendor's row must NOT, or one vendor's command would run at another's device.
func TestOSVersionProbeForDeviceIsVendorBounded(t *testing.T) {
	reg := Default()

	p, probe, ok := reg.OSVersionProbeForDevice("nokia", "SR Linux")
	if !ok {
		t.Fatal("the reference lab's own row does not resolve a probe — the feature is inert where it was needed")
	}
	if p.ID != "nokia/srlinux" || !probe.HasCLI() {
		t.Errorf("resolved %s (cli=%v), want nokia/srlinux with a CLI rung", p.ID, probe.HasCLI())
	}

	// cisco declares no unconditional os_parse default, so this case reaches the
	// platform-text backstop — which must refuse a label owned by another vendor.
	if _, _, ok := reg.OSVersionProbeForDevice("cisco", "Nokia SR Linux"); ok {
		t.Error("a cisco row resolved Nokia SR Linux's probe — cross-vendor leak")
	}
	// An unknown vendor, an empty label and an authored vendor's UNauthored
	// platform are all honest non-answers, never a fallback profile.
	for _, tc := range []struct{ vendor, osText string }{
		{"", "SR Linux"}, {"nokia", ""}, {"acme", "SR Linux"}, {"nokia", "Nokia SR OS"},
	} {
		if _, _, ok := reg.OSVersionProbeForDevice(tc.vendor, tc.osText); ok {
			t.Errorf("OSVersionProbeForDevice(%q, %q) claimed a probe it should not have", tc.vendor, tc.osText)
		}
	}
}

// ─── loader refusals ─────────────────────────────────────────────────────────

// probeDoc renders a minimal one-profile vendor document carrying the given
// os_version_probe JSON body.
func probeDoc(probeJSON string) map[string]string {
	body := `{
  "schema_version": 1,
  "vendor": "acme",
  "display_name": "Acme",
  "detection": {
    "sysobjectid_prefixes": ["1.3.6.1.4.1.99999"],
    "os_version_pattern": "(?i)\\bAcmeOS-v([0-9][0-9A-Za-z.]*)"
  },
  "dialect": {},
  "verify": {},
  "config_capture": {},
  "snmp_configgen": {},
  "device_type": {},
  "profiles": [
    {
      "platform": "acmeos",
      "display_name": "Acme OS",
      "device_class": ["router"],
      "fidelity": "doc_claimed",
      "detection": {"os_parse": {"product": "acmeos", "rank": 1, "sysdescr_contains_any": []}},
      "capture": {"show_version_cmd": "show version"},
      "advisory": {},
      "hardening": {},
      "threat": {},
      "os_version_probe": ` + probeJSON + `
    }
  ]
}`
	return map[string]string{"profiles/acme.json": body}
}

func loadProbeDoc(t *testing.T, probeJSON string) error {
	t.Helper()
	files := fstest.MapFS{}
	for name, body := range probeDoc(probeJSON) {
		files[name] = &fstest.MapFile{Data: []byte(body)}
	}
	_, err := Load(files, "profiles")
	return err
}

func TestLoaderAcceptsAWellFormedProbe(t *testing.T) {
	if err := loadProbeDoc(t, `{
      "gnmi_paths": ["/system/state/software-version"],
      "gnmi_version_pattern": "(?i)^v?([0-9][0-9A-Za-z.]*)",
      "cli_version_pattern": "(?im)^Version:\\s+([0-9][0-9A-Za-z.]*)",
      "version_render": "AcmeOS-v{version}"
    }`); err != nil {
		t.Fatalf("a complete, round-tripping probe was refused: %v", err)
	}
}

// TestLoaderRefusesAHalfDeclaredProbe — a half-declared probe is worse than
// none: the ladder would run a transport at a live device and then be unable to
// use what it got.
func TestLoaderRefusesAHalfDeclaredProbe(t *testing.T) {
	cases := map[string]struct{ probe, wantIn string }{
		"a path with nothing to read its value": {
			`{"gnmi_paths": ["/system/state/software-version"], "version_render": "AcmeOS-v{version}"}`,
			"must be set together",
		},
		"a pattern with no path to read from": {
			`{"gnmi_version_pattern": "^v?([0-9.]+)$", "version_render": "AcmeOS-v{version}"}`,
			"must be set together",
		},
		"a source with no canonical rendering": {
			`{"cli_version_pattern": "^Version: ([0-9.]+)$"}`,
			"version_render is required",
		},
		"a rendering with no source": {
			`{"version_render": "AcmeOS-v{version}"}`,
			"with no version source",
		},
		"a rendering with no placeholder": {
			`{"cli_version_pattern": "^Version: ([0-9.]+)$", "version_render": "AcmeOS-v1.0"}`,
			"exactly one {version}",
		},
		"a rendering with two placeholders": {
			`{"cli_version_pattern": "^Version: ([0-9.]+)$", "version_render": "AcmeOS-v{version}-{version}"}`,
			"exactly one {version}",
		},
		"a pattern with no capture group": {
			`{"cli_version_pattern": "^Version: [0-9.]+$", "version_render": "AcmeOS-v{version}"}`,
			"no capture group",
		},
		"a pattern that does not compile": {
			`{"cli_version_pattern": "^Version: ([0-9.+$", "version_render": "AcmeOS-v{version}"}`,
			"cli_version_pattern",
		},
		"a relative gNMI path": {
			`{"gnmi_paths": ["system/state/software-version"], "gnmi_version_pattern": "^v?([0-9.]+)$", "version_render": "AcmeOS-v{version}"}`,
			"not an absolute gNMI path",
		},
		"a duplicated gNMI path": {
			`{"gnmi_paths": ["/a/b", "/a/b"], "gnmi_version_pattern": "^v?([0-9.]+)$", "version_render": "AcmeOS-v{version}"}`,
			"declared twice",
		},
		"a rendering carrying a shell metacharacter": {
			`{"cli_version_pattern": "^Version: ([0-9.]+)$", "version_render": "AcmeOS-v{version}; reload"}`,
			"contains",
		},
		"an unknown key": {
			`{"cli_command": "show version", "version_render": "AcmeOS-v{version}"}`,
			"unknown field",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadProbeDoc(t, tc.probe)
			if err == nil {
				t.Fatalf("accepted: %s", tc.probe)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestLoaderRefusesARenderingItsOwnVendorCannotReadBack is the round-trip guard
// itself: the exact defect the ladder would otherwise ship — a probe writing a
// bare version onto a row whose vendor pattern is anchored on a prefix.
func TestLoaderRefusesARenderingItsOwnVendorCannotReadBack(t *testing.T) {
	err := loadProbeDoc(t, `{
      "cli_version_pattern": "(?im)^Version:\\s+([0-9][0-9A-Za-z.]*)",
      "version_render": "{version}"
    }`)
	if err == nil {
		t.Fatal("a bare-version rendering was accepted — the row would carry a version its own platform cannot parse")
	}
	if !strings.Contains(err.Error(), "reads back as") {
		t.Errorf("err = %v, want the round-trip refusal", err)
	}
}

// TestLoaderRefusesACLIProbeWithNoCommandToRun — the ladder never invents a
// command at a device, so the data may not ask it to.
func TestLoaderRefusesACLIProbeWithNoCommandToRun(t *testing.T) {
	files := fstest.MapFS{}
	for name, body := range probeDoc(`{"cli_version_pattern": "^V ([0-9.]+)$", "version_render": "AcmeOS-v{version}"}`) {
		files[name] = &fstest.MapFile{Data: []byte(strings.Replace(body, `"capture": {"show_version_cmd": "show version"}`, `"capture": {}`, 1))}
	}
	_, err := Load(files, "profiles")
	if err == nil {
		t.Fatal("a CLI probe with no show-version command was accepted")
	}
	if !strings.Contains(err.Error(), "no capture.show_version_cmd") {
		t.Errorf("err = %v, want the missing-command refusal", err)
	}
}
