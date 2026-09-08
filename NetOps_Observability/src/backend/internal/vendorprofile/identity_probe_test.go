// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

// identity_probe_test.go — the HARDWARE IDENTITY probe's profile contract.
//
// The registry's job here is to make three classes of defect impossible:
// a platform that names a command with nothing to read out of it, a command
// that is not safe to put on a wire at a live device, and a pattern that can
// wander off the line it was written for. The first two are loader refusals;
// the third is a shape guard over the shipped data, and it exists because it
// caught a real bug: `\s*` in a `key: value` pattern matches the NEWLINE too, so
// `Serial Number :` with an empty value happily captured the NEXT line's label
// as the serial.

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// TestShippedIdentityProbeRowsArePinned binds internal/deviceident and the SSH
// rung to the DATA, so a silent edit to a command shows up as a failing test
// naming the row rather than as a device that quietly stops answering. The
// commands are executed on production routers: they are not a detail, they are
// the contract.
func TestShippedIdentityProbeRowsArePinned(t *testing.T) {
	want := map[string][]string{
		"cisco/ios_xe":     {"show version", "show inventory"},
		"cisco/ios":        {"show version", "show inventory"},
		"cisco/nx-os":      {"show version", "show inventory"},
		"cisco/ios_xr":     {"show inventory"},
		"arista/eos":       {"show version"},
		"juniper/junos":    {"show version", "show chassis hardware"},
		"nokia/srlinux":    {"show version"},
		"nokia/sros":       {"show chassis"},
		"paloalto/pan-os":  {"show system info"},
		"fortinet/fortios": {"get system status"},
	}
	reg := Default()
	for id, cmds := range want {
		p, ok := reg.Lookup(id)
		if !ok {
			t.Errorf("profile %s is gone", id)
			continue
		}
		got := make([]string, 0, len(p.IdentityProbe.Commands))
		for _, c := range p.IdentityProbe.Commands {
			got = append(got, c.Command)
		}
		if strings.Join(got, "|") != strings.Join(cmds, "|") {
			t.Errorf("%s: identity commands = %v, want %v", id, got, cmds)
		}
	}
	// And the converse: a profile that acquired an identity probe without a row
	// here is an unreviewed set of commands aimed at somebody's chassis.
	for _, p := range reg.Profiles() {
		if p.IdentityProbe.Declared() {
			if _, pinned := want[p.ID]; !pinned {
				t.Errorf("%s declares an identity probe with no row in this test — pin it", p.ID)
			}
		}
	}
}

// TestEveryIdentityCommandIsAReadOnlyShow — least privilege (§8). Every authored
// command is a read: a probe must never be able to configure, clear or reload
// anything, and the check is on the DATA rather than on a reviewer's memory.
func TestEveryIdentityCommandIsAReadOnlyShow(t *testing.T) {
	readVerbs := []string{"show ", "get ", "display "}
	for _, p := range Default().Profiles() {
		for _, c := range p.IdentityProbe.Commands {
			ok := false
			for _, verb := range readVerbs {
				if strings.HasPrefix(c.Command, verb) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: identity command %q does not start with a read verb %v", p.ID, c.Command, readVerbs)
			}
		}
	}
}

// TestEveryIdentityCommandDeclaresAtLeastOnePattern — a command with nothing to
// read out of it is a device round-trip for nothing.
func TestEveryIdentityCommandDeclaresAtLeastOnePattern(t *testing.T) {
	declared := 0
	for _, p := range Default().Profiles() {
		if !p.IdentityProbe.Declared() {
			continue
		}
		declared++
		if strings.TrimSpace(p.IdentityProbe.Notes) == "" {
			t.Errorf("%s declares an identity probe with no notes — the evidence behind a pattern is part of the pattern", p.ID)
		}
		for _, c := range p.IdentityProbe.Commands {
			if len(c.SerialPatterns) == 0 && len(c.ModelPatterns) == 0 {
				t.Errorf("%s: %q declares no pattern", p.ID, c.Command)
			}
		}
	}
	if declared == 0 {
		t.Fatal("no profile declares an identity_probe — the feature has no data and these tests are vacuous")
	}
	t.Logf("%d profiles declare an identity probe", declared)
}

// TestIdentityPatternsAreLineBounded is the shape guard, and it is the one that
// found a real defect. `\s` matches a NEWLINE, so a `label\s*:\s*(\S.*?)\s*$`
// pattern will happily skip an empty value and capture the NEXT LINE's content
// as the serial. Every authored pattern must therefore use horizontal-space
// classes only, and must be multi-line anchored so it reads ONE line.
func TestIdentityPatternsAreLineBounded(t *testing.T) {
	bareWhitespace := regexp.MustCompile(`\\s`)
	for _, p := range Default().Profiles() {
		for _, c := range p.IdentityProbe.Commands {
			for _, expr := range append(append([]string(nil), c.SerialPatterns...), c.ModelPatterns...) {
				if bareWhitespace.MatchString(expr) {
					t.Errorf("%s: %q pattern %q uses \\s, which matches a NEWLINE and lets the match leave its line — use [ \\t] instead",
						p.ID, c.Command, expr)
				}
				if !strings.Contains(expr, "m)") {
					t.Errorf("%s: %q pattern %q is not multi-line anchored", p.ID, c.Command, expr)
				}
				if !strings.Contains(expr, "^") {
					t.Errorf("%s: %q pattern %q is not anchored to the start of a line", p.ID, c.Command, expr)
				}
			}
		}
	}
}

// TestIdentityProbeForDeviceIsVendorBounded — the resolution rule for a LIVE
// probe. The commands it returns will be RUN at the device, so a label owned by
// another vendor must never resolve.
func TestIdentityProbeForDeviceIsVendorBounded(t *testing.T) {
	reg := Default()

	p, probe, ok := reg.IdentityProbeForDevice("nokia", "SR Linux")
	if !ok {
		t.Fatal("the reference lab's own row resolves no identity probe")
	}
	if p.ID != "nokia/srlinux" || len(probe.Commands) == 0 {
		t.Errorf("resolved %s with %d commands, want nokia/srlinux", p.ID, len(probe.Commands))
	}
	if _, _, ok := reg.IdentityProbeForDevice("cisco", "Nokia SR Linux"); ok {
		t.Error("a cisco row resolved Nokia SR Linux's identity commands — cross-vendor leak")
	}
	for _, tc := range []struct{ vendor, osText string }{
		{"", "SR Linux"}, {"nokia", ""}, {"acme", "SR Linux"}, {"huawei", "Huawei VRP"},
	} {
		if _, _, ok := reg.IdentityProbeForDevice(tc.vendor, tc.osText); ok {
			t.Errorf("IdentityProbeForDevice(%q, %q) claimed a probe it should not have", tc.vendor, tc.osText)
		}
	}
}

// TestProfileForPlatformIDIsExactBeforeItIsFuzzy — the capture-side resolution.
// The IOS-XR case is the point: the ranked SUBSTRING table maps "cisco-iosxr"
// onto cisco/ios (which owns the bare token "cisco"), which would read an
// IOS-XR capture with IOS patterns. Identifier resolution must beat it.
func TestProfileForPlatformIDIsExactBeforeItIsFuzzy(t *testing.T) {
	reg := Default()
	want := map[string]string{
		"cisco-iosxe":      "cisco/ios_xe",
		"cisco-iosxr":      "cisco/ios_xr",
		"cisco-nxos":       "cisco/nx-os",
		"cisco-ios":        "cisco/ios",
		"cisco-asa":        "cisco/asa",
		"arista-eos":       "arista/eos",
		"juniper-junos":    "juniper/junos",
		"nokia-sros":       "nokia/sros",
		"nokia-srlinux":    "nokia/srlinux",
		"paloalto-panos":   "paloalto/pan-os",
		"fortinet-fortios": "fortinet/fortios",
		"huawei-vrp":       "huawei/vrp",
		// canonical and separator variants of the same key
		"cisco/ios_xr": "cisco/ios_xr",
		"cisco_ios_xr": "cisco/ios_xr",
		"CISCO-IOSXR":  "cisco/ios_xr",
		// and the free-form backstop still works
		"Cisco IOS-XE 17.9": "cisco/ios_xe",
		"Nokia SR Linux":    "nokia/srlinux",
	}
	for platform, id := range want {
		p, ok := reg.ProfileForPlatformID(platform)
		if !ok {
			t.Errorf("ProfileForPlatformID(%q) resolved nothing, want %s", platform, id)
			continue
		}
		if p.ID != id {
			t.Errorf("ProfileForPlatformID(%q) = %s, want %s", platform, p.ID, id)
		}
	}
	for _, platform := range []string{"", "   ", "acme-netos", "!!!"} {
		if p, ok := reg.ProfileForPlatformID(platform); ok {
			t.Errorf("ProfileForPlatformID(%q) claimed %s", platform, p.ID)
		}
	}
}

// ─── loader refusals ─────────────────────────────────────────────────────────

// identityDoc renders a minimal one-profile vendor document carrying the given
// identity_probe JSON body.
func identityDoc(identityJSON string) string {
	return `{
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
      "identity_probe": ` + identityJSON + `
    }
  ]
}`
}

func loadIdentityDoc(t *testing.T, identityJSON string) error {
	t.Helper()
	files := fstest.MapFS{"profiles/acme.json": &fstest.MapFile{Data: []byte(identityDoc(identityJSON))}}
	_, err := Load(files, "profiles")
	return err
}

func TestLoaderAcceptsAWellFormedIdentityProbe(t *testing.T) {
	if err := loadIdentityDoc(t, `{
      "commands": [
        {"command": "show version",
         "serial_patterns": ["(?m)^Serial:[ \\t]*([A-Z0-9]{4,20})[ \\t\\r]*$"],
         "model_patterns": ["(?m)^Model:[ \\t]*([A-Z0-9-]{2,20})[ \\t\\r]*$"]}
      ],
      "notes": "authored from the Acme OS command reference"
    }`); err != nil {
		t.Fatalf("a complete identity probe was refused: %v", err)
	}
}

// TestLoaderRefusesAnUnusableIdentityProbe — every rule, each with the reason it
// exists stated in its name.
func TestLoaderRefusesAnUnusableIdentityProbe(t *testing.T) {
	pat := `"serial_patterns": ["(?m)^SN:[ \\t]*(\\S+)[ \\t\\r]*$"]`
	cases := map[string]struct{ probe, wantIn string }{
		"a command with nothing to read out of it": {
			`{"commands": [{"command": "show version"}]}`,
			"declares no pattern",
		},
		"an empty command": {
			`{"commands": [{"command": "", ` + pat + `}]}`,
			"command is empty",
		},
		"a command carrying a chaining metacharacter": {
			`{"commands": [{"command": "show version; reload", ` + pat + `}]}`,
			"contains",
		},
		"a command carrying a redirection": {
			`{"commands": [{"command": "show version > flash:x", ` + pat + `}]}`,
			"contains",
		},
		"a command with untrimmed space": {
			`{"commands": [{"command": " show version", ` + pat + `}]}`,
			"leading/trailing space",
		},
		"the same command twice": {
			`{"commands": [{"command": "show version", ` + pat + `}, {"command": "show version", ` + pat + `}]}`,
			"declared twice",
		},
		"more commands than the bound allows": {
			`{"commands": [{"command": "show a", ` + pat + `}, {"command": "show b", ` + pat + `},
			               {"command": "show c", ` + pat + `}, {"command": "show d", ` + pat + `}]}`,
			"at most",
		},
		"a pattern that does not compile": {
			`{"commands": [{"command": "show version", "serial_patterns": ["^SN: ([A-Z"]}]}`,
			"serial_patterns",
		},
		"a pattern with no capture group": {
			`{"commands": [{"command": "show version", "serial_patterns": ["^SN: \\S+$"]}]}`,
			"no capture group",
		},
		"an empty pattern": {
			`{"commands": [{"command": "show version", "model_patterns": [""]}]}`,
			"empty pattern",
		},
		"notes with no command": {
			`{"notes": "we looked into it"}`,
			"notes set with no command",
		},
		"an unknown key": {
			`{"commands": [{"command": "show version", "serial_regex": "SN: (.*)"}]}`,
			"unknown field",
		},
	}
	for name, tc := range cases {
		err := loadIdentityDoc(t, tc.probe)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantIn) {
			t.Errorf("%s: error %q does not mention %q", name, err, tc.wantIn)
		}
	}
}

// TestIdentityProbeIsDeepCopiedOut — the registry is shared immutable reference
// data; a caller must never be able to reach back into it through a slice.
func TestIdentityProbeIsDeepCopiedOut(t *testing.T) {
	reg := Default()
	_, probe, ok := reg.IdentityProbeForPlatformID("cisco/ios_xe")
	if !ok || len(probe.Commands) == 0 || len(probe.Commands[0].SerialPatterns) == 0 {
		t.Fatal("cisco/ios_xe carries no identity commands to copy")
	}
	probe.Commands[0].Command = "reload"
	probe.Commands[0].SerialPatterns[0] = "sabotaged"

	_, again, _ := reg.IdentityProbeForPlatformID("cisco/ios_xe")
	if again.Commands[0].Command == "reload" || again.Commands[0].SerialPatterns[0] == "sabotaged" {
		t.Fatal("a caller mutated the registry's own identity data")
	}
}
