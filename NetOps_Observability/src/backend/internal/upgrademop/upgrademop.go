// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package upgrademop holds Correlix's built-in software-upgrade procedures: one
// method of procedure (MOP) per platform family, written for a PERSON to follow.
//
// READ-ONLY BY DESIGN (owner decision 2026-11-18, "will go with readonly";
// device writes structurally prohibited since 2026-09-05). Nothing here runs a
// command. Every step names who performs it — the engineer — and, where one
// exists, the read-only show command Iris can run to confirm the step's result.
// Those commands are the only device text in the package, and a test holds each
// of them to the device gateway's read guard (protocoldiag.ValidateReadOnly).
//
// Each procedure is written in Correlix's own words from the vendor's PUBLIC
// documentation, cited (title, URL, the version read and when). No image URL,
// no credential and no configuration command a device would accept as a change
// appears as a check.
//
// A workspace admin can adopt a procedure as a draft of their own runbook
// (tenantrunbook, kind "mop"): from there the usual two-person approval decides
// whether it reaches Iris. Iris itself shows a procedure step by step when asked
// how to upgrade a platform.
//
// This package is a leaf (stdlib only) so both the assistant (ai) and the
// runbook store (tenantrunbook) can read it without importing each other.
package upgrademop

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ActorEngineer is who performs every step that changes a device.
const ActorEngineer = "engineer"

// Step is one line of a procedure.
type Step struct {
	// Do is what the engineer does, in plain words.
	Do string
	// Check is the read-only show command Iris can run to confirm the step's
	// result, or "" when there is no read-only check for it.
	Check string
}

// Template is one built-in procedure.
type Template struct {
	// Name is the runbook name an adopted copy takes by default.
	Name string
	// Vendor and Family say what it is for ("Cisco", "IOS XE (install mode)").
	Vendor string
	Family string
	// Title is the procedure's heading.
	Title string
	// AppliesTo lists the platforms the source documentation covers.
	AppliesTo string
	// Doc is the public source the steps were written from.
	Doc Citation
	// Intro is the one-paragraph body a reader sees above the steps.
	Intro string
	Steps []Step
	// dialects are the show-command dialect ids (showparse, e.g. "cisco/ios_xe")
	// this procedure fits.
	dialects []string
	// cue matches a question that names this platform.
	cue *regexp.Regexp
}

// Citation is a public document a procedure was written from.
type Citation struct {
	Title   string
	URL     string
	Version string // the edition or release read
	Read    string // when it was read (YYYY-MM-DD)
}

// reParen drops a parenthetical ("IOS XE (install mode)" → "IOS XE").
var reParen = regexp.MustCompile(`\s*\([^)]*\)`)

// templates is the closed set, in display order.
var templates = []Template{
	{
		Name:      "upgrade-cisco-iosxe-install",
		Vendor:    "Cisco",
		Family:    "IOS XE (install mode)",
		Title:     "Upgrade a Cisco IOS XE device in install mode",
		AppliesTo: "Catalyst 9000 switches; the same install workflow applies to other IOS XE platforms that run in install mode",
		Doc: Citation{
			Title:   "Upgrade Guide for Catalyst 9000 Switches (Cisco tech note 216231)",
			URL:     "https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/216231-upgrade-guide-for-cisco-catalyst-9000-sw.html",
			Version: "Cisco tech note 216231",
			Read:    "2026-11-18",
		},
		Intro: "Install mode loads the release as packages listed in packages.conf. The engineer performs every change below; Iris only reads the device to confirm each step. Commands differ between releases and models, so read the release notes for the exact image first. An SD-WAN edge is upgraded from the SD-WAN Manager, not with this procedure.",
		Steps: []Step{
			{"Read the target release's notes for this model and confirm the upgrade path and the bootloader (ROMMON) version they require.", "show version"},
			{"Confirm the device already runs in install mode (it boots packages.conf); convert it from bundle mode first if it does not.", "show version | include Installation mode"},
			{"Record a baseline before the window: interface states, routing neighbours and route counts, and save a copy of the running configuration off the device.", "show ip interface brief"},
			{"Check the boot flash has room for the new image and its expanded packages; remove inactive packages with the platform's clean-up command if it does not.", "show file systems"},
			{"Copy the new image to the boot flash and verify its checksum against the value Cisco publishes for that image.", "show file systems"},
			{"Confirm the boot variable points at packages.conf and that the running configuration is saved.", "show boot"},
			{"In the approved window, add, activate and commit the new image with the install command, accepting the reload it starts.", "show install summary"},
			{"If the activation set a rollback timer, commit before it expires, or the device returns to the previous release on its own.", "show install summary"},
			{"After the reload, confirm the running release is the new one and every stack member or supervisor is ready.", "show version"},
			{"Compare the device with the baseline (interfaces, neighbours, routes) and close the change only when they match.", "show ip interface brief"},
			{"If the new release misbehaves, return to the previously committed release with the install rollback command, then compare with the baseline again.", "show install summary"},
		},
		dialects: []string{"cisco/ios_xe"},
		cue:      regexp.MustCompile(`\b(ios[\s-]?xe|catalyst\s?9\d{2,3}|catalyst\s?9k|cat\s?9k|c9[2-6]00|c9k|isr\s?4\d{3}|asr\s?1\d{3}|c8[0-5]00|catalyst\s?8\d{3})\b`),
	},
	{
		Name:      "upgrade-cisco-nxos",
		Vendor:    "Cisco",
		Family:    "NX-OS",
		Title:     "Upgrade a Cisco Nexus 9000 switch running NX-OS",
		AppliesTo: "Nexus 9000 series switches",
		Doc: Citation{
			Title:   "Cisco Nexus 9000 Series NX-OS Software Upgrade and Downgrade Guide, Release 10.5(x)",
			URL:     "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/105x/upgrade/cisco-nexus-9000-series-nx-os-software-upgrade-and-downgrade-guide-105x/m-upgrade-or-downgrade-the-cisco-nexus-9000-series-nx-os-software.html",
			Version: "Release 10.5(x)",
			Read:    "2026-11-18",
		},
		Intro: "Cisco recommends the install all command for NX-OS upgrades because it checks configuration compatibility and upgrades the BIOS as part of the run, and it is the only supported way to downgrade. The engineer performs every change below; Iris only reads the switch to confirm each step.",
		Steps: []Step{
			{"Read the target release's notes and the upgrade guide for your release train, and confirm the path from the running release is supported directly.", "show version"},
			{"Record a baseline before the window: interface states, routing neighbours and route counts, and save a copy of the running configuration off the switch.", "show interface brief"},
			{"Confirm every module is online before you start.", "show module"},
			{"Copy the new image to bootflash and verify its checksum against the value Cisco publishes for that image.", ""},
			{"Run the install all impact check for the new image and read what it reports as disruptive; this check changes nothing.", ""},
			{"If the switch is a vPC peer, upgrade one peer at a time and confirm the vPC is healthy before and after each one.", "show vpc"},
			{"In the approved window, run install all with the new image and let it reload the switch.", "show install all status"},
			{"After the reload, confirm the running release is the new one and every module is online.", "show version"},
			{"Compare the switch with the baseline (interfaces, neighbours, routes) and close the change only when they match.", "show interface brief"},
			{"If you need to go back, downgrade with install all to the previous release; changing the boot variable and reloading is not a supported downgrade.", "show install all status"},
		},
		dialects: []string{"cisco/nx-os"},
		cue:      regexp.MustCompile(`\b(nx[\s-]?os|nexus(\s?9\d{3}|\s?9k)?|n9k)\b`),
	},
	{
		Name:      "upgrade-juniper-junos",
		Vendor:    "Juniper",
		Family:    "Junos OS",
		Title:     "Upgrade a Juniper device running Junos OS",
		AppliesTo: "Junos OS devices (MX, EX, QFX, SRX and others); routers with two Routing Engines upgrade one at a time",
		Doc: Citation{
			Title:   "Junos OS Software Installation and Upgrade Guide: Preparing for Software Installation and Upgrade",
			URL:     "https://www.juniper.net/documentation/us/en/software/junos/junos-install-upgrade/topics/topic-map/prepare-sotware-install-and-upgrade.html",
			Version: "Junos OS Software Installation and Upgrade Guide (current online edition)",
			Read:    "2026-11-18",
		},
		Intro: "A Junos upgrade copies the installation package to the device, installs it from the command line, and reboots into the new release. The engineer performs every change below; Iris only reads the device to confirm each step. Package names differ by platform, so check that the package matches the device.",
		Steps: []Step{
			{"Read the target release's notes and confirm the installation package is the one for this platform and the upgrade path is supported.", "show version"},
			{"Record a baseline before the window: interface states, routing neighbours and route counts, and save a rescue configuration and a copy of the configuration off the device.", "show interfaces terse"},
			{"Check there is room for the package; clean up old files with the storage clean-up command if there is not.", "show system storage"},
			{"Copy the package to the device and verify its checksum against the value Juniper publishes for it.", "show system storage"},
			{"On a router with two Routing Engines, upgrade the backup Routing Engine first, switch over to it once it runs correctly, then upgrade the other.", "show chassis routing-engine"},
			{"Install the package with validation against the current configuration, so an incompatible configuration is caught before the reboot.", ""},
			{"In the approved window, reboot into the new release.", "show system uptime"},
			{"After the reboot, confirm the running release is the new one and that there are no new system or chassis alarms.", "show system alarms"},
			{"Compare the device with the baseline (interfaces, neighbours, routes) and close the change only when they match.", "show route summary"},
			{"If the new release misbehaves, roll back to the previous software with the software rollback command and reboot, then compare with the baseline again.", "show version"},
		},
		dialects: []string{"juniper/junos"},
		cue:      regexp.MustCompile(`\b(junos|juniper|mx\s?\d{2,4}|ex\s?\d{4}|qfx\s?\d{4}|srx\s?\d{3,4}|ptx\s?\d{4})\b`),
	},
	{
		Name:      "upgrade-arista-eos",
		Vendor:    "Arista",
		Family:    "EOS",
		Title:     "Upgrade an Arista switch running EOS",
		AppliesTo: "Arista EOS switches with one supervisor; dual-supervisor chassis use the install command instead of editing boot-config",
		Doc: Citation{
			Title:   "Arista EOS User Manual: Standard Upgrades and Downgrades",
			URL:     "https://www.arista.com/en/um-eos/eos-standard-upgrades-and-downgrades",
			Version: "EOS 4.37.0F manual",
			Read:    "2026-11-18",
		},
		Intro: "A standard EOS upgrade replaces the image the switch boots and reloads it. The engineer performs every change below; Iris only reads the switch to confirm each step. Smart System Upgrade, where the platform supports it, reduces the outage and has its own procedure.",
		Steps: []Step{
			{"Read the target release's notes and confirm the release supports this platform.", "show version"},
			{"Record a baseline before the window: interface states, routing neighbours and route counts, and save a copy of the running configuration off the switch.", "show interfaces status"},
			{"Check the flash has room for two copies of the new image, because EOS copies the image again while it boots.", "show file systems"},
			{"Copy the new image to flash and verify its checksum against the value Arista publishes for it.", "show file systems"},
			{"If the switch is an MLAG peer, upgrade one peer at a time and confirm MLAG is healthy before and after each one.", "show mlag"},
			{"Point the boot configuration at the new image and save the running configuration.", "show boot-config"},
			{"In the approved window, reload the switch.", "show reload cause"},
			{"After the reload, confirm the running release is the new one and that installed extensions still load.", "show version"},
			{"Compare the switch with the baseline (interfaces, neighbours, routes) and close the change only when they match.", "show ip route summary"},
			{"If the new release misbehaves, point the boot configuration back at the previous image and reload, then compare with the baseline again.", "show boot-config"},
		},
		dialects: []string{"arista/eos"},
		cue:      regexp.MustCompile(`\b(arista|eos|dcs-\d{4}|7[0-9]{3}[a-z]{0,2}\s?series)\b`),
	},
}

// All returns the built-in procedures, in display order. The slice is a copy.
func All() []Template {
	out := make([]Template, len(templates))
	copy(out, templates)
	return out
}

// Get returns the procedure named name.
func Get(name string) (Template, bool) {
	for _, t := range templates {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}

// Names lists the procedures' names, sorted.
func Names() []string {
	out := make([]string, 0, len(templates))
	for _, t := range templates {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

// Match picks the procedure a question names ("how do I upgrade a Catalyst 9300"),
// else the one that fits a device's discovered dialect ("" = unknown). ok=false
// when neither says which platform is meant: the caller asks, never guesses.
func Match(question, dialect string) (Template, bool) {
	q := strings.ToLower(question)
	for _, t := range templates {
		if t.cue.MatchString(q) {
			return t, true
		}
	}
	d := strings.ToLower(strings.TrimSpace(dialect))
	if d == "" {
		return Template{}, false
	}
	for _, t := range templates {
		for _, td := range t.dialects {
			if d == td {
				return t, true
			}
		}
	}
	return Template{}, false
}

// Checks returns the procedure's read-only show commands, in step order, without
// repeats.
func (t Template) Checks() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range t.Steps {
		if c := strings.TrimSpace(s.Check); c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// StepLine renders one step as a single line: who does it, and what Iris can read
// to confirm it.
func (s Step) StepLine() string {
	if strings.TrimSpace(s.Check) == "" {
		return "Performed by the engineer: " + s.Do + " (no read-only check for this step)"
	}
	return "Performed by the engineer: " + s.Do + " Iris can confirm it read-only with: " + s.Check
}

// SkillMD renders the procedure as a tenant runbook of kind "mop" (the dialect
// the skill loader parses). It carries no link and names no Iris tool in prose:
// a runbook is data, and the runbook rules refuse both. The gather line is the
// read Iris uses for the checks; a MOP's gather is never dispatched on its own.
func (t Template) SkillMD() string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "name: %s\n", t.Name)
	b.WriteString("layer: platform\n")
	b.WriteString("version: 1\n")
	b.WriteString("kind: mop\n")
	family := strings.ToLower(strings.TrimSpace(reParen.ReplaceAllString(t.Family, "")))
	fmt.Fprintf(&b, "when_to_use: upgrade %s %s, %s software upgrade, %s upgrade steps\n",
		strings.ToLower(t.Vendor), family, family, strings.ToLower(t.Vendor))
	b.WriteString("symptom_kinds: upgrade, change\n")
	b.WriteString("tools: get_device_state\n")
	b.WriteString("gather:\n  - get_device_state(device_id, area=platform)\n")
	b.WriteString("look_for:\n")
	b.WriteString("  - the running release before and after the change, and whether it is the target release\n")
	b.WriteString("  - the baseline taken before the window, and what differs from it afterwards\n")
	b.WriteString("decisions:\n")
	b.WriteString("  - verdict=state which step the engineer has reached, what the read-only check showed for it, and whether the device matches its baseline\n")
	b.WriteString("steps:\n")
	for _, s := range t.Steps {
		fmt.Fprintf(&b, "  - %s\n", s.StepLine())
	}
	b.WriteString("---\n")
	fmt.Fprintf(&b, "%s\n\n", t.Intro)
	fmt.Fprintf(&b, "Applies to: %s.\n\n", t.AppliesTo)
	fmt.Fprintf(&b, "Written in Correlix's own words from %s (%s, read %s). Check the release notes for your exact model and release before you start; commands differ between releases.\n",
		t.Doc.Title, t.Doc.Version, t.Doc.Read)
	return b.String()
}
