package vendorprofile

// consumer_bindings_test.go — the ROW PINS for the vendor knowledge that moved
// into this registry when tracker 221 closed the last five vendor-keyed tables
// outside it (internal/configstore's platform/command/volatile tables,
// internal/snmpcred's onboarding CLI blocks, internal/pcap's capture-family
// resolver, the root device-type inference and topology's firewall vendor hint).
//
// A move is only a move if the DATA is the same data. Each consumer keeps its
// own byte-parity golden against the implementation it had before (see
// snmpcred/configgen_parity_test.go, pcap/commands_parity_test.go,
// backend/devicetype_parity_test.go); these tests are the other half — they pin
// the rows AT THE REGISTRY, verbatim, so a profile edit that changes what a
// device is sent, what an operator pastes, or what a box is called fails HERE,
// naming the row, rather than somewhere downstream naming a symptom.

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ─── config capture (internal/configstore) ───────────────────────────────────

// TestConfigCaptureCommandsAreTheRowsTheModuleShipped pins the EXACT command a
// config backup issues at a device prompt, per vendor family. These strings are
// executed on production routers: they are not a detail, they are the contract.
func TestConfigCaptureCommandsAreTheRowsTheModuleShipped(t *testing.T) {
	want := map[string]string{
		"cisco":   "show running-config",
		"arista":  "show running-config",
		"juniper": "show configuration | display set | no-more",
		"huawei":  "display current-configuration",
		"nokia":   "admin display-config",
		// A SIBLING DIALECT, not a vendor: Nokia ships two CLIs and SR Linux
		// answers neither `admin display-config` nor anything else SR OS knows.
		// LIVE-VERIFIED on lab spine1 (172.40.40.11, SR Linux v26.3.2) over the
		// same single non-interactive SSH exec the capture gateway uses — `info`
		// with a path argument returns NOTHING there, so the root form and the
		// explicit `from running` are both load-bearing.
		"srlinux": "info from running flat",
	}
	reg := Default()
	for family, cmd := range want {
		got, ok := reg.ConfigCaptureCommand(family)
		if !ok {
			t.Errorf("capture family %q declares no config-capture command", family)
			continue
		}
		if got != cmd {
			t.Errorf("config-capture command for %q changed:\n got %q\nwant %q", family, got, cmd)
		}
	}
	// The table is CLOSED: a family outside it must have no command, so the
	// module refuses the device instead of probing it. Iterating the FAMILIES
	// (vendors + their dialects) is what makes a new dialect fail here rather
	// than ship a device-facing command with no golden behind it.
	for _, family := range reg.ConfigCaptureFamilies() {
		if _, pinned := want[family]; pinned {
			continue
		}
		if cmd, ok := reg.ConfigCaptureCommand(family); ok {
			t.Errorf("capture family %q gained a config-capture command (%q) with no golden — add the row to this test deliberately", family, cmd)
		}
	}
	for _, vendor := range reg.VendorIDs() {
		if _, pinned := want[vendor]; pinned {
			continue
		}
		if cmd, ok := reg.ConfigCaptureCommand(vendor); ok {
			t.Errorf("vendor %q gained a config-capture command (%q) with no golden — add the row to this test deliberately", vendor, cmd)
		}
	}
	if _, ok := reg.ConfigCaptureCommand(""); ok {
		t.Error("the empty vendor must have no capture command")
	}
}

// TestConfigCaptureVendorResolutionOrder pins the platform-text table AND the
// order that makes it correct: Arista is tested before Cisco because EOS
// platform strings frequently name a "Cisco-compatible" CLI, and EOS wants its
// own volatile-line rules.
func TestConfigCaptureVendorResolutionOrder(t *testing.T) {
	cases := map[string]string{
		"Cisco IOS-XE 17.9":     "cisco",
		"cisco nx-os 9.3":       "cisco",
		"Cisco IOS XR 7.3":      "cisco",
		"Arista EOS 4.30":       "arista",
		"Juniper Junos 21.4":    "juniper",
		"Huawei VRP V800":       "huawei",
		"Nokia SR OS 22.10":     "nokia",
		"alcatel 7750":          "nokia",
		"TiMOS-B-22.10":         "nokia",
		"arista cisco-like eos": "arista",
		// The srlinux DIALECT must win over its own vendor: "Nokia SR Linux"
		// contains "nokia", and the nokia family would answer it with SR OS'
		// `admin display-config` — a command SR Linux does not have.
		"Nokia SR Linux":       "srlinux",
		"srlinux 24.3.2":       "srlinux",
		"Nokia SR Linux 26.3":  "srlinux",
		"":                     "",
		"SomeVendor MagicOS 1": "",
	}
	reg := Default()
	for platform, want := range cases {
		got, ok := reg.ConfigCaptureVendorForPlatform(platform)
		if want == "" {
			if ok {
				t.Errorf("ConfigCaptureVendorForPlatform(%q) = %q, want no vendor", platform, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("ConfigCaptureVendorForPlatform(%q) = %q (ok=%v), want %q", platform, got, ok, want)
		}
	}
}

// TestConfigVolatileRuleNamesArePinned pins the documented normalization rules
// by NAME. A rule that silently disappears would mint a new config "version" on
// every capture (a clock line back in the hash); one that appears without review
// could eat real configuration and hide a change.
func TestConfigVolatileRuleNamesArePinned(t *testing.T) {
	want := map[string][]string{
		"cisco":   {"building-config", "current-config", "last-change", "nvram-updated", "ntp-clock-period", "time-stamp"},
		"arista":  {"eos-time", "eos-device-banner", "eos-command"},
		"juniper": {"junos-last-commit", "junos-version-cmt"},
		"huawei":  {"vrp-last-updated", "vrp-saved-by", "vrp-software"},
		"nokia":   {"sros-generated", "sros-finished", "sros-tim-version"},
		// SR Linux declares NONE, and that is a measured claim, not a gap: the
		// `info from running flat` form stamps no timestamp, counter or build
		// header, and two consecutive captures of lab spine1 were byte-identical
		// (728 lines). Inheriting SR OS' three `# Generated/# Finished/# TiMOS-`
		// rules would have been three patterns that can never match.
		"srlinux": nil,
	}
	reg := Default()
	for family, names := range want {
		if got := reg.ConfigVolatileRuleNames(family); !reflect.DeepEqual(got, names) {
			t.Errorf("volatile rules for %q changed:\n got %v\nwant %v", family, got, names)
		}
	}
	if got := reg.ConfigVolatileRuleNames("acme"); got != nil {
		t.Errorf("an unknown vendor must have no volatile rules, got %v", got)
	}
}

// TestConfigVolatileRulesMatchTheLinesTheyDocument is the behaviour half: each
// rule's NAME says what it drops, and this asserts it actually drops it — and,
// as importantly, that it leaves real configuration alone.
func TestConfigVolatileRulesMatchTheLinesTheyDocument(t *testing.T) {
	reg := Default()
	drops := []struct{ vendor, line string }{
		{"cisco", "Building configuration..."},
		{"cisco", "Current configuration : 4231 bytes"},
		{"cisco", "! Last configuration change at 10:00:00 UTC Mon Aug 25 2026"},
		{"cisco", "! NVRAM config last updated at 09:59:00 UTC Mon Aug 25 2026"},
		{"cisco", "ntp clock-period 17179869"},
		{"cisco", "! Time: Mon Aug 25 10:00:00 2026"},
		{"arista", "! Time: Mon Aug 25 10:00:00 2026"},
		{"arista", "! device: sw1 (DCS-7050, EOS-4.30)"},
		{"arista", "! command: show running-config"},
		{"juniper", "## Last commit: 2026-08-25 10:00:00 UTC"},
		{"juniper", "## Last changed: 2026-08-25 10:00:00 UTC"},
		{"juniper", "## version 21.4R3"},
		{"huawei", "!Last configuration was updated at 2026-08-25"},
		{"huawei", "!Last configuration was saved at 2026-08-25"},
		{"huawei", "#saved by admin"},
		{"huawei", "!Software Version V800R011C10"},
		{"nokia", "# Generated THU AUG 25 10:00:00 2026 UTC"},
		{"nokia", "# Finished THU AUG 25 10:00:02 2026 UTC"},
		{"nokia", "# TiMOS-B-22.10.R3"},
	}
	// SR Linux drops NOTHING of its own — the assertion is the absence.
	for _, line := range []string{
		"set / system information description SRLinux-v26.3.2",
		"# Generated THU AUG 25 10:00:00 2026 UTC",
	} {
		if reg.IsConfigVolatileLine("srlinux", line) {
			t.Errorf("srlinux: line dropped by a rule the dialect does not declare: %q", line)
		}
	}
	for _, d := range drops {
		if !reg.IsConfigVolatileLine(d.vendor, d.line) {
			t.Errorf("%s: volatile line survived normalization: %q", d.vendor, d.line)
		}
	}
	keeps := []struct{ vendor, line string }{
		{"cisco", "ntp server 10.1.1.1"},
		{"cisco", "hostname edge-01"},
		{"cisco", "boot system flash:image.bin"},
		{"cisco", "snmp-server host 10.2.2.2 version 2c public"},
		{"arista", "hostname sw1"},
		{"juniper", "set system host-name r1"},
		{"huawei", "sysname r1"},
		{"nokia", "configure system name \"r1\""},
	}
	for _, k := range keeps {
		if reg.IsConfigVolatileLine(k.vendor, k.line) {
			t.Errorf("%s: normalization ate real configuration: %q", k.vendor, k.line)
		}
	}
}

// ─── SNMP onboarding templates (internal/snmpcred) ───────────────────────────

// TestSNMPConfigGenVendorsArePinned pins WHICH vendors claim a first-class
// onboarding block. The set is what the API reports as `templated`.
func TestSNMPConfigGenVendorsArePinned(t *testing.T) {
	want := []string{"arista", "checkpoint", "cisco", "extreme", "f5", "fortinet",
		"huawei", "juniper", "mikrotik", "paloalto", "ubiquiti"}
	if got := Default().SNMPConfigGenVendors(); !reflect.DeepEqual(got, want) {
		t.Errorf("the templated vendor set changed:\n got %v\nwant %v", got, want)
	}
}

// TestSNMPConfigGenPlaceholderUsageIsPinned pins which HOLES each block carries.
// It is the assertion that catches the failure mode a rendered-block eyeball
// test does not: a template that stops naming <<priv_key>>, or starts naming
// <<mgmt_subnet>> where no operator value is supplied, still renders something
// that looks like a device configuration.
func TestSNMPConfigGenPlaceholderUsageIsPinned(t *testing.T) {
	want := map[string]struct{ v2c, v3 []string }{
		"cisco":      {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"arista":     {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"juniper":    {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"fortinet":   {v2c: []string{"community", "mask", "mgmt_subnet"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"paloalto":   {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"f5":         {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"checkpoint": {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"mikrotik":   {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"huawei":     {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"extreme":    {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
		"ubiquiti":   {v2c: []string{"community"}, v3: []string{"auth_key", "priv_key", "sec_name"}},
	}
	reg := Default()
	for vendor, holes := range want {
		g, ok := reg.SNMPConfigGenFor(vendor)
		if !ok {
			t.Errorf("vendor %q declares no snmp_configgen block", vendor)
			continue
		}
		if got := holesOf(g.V2CTemplate); !reflect.DeepEqual(got, holes.v2c) {
			t.Errorf("%s v2c_template holes changed: got %v, want %v", vendor, got, holes.v2c)
		}
		if got := holesOf(g.V3Template); !reflect.DeepEqual(got, holes.v3) {
			t.Errorf("%s v3_template holes changed: got %v, want %v", vendor, got, holes.v3)
		}
	}
}

// holesOf returns the sorted, distinct placeholder names a template carries.
func holesOf(tpl string) []string {
	seen := map[string]bool{}
	rest := tpl
	for {
		i := strings.Index(rest, "<<")
		if i < 0 {
			break
		}
		rest = rest[i+2:]
		end := strings.Index(rest, ">>")
		if end < 0 {
			break
		}
		seen[rest[:end]] = true
		rest = rest[end+2:]
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// TestSNMPConfigGenRendersTheJunosBlockVerbatim pins ONE whole multi-line block
// byte for byte — the Junos one, because it carries newlines, embedded quotes
// and the same hole three times, so it proves the JSON round trip and the
// single-pass renderer reproduce an authored block exactly. (Every vendor's
// block is pinned against the pre-move implementation by
// snmpcred.TestDeviceConfigIsByteIdenticalToTheHandWrittenTable.)
func TestSNMPConfigGenRendersTheJunosBlockVerbatim(t *testing.T) {
	const want = `set snmp v3 usm local-engine user correlix authentication-sha authentication-key "AUTH"
set snmp v3 usm local-engine user correlix privacy-aes128 privacy-key "PRIV"
set snmp v3 vacm security-to-group security-model usm security-name correlix group correlix-grp
set snmp v3 vacm access group correlix-grp default-context-prefix security-model usm security-level privacy read-view all
set snmp view all oid .1 include`
	got, ok := Default().RenderSNMPConfig("juniper", "v3", map[string]string{
		"sec_name": "correlix", "auth_key": "AUTH", "priv_key": "PRIV",
	})
	if !ok {
		t.Fatal("juniper declares no v3 onboarding template")
	}
	if got != want {
		t.Errorf("the Junos onboarding block changed:\n got:\n%s\nwant:\n%s", got, want)
	}
}

// TestRenderSNMPConfigIsSinglePass — a rendered VALUE must never be re-scanned
// for holes. One of the values (the management subnet) is operator input, so a
// sequential ReplaceAll renderer would let "<<priv_key>>" as a subnet pull the
// MINTED PRIVACY KEY into the block.
func TestRenderSNMPConfigIsSinglePass(t *testing.T) {
	got, ok := Default().RenderSNMPConfig("fortinet", "v2c", map[string]string{
		"community": "<<priv_key>>", "mgmt_subnet": "<<auth_key>>", "mask": "255.0.0.0",
		"auth_key": "AUTHCANARY", "priv_key": "PRIVCANARY",
	})
	if !ok {
		t.Fatal("fortinet declares no v2c onboarding template")
	}
	for _, canary := range []string{"AUTHCANARY", "PRIVCANARY"} {
		if strings.Contains(got, canary) {
			t.Fatalf("SECRET LEAK: %q reached the block through an operator-supplied value:\n%s", canary, got)
		}
	}
}

// TestSNMPConfigGenRefusesAnUnknownVendorOrVersion — no ambient fallback in the
// registry: the honest "no template" answer is what lets the generator print
// generic guidance instead of another vendor's grammar.
func TestSNMPConfigGenRefusesAnUnknownVendorOrVersion(t *testing.T) {
	reg := Default()
	if _, ok := reg.RenderSNMPConfig("acme", "v3", nil); ok {
		t.Error("an unknown vendor rendered a template")
	}
	if _, ok := reg.RenderSNMPConfig("nokia", "v3", nil); ok {
		t.Error("nokia declares no onboarding template but rendered one")
	}
}

// ─── functional device type (root inference + topology node kind) ────────────

// TestDeviceTypeTextHintsArePinned pins the WHOLE moved hint table, per type.
// The union is what the inference reads; the per-vendor documents it is
// assembled from are an authoring convenience, so the union is what a test must
// pin or the table could be shuffled between documents unnoticed.
func TestDeviceTypeTextHintsArePinned(t *testing.T) {
	want := map[string][]string{
		"firewall":      {"asa", "check point", "checkpoint", "firepower", "firewall", "fortigate", "fortios", "fpr-", "ftd", "ngfw", "palo alto", "pan-os", "panos", "srx"},
		"load-balancer": {"avi vantage", "big-ip", "bigip", "citrix adc", "f5 ", "load-balanc", "loadbalanc", "netscaler"},
		"wlc":           {"9800", "mobility express", "wireless controller", "wireless lan controller", "wism", "wlc"},
		"ap":            {"access point", "accesspoint", "air-ap", "air-cap", "aironet", "meraki mr", "uap-", "wifi", "wireless ap"},
		"cloud-gw":      {"c8000v cloud", "cloud gateway", "cloud-gw", "cloudgw", "csr1000v", "tgw", "transit gateway", "vgw", "vmx cloud", "vpn gateway"},
		"switch":        {" eos", " ex2", " ex3", " ex4", "arista", "catalyst", "dcs-", "icx", "nexus", "powerconnect", "qfx", "switch", "ws-c"},
		"router":        {" mx", "7250", "7750", "asr", "c8000v", "crs", "csr", "gsr", "isr", "ncs", "ptx", "router", "vmx", "vsr"},
	}
	reg := Default()
	for _, kind := range DeviceTypeOrder {
		if got := reg.DeviceTypeTextHints(kind); !reflect.DeepEqual(got, want[kind]) {
			t.Errorf("device-type hints for %q changed:\n got %q\nwant %q", kind, got, want[kind])
		}
	}
	// No hint may be authored outside the closed vocabulary.
	for kind := range reg.devTypeText {
		if _, ok := want[kind]; !ok {
			t.Errorf("device-type hints appeared for the unpinned type %q", kind)
		}
	}
}

// TestDeviceTypeOrderIsSpecificRolesFirst pins the ORDER, which is the policy
// half: a Catalyst 9800 carries both "catalyst" (switch) and "9800" (wlc), and
// it is a WLC. If the order ever inverted, every wireless controller in the
// estate would silently become a switch.
func TestDeviceTypeOrderIsSpecificRolesFirst(t *testing.T) {
	want := []string{"firewall", "load-balancer", "wlc", "ap", "cloud-gw", "switch", "router"}
	if !reflect.DeepEqual(DeviceTypeOrder, want) {
		t.Fatalf("DeviceTypeOrder changed: got %v, want %v", DeviceTypeOrder, want)
	}
	reg := Default()
	cases := map[string]string{
		"cisco catalyst 9800-cl":             "wlc",
		"cisco catalyst 9300":                "switch",
		"cisco asr1000":                      "router",
		"cisco asa 5525 firewall":            "firewall",
		"arista dcs-7050":                    "switch",
		"f5 big-ip i4800":                    "load-balancer",
		"ubiquiti uap-ac-pro":                "ap",
		"aws-transit gateway":                "cloud-gw",
		"juniper mx240":                      "router",
		"cisco csr1000v router in the cloud": "cloud-gw",
		"acme widget":                        "",
		"":                                   "",
	}
	for text, want := range cases {
		got, ok := reg.DeviceTypeForText(text)
		if want == "" {
			if ok {
				t.Errorf("DeviceTypeForText(%q) = %q, want no answer", text, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("DeviceTypeForText(%q) = %q (ok=%v), want %q", text, got, ok, want)
		}
	}
}

// TestDeviceTypeVendorTokensArePinned pins the vendor spellings that are
// themselves a role claim — topology's firewall hint. The match is EXACT: a
// vendor id is an identity, and a substring rule here would call every device
// whose vendor string merely mentions a firewall vendor a firewall.
func TestDeviceTypeVendorTokensArePinned(t *testing.T) {
	want := map[string]string{
		"fortinet": "firewall", "fortigate": "firewall",
		"palo alto": "firewall", "paloalto": "firewall", "palo-alto": "firewall", "panw": "firewall",
		"checkpoint": "firewall", "check point": "firewall",
	}
	reg := Default()
	if len(reg.devTypeVend) != len(want) {
		t.Errorf("the vendor-kind table changed size: got %v, want %v", reg.devTypeVend, want)
	}
	for token, kind := range want {
		got, ok := reg.DeviceTypeForVendorToken(token)
		if !ok || got != kind {
			t.Errorf("DeviceTypeForVendorToken(%q) = %q (ok=%v), want %q", token, got, ok, kind)
		}
	}
	for _, token := range []string{"cisco", "juniper", "arista", "fortinet-lookalike", ""} {
		if kind, ok := reg.DeviceTypeForVendorToken(token); ok {
			t.Errorf("DeviceTypeForVendorToken(%q) = %q, want no claim", token, kind)
		}
	}
	// Case and surrounding space are normalized, exactly as the callers pass it.
	if kind, ok := reg.DeviceTypeForVendorToken("  Palo Alto "); !ok || kind != "firewall" {
		t.Errorf("vendor token normalization changed: %q %v", kind, ok)
	}
}

// ─── packet-capture families (internal/pcap) ─────────────────────────────────

// TestPcapFamiliesArePinned pins which profile owns which capture family. A
// family silently re-pointed at another profile would send one platform's
// commands to another platform's device.
func TestPcapFamiliesArePinned(t *testing.T) {
	want := map[string]string{
		"cisco_iosxe":   "cisco/ios_xe",
		"cisco_nxos":    "cisco/nx-os",
		"juniper_junos": "juniper/junos",
		"arista_eos":    "arista/eos",
	}
	reg := Default()
	if got := reg.PcapFamilies(); !reflect.DeepEqual(got, want) {
		t.Errorf("the capture-family table changed:\n got %v\nwant %v", got, want)
	}
	wantKeys := []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"}
	if got := reg.PcapFamilyKeys(); !reflect.DeepEqual(got, wantKeys) {
		t.Errorf("PcapFamilyKeys() = %v, want %v", got, wantKeys)
	}
	// Every family must declare commands, or a device it names is refused.
	for _, key := range wantKeys {
		c, err := reg.CaptureFor(want[key])
		if err != nil || !c.HasPcapCommands() {
			t.Errorf("family %q resolves to %q, which declares no packet-capture commands (%v)", key, want[key], err)
		}
	}
}

// TestPcapPlatformRuleOrderIsPinned pins the RANKS, which are the resolver: the
// specific families must be tested before the bare-vendor fallback, or a Nexus
// (whose platform text also says "cisco") would be sent IOS-XE commands.
func TestPcapPlatformRuleOrderIsPinned(t *testing.T) {
	want := []pcapRule{
		{rank: 10, family: "cisco_nxos", tokens: []string{"nexus"}, joined: []string{"nxos"}},
		{rank: 20, family: "cisco_iosxe", tokens: []string{"catalyst", "isr", "asr"}, joined: []string{"iosxe"}},
		{rank: 30, family: "juniper_junos", tokens: []string{"junos", "juniper"}},
		{rank: 40, family: "arista_eos", tokens: []string{"eos", "arista"}},
		{rank: 50, family: "cisco_iosxe", tokens: []string{"cisco"}},
	}
	if got := Default().pcapRules; !reflect.DeepEqual(got, want) {
		t.Errorf("the capture-family resolution order changed:\n got %+v\nwant %+v", got, want)
	}
}

// ─── dialect: VRF scope keyword (internal/tac) ───────────────────────────────

// TestVRFScopeKeywordsArePinned pins the CLI token each vendor's dialect puts
// ahead of a VRF / routing-instance name, which internal/tac renders into the
// `{vrf-scope}` placeholder of its command plans (tracker row 248, where it
// stopped being a switch in internal/tac/plan.go). These strings go on a wire:
// a wrong keyword is a command the device rejects, so the row is the contract.
//
// An EMPTY keyword is an authored answer, not a gap — that vendor's own command
// templates already carry the keyword the CLI needs and take the bare instance
// name after it (SR Linux `show network-instance <name> …`, SR OS
// `show router <name> …`, PAN-OS `logical-router <name>`).
func TestVRFScopeKeywordsArePinned(t *testing.T) {
	want := map[string]string{
		"arista":   "vrf",          // EOS: show ip ospf vrf <name>
		"cisco":    "vrf",          // IOS / IOS-XE / IOS-XR / NX-OS: show ip route vrf <name>
		"huawei":   "vpn-instance", // VRP: display ip routing-table vpn-instance <name>
		"juniper":  "instance",     // Junos: show ospf neighbor instance <name>
		"nokia":    "",             // SR Linux / SR OS scope with the bare instance name
		"paloalto": "",             // PAN-OS scopes with logical-router / virtual-router <name>
		"fortinet": "",             // no authored FortiOS command is VRF-scoped
	}
	reg := Default()
	for vendor, kw := range want {
		rec, ok := reg.Vendor(vendor)
		if !ok {
			t.Errorf("vendor %q is not in the registry", vendor)
			continue
		}
		if got := rec.Dialect.VRFScopeKeyword; got != kw {
			t.Errorf("vendor %q vrf_scope_keyword = %q, pinned %q", vendor, got, kw)
		}
	}
	// Every OTHER vendor must leave it unset: an unauthored keyword is the bare
	// name, and inventing one for a vendor with no command plan would be a
	// vendor fact nobody checked.
	for _, id := range reg.VendorIDs() {
		if _, pinned := want[id]; pinned {
			continue
		}
		rec, ok := reg.Vendor(id)
		if !ok {
			t.Fatalf("vendor %q listed but not resolvable", id)
		}
		if kw := rec.Dialect.VRFScopeKeyword; kw != "" {
			t.Errorf("vendor %q authors vrf_scope_keyword %q but is not pinned here", id, kw)
		}
	}
}
