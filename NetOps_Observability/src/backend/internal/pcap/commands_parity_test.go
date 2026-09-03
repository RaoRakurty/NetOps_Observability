package pcap

// commands_parity_test.go — the PARITY FIXTURE for the move of the packet-capture
// command set into the Vendor Profile registry.
//
// Until this change internal/pcap SHIPPED the per-vendor commands as Go format
// strings. They now live in internal/vendorprofile's profile documents
// (capture.pcap_*), and NewProfileCommandTable renders them. A move like that is
// only safe if it is a move: the exact bytes that used to reach a production
// router must still reach it, on every platform, for every interface and filter
// the module's own fixtures exercise.
//
// So the deleted hand-written table is preserved HERE, verbatim, as the golden.
// TestRegistryTableRendersByteIdenticalCommandsToTheHandWrittenTable renders
// both tables over the same request matrix and compares the CommandSets field by
// field. If a profile edit ever changes what a device is told to do, this test
// says so in terms of the command line, not in terms of JSON.
//
// It is a golden, not a second implementation: nothing in the package builds on
// it, and when a profile deliberately changes a command the golden is updated in
// the same commit as the profile — deliberately, and visibly in the diff.

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"netops/backend/internal/vendorprofile"
)

// handWrittenTable is the table internal/pcap shipped before the registry owned
// these commands. It implements CommandTable through the SAME prepareRequest
// pass the registry-backed table uses, so the comparison isolates the templates
// and nothing else.
type handWrittenTable struct{}

func newHandWrittenCommandTable() CommandTable { return handWrittenTable{} }

// goldenResolve is the platform → capture-family resolution the golden uses. It
// goes through the SHIPPED registry, exactly as the production table does over
// its own registry, so the comparison below isolates the TEMPLATES and nothing
// else. (Resolution itself is pinned separately, against the token rules the
// hand-written switch used to carry, by
// TestPcapFamilyResolutionMatchesTheHandWrittenSwitch.)
func goldenResolve(platform string) (string, bool) {
	return vendorprofile.Default().PcapFamilyForPlatform(platform)
}

func (handWrittenTable) Supports(platform string) (string, bool, bool) {
	key, ok := goldenResolve(platform)
	if !ok {
		return "", false, false
	}
	pc, ok := handWrittenPlatforms[key]
	if !ok {
		return "", false, false
	}
	return key, pc.SupportsFilter, true
}

func (handWrittenTable) For(platform string, req CommandRequest) (CommandSet, error) {
	key, ok := goldenResolve(platform)
	if !ok {
		return CommandSet{}, ErrNoPlatform
	}
	pc, ok := handWrittenPlatforms[key]
	if !ok {
		return CommandSet{}, ErrNoPlatform
	}
	if req.Filter != "" && !pc.SupportsFilter {
		return CommandSet{}, ErrFilterUnsupported
	}
	req, err := prepareRequest(req)
	if err != nil {
		return CommandSet{}, err
	}
	return pc.Render(req), nil
}

// handWrittenPlatforms is that table, verbatim.
var handWrittenPlatforms = map[string]PlatformCommands{
	// Cisco IOS-XE Embedded Packet Capture. EPC has NO pcap-filter syntax — its
	// selection is an access-list or a `match` clause with a fixed shape — so
	// this platform declares SupportsFilter=false and a filtered request is
	// refused rather than run unfiltered (design: a capture must never be wider
	// than the operator asked for).
	"cisco_iosxe": {
		Key:            "cisco_iosxe",
		SupportsFilter: false,
		Render: func(r CommandRequest) CommandSet {
			path := "flash:" + r.File + ".pcap"
			return CommandSet{
				Start: []string{
					fmt.Sprintf("monitor capture %s interface %s both", r.Name, r.Interface),
					fmt.Sprintf("monitor capture %s match any", r.Name),
					fmt.Sprintf("monitor capture %s buffer size %d", r.Name, mibCeil(r.MaxBytes)),
					fmt.Sprintf("monitor capture %s limit packets %d duration %d", r.Name, r.MaxPackets, r.DurationSec),
					fmt.Sprintf("monitor capture %s start", r.Name),
				},
				Stop:       []string{fmt.Sprintf("monitor capture %s stop", r.Name)},
				RemotePath: path,
				Cleanup: []string{
					fmt.Sprintf("monitor capture %s stop", r.Name),
					fmt.Sprintf("no monitor capture %s", r.Name),
					fmt.Sprintf("delete /force %s", path),
				},
			}
		},
	},
	// Cisco NX-OS ethanalyzer. `capture-filter` takes a genuine pcap-filter
	// expression, so this platform can express the operator's filter.
	"cisco_nxos": {
		Key:            "cisco_nxos",
		SupportsFilter: true,
		Render: func(r CommandRequest) CommandSet {
			path := "bootflash:" + r.File + ".pcap"
			cmd := fmt.Sprintf("ethanalyzer local interface %s limit-captured-frames %d limit-frame-size 0",
				r.Interface, r.MaxPackets)
			if r.Filter != "" {
				// The filter is already proven to contain no quote and no byte
				// outside [a-z0-9./:-() ]. The quotes are belt-and-braces; the
				// grammar is the actual defence.
				cmd += fmt.Sprintf(" capture-filter %q", r.Filter)
			}
			cmd += " write " + path
			return CommandSet{
				Start:      []string{cmd},
				Stop:       nil, // ethanalyzer is synchronous and self-bounding
				RemotePath: "/" + r.File + ".pcap",
				Cleanup:    []string{fmt.Sprintf("delete %s no-prompt", path)},
			}
		},
	},
	// Juniper Junos `monitor traffic … write-file`. `matching` takes a tcpdump
	// expression.
	"juniper_junos": {
		Key:            "juniper_junos",
		SupportsFilter: true,
		Render: func(r CommandRequest) CommandSet {
			path := "/var/tmp/" + r.File + ".pcap"
			cmd := fmt.Sprintf("monitor traffic interface %s no-resolve brief count %d write-file %s",
				r.Interface, r.MaxPackets, path)
			if r.Filter != "" {
				cmd += fmt.Sprintf(" matching %q", r.Filter)
			}
			return CommandSet{
				Start:      []string{cmd},
				Stop:       nil, // `count` bounds it; the runtime's deadline is the backstop
				RemotePath: path,
				Cleanup:    []string{"file delete " + path},
			}
		},
	},
	// Arista EOS runs tcpdump under `bash`. This is the ONLY platform where the
	// rendered command reaches a real shell, which is why the filter grammar is
	// an allowlist rather than an escaping pass: the filter is single-quoted
	// here AND cannot contain a quote, a backslash, a `$`, a backtick or a
	// newline, because ValidateFilter refuses those bytes outright.
	"arista_eos": {
		Key:            "arista_eos",
		SupportsFilter: true,
		Render: func(r CommandRequest) CommandSet {
			path := "/mnt/flash/" + r.File + ".pcap"
			cmd := fmt.Sprintf("bash timeout %d tcpdump -i %s -c %d -s 0 -U -w %s",
				r.DurationSec, r.Interface, r.MaxPackets, path)
			if r.Filter != "" {
				cmd += " '" + r.Filter + "'"
			}
			return CommandSet{
				Start:      []string{cmd},
				Stop:       nil, // `timeout` + `-c` bound it on the device
				RemotePath: path,
				Cleanup:    []string{"bash rm -f " + path},
			}
		},
	},
}

// TestShippedProfileTableBuilds — the embedded profile set must yield a usable
// table for every capture family this package names. A family that silently
// lost its commands would answer "platform not supported" at the API, which is
// honest but wrong; this catches it in CI instead.
func TestShippedProfileTableBuilds(t *testing.T) {
	table := NewProfileCommandTable()
	for _, key := range PlatformKeys() {
		gotKey, _, ok := table.Supports(key)
		if !ok || gotKey != key {
			t.Errorf("the shipped profiles declare no capture commands for %q", key)
		}
	}
	if _, ok := handWrittenPlatforms["cisco_iosxe"]; !ok {
		t.Fatal("the parity golden is empty — the comparison below would be vacuous")
	}
}

// parityRequests is the matrix the two tables are compared over: every platform,
// every interface shape the grammar admits, every filter the grammar accepts,
// and the bound values that exercise clamping and the megabyte knob.
func parityRequests(t *testing.T) []struct {
	platform string
	req      CommandRequest
} {
	t.Helper()
	ifaces := []string{"Ethernet1/1", "ge-0/0/0.100", "GigabitEthernet0/0/1", "xe-0/0/0:1", "eth0"}
	filters := []string{"", "host 10.1.2.3", "tcp and port 22", "(tcp and port 80) or udp", "net 10.0.0.0/8 and not port 22"}
	bounds := []struct {
		secs, count int
		bytes       int64
	}{
		{30, 100, MaxBytes},
		{1, 1, 1},
		{MaxDurationSeconds, MaxPackets, MaxBytes},
		{100000, MaxPackets * 100, MaxBytes * 4}, // out of range on purpose: both tables clamp
		{7, 3, 3 << 20},
	}
	var out []struct {
		platform string
		req      CommandRequest
	}
	for _, platform := range PlatformKeys() {
		for _, iface := range ifaces {
			for _, f := range filters {
				for _, b := range bounds {
					out = append(out, struct {
						platform string
						req      CommandRequest
					}{platform, CommandRequest{
						Interface: iface, File: captureFileName(testCaptureID), Name: captureName(testCaptureID),
						DurationSec: b.secs, MaxPackets: b.count, MaxBytes: b.bytes, Filter: f,
					}})
				}
			}
		}
	}
	return out
}

// TestRegistryTableRendersByteIdenticalCommandsToTheHandWrittenTable is the
// whole justification for moving the commands into the registry: the device sees
// exactly what it saw before.
func TestRegistryTableRendersByteIdenticalCommandsToTheHandWrittenTable(t *testing.T) {
	registry := NewProfileCommandTable()
	golden := newHandWrittenCommandTable()

	cases := parityRequests(t)
	if len(cases) < 100 {
		t.Fatalf("only %d parity cases — the matrix is not exercising the templates", len(cases))
	}
	rendered := 0
	for _, tc := range cases {
		gotKey, gotFilter, gotOK := registry.Supports(tc.platform)
		wantKey, wantFilter, wantOK := golden.Supports(tc.platform)
		if gotKey != wantKey || gotFilter != wantFilter || gotOK != wantOK {
			t.Fatalf("Supports(%q): registry = (%q,%v,%v), golden = (%q,%v,%v)",
				tc.platform, gotKey, gotFilter, gotOK, wantKey, wantFilter, wantOK)
		}
		got, gotErr := registry.For(tc.platform, tc.req)
		want, wantErr := golden.For(tc.platform, tc.req)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Fatalf("For(%q, iface=%q, filter=%q): registry err = %v, golden err = %v",
				tc.platform, tc.req.Interface, tc.req.Filter, gotErr, wantErr)
		}
		if gotErr != nil {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("COMMAND DRIFT on %s (iface=%q filter=%q secs=%d count=%d bytes=%d):\n registry: %s\n golden:   %s",
				tc.platform, tc.req.Interface, tc.req.Filter, tc.req.DurationSec, tc.req.MaxPackets, tc.req.MaxBytes,
				showSet(got), showSet(want))
		}
		rendered++
	}
	if rendered == 0 {
		t.Fatal("no case rendered — the parity assertion is vacuous")
	}
}

func showSet(s CommandSet) string {
	return fmt.Sprintf("start=%q stop=%q path=%q cleanup=%q", s.Start, s.Stop, s.RemotePath, s.Cleanup)
}

// TestProfileTableRefusesAPlatformTheProfilesDoNotEstablish — the honest-refusal
// half. A registry that knows a vendor but declares no capture commands for it
// must yield "not supported", never a command assembled from a guess.
func TestProfileTableRefusesAPlatformTheProfilesDoNotEstablish(t *testing.T) {
	table, err := NewCommandTableFrom(emptyCaptureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range append(PlatformKeys(), "cisco IOS-XE", "arista EOS", "acme-networks SomeOS") {
		if key, _, ok := table.Supports(platform); ok {
			t.Errorf("Supports(%q) = %q, true — a platform with no declared commands must be refused", platform, key)
		}
		if _, err := table.For(platform, testRequest("Ethernet1/1", "")); !errors.Is(err, ErrNoPlatform) {
			t.Errorf("For(%q) = %v, want ErrNoPlatform", platform, err)
		}
	}
}

// TestProfileTableRefusesAFetchCommandItCannotRun — a profile that declares a
// command this package will never execute is a lie about what happens at the
// device, so the table refuses to build rather than ignoring the field (§10).
func TestProfileTableRefusesAFetchCommandItCannotRun(t *testing.T) {
	_, err := NewCommandTableFrom(fetchCmdRegistry(t))
	if err == nil {
		t.Fatal("a profile declaring pcap_fetch_cmd built a table — the declared command would be silently dropped")
	}
	if !strings.Contains(err.Error(), "pcap_fetch_cmd") {
		t.Fatalf("the refusal does not name the offending field: %v", err)
	}
}

// TestCommandTableFromNilRegistryIsRefused — no ambient fallback: a table with
// no registry is a construction error, not an empty table that quietly refuses
// every device.
func TestCommandTableFromNilRegistryIsRefused(t *testing.T) {
	if _, err := NewCommandTableFrom(nil); err == nil {
		t.Fatal("a nil registry built a table")
	}
}

// ─── synthetic registries ────────────────────────────────────────────────────
//
// Both helpers build a REAL vendorprofile.Registry through the real loader, so
// these tests exercise the same construction path production does — an
// operator-loadable profile directory is the design's air-gap story, and a fake
// registry would prove nothing about it.

func loadRegistry(t *testing.T, vendor string, doc map[string]any) *vendorprofile.Registry {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := vendorprofile.Load(fstest.MapFS{"p/" + vendor + ".json": &fstest.MapFile{Data: b}}, "p")
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return reg
}

// profileDoc is the minimum valid vendor document with one platform.
func profileDoc(vendor, platform string, capture map[string]any) map[string]any {
	return map[string]any{
		"schema_version": vendorprofile.SchemaVersion,
		"vendor":         vendor,
		"display_name":   strings.ToUpper(vendor),
		"detection":      map[string]any{},
		"dialect":        map[string]any{},
		"profiles": []any{map[string]any{
			"platform":     platform,
			"display_name": vendor + " " + platform,
			"device_class": []string{"switch"},
			"fidelity":     vendorprofile.FidelityDocClaimed,
			"detection":    map[string]any{},
			"capture":      capture,
			"advisory":     map[string]any{},
			"hardening":    map[string]any{},
			"threat":       map[string]any{},
		}},
	}
}

// emptyCaptureRegistry knows a vendor but establishes NO capture commands.
func emptyCaptureRegistry(t *testing.T) *vendorprofile.Registry {
	t.Helper()
	return loadRegistry(t, "cisco", profileDoc("cisco", "ios_xe", map[string]any{
		"running_config_cmd": "show running-config",
	}))
}

// fetchCmdRegistry declares a fetch command internal/pcap cannot execute.
func fetchCmdRegistry(t *testing.T) *vendorprofile.Registry {
	t.Helper()
	return loadRegistry(t, "cisco", profileDoc("cisco", "ios_xe", map[string]any{
		"pcap_start_cmd":   []string{"monitor capture {name} interface {iface} both"},
		"pcap_fetch_cmd":   []string{"copy flash:{file}.pcap running"},
		"pcap_cleanup_cmd": []string{"no monitor capture {name}"},
		"pcap_remote_path": "flash:{file}.pcap",
		// A profile that declares capture commands must name the family they
		// belong to — the registry refuses commands no platform could reach.
		"pcap_family": "cisco_iosxe",
	}))
}

// ─── capture-family RESOLUTION parity ────────────────────────────────────────
//
// The templates were moved into the registry earlier; the RESOLVER — free-form
// platform text → capture-family key — moved with tracker 221. It was the last
// vendor-keyed switch in this package, and this is its golden: the deleted
// function, verbatim, compared against Registry.PcapFamilyForPlatform over a
// corpus of platform strings.
//
// Resolution is the half of the move with the most room to go quietly wrong: a
// rule that stops matching does not render a bad command, it renders NO command,
// and the device is refused. That failure is honest but wrong, and a golden is
// the only way to know the ranked rules in the profiles reproduce the order the
// switch had (nxos before iosxe before junos before eos before the bare-vendor
// fallback).

// handWrittenPlatformTokens is the deleted tokenizer, verbatim.
func handWrittenPlatformTokens(platform string) (map[string]bool, string) {
	set := map[string]bool{}
	var cur strings.Builder
	var joined strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			set[cur.String()] = true
			joined.WriteString(cur.String())
			cur.Reset()
		}
	}
	for _, r := range strings.ToLower(platform) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return set, joined.String()
}

// handWrittenResolvePlatform is the deleted resolver, verbatim, including the
// family-key table it consulted first.
func handWrittenResolvePlatform(platform string) (string, bool) {
	handWrittenProfileIDForKey := map[string]string{
		"cisco_iosxe":   "cisco/ios_xe",
		"cisco_nxos":    "cisco/nx-os",
		"juniper_junos": "juniper/junos",
		"arista_eos":    "arista/eos",
	}
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return "", false
	}
	if _, ok := handWrittenProfileIDForKey[p]; ok {
		return p, true
	}
	tok, joined := handWrittenPlatformTokens(p)
	switch {
	case tok["nxos"] || tok["nexus"] || strings.Contains(joined, "nxos"):
		return "cisco_nxos", true
	case tok["iosxe"] || tok["catalyst"] || tok["isr"] || tok["asr"] || strings.Contains(joined, "iosxe"):
		return "cisco_iosxe", true
	case tok["junos"] || tok["juniper"]:
		return "juniper_junos", true
	case tok["eos"] || tok["arista"]:
		return "arista_eos", true
	case tok["cisco"]:
		return "cisco_iosxe", true
	}
	return "", false
}

// resolutionCorpus is every platform string shape this resolver has ever had to
// answer for, crossed with the separators, cases and version suffixes real
// discovery data carries — plus the near-misses the token rule exists to refuse
// ("acme-networks SomeOS" must not become Arista).
func resolutionCorpus() []string {
	bases := []string{
		"", " ", "cisco_iosxe", "cisco_nxos", "juniper_junos", "arista_eos",
		"cisco", "Cisco", "CISCO", "cisco ios", "Cisco IOS 15.2", "cisco ios-xe",
		"Cisco IOS-XE 17.9", "cisco iosxe", "cisco ios xe", "IOS-XE", "iosxe",
		"cisco ios-xr", "Cisco IOS XR 7.3", "cisco nx-os", "Cisco NX-OS 9.3",
		"nxos", "nx-os", "Nexus 9000", "cisco nexus 93180", "catalyst", "Catalyst 9300",
		"ISR4451", "isr 4331", "ASR1001-X", "asr 9000", "cisco asa 9.12",
		"juniper", "Juniper Junos 21.4", "junos", "JUNOS 20.4R3", "juniper mx240",
		"arista", "Arista EOS 4.30", "eos", "cEOS-lab", "arista dcs-7050",
		"nokia sr os", "Nokia SR Linux", "huawei vrp", "Huawei VRP V800",
		"acme-networks SomeOS", "SomeVendor MagicOS 1", "generic", "linux 5.15",
		"f5 big-ip", "fortigate 100f", "palo alto pan-os", "mikrotik routeros",
		"paloalto", "checkpoint gaia", "ubiquiti unifi", "extreme exos",
		"arista cisco-like eos", "cisco-compatible eos", "nexus + catalyst",
		"ios-xe on a catalyst", "somejunosbox", "not-a-junos-box", "myeoshost",
		"asrouter", "isr", "asr", "wan-r2", "core-sw-01", "1.2.3.4", "!!!", "___",
	}
	seps := []string{" ", "-", "_", ".", "/", ""}
	var out []string
	out = append(out, bases...)
	for _, b := range bases {
		for _, sep := range seps {
			out = append(out, b+sep+"17.9.3a", "vendor"+sep+b, strings.ToUpper(b)+sep+"x")
		}
	}
	return out
}

// TestPcapFamilyResolutionMatchesTheHandWrittenSwitch — the resolver moved, and
// it answers exactly what it answered before.
func TestPcapFamilyResolutionMatchesTheHandWrittenSwitch(t *testing.T) {
	reg := vendorprofile.Default()
	corpus := resolutionCorpus()
	if len(corpus) < 500 {
		t.Fatalf("only %d resolution cases — the corpus is not exercising the rules", len(corpus))
	}
	for _, platform := range corpus {
		gotKey, gotOK := reg.PcapFamilyForPlatform(platform)
		wantKey, wantOK := handWrittenResolvePlatform(platform)
		if gotKey != wantKey || gotOK != wantOK {
			t.Fatalf("RESOLUTION DRIFT for %q: registry = (%q,%v), golden = (%q,%v)",
				platform, gotKey, gotOK, wantKey, wantOK)
		}
	}
	// The corpus must actually reach every family, or "identical" is vacuous.
	seen := map[string]bool{}
	for _, platform := range corpus {
		if key, ok := reg.PcapFamilyForPlatform(platform); ok {
			seen[key] = true
		}
	}
	for _, key := range PlatformKeys() {
		if !seen[key] {
			t.Errorf("the resolution corpus never reaches family %q", key)
		}
	}
	t.Logf("compared %d platform strings across %d capture families", len(corpus), len(seen))
}
