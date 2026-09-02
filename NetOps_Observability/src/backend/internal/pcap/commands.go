package pcap

import (
	"fmt"
	"sort"
	"strings"
)

// commands.go — the CLOSED per-vendor capture command set.
//
// WHY THIS IS AN INTERFACE. The vendor-keyed capture commands belong in the
// Vendor Profile registry (internal/vendorprofile), next to the config-capture
// commands already declared there — one declarative place per (vendor,
// platform). That registry is owned elsewhere, so this module takes a
// CommandTable seam instead and ships a default table here. When the registry
// grows the `capture.pcap_start_cmd` / `pcap_stop_cmd` / `pcap_fetch_cmd` field
// set (the hunk is reported alongside this module), the integrator swaps this
// default for a registry-backed table with no change to anything else — the
// Deps seam is exactly the swap point.
//
// WHAT A TEMPLATE MAY CONTAIN. Every command below is a CONSTANT with typed
// holes. The only values interpolated are:
//
//	{iface}  — through ValidateInterface (letters/digits and / . - _ : only)
//	{file}   — derived from a server-minted 32-hex capture id, never a caller
//	           string
//	{count}  — an int already clamped to [1, MaxPackets]
//	{secs}   — an int already clamped to [1, MaxDurationSeconds]
//	{filter} — through ValidateFilter, re-rendered from validated tokens
//
// There is no path by which a caller's bytes reach a device un-validated, and no
// template concatenates a caller string into a shell word without the grammar
// above having proved it contains no shell-meaningful byte.

// CommandRequest is the fully-VALIDATED, already-clamped input to rendering.
// Rendering never validates: by the time a request reaches a table the manager
// has proved every field, which is why the table can be a set of format strings
// rather than an escaping engine.
type CommandRequest struct {
	// Interface is the validated interface name.
	Interface string
	// File is the on-device file base name (derived from the capture id).
	File string
	// DurationSec is in [1, MaxDurationSeconds].
	DurationSec int
	// MaxPackets is in [1, MaxPackets].
	MaxPackets int
	// MaxBytes is the size ceiling in bytes.
	MaxBytes int64
	// Filter is the canonical validated filter, or "" for none.
	Filter string
	// Name is the capture-point name on platforms that need one (IOS-XE).
	Name string
}

// CommandSet is what the runtime executes, in order. Every slice is a list of
// COMPLETE commands; the runtime never joins them with a shell operator.
type CommandSet struct {
	// Start brings the capture point up and begins capturing.
	Start []string
	// Stop ends the capture (idempotent — it may run after the device already
	// stopped on its own bound).
	Stop []string
	// RemotePath is the absolute on-device path of the resulting file.
	RemotePath string
	// Cleanup removes the on-device capture point AND the file. It is run on
	// every exit path, success or failure: leaving a capture point configured on
	// a production interface is the device-impact risk the design leads with.
	Cleanup []string
}

// PlatformCommands describes ONE platform's capability and templates.
type PlatformCommands struct {
	// Key is the canonical platform id ("cisco_iosxe", "cisco_nxos",
	// "juniper_junos", "arista_eos").
	Key string
	// SupportsFilter reports whether this platform's capture command can express
	// a pcap-style filter. FALSE means a filtered request is REFUSED, not
	// silently widened.
	SupportsFilter bool
	// Render builds the command set. It is a method value rather than a format
	// string so a platform whose stop/cleanup is conditional can express that
	// without a template language.
	Render func(CommandRequest) CommandSet
}

// CommandTable resolves a device platform to its capture command set. Injecting
// it is what lets the whole capture path be tested with no device, and what lets
// the Vendor Profile registry take over as the source of these commands without
// touching this package.
type CommandTable interface {
	// For returns the platform's capability and rendered commands. An unknown
	// platform is ErrNoPlatform — never a guessed command at a live device.
	For(platform string, req CommandRequest) (CommandSet, error)
	// Supports reports the platform key and whether it can filter, WITHOUT
	// rendering. The manager calls this to refuse a filtered request up front,
	// so the operator gets a 400 before anything touches the device.
	Supports(platform string) (key string, supportsFilter bool, ok bool)
}

// ── the default table ───────────────────────────────────────────────────────

// defaultTable is the shipped command set. It is a value type with no state, so
// it is safe to share.
type defaultTable struct{}

// NewDefaultCommandTable returns the built-in per-vendor table (Cisco IOS-XE,
// Cisco NX-OS, Juniper Junos, Arista EOS).
func NewDefaultCommandTable() CommandTable { return defaultTable{} }

// defaultPlatforms is the closed set. Order is irrelevant; resolution is by key.
var defaultPlatforms = map[string]PlatformCommands{
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

// platformTokens splits a free-form vendor/OS/model string into lower-case
// alphanumeric tokens plus their concatenation. Matching on TOKENS rather than
// substrings is deliberate: a substring rule for "eos" also matches the vendor
// string "acme-networks SomeOS", and silently rendering Arista commands at an
// unknown device is exactly the "invent an API at a live router" failure §7
// forbids. The joined form is used only for the two-part names ("ios-xe",
// "nx-os") that a substring test can identify unambiguously.
func platformTokens(platform string) (map[string]bool, string) {
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

// resolvePlatform maps a device platform token onto a table key. Order matters:
// the specific families are tested before the bare-vendor fallback.
func resolvePlatform(platform string) (string, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return "", false
	}
	if _, ok := defaultPlatforms[p]; ok {
		return p, true
	}
	tok, joined := platformTokens(p)
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
		// Plain "cisco ios" is the IOS-XE command family for our purposes; the
		// more specific families above have already claimed their devices.
		return "cisco_iosxe", true
	}
	return "", false
}

// Supports implements CommandTable.
func (defaultTable) Supports(platform string) (string, bool, bool) {
	key, ok := resolvePlatform(platform)
	if !ok {
		return "", false, false
	}
	return key, defaultPlatforms[key].SupportsFilter, true
}

// For implements CommandTable.
func (t defaultTable) For(platform string, req CommandRequest) (CommandSet, error) {
	key, ok := resolvePlatform(platform)
	if !ok {
		return CommandSet{}, ErrNoPlatform
	}
	pc := defaultPlatforms[key]
	if req.Filter != "" && !pc.SupportsFilter {
		return CommandSet{}, ErrFilterUnsupported
	}
	// Defence in depth: rendering re-checks the two untrusted strings even
	// though the manager already validated them. A future caller that reaches a
	// table directly must not be able to skip the grammar.
	if _, err := ValidateInterface(req.Interface); err != nil {
		return CommandSet{}, err
	}
	if req.Filter != "" {
		canon, err := ValidateFilter(req.Filter)
		if err != nil {
			return CommandSet{}, err
		}
		req.Filter = canon
	}
	if !ValidateCaptureID(strings.TrimPrefix(req.File, "correlix-")) {
		return CommandSet{}, fmt.Errorf("pcap: refusing to render a command for an unminted capture file name")
	}
	if req.Name == "" {
		req.Name = "CORRELIX"
	}
	req.DurationSec = clampInt(req.DurationSec, 1, MaxDurationSeconds)
	req.MaxPackets = clampInt(req.MaxPackets, 1, MaxPackets)
	if req.MaxBytes <= 0 || req.MaxBytes > MaxBytes {
		req.MaxBytes = MaxBytes
	}
	return pc.Render(req), nil
}

// PlatformKeys lists the table's platform keys (tests + the status surface).
func PlatformKeys() []string {
	out := make([]string, 0, len(defaultPlatforms))
	for k := range defaultPlatforms {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clampInt(v, lo, hi int) int {
	switch {
	case v < lo:
		return lo
	case v > hi:
		return hi
	default:
		return v
	}
}

// mibCeil renders a byte cap as whole megabytes, minimum 1 — IOS-XE's buffer
// size knob is in MB.
func mibCeil(b int64) int {
	if b <= 0 {
		return 1
	}
	mb := (b + (1 << 20) - 1) / (1 << 20)
	if mb < 1 {
		return 1
	}
	return int(mb)
}

// captureFileName derives the on-device file base name from a minted capture id.
// It is NOT caller input: the id is 32 hex characters this package generated.
func captureFileName(id string) string { return "correlix-" + id }

// captureName renders the capture-point name for platforms that need one.
func captureName(id string) string {
	if len(id) >= 8 {
		return "CORRELIX" + strings.ToUpper(id[:8])
	}
	return "CORRELIX"
}
