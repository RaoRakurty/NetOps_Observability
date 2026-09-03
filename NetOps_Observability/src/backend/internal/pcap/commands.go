package pcap

import (
	"fmt"
	"strconv"
	"strings"

	"netops/backend/internal/vendorprofile"
)

// commands.go — the CLOSED per-vendor capture command set.
//
// WHERE THE COMMANDS LIVE. In the Vendor Profile registry
// (internal/vendorprofile), next to the config-capture commands already declared
// there — one declarative place per (vendor, platform), so onboarding a
// platform's packet capture is "author a profile", not "edit an engine". The
// registry now carries `capture.pcap_start_cmd` / `pcap_stop_cmd` /
// `pcap_cleanup_cmd` / `pcap_remote_path` / `pcap_supports_filter`, the family
// key `capture.pcap_family` and the platform text that resolves to it
// (`capture.pcap_platform_rules`), and NewProfileCommandTable is the shipped
// table that reads them.
//
// WHY THIS IS STILL AN INTERFACE. CommandTable is what lets the whole capture
// path be tested with no device and no registry, and it is what kept this
// package buildable while the templates lived here. The hand-written table this
// package used to ship is now the PARITY FIXTURE in commands_test.go: the
// registry-backed table must render byte-identical commands to it on every
// platform, interface and filter the fixtures cover. That test is the reason the
// move is verifiable rather than merely plausible.
//
// WHAT THIS PACKAGE STILL OWNS. The registry supplies TEMPLATES; this package
// owns the GRAMMAR that validates the values going into them (ValidateInterface,
// ValidateFilter, ValidateCaptureID) and the bounds that clamp them. Both must
// hold: a registry template is untrusted input to the renderer (§3), so For()
// re-validates every interpolated value even though the manager validated it
// first.
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
//	{name}   — the capture-point name, also derived from the minted capture id
//	{mb}     — the byte ceiling in whole megabytes (IOS-XE's buffer knob)
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
	// Render builds the command set. It is a closure rather than a raw template
	// so the compilation of a profile's templates happens ONCE, at table
	// construction, and rendering at capture time cannot fail on a template
	// defect.
	Render func(CommandRequest) CommandSet
}

// CommandTable resolves a device platform to its capture command set. Injecting
// it is what lets the whole capture path be tested with no device, and it is the
// seam through which the Vendor Profile registry became the source of these
// commands with no change to the manager, the HTTP surface or the store.
type CommandTable interface {
	// For returns the platform's capability and rendered commands. An unknown
	// platform is ErrNoPlatform — never a guessed command at a live device.
	For(platform string, req CommandRequest) (CommandSet, error)
	// Supports reports the platform key and whether it can filter, WITHOUT
	// rendering. The manager calls this to refuse a filtered request up front,
	// so the operator gets a 400 before anything touches the device.
	Supports(platform string) (key string, supportsFilter bool, ok bool)
}

// ── the shipped, registry-backed table ──────────────────────────────────────

// This package no longer carries a family table at all. The capture-family key
// ("cisco_iosxe", "cisco_nxos", "juniper_junos", "arista_eos") is declared BY
// the profile that owns the commands (capture.pcap_family), and the platform
// text that resolves to it is declared beside it (capture.pcap_platform_rules).
// Onboarding a platform's packet capture is therefore one document: name the
// family, say what platform text reaches it, author the commands.

// profileTable is a CommandTable whose templates come from a Vendor Profile
// registry. It is fully built by the constructor and never mutated afterwards,
// so it is safe to share across goroutines.
type profileTable struct {
	// reg is the registry this table was built from: it supplies the templates
	// AND the family resolution, so a table built over an operator-loaded
	// profile directory (the design's air-gap path) resolves platforms by that
	// directory's rules, not by the shipped ones.
	reg       *vendorprofile.Registry
	platforms map[string]PlatformCommands
}

// NewProfileCommandTable returns the SHIPPED table: the capture families above,
// resolved against the embedded Vendor Profile registry.
//
// It panics only on a malformed EMBEDDED profile set — the same impossible-in-
// production build defect vendorprofile.Default() already panics on, checked in
// CI by TestShippedProfileTableBuilds. There is no runtime condition here: a
// platform whose profile simply declares no packet-capture commands is ABSENT
// from the table and refused honestly, which is not an error.
func NewProfileCommandTable() CommandTable {
	t, err := NewCommandTableFrom(vendorprofile.Default())
	if err != nil {
		panic("pcap: embedded vendor profiles carry an unusable capture command set: " + err.Error())
	}
	return t
}

// NewCommandTableFrom builds a table over an arbitrary registry, so an
// operator-loaded profile directory (the design's air-gap path) and the tests
// both go through the same code as production.
//
// A profile that declares pcap_fetch_cmd is an ERROR, not a skip: the capture
// file is retrieved over the SSH gateway's transfer channel, so a fetch command
// declared here would never run, and a profile that describes a command nobody
// executes is a lie about what happens at the device (§10, no silent failure).
func NewCommandTableFrom(reg *vendorprofile.Registry) (CommandTable, error) {
	if reg == nil {
		return nil, fmt.Errorf("pcap: a command table needs a vendor profile registry")
	}
	families := reg.PcapFamilies()
	t := &profileTable{reg: reg, platforms: make(map[string]PlatformCommands, len(families))}
	for key, id := range families {
		capture, err := reg.CaptureFor(id)
		if err != nil || !capture.HasPcapCommands() {
			// No profile, or a profile that establishes no capture commands for
			// this platform. Absent from the table = refused at the device.
			continue
		}
		if len(capture.PcapFetchCmd) > 0 {
			return nil, fmt.Errorf("pcap: profile %s declares pcap_fetch_cmd, which this package cannot execute "+
				"(the capture file is fetched over the SSH gateway, not by a CLI command)", id)
		}
		pc, err := compilePlatform(key, id, capture)
		if err != nil {
			return nil, err
		}
		t.platforms[key] = pc
	}
	return t, nil
}

// compilePlatform turns one profile's capture block into a rendering closure.
// Every template is compiled ONCE here, so rendering at capture time cannot
// fail on a template defect and cannot be made to re-parse attacker-influenced
// text.
func compilePlatform(key, id string, capture vendorprofile.Capture) (PlatformCommands, error) {
	start, err := compileTemplates(id, "pcap_start_cmd", capture.PcapStartCmd)
	if err != nil {
		return PlatformCommands{}, err
	}
	stop, err := compileTemplates(id, "pcap_stop_cmd", capture.PcapStopCmd)
	if err != nil {
		return PlatformCommands{}, err
	}
	cleanup, err := compileTemplates(id, "pcap_cleanup_cmd", capture.PcapCleanupCmd)
	if err != nil {
		return PlatformCommands{}, err
	}
	path, err := compileTemplate(id, "pcap_remote_path", capture.PcapRemotePath)
	if err != nil {
		return PlatformCommands{}, err
	}
	if len(cleanup) == 0 {
		return PlatformCommands{}, fmt.Errorf("pcap: profile %s declares a capture start with no cleanup — "+
			"a capture point could be left configured on a production interface", id)
	}
	return PlatformCommands{
		Key:            key,
		SupportsFilter: capture.PcapSupportsFilter,
		Render: func(r CommandRequest) CommandSet {
			vals := templateValues(r)
			return CommandSet{
				Start:      renderAll(start, vals),
				Stop:       renderAll(stop, vals),
				RemotePath: renderParts(path, vals),
				Cleanup:    renderAll(cleanup, vals),
			}
		},
	}, nil
}

// Supports implements CommandTable.
func (t *profileTable) Supports(platform string) (string, bool, bool) {
	key, ok := t.reg.PcapFamilyForPlatform(platform)
	if !ok {
		return "", false, false
	}
	pc, ok := t.platforms[key]
	if !ok {
		// A family this package can NAME but whose profile establishes no
		// capture commands. Refused, never guessed.
		return "", false, false
	}
	return key, pc.SupportsFilter, true
}

// For implements CommandTable.
func (t *profileTable) For(platform string, req CommandRequest) (CommandSet, error) {
	key, ok := t.reg.PcapFamilyForPlatform(platform)
	if !ok {
		return CommandSet{}, ErrNoPlatform
	}
	pc, ok := t.platforms[key]
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

// prepareRequest is the defence-in-depth pass EVERY table runs before rendering.
// It re-checks the two untrusted strings and re-clamps the two bounds even
// though the manager already did both: a future caller that reaches a table
// directly must not be able to skip the grammar, and a table that trusted its
// input would make the grammar advisory. It is shared by the shipped table and
// by the parity fixture, so the two cannot drift on what "validated" means.
func prepareRequest(req CommandRequest) (CommandRequest, error) {
	if _, err := ValidateInterface(req.Interface); err != nil {
		return CommandRequest{}, err
	}
	if req.Filter != "" {
		canon, err := ValidateFilter(req.Filter)
		if err != nil {
			return CommandRequest{}, err
		}
		req.Filter = canon
	}
	if !ValidateCaptureID(strings.TrimPrefix(req.File, "correlix-")) {
		return CommandRequest{}, fmt.Errorf("pcap: refusing to render a command for an unminted capture file name")
	}
	if req.Name == "" {
		req.Name = "CORRELIX"
	}
	req.DurationSec = clampInt(req.DurationSec, 1, MaxDurationSeconds)
	req.MaxPackets = clampInt(req.MaxPackets, 1, MaxPackets)
	if req.MaxBytes <= 0 || req.MaxBytes > MaxBytes {
		req.MaxBytes = MaxBytes
	}
	return req, nil
}

// ── template compilation and rendering ──────────────────────────────────────
//
// A template is literal text plus `{hole}` placeholders, with optional `[ … ]`
// groups that are emitted only when every placeholder inside them has a value.
// That is the whole language — it exists so ONE template can express "…and, if
// the operator asked for a filter, this clause" without a second template. The
// registry validates the same rules at LOAD (vendorprofile.validatePcapCapture);
// they are re-checked here because a registry is an external dependency and §3
// does not exempt one.

// tplPart is one compiled fragment: literal text, a placeholder, or an optional
// group of fragments. Exactly one of the three is set.
type tplPart struct {
	lit  string
	hole string
	grp  []tplPart
}

// pcapHoles is the closed placeholder set, taken from the registry's own
// exported contract so the two packages cannot disagree about it.
var pcapHoles = func() map[string]bool {
	m := make(map[string]bool, len(vendorprofile.CapturePcapPlaceholders))
	for _, n := range vendorprofile.CapturePcapPlaceholders {
		m[n] = true
	}
	return m
}()

func compileTemplates(id, field string, tpls []string) ([][]tplPart, error) {
	if len(tpls) == 0 {
		// nil, not an empty slice: a platform with no stop command renders a nil
		// Stop, which is what the runtime treats as "nothing to run".
		return nil, nil
	}
	out := make([][]tplPart, 0, len(tpls))
	for _, tpl := range tpls {
		parts, err := compileTemplate(id, field, tpl)
		if err != nil {
			return nil, err
		}
		out = append(out, parts)
	}
	return out, nil
}

func compileTemplate(id, field, tpl string) ([]tplPart, error) {
	if strings.TrimSpace(tpl) == "" {
		return nil, fmt.Errorf("pcap: profile %s %s: empty command template", id, field)
	}
	var out, group []tplPart
	inGroup, groupHoles := false, 0
	var lit strings.Builder
	flush := func() {
		if lit.Len() == 0 {
			return
		}
		part := tplPart{lit: lit.String()}
		if inGroup {
			group = append(group, part)
		} else {
			out = append(out, part)
		}
		lit.Reset()
	}
	for i := 0; i < len(tpl); i++ {
		switch c := tpl[i]; c {
		case '{':
			end := strings.IndexByte(tpl[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("pcap: profile %s %s: unterminated placeholder in %q", id, field, tpl)
			}
			name := tpl[i+1 : i+end]
			if !pcapHoles[name] {
				return nil, fmt.Errorf("pcap: profile %s %s: unknown placeholder {%s} in %q", id, field, name, tpl)
			}
			flush()
			part := tplPart{hole: name}
			if inGroup {
				group = append(group, part)
				groupHoles++
			} else {
				out = append(out, part)
			}
			i += end
		case '}':
			return nil, fmt.Errorf("pcap: profile %s %s: stray '}' in %q", id, field, tpl)
		case '[':
			if inGroup {
				return nil, fmt.Errorf("pcap: profile %s %s: nested optional group in %q", id, field, tpl)
			}
			flush()
			inGroup, group, groupHoles = true, nil, 0
		case ']':
			if !inGroup {
				return nil, fmt.Errorf("pcap: profile %s %s: stray ']' in %q", id, field, tpl)
			}
			flush()
			if groupHoles == 0 {
				return nil, fmt.Errorf("pcap: profile %s %s: optional group with no placeholder in %q", id, field, tpl)
			}
			out = append(out, tplPart{grp: group})
			inGroup, group = false, nil
		default:
			lit.WriteByte(c)
		}
	}
	if inGroup {
		return nil, fmt.Errorf("pcap: profile %s %s: unclosed optional group in %q", id, field, tpl)
	}
	flush()
	return out, nil
}

// templateValues is the ONLY place a request becomes template input. Every value
// here has already been through prepareRequest; {filter} is the one that may be
// empty, and an empty one is exactly what makes its optional group disappear.
func templateValues(r CommandRequest) map[string]string {
	return map[string]string{
		"iface":  r.Interface,
		"file":   r.File,
		"count":  strconv.Itoa(r.MaxPackets),
		"secs":   strconv.Itoa(r.DurationSec),
		"filter": r.Filter,
		"name":   r.Name,
		"mb":     strconv.Itoa(mibCeil(r.MaxBytes)),
	}
}

func renderAll(tpls [][]tplPart, vals map[string]string) []string {
	if len(tpls) == 0 {
		return nil
	}
	out := make([]string, 0, len(tpls))
	for _, parts := range tpls {
		out = append(out, renderParts(parts, vals))
	}
	return out
}

func renderParts(parts []tplPart, vals map[string]string) string {
	var b strings.Builder
	for _, part := range parts {
		switch {
		case part.grp != nil:
			if groupHasEveryValue(part.grp, vals) {
				b.WriteString(renderParts(part.grp, vals))
			}
		case part.hole != "":
			b.WriteString(vals[part.hole])
		default:
			b.WriteString(part.lit)
		}
	}
	return b.String()
}

// groupHasEveryValue decides whether an optional group is emitted: it is, only
// if every placeholder inside it resolved to a non-empty value. A group is never
// emitted half-rendered.
func groupHasEveryValue(parts []tplPart, vals map[string]string) bool {
	for _, part := range parts {
		if part.hole != "" && vals[part.hole] == "" {
			return false
		}
	}
	return true
}

// PlatformKeys lists the capture-family keys the SHIPPED profiles name, sorted.
// Whether a given family has COMMANDS is the table's answer, not this list's: a
// key here whose profile declares no capture commands is refused by Supports.
//
// The resolution of free-form platform text ONTO one of these keys now lives in
// the registry (Registry.PcapFamilyForPlatform), beside the rules that drive it:
// this package owns the capture GRAMMAR (ValidateInterface, ValidateFilter,
// ValidateCaptureID) and the bounds, never the vendor vocabulary.
func PlatformKeys() []string { return vendorprofile.Default().PcapFamilyKeys() }

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
