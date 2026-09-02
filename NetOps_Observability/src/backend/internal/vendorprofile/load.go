package vendorprofile

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// profilesFS holds the checked-in, embedded profile documents. An embedded FS
// var is necessarily package-level (//go:embed requires it) but is IMMUTABLE
// read-only data, not shared mutable program state — the same carve-out
// internal/hardening documents for its compile-once matchers (§5).
//
//go:embed profiles/*.json
var profilesFS embed.FS

// enterpriseOIDPrefix is the fixed arc every IANA private-enterprise
// sysObjectID sits under.
const enterpriseOIDPrefix = "1.3.6.1.4.1."

// vendorDoc is the on-disk shape of one vendor document (profiles/<vendor>.json).
type vendorDoc struct {
	SchemaVersion int       `json:"schema_version"`
	Vendor        string    `json:"vendor"`
	DisplayName   string    `json:"display_name"`
	Detection     Detection `json:"detection"`
	Dialect       Dialect   `json:"dialect"`
	Profiles      []Profile `json:"profiles"`
	Notes         string    `json:"notes,omitempty"`
}

// ErrNotFound is returned by the lookup helpers that report an error rather than
// an ok-flag. It is the HONEST answer for a vendor or platform the registry does
// not know: the caller reports unassessed and applies NO fallback profile.
var ErrNotFound = errors.New("vendorprofile: no profile for the given vendor/platform")

// defaultRegistry builds the shipped registry exactly once. The embedded data is
// a build-time constant validated by TestEmbeddedProfilesLoad in CI, so a load
// failure here is an impossible-in-production build defect, not a runtime
// condition — it panics loudly rather than degrading a vendor lookup silently.
var defaultRegistry = sync.OnceValue(func() *Registry {
	reg, err := Load(profilesFS, "profiles")
	if err != nil {
		panic("vendorprofile: embedded profile set is invalid: " + err.Error())
	}
	return reg
})

// Default returns the shipped, immutable registry built from the embedded
// profile documents.
func Default() *Registry { return defaultRegistry() }

// Load parses and validates every *.json document under dir in fsys and builds a
// Registry. It is exported so tests (and a future operator-loadable profile
// directory, the air-gap path in the design) can build a registry from any
// filesystem. Parsing is STRICT: unknown keys, missing required fields and
// violated cross-document invariants are all errors.
func Load(fsys fs.FS, dir string) (*Registry, error) {
	names, err := fs.Glob(fsys, path.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("vendorprofile: glob %s: %w", dir, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("vendorprofile: no profile documents under %s", dir)
	}
	sort.Strings(names) // deterministic load order → deterministic registry
	docs := make([]vendorDoc, 0, len(names))
	for _, name := range names {
		b, rerr := fs.ReadFile(fsys, name)
		if rerr != nil {
			return nil, fmt.Errorf("vendorprofile: read %s: %w", name, rerr)
		}
		doc, derr := decodeVendorDoc(name, b)
		if derr != nil {
			return nil, derr
		}
		docs = append(docs, doc)
	}
	return build(docs)
}

// decodeVendorDoc strictly decodes one vendor document and validates the fields
// that can be checked without cross-document context.
func decodeVendorDoc(name string, b []byte) (vendorDoc, error) {
	var doc vendorDoc
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: %w", name, err)
	}
	if dec.More() {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: trailing content after the document", name)
	}
	if doc.SchemaVersion != SchemaVersion {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: schema_version %d, want %d", name, doc.SchemaVersion, SchemaVersion)
	}
	if doc.Vendor == "" {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: vendor is required", name)
	}
	if doc.Vendor != strings.ToLower(doc.Vendor) || strings.TrimSpace(doc.Vendor) != doc.Vendor {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: vendor %q must be lower-case and untrimmed-free", name, doc.Vendor)
	}
	if want := path.Base(name); want != doc.Vendor+".json" {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: file name must be %s.json", name, doc.Vendor)
	}
	if doc.DisplayName == "" {
		return vendorDoc{}, fmt.Errorf("vendorprofile: %s: display_name is required", name)
	}
	if err := validateVendorDetection(name, doc.Detection); err != nil {
		return vendorDoc{}, err
	}
	if err := validateDialect(name, doc.Dialect); err != nil {
		return vendorDoc{}, err
	}
	for i := range doc.Profiles {
		if err := validateProfile(name, doc.Profiles[i]); err != nil {
			return vendorDoc{}, err
		}
	}
	return doc, nil
}

// validateVendorDetection enforces that a vendor-level detection block carries
// ONLY vendor-level fields (a profile-level key here is a schema error, not a
// silently ignored one) and that every value is well-formed.
func validateVendorDetection(name string, d Detection) error {
	if d.OSParse != nil || len(d.PlatformContains) > 0 || d.PlatformRank != 0 ||
		len(d.SyslogAppNames) > 0 || len(d.SyslogFacilities) > 0 {
		return fmt.Errorf("vendorprofile: %s: vendor detection may not carry profile-level keys (os_parse/platform_*/syslog_*)", name)
	}
	for _, p := range d.SysObjectIDPrefixes {
		if _, err := enterpriseOf(p); err != nil {
			return fmt.Errorf("vendorprofile: %s: %w", name, err)
		}
	}
	for _, s := range d.SysDescrContains {
		if s == "" || s != strings.ToLower(s) {
			return fmt.Errorf("vendorprofile: %s: sysdescr_contains %q must be non-empty and lower-case", name, s)
		}
	}
	if len(d.SysDescrContains) > 0 && d.SysDescrRank <= 0 {
		return fmt.Errorf("vendorprofile: %s: sysdescr_rank must be > 0 when sysdescr_contains is set", name)
	}
	if d.SysDescrRank > 0 && len(d.SysDescrContains) == 0 {
		return fmt.Errorf("vendorprofile: %s: sysdescr_rank set with no sysdescr_contains", name)
	}
	if d.OSVersionPattern != "" {
		if _, err := regexp.Compile(d.OSVersionPattern); err != nil {
			return fmt.Errorf("vendorprofile: %s: os_version_pattern: %w", name, err)
		}
	}
	return nil
}

func validateDialect(name string, dl Dialect) error {
	if dl.VRFTerm == "" && (len(dl.VRFTermKeys) > 0 || len(dl.VRFSynonyms) > 0) {
		return fmt.Errorf("vendorprofile: %s: dialect keys/synonyms declared with no vrf_term", name)
	}
	if dl.VRFTerm != "" && len(dl.VRFTermKeys) == 0 {
		return fmt.Errorf("vendorprofile: %s: vrf_term declared with no vrf_term_keys", name)
	}
	for _, k := range dl.VRFTermKeys {
		if canon(k) == "" {
			return fmt.Errorf("vendorprofile: %s: empty vrf_term_key %q", name, k)
		}
	}
	for _, s := range dl.VRFSynonyms {
		if canon(s) == "" {
			return fmt.Errorf("vendorprofile: %s: empty vrf_synonym %q", name, s)
		}
	}
	return nil
}

// validFidelity is the closed fidelity vocabulary (the telemetry catalog's
// ladder plus the explicit unassessed rung).
var validFidelity = map[string]struct{}{
	FidelityUnassessed: {}, FidelityDocClaimed: {}, FidelityLabValidated: {},
	FidelityLiveValidated: {}, FidelityDegraded: {}, FidelityFailed: {},
}

// validDeviceClass is the closed device-class vocabulary; it selects which
// hardening rule families apply.
var validDeviceClass = map[string]struct{}{
	"router": {}, "switch": {}, "firewall": {}, "wireless": {}, "host": {},
}

func validateProfile(name string, p Profile) error {
	where := name + " profile " + p.Platform
	if p.Platform == "" {
		return fmt.Errorf("vendorprofile: %s: platform is required", name)
	}
	if p.Platform != strings.ToLower(p.Platform) || strings.ContainsAny(p.Platform, " /") {
		return fmt.Errorf("vendorprofile: %s: platform %q must be lower-case with no space or slash", name, p.Platform)
	}
	if p.DisplayName == "" {
		return fmt.Errorf("vendorprofile: %s: display_name is required", where)
	}
	if len(p.DeviceClass) == 0 {
		return fmt.Errorf("vendorprofile: %s: device_class is required", where)
	}
	for _, dc := range p.DeviceClass {
		if _, ok := validDeviceClass[dc]; !ok {
			return fmt.Errorf("vendorprofile: %s: unknown device_class %q", where, dc)
		}
	}
	if _, ok := validFidelity[p.Fidelity]; !ok {
		return fmt.Errorf("vendorprofile: %s: unknown fidelity %q", where, p.Fidelity)
	}
	d := p.Detection
	if len(d.SysObjectIDPrefixes) > 0 || len(d.SysDescrContains) > 0 || d.SysDescrRank != 0 || d.OSVersionPattern != "" {
		return fmt.Errorf("vendorprofile: %s: profile detection may not carry vendor-level keys (sysobjectid_prefixes/sysdescr_*/os_version_pattern)", where)
	}
	if d.OSParse != nil {
		if d.OSParse.Product == "" {
			return fmt.Errorf("vendorprofile: %s: os_parse.product is required", where)
		}
		if d.OSParse.Rank <= 0 {
			return fmt.Errorf("vendorprofile: %s: os_parse.rank must be > 0", where)
		}
		for _, s := range d.OSParse.SysDescrContainsAny {
			if s == "" || s != strings.ToLower(s) {
				return fmt.Errorf("vendorprofile: %s: os_parse marker %q must be non-empty and lower-case", where, s)
			}
		}
	}
	for _, s := range d.PlatformContains {
		if s == "" || s != strings.ToLower(s) {
			return fmt.Errorf("vendorprofile: %s: platform_contains %q must be non-empty and lower-case", where, s)
		}
	}
	if len(d.PlatformContains) > 0 && d.PlatformRank <= 0 {
		return fmt.Errorf("vendorprofile: %s: platform_rank must be > 0 when platform_contains is set", where)
	}
	if d.PlatformRank > 0 && len(d.PlatformContains) == 0 {
		return fmt.Errorf("vendorprofile: %s: platform_rank set with no platform_contains", where)
	}
	if p.Capture.PromptRegex != "" {
		if _, err := regexp.Compile(p.Capture.PromptRegex); err != nil {
			return fmt.Errorf("vendorprofile: %s: capture.prompt_regex: %w", where, err)
		}
	}
	if err := validatePcapCapture(where, p.Capture); err != nil {
		return err
	}
	if (p.Hardening.Binding == "") != (p.Hardening.Display == "") {
		return fmt.Errorf("vendorprofile: %s: hardening binding and display must be set together", where)
	}
	if len(p.Advisory.ProductIDs) > 0 && p.Advisory.Provider == "" {
		return fmt.Errorf("vendorprofile: %s: advisory.product_ids set with no provider", where)
	}
	return nil
}

// ─── packet-capture command templates ────────────────────────────────────────

// pcapPlaceholderSet is CapturePcapPlaceholders as a set, for validation.
var pcapPlaceholderSet = func() map[string]bool {
	m := make(map[string]bool, len(CapturePcapPlaceholders))
	for _, n := range CapturePcapPlaceholders {
		m[n] = true
	}
	return m
}()

// pcapLiteralByte reports whether a byte may appear as LITERAL text in a
// packet-capture template. The set is an ALLOWLIST, not an escape pass: every
// byte that means something to a shell or a device CLI parser (`;` `|` `&` `$`
// backtick `\` `<` `>` `*` `?` `#` `!` `%` `(` `)` newline …) is absent, so a
// template can no more carry an injection than a rendered command can. The
// template syntax bytes `{` `}` `[` `]` are handled by the parser and never
// reach here — a stray one is an error, which is why they are excluded too.
//
// A template that needs a byte outside this set is not a template we know how to
// render safely: it must fail at LOAD, in CI, rather than at a live router.
func pcapLiteralByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case ' ', '_', '-', '.', '/', ':', '"', '\'':
		return true
	}
	return false
}

// validatePcapTemplate checks ONE template's bytes and structure and reports the
// placeholders it uses and whether each sits inside an optional `[ … ]` group.
//
// Structure rules (all enforced here, all cheap, all load-time):
//   - `{name}` holes only, name drawn from CapturePcapPlaceholders;
//   - `[ … ]` optional groups, non-empty, NOT nested, balanced;
//   - a group must contain at least one placeholder — an unconditional group
//     would silently mean something different from what it looks like;
//   - no stray `{`, `}`, `[` or `]`, and no literal byte outside the allowlist.
func validatePcapTemplate(where, field, tpl string) (used map[string]bool, grouped map[string]bool, err error) {
	if strings.TrimSpace(tpl) == "" {
		return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: empty command template", where, field)
	}
	used, grouped = map[string]bool{}, map[string]bool{}
	inGroup, groupHoles := false, 0
	for i := 0; i < len(tpl); i++ {
		switch c := tpl[i]; c {
		case '{':
			end := strings.IndexByte(tpl[i:], '}')
			if end < 0 {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: unterminated placeholder in %q", where, field, tpl)
			}
			name := tpl[i+1 : i+end]
			if !pcapPlaceholderSet[name] {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: unknown placeholder {%s} (allowed: %s)",
					where, field, name, strings.Join(CapturePcapPlaceholders, ", "))
			}
			used[name] = true
			if inGroup {
				grouped[name] = true
				groupHoles++
			}
			i += end
		case '}':
			return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: stray '}' in %q", where, field, tpl)
		case '[':
			if inGroup {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: nested optional group in %q", where, field, tpl)
			}
			inGroup, groupHoles = true, 0
		case ']':
			if !inGroup {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: stray ']' in %q", where, field, tpl)
			}
			if groupHoles == 0 {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: optional group with no placeholder in %q", where, field, tpl)
			}
			inGroup = false
		default:
			if !pcapLiteralByte(c) {
				return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: byte %q is not permitted in a capture command template (%q)",
					where, field, string(c), tpl)
			}
		}
	}
	if inGroup {
		return nil, nil, fmt.Errorf("vendorprofile: %s: capture.%s: unclosed optional group in %q", where, field, tpl)
	}
	return used, grouped, nil
}

// validatePcapCapture enforces the packet-capture half of a profile's capture
// block. A platform either declares NOTHING here (internal/pcap refuses the
// device honestly) or declares a COMPLETE, well-formed set: a start, a remote
// path and a cleanup. A half-declared platform would leave a capture point
// configured on a production interface, which is the one failure the packet-
// capture design leads with.
func validatePcapCapture(where string, c Capture) error {
	sets := []struct {
		field string
		cmds  []string
	}{
		{"pcap_start_cmd", c.PcapStartCmd},
		{"pcap_stop_cmd", c.PcapStopCmd},
		{"pcap_fetch_cmd", c.PcapFetchCmd},
		{"pcap_cleanup_cmd", c.PcapCleanupCmd},
	}
	declared := c.PcapRemotePath != "" || c.PcapSupportsFilter
	for _, s := range sets {
		if len(s.cmds) > 0 {
			declared = true
		}
	}
	if !declared {
		return nil
	}
	if len(c.PcapStartCmd) == 0 {
		return fmt.Errorf("vendorprofile: %s: capture declares packet-capture fields but no pcap_start_cmd", where)
	}
	if c.PcapRemotePath == "" {
		return fmt.Errorf("vendorprofile: %s: pcap_start_cmd set with no pcap_remote_path — the captured file would be unreachable", where)
	}
	if len(c.PcapCleanupCmd) == 0 {
		return fmt.Errorf("vendorprofile: %s: pcap_start_cmd set with no pcap_cleanup_cmd — a capture point could be left on a production interface", where)
	}
	usesFilter, ungroupedFilter := false, false
	for _, s := range sets {
		for _, tpl := range s.cmds {
			used, grouped, err := validatePcapTemplate(where, s.field, tpl)
			if err != nil {
				return err
			}
			if used["filter"] {
				usesFilter = true
				if !grouped["filter"] {
					ungroupedFilter = true
				}
			}
		}
	}
	pathUsed, _, err := validatePcapTemplate(where, "pcap_remote_path", c.PcapRemotePath)
	if err != nil {
		return err
	}
	if strings.ContainsAny(c.PcapRemotePath, "[]") {
		return fmt.Errorf("vendorprofile: %s: pcap_remote_path may not carry an optional group — a file either has a path or it does not", where)
	}
	if !pathUsed["file"] {
		return fmt.Errorf("vendorprofile: %s: pcap_remote_path must carry {file}, or two captures would collide on one path", where)
	}
	if usesFilter && ungroupedFilter {
		return fmt.Errorf("vendorprofile: %s: {filter} must sit inside an optional [ … ] group, or an unfiltered capture renders a dangling clause", where)
	}
	if usesFilter && !c.PcapSupportsFilter {
		return fmt.Errorf("vendorprofile: %s: a template carries {filter} but pcap_supports_filter is false", where)
	}
	if !usesFilter && c.PcapSupportsFilter {
		return fmt.Errorf("vendorprofile: %s: pcap_supports_filter is true but no template carries {filter} — the claim would silently widen a capture", where)
	}
	return nil
}

// enterpriseOf parses "1.3.6.1.4.1.<n>" into <n>.
func enterpriseOf(prefix string) (int, error) {
	rest, ok := strings.CutPrefix(prefix, enterpriseOIDPrefix)
	if !ok || rest == "" || strings.Contains(rest, ".") {
		return 0, fmt.Errorf("sysobjectid prefix %q must be exactly %s<enterprise>", prefix, enterpriseOIDPrefix)
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("sysobjectid prefix %q has a non-numeric enterprise arc", prefix)
	}
	return n, nil
}

// canon normalizes a free-form vendor/dialect token: lower-cased with separators
// removed, so "SR-Linux", "sr linux" and "sr_linux" are one key. It is the same
// normalization internal/netconcepts applied before this registry existed.
func canon(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer("-", "", "_", "", " ", "", ".", "")
	return repl.Replace(s)
}
