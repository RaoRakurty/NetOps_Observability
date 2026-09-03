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
	SchemaVersion int           `json:"schema_version"`
	Vendor        string        `json:"vendor"`
	DisplayName   string        `json:"display_name"`
	Detection     Detection     `json:"detection"`
	Dialect       Dialect       `json:"dialect"`
	Verify        VerifyBinding `json:"verify"`
	// ConfigCapture / SNMPConfigGen / DeviceType are the VENDOR-LEVEL bindings
	// consumed by the config-backup module, the SNMP onboarding generator and
	// functional device-type inference. They sit at the vendor level because
	// each of those engines resolves a device to a VENDOR FAMILY, never to a
	// platform (see the type docs for why that is not an accident).
	ConfigCapture ConfigCapture   `json:"config_capture"`
	SNMPConfigGen SNMPConfigGen   `json:"snmp_configgen"`
	DeviceType    DeviceTypeHints `json:"device_type"`
	Profiles      []Profile       `json:"profiles"`
	Notes         string          `json:"notes,omitempty"`
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
	if err := validateVerify(name, doc.Verify); err != nil {
		return vendorDoc{}, err
	}
	if err := validateConfigCapture(name, doc.ConfigCapture); err != nil {
		return vendorDoc{}, err
	}
	if err := validateSNMPConfigGen(name, doc.SNMPConfigGen); err != nil {
		return vendorDoc{}, err
	}
	if err := validateDeviceTypeHints(name, doc.DeviceType); err != nil {
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
	if err := validatePcapFamily(where, p.Capture); err != nil {
		return err
	}
	if (p.Hardening.Binding == "") != (p.Hardening.Display == "") {
		return fmt.Errorf("vendorprofile: %s: hardening binding and display must be set together", where)
	}
	if (p.CLI.Dialect == "") != (p.CLI.Display == "") {
		return fmt.Errorf("vendorprofile: %s: cli dialect and display must be set together", where)
	}
	if p.CLI.Dialect != "" && (p.CLI.Dialect != strings.ToLower(p.CLI.Dialect) || strings.ContainsAny(p.CLI.Dialect, " /")) {
		return fmt.Errorf("vendorprofile: %s: cli dialect %q must be lower-case with no space or slash", where, p.CLI.Dialect)
	}
	if len(p.Advisory.ProductIDs) > 0 && p.Advisory.Provider == "" {
		return fmt.Errorf("vendorprofile: %s: advisory.product_ids set with no provider", where)
	}
	return nil
}

// ─── vendor-level consumer bindings ──────────────────────────────────────────

// configCaptureForbiddenBytes are the bytes a running-config capture command may
// never contain: shell/CLI CHAINING metacharacters and control characters.
//
// NOTE what is NOT here: `|`. The verification allowlist (validateVerifyCommand)
// forbids the pipe because that engine composes a battery of commands it must
// prove cannot carry a second one. A config capture is ONE authored constant per
// vendor, and on Junos the only way to read a set-format configuration is
// `show configuration | display set | no-more` — a device-CLI display filter,
// not a shell pipeline. Forbidding it would not harden anything; it would make
// the registry unable to state the command the module actually runs.
var configCaptureForbiddenBytes = []string{";", "&", "`", "$", "\\", "\n", "\r", ">", "<"}

// validateConfigCapture enforces the vendor-level config-capture binding: a
// ranked, well-formed platform table, a READ-ONLY capture command, and volatile
// rules whose patterns compile and whose names are unique.
//
// A vendor may declare a platform table with NO command: that is the honest
// "we can name this family but its capture command is not established" state,
// and internal/configstore already refuses such a device (ErrNoVendor) rather
// than probing it. Only a rule list or a command with no way to reach them is a
// defect.
func validateConfigCapture(name string, c ConfigCapture) error {
	for _, sub := range c.PlatformContains {
		if sub == "" || sub != strings.ToLower(sub) || strings.TrimSpace(sub) != sub {
			return fmt.Errorf("vendorprofile: %s: config_capture.platform_contains %q must be non-empty, lower-case and trimmed", name, sub)
		}
	}
	if len(c.PlatformContains) > 0 && c.PlatformRank <= 0 {
		return fmt.Errorf("vendorprofile: %s: config_capture.platform_rank must be > 0 when platform_contains is set", name)
	}
	if c.PlatformRank > 0 && len(c.PlatformContains) == 0 {
		return fmt.Errorf("vendorprofile: %s: config_capture.platform_rank set with no platform_contains", name)
	}
	if err := validateCaptureCommand(name, "config_capture.running_config_cmd", c.RunningConfigCmd); err != nil {
		return err
	}
	if len(c.VolatileRules) > 0 && len(c.PlatformContains) == 0 {
		return fmt.Errorf("vendorprofile: %s: config_capture.volatile_rules declared for a vendor no platform text resolves to", name)
	}
	if err := validateVolatileRules(name, "config_capture", c.VolatileRules); err != nil {
		return err
	}
	seenDialect := map[string]bool{}
	for _, d := range c.PlatformDialects {
		field := "config_capture.platform_dialects[" + d.ID + "]"
		if d.ID == "" || strings.TrimSpace(d.ID) != d.ID || d.ID != strings.ToLower(d.ID) {
			return fmt.Errorf("vendorprofile: %s: config_capture.platform_dialects id %q must be non-empty, trimmed and lower-case", name, d.ID)
		}
		if seenDialect[d.ID] {
			return fmt.Errorf("vendorprofile: %s: duplicate config_capture platform dialect %q", name, d.ID)
		}
		seenDialect[d.ID] = true
		// A dialect exists to be RESOLVED. Without its own platform text nothing
		// can ever reach it, which is a silently dead command table.
		if len(d.PlatformContains) == 0 || d.PlatformRank <= 0 {
			return fmt.Errorf("vendorprofile: %s: %s must declare platform_contains and a platform_rank > 0", name, field)
		}
		for _, sub := range d.PlatformContains {
			if sub == "" || sub != strings.ToLower(sub) || strings.TrimSpace(sub) != sub {
				return fmt.Errorf("vendorprofile: %s: %s platform_contains %q must be non-empty, lower-case and trimmed", name, field, sub)
			}
		}
		if err := validateCaptureCommand(name, field+".running_config_cmd", d.RunningConfigCmd); err != nil {
			return err
		}
		if err := validateVolatileRules(name, field, d.VolatileRules); err != nil {
			return err
		}
	}
	return nil
}

// captureCommandVerbs are the read-only display verbs a running-config capture
// command may start with. The list is a GUARD, not the authorization: the
// command itself is a checked-in constant, and this only refuses a profile edit
// that would send something other than a display verb to a device prompt.
//
//	show / display        — the near-universal spelling (IOS, EOS, Junos, VRP)
//	admin display         — SR OS' classic-CLI running-config display
//	info                  — SR Linux' CLI display verb: its configuration is read
//	                        with `info from running flat`, and it has no `show`
//	                        form of the running config at all.
var captureCommandVerbs = []string{"show ", "display ", "admin display", "info "}

// validateCaptureCommand enforces the read-only + no-chaining contract on ONE
// capture command string, wherever it is declared (vendor level or dialect).
func validateCaptureCommand(name, field, cmd string) error {
	if cmd == "" {
		return nil
	}
	if strings.TrimSpace(cmd) != cmd {
		return fmt.Errorf("vendorprofile: %s: %s %q must be trimmed", name, field, cmd)
	}
	lower := strings.ToLower(cmd)
	ok := false
	for _, verb := range captureCommandVerbs {
		if strings.HasPrefix(lower, verb) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("vendorprofile: %s: %s %q is not a read-only show/display command", name, field, cmd)
	}
	for _, tok := range configCaptureForbiddenBytes {
		if strings.Contains(cmd, tok) {
			return fmt.Errorf("vendorprofile: %s: %s %q contains the forbidden token %q", name, field, cmd, tok)
		}
	}
	for i := 0; i < len(cmd); i++ {
		if b := cmd[i]; b < 0x20 || b == 0x7f {
			return fmt.Errorf("vendorprofile: %s: %s %q contains a control character", name, field, cmd)
		}
	}
	return nil
}

// validateVolatileRules enforces the named/unique/compilable contract on one
// volatile-rule list.
func validateVolatileRules(name, field string, rules []VolatileRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.Name == "" || strings.TrimSpace(r.Name) != r.Name || r.Name != strings.ToLower(r.Name) {
			return fmt.Errorf("vendorprofile: %s: %s volatile rule name %q must be non-empty, trimmed and lower-case", name, field, r.Name)
		}
		if seen[r.Name] {
			return fmt.Errorf("vendorprofile: %s: duplicate %s volatile rule name %q", name, field, r.Name)
		}
		seen[r.Name] = true
		if r.Pattern == "" {
			return fmt.Errorf("vendorprofile: %s: %s volatile rule %q has no pattern", name, field, r.Name)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("vendorprofile: %s: %s volatile rule %q: %w", name, field, r.Name, err)
		}
	}
	return nil
}

// snmpConfigGenPlaceholderSet is SNMPConfigGenPlaceholders as a set.
var snmpConfigGenPlaceholderSet = func() map[string]bool {
	m := make(map[string]bool, len(SNMPConfigGenPlaceholders))
	for _, n := range SNMPConfigGenPlaceholders {
		m[n] = true
	}
	return m
}()

// validateSNMPTemplate checks one onboarding template's holes and reports which
// ones it uses. `<<` and `>>` are the ONLY structural bytes: everything else is
// literal, because the payload is a vendor CLI block an operator pastes, not a
// command this platform executes. A stray delimiter is an error — a template
// that looks like it names a hole but does not would render the literal text
// `<<auth_key>>` into somebody's device configuration.
func validateSNMPTemplate(name, field, tpl string) (map[string]bool, error) {
	if strings.TrimSpace(tpl) != tpl {
		return nil, fmt.Errorf("vendorprofile: %s: snmp_configgen.%s must be trimmed", name, field)
	}
	for i := 0; i < len(tpl); i++ {
		if b := tpl[i]; (b < 0x20 && b != '\n') || b == 0x7f {
			return nil, fmt.Errorf("vendorprofile: %s: snmp_configgen.%s contains a control character", name, field)
		}
	}
	used := map[string]bool{}
	rest := tpl
	for {
		i := strings.Index(rest, "<<")
		if i < 0 {
			break
		}
		rest = rest[i+2:]
		end := strings.Index(rest, ">>")
		if end < 0 {
			return nil, fmt.Errorf("vendorprofile: %s: snmp_configgen.%s: unterminated placeholder", name, field)
		}
		hole := rest[:end]
		if !snmpConfigGenPlaceholderSet[hole] {
			return nil, fmt.Errorf("vendorprofile: %s: snmp_configgen.%s: unknown placeholder <<%s>> (allowed: %s)",
				name, field, hole, strings.Join(SNMPConfigGenPlaceholders, ", "))
		}
		used[hole] = true
		rest = rest[end+2:]
	}
	if strings.Contains(rest, ">>") {
		return nil, fmt.Errorf("vendorprofile: %s: snmp_configgen.%s: stray '>>'", name, field)
	}
	return used, nil
}

// validateSNMPConfigGen enforces the onboarding-template contract: both versions
// or neither, closed placeholders, and — the rule that matters — a v3 block that
// actually carries the minted key material. A v3 template missing <<auth_key>>
// or <<priv_key>> would hand an operator a block that configures a user the
// collector cannot authenticate as, which is worse than no template at all.
func validateSNMPConfigGen(name string, g SNMPConfigGen) error {
	if (g.V2CTemplate == "") != (g.V3Template == "") {
		return fmt.Errorf("vendorprofile: %s: snmp_configgen must declare both v2c_template and v3_template, or neither", name)
	}
	if g.V2CTemplate == "" {
		return nil
	}
	v2c, err := validateSNMPTemplate(name, "v2c_template", g.V2CTemplate)
	if err != nil {
		return err
	}
	if !v2c["community"] {
		return fmt.Errorf("vendorprofile: %s: snmp_configgen.v2c_template does not carry <<community>>", name)
	}
	v3, err := validateSNMPTemplate(name, "v3_template", g.V3Template)
	if err != nil {
		return err
	}
	if !v3["auth_key"] || !v3["priv_key"] {
		return fmt.Errorf("vendorprofile: %s: snmp_configgen.v3_template must carry both <<auth_key>> and <<priv_key>>", name)
	}
	if v3["community"] {
		return fmt.Errorf("vendorprofile: %s: snmp_configgen.v3_template carries <<community>> — v3 has no community", name)
	}
	return nil
}

// deviceTypeSet is DeviceTypeOrder as a set, for validation.
var deviceTypeSet = func() map[string]bool {
	m := make(map[string]bool, len(DeviceTypeOrder))
	for _, t := range DeviceTypeOrder {
		m[t] = true
	}
	return m
}()

// validateDeviceTypeHints enforces the closed device-type vocabulary and the
// shape of the two hint kinds. Text hints are the ONE string list the loader
// does not require to be trimmed: a leading or trailing space is how " mx"
// says "the token mx", and trimming it would silently widen the rule to every
// model whose name contains those two letters.
func validateDeviceTypeHints(name string, h DeviceTypeHints) error {
	if len(h.VendorTokens) > 0 && h.VendorKind == "" {
		return fmt.Errorf("vendorprofile: %s: device_type.vendor_tokens set with no vendor_kind", name)
	}
	if h.VendorKind != "" && len(h.VendorTokens) == 0 {
		return fmt.Errorf("vendorprofile: %s: device_type.vendor_kind set with no vendor_tokens", name)
	}
	if h.VendorKind != "" && !deviceTypeSet[h.VendorKind] {
		return fmt.Errorf("vendorprofile: %s: unknown device_type.vendor_kind %q (allowed: %s)", name, h.VendorKind, strings.Join(DeviceTypeOrder, ", "))
	}
	for _, tok := range h.VendorTokens {
		if tok == "" || tok != strings.ToLower(tok) || strings.TrimSpace(tok) != tok {
			return fmt.Errorf("vendorprofile: %s: device_type.vendor_token %q must be non-empty, lower-case and trimmed", name, tok)
		}
	}
	for kind, hints := range h.TextHints {
		if !deviceTypeSet[kind] {
			return fmt.Errorf("vendorprofile: %s: unknown device_type.text_hints key %q (allowed: %s)", name, kind, strings.Join(DeviceTypeOrder, ", "))
		}
		if len(hints) == 0 {
			return fmt.Errorf("vendorprofile: %s: device_type.text_hints[%s] is empty", name, kind)
		}
		seen := map[string]bool{}
		for _, hint := range hints {
			if strings.TrimSpace(hint) == "" || hint != strings.ToLower(hint) {
				return fmt.Errorf("vendorprofile: %s: device_type.text_hints[%s] hint %q must be non-empty and lower-case", name, kind, hint)
			}
			if seen[hint] {
				return fmt.Errorf("vendorprofile: %s: duplicate device_type.text_hints[%s] hint %q", name, kind, hint)
			}
			seen[hint] = true
		}
	}
	return nil
}

// ─── active-verification commands ────────────────────────────────────────────

// verifyForbiddenTokens are the substrings a verification command may NEVER
// contain. Two families, one rule: shell/CLI CHAINING metacharacters (a command
// that can carry a second command is not one command), and STATE-CHANGING verbs
// (the battery is read-only by contract — CLAUDE.md §8).
//
// The trailing spaces are load-bearing: `show system rollback` READS the
// rollback history and is legal, while `rollback ` followed by an argument
// applies one and is not.
var verifyForbiddenTokens = []string{
	";", "|", "&", "`", "$", "\n", "\r", "\\",
	"reload", "configure", "write ", "copy ", "delete", "clear ", "request ", "rollback ",
}

// validateVerifyCommand enforces the READ-ONLY SHAPE of one verification
// command AT LOAD, so a command the engine could not safely run fails the build
// rather than a live router. The engine's own allowlist gate and its test then
// assert the same invariant over this data — defense in depth, one authority.
func validateVerifyCommand(name, checkID, cmd string) error {
	if strings.TrimSpace(cmd) != cmd || cmd == "" {
		return fmt.Errorf("vendorprofile: %s: verify.commands[%s]: command must be non-empty and untrimmed-free", name, checkID)
	}
	if !strings.HasPrefix(cmd, "show ") && !strings.HasPrefix(cmd, "display ") {
		return fmt.Errorf("vendorprofile: %s: verify.commands[%s]: %q is not a read-only show/display command", name, checkID, cmd)
	}
	for _, tok := range verifyForbiddenTokens {
		if strings.Contains(cmd, tok) {
			return fmt.Errorf("vendorprofile: %s: verify.commands[%s]: %q contains the forbidden token %q", name, checkID, cmd, tok)
		}
	}
	for i := 0; i < len(cmd); i++ {
		if c := cmd[i]; c < 0x20 || c == 0x7f {
			return fmt.Errorf("vendorprofile: %s: verify.commands[%s]: %q contains a control character", name, checkID, cmd)
		}
	}
	return nil
}

// validateVerify checks a vendor's whole verification allowlist: well-formed
// check ids and a read-only command for each.
func validateVerify(name string, v VerifyBinding) error {
	for checkID, cmd := range v.Commands {
		if checkID == "" || checkID != strings.ToLower(checkID) || strings.ContainsAny(checkID, " /") {
			return fmt.Errorf("vendorprofile: %s: verify check id %q must be non-empty, lower-case, with no space or slash", name, checkID)
		}
		if err := validateVerifyCommand(name, checkID, cmd); err != nil {
			return err
		}
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

// pcapFamilyToken matches a capture-family key and the tokens/joined substrings
// of a platform rule: lower-case letters, digits and (for the family key)
// underscores. The rule side is deliberately NARROWER than free text — the
// resolver tokenizes a platform label into runs of [a-z0-9], so a rule carrying
// a hyphen or a space could never match anything and would be dead data that
// LOOKS live.
var (
	pcapFamilyToken = regexp.MustCompile(`^[a-z0-9_]+$`)
	pcapRuleToken   = regexp.MustCompile(`^[a-z0-9]+$`)
)

// validatePcapFamily enforces the capture-family half of a profile's capture
// block: a well-formed key, rules that can actually match, and no rule without
// a family to resolve to.
func validatePcapFamily(where string, c Capture) error {
	if c.PcapFamily != "" && !pcapFamilyToken.MatchString(c.PcapFamily) {
		return fmt.Errorf("vendorprofile: %s: capture.pcap_family %q must be lower-case letters, digits and underscores", where, c.PcapFamily)
	}
	if len(c.PcapPlatformRules) > 0 && c.PcapFamily == "" {
		return fmt.Errorf("vendorprofile: %s: capture.pcap_platform_rules declared with no pcap_family to resolve to", where)
	}
	if c.PcapFamily == "" && c.HasPcapCommands() {
		return fmt.Errorf("vendorprofile: %s: packet-capture commands declared with no capture.pcap_family — no device platform could ever reach them", where)
	}
	for _, rule := range c.PcapPlatformRules {
		if rule.Rank <= 0 {
			return fmt.Errorf("vendorprofile: %s: capture.pcap_platform_rules rank must be > 0", where)
		}
		if len(rule.Tokens) == 0 && len(rule.Joined) == 0 {
			return fmt.Errorf("vendorprofile: %s: capture.pcap_platform_rules rank %d matches nothing", where, rule.Rank)
		}
		for _, tok := range append(append([]string(nil), rule.Tokens...), rule.Joined...) {
			if !pcapRuleToken.MatchString(tok) {
				return fmt.Errorf("vendorprofile: %s: capture.pcap_platform_rules token %q must be lower-case letters and digits "+
					"(a platform label is tokenized on every other byte, so anything else is unreachable)", where, tok)
			}
		}
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
