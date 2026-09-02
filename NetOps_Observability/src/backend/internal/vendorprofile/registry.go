package vendorprofile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Registry is the immutable, in-memory index over the loaded profiles. It is
// built once by Load and never mutated afterwards, so it is safe to share across
// goroutines (every accessor returns a copy of any slice it owns).
type Registry struct {
	profiles   map[string]Profile // by canonical id "<vendor>/<platform>"
	aliasToID  map[string]string  // "<vendor>/<alias>" → canonical id
	order      []string           // profile ids, sorted (deterministic iteration)
	vendors    map[string]VendorRecord
	vendorIDs  []string // sorted
	enterprise map[int]string
	descrRules []descrRule // sysDescr text backstop, ascending rank
	osParse    map[string]vendorOSParse
	platRules  []platRule // platform-text resolution, ascending rank
	vrfTerms   map[string]string
	vrfSyn     map[string]struct{}
	hardDisp   map[string]string
	cliDisp    map[string]string
	verifyCmds map[string]map[string]string // vendor → check id → command
	verifyAll  map[string]struct{}          // every declared command, verbatim
}

type descrRule struct {
	rank     int
	vendor   string
	contains []string
}

type platRule struct {
	rank      int
	profileID string
	contains  []string
}

type productRule struct {
	rank     int
	product  string
	contains []string
}

type vendorOSParse struct {
	versionRe *regexp.Regexp
	products  []productRule // ascending rank
}

// build indexes the decoded documents and enforces the cross-document
// invariants. Any violation is an error — the registry never starts up half-valid.
func build(docs []vendorDoc) (*Registry, error) {
	r := &Registry{
		profiles:   make(map[string]Profile),
		aliasToID:  make(map[string]string),
		vendors:    make(map[string]VendorRecord),
		enterprise: make(map[int]string),
		osParse:    make(map[string]vendorOSParse),
		vrfTerms:   make(map[string]string),
		vrfSyn:     make(map[string]struct{}),
		hardDisp:   make(map[string]string),
		cliDisp:    make(map[string]string),
		verifyCmds: make(map[string]map[string]string),
		verifyAll:  make(map[string]struct{}),
	}
	seenDescrRank := make(map[int]string)
	seenPlatRank := make(map[int]string)

	for _, doc := range docs {
		if _, dup := r.vendors[doc.Vendor]; dup {
			return nil, fmt.Errorf("vendorprofile: duplicate vendor %q", doc.Vendor)
		}
		// ── sysObjectID enterprise index ─────────────────────────────────────
		for _, prefix := range doc.Detection.SysObjectIDPrefixes {
			ent, err := enterpriseOf(prefix)
			if err != nil {
				return nil, fmt.Errorf("vendorprofile: vendor %q: %w", doc.Vendor, err)
			}
			if other, dup := r.enterprise[ent]; dup {
				return nil, fmt.Errorf("vendorprofile: enterprise %d claimed by both %q and %q", ent, other, doc.Vendor)
			}
			r.enterprise[ent] = doc.Vendor
		}
		// ── sysDescr text backstop (ranked, first match wins) ────────────────
		if doc.Detection.SysDescrRank > 0 {
			if other, dup := seenDescrRank[doc.Detection.SysDescrRank]; dup {
				return nil, fmt.Errorf("vendorprofile: sysdescr_rank %d claimed by both %q and %q",
					doc.Detection.SysDescrRank, other, doc.Vendor)
			}
			seenDescrRank[doc.Detection.SysDescrRank] = doc.Vendor
			r.descrRules = append(r.descrRules, descrRule{
				rank: doc.Detection.SysDescrRank, vendor: doc.Vendor,
				contains: append([]string(nil), doc.Detection.SysDescrContains...),
			})
		}
		// ── dialect ──────────────────────────────────────────────────────────
		for _, k := range doc.Dialect.VRFTermKeys {
			key := canon(k)
			if other, dup := r.vrfTerms[key]; dup && other != doc.Dialect.VRFTerm {
				return nil, fmt.Errorf("vendorprofile: vrf_term_key %q maps to both %q and %q", key, other, doc.Dialect.VRFTerm)
			}
			r.vrfTerms[key] = doc.Dialect.VRFTerm
		}
		for _, s := range doc.Dialect.VRFSynonyms {
			r.vrfSyn[canon(s)] = struct{}{}
		}
		// ── active-verification command allowlist (vendor level) ─────────────
		if len(doc.Verify.Commands) > 0 {
			cmds := make(map[string]string, len(doc.Verify.Commands))
			for checkID, cmd := range doc.Verify.Commands {
				cmds[checkID] = cmd
				r.verifyAll[cmd] = struct{}{}
			}
			r.verifyCmds[doc.Vendor] = cmds
		}
		// ── profiles ─────────────────────────────────────────────────────────
		var osp vendorOSParse
		if doc.Detection.OSVersionPattern != "" {
			re, err := regexp.Compile(doc.Detection.OSVersionPattern)
			if err != nil {
				return nil, fmt.Errorf("vendorprofile: vendor %q os_version_pattern: %w", doc.Vendor, err)
			}
			osp.versionRe = re
		}
		seenOSRank := make(map[int]string)
		defaultProduct := ""
		rec := VendorRecord{
			ID: doc.Vendor, DisplayName: doc.DisplayName,
			Detection: doc.Detection, Dialect: doc.Dialect, Verify: doc.Verify,
		}
		for _, p := range doc.Profiles {
			p.Vendor = doc.Vendor
			p.ID = doc.Vendor + "/" + p.Platform
			p.Dialect = doc.Dialect
			// The vendor-level detection fields are COPIED onto every profile so
			// a Profile is self-describing (the design's single descriptor).
			p.Detection.SysObjectIDPrefixes = append([]string(nil), doc.Detection.SysObjectIDPrefixes...)
			p.Detection.SysDescrContains = append([]string(nil), doc.Detection.SysDescrContains...)
			p.Detection.SysDescrRank = doc.Detection.SysDescrRank
			p.Detection.OSVersionPattern = doc.Detection.OSVersionPattern
			if _, dup := r.profiles[p.ID]; dup {
				return nil, fmt.Errorf("vendorprofile: duplicate profile id %q", p.ID)
			}
			r.profiles[p.ID] = p
			r.order = append(r.order, p.ID)
			rec.ProfileIDs = append(rec.ProfileIDs, p.ID)
			for _, al := range p.PlatformAliases {
				key := doc.Vendor + "/" + strings.ToLower(al)
				if other, dup := r.aliasToID[key]; dup {
					return nil, fmt.Errorf("vendorprofile: platform alias %q claimed by both %q and %q", key, other, p.ID)
				}
				if _, clash := r.profiles[key]; clash {
					return nil, fmt.Errorf("vendorprofile: platform alias %q collides with a canonical profile id", key)
				}
				r.aliasToID[key] = p.ID
			}
			// os-parse product resolution
			if op := p.Detection.OSParse; op != nil {
				if osp.versionRe == nil {
					return nil, fmt.Errorf("vendorprofile: %s declares os_parse but vendor %q has no os_version_pattern", p.ID, doc.Vendor)
				}
				if other, dup := seenOSRank[op.Rank]; dup {
					return nil, fmt.Errorf("vendorprofile: os_parse rank %d claimed by both %q and %q", op.Rank, other, p.ID)
				}
				seenOSRank[op.Rank] = p.ID
				if len(op.SysDescrContainsAny) == 0 {
					if defaultProduct != "" {
						return nil, fmt.Errorf("vendorprofile: vendor %q declares two unconditional os_parse defaults (%q and %q)", doc.Vendor, defaultProduct, p.ID)
					}
					defaultProduct = p.ID
				}
				osp.products = append(osp.products, productRule{
					rank: op.Rank, product: op.Product,
					contains: append([]string(nil), op.SysDescrContainsAny...),
				})
			}
			// platform-text resolution
			if p.Detection.PlatformRank > 0 {
				if other, dup := seenPlatRank[p.Detection.PlatformRank]; dup {
					return nil, fmt.Errorf("vendorprofile: platform_rank %d claimed by both %q and %q", p.Detection.PlatformRank, other, p.ID)
				}
				seenPlatRank[p.Detection.PlatformRank] = p.ID
				r.platRules = append(r.platRules, platRule{
					rank: p.Detection.PlatformRank, profileID: p.ID,
					contains: append([]string(nil), p.Detection.PlatformContains...),
				})
			}
			// hardening binding display must be consistent across profiles
			if p.Hardening.Binding != "" {
				if other, dup := r.hardDisp[p.Hardening.Binding]; dup && other != p.Hardening.Display {
					return nil, fmt.Errorf("vendorprofile: hardening binding %q has two displays (%q, %q)", p.Hardening.Binding, other, p.Hardening.Display)
				}
				r.hardDisp[p.Hardening.Binding] = p.Hardening.Display
			}
			// cli dialect display must be consistent across profiles
			if p.CLI.Dialect != "" {
				if other, dup := r.cliDisp[p.CLI.Dialect]; dup && other != p.CLI.Display {
					return nil, fmt.Errorf("vendorprofile: cli dialect %q has two displays (%q, %q)", p.CLI.Dialect, other, p.CLI.Display)
				}
				r.cliDisp[p.CLI.Dialect] = p.CLI.Display
			}
		}
		sort.Slice(osp.products, func(i, j int) bool { return osp.products[i].rank < osp.products[j].rank })
		// The unconditional default must be evaluated LAST, or a marker-gated
		// product could never win.
		if defaultProduct != "" && len(osp.products) > 0 {
			last := osp.products[len(osp.products)-1]
			if len(last.contains) != 0 {
				return nil, fmt.Errorf("vendorprofile: vendor %q unconditional os_parse default %q must carry the highest rank", doc.Vendor, defaultProduct)
			}
		}
		if len(osp.products) > 0 {
			r.osParse[doc.Vendor] = osp
		}
		r.vendors[doc.Vendor] = rec
		r.vendorIDs = append(r.vendorIDs, doc.Vendor)
	}
	sort.Strings(r.order)
	sort.Strings(r.vendorIDs)
	sort.Slice(r.descrRules, func(i, j int) bool { return r.descrRules[i].rank < r.descrRules[j].rank })
	sort.Slice(r.platRules, func(i, j int) bool { return r.platRules[i].rank < r.platRules[j].rank })
	return r, nil
}

// ─── defensive copying ───────────────────────────────────────────────────────

func cp(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

// clone returns a deep copy of the profile. The registry is shared, immutable
// reference data: every accessor hands out a copy so a caller can never reach
// back into the index through a slice or the OSParse pointer.
func (p Profile) clone() Profile {
	out := p
	out.PlatformAliases = cp(p.PlatformAliases)
	out.DeviceClass = cp(p.DeviceClass)
	out.Detection = p.Detection.clone()
	out.Dialect = p.Dialect.clone()
	out.Capture.PagerOffCmds = cp(p.Capture.PagerOffCmds)
	out.Capture.PcapStartCmd = cp(p.Capture.PcapStartCmd)
	out.Capture.PcapStopCmd = cp(p.Capture.PcapStopCmd)
	out.Capture.PcapFetchCmd = cp(p.Capture.PcapFetchCmd)
	out.Capture.PcapCleanupCmd = cp(p.Capture.PcapCleanupCmd)
	out.Advisory.ProductIDs = cp(p.Advisory.ProductIDs)
	out.Threat.LogRuleIDs = cp(p.Threat.LogRuleIDs)
	out.Threat.MnemonicPrefixes = cp(p.Threat.MnemonicPrefixes)
	return out
}

func (d Detection) clone() Detection {
	out := d
	out.SysObjectIDPrefixes = cp(d.SysObjectIDPrefixes)
	out.SysDescrContains = cp(d.SysDescrContains)
	out.PlatformContains = cp(d.PlatformContains)
	out.SyslogAppNames = cp(d.SyslogAppNames)
	out.SyslogFacilities = cp(d.SyslogFacilities)
	if d.OSParse != nil {
		op := *d.OSParse
		op.SysDescrContainsAny = cp(d.OSParse.SysDescrContainsAny)
		out.OSParse = &op
	}
	return out
}

func (dl Dialect) clone() Dialect {
	out := dl
	out.VRFTermKeys = cp(dl.VRFTermKeys)
	out.VRFSynonyms = cp(dl.VRFSynonyms)
	return out
}

func (v VendorRecord) clone() VendorRecord {
	out := v
	out.Detection = v.Detection.clone()
	out.Dialect = v.Dialect.clone()
	out.Verify = v.Verify.clone()
	out.ProfileIDs = cp(v.ProfileIDs)
	return out
}

// clone deep-copies the verification allowlist so a caller can never reach back
// into the shared index through the map.
func (vb VerifyBinding) clone() VerifyBinding {
	if vb.Commands == nil {
		return VerifyBinding{}
	}
	out := VerifyBinding{Commands: make(map[string]string, len(vb.Commands))}
	for k, v := range vb.Commands {
		out.Commands[k] = v
	}
	return out
}

// ─── identity lookups ────────────────────────────────────────────────────────

// Lookup resolves a profile by its canonical id ("cisco/ios_xe") or by a
// vendor-qualified platform alias ("arista/ceos"). It never falls back to a
// default profile: an unknown id is simply not found.
func (r *Registry) Lookup(id string) (Profile, bool) {
	if p, ok := r.profiles[id]; ok {
		return p.clone(), true
	}
	if canonical, ok := r.aliasToID[strings.ToLower(strings.TrimSpace(id))]; ok {
		return r.profiles[canonical].clone(), true
	}
	return Profile{}, false
}

// LookupPlatform resolves a (vendor, platform) pair, honouring platform aliases.
func (r *Registry) LookupPlatform(vendor, platform string) (Profile, bool) {
	return r.Lookup(strings.ToLower(strings.TrimSpace(vendor)) + "/" + strings.ToLower(strings.TrimSpace(platform)))
}

// Profiles returns every profile in deterministic id order.
func (r *Registry) Profiles() []Profile {
	out := make([]Profile, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.profiles[id].clone())
	}
	return out
}

// IDs returns every canonical profile id in sorted order.
func (r *Registry) IDs() []string { return append([]string(nil), r.order...) }

// Vendor returns the vendor-level record for a vendor id.
func (r *Registry) Vendor(id string) (VendorRecord, bool) {
	v, ok := r.vendors[id]
	if !ok {
		return VendorRecord{}, false
	}
	return v.clone(), true
}

// VendorIDs returns every known vendor id in sorted order.
func (r *Registry) VendorIDs() []string { return append([]string(nil), r.vendorIDs...) }

// ─── detection ───────────────────────────────────────────────────────────────

// VendorForEnterprise maps an IANA Private Enterprise Number (the 7th arc of a
// sysObjectID under 1.3.6.1.4.1.<ENT>) to a vendor id.
func (r *Registry) VendorForEnterprise(ent int) (string, bool) {
	v, ok := r.enterprise[ent]
	return v, ok
}

// VendorForSysObjectID maps a dotted sysObjectID to a vendor id via its
// enterprise arc. A sysObjectID outside the private-enterprise tree is unknown.
func (r *Registry) VendorForSysObjectID(oid string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(oid), enterpriseOIDPrefix)
	if !ok || rest == "" {
		return "", false
	}
	if i := strings.Index(rest, "."); i >= 0 {
		rest = rest[:i]
	}
	ent, err := enterpriseOf(enterpriseOIDPrefix + rest)
	if err != nil {
		return "", false
	}
	return r.VendorForEnterprise(ent)
}

// VendorForSysDescr is the TEXT BACKSTOP used when the enterprise number is
// unknown: the ranked sysDescr substring table, first match wins. The rank order
// is load-bearing (a BIG-IP sysDescr embeds "Linux" and must resolve to f5).
func (r *Registry) VendorForSysDescr(sysDescr string) (string, bool) {
	s := strings.ToLower(sysDescr)
	for _, rule := range r.descrRules {
		for _, sub := range rule.contains {
			if strings.Contains(s, sub) {
				return rule.vendor, true
			}
		}
	}
	return "", false
}

// ResolveOS extracts the OS product + version a sysDescr carries for an ALREADY
// IDENTIFIED vendor. The vendor id must match exactly (it comes from
// sysObjectID/sysDescr detection, which is authoritative and already
// lower-cased); a vendor the registry does not know, or one that declares no
// os_parse, returns ok=false so the caller reports the device UNASSESSED rather
// than guessing against another vendor's grammar.
func (r *Registry) ResolveOS(vendor, sysDescr string) (OSIdentity, bool) {
	osp, ok := r.osParse[vendor]
	if !ok {
		return OSIdentity{}, false
	}
	d := strings.TrimSpace(sysDescr)
	if d == "" {
		return OSIdentity{}, false
	}
	lower := strings.ToLower(d)
	product := ""
	for _, pr := range osp.products {
		if len(pr.contains) == 0 {
			product = pr.product
			break
		}
		matched := false
		for _, sub := range pr.contains {
			if strings.Contains(lower, sub) {
				matched = true
				break
			}
		}
		if matched {
			product = pr.product
			break
		}
	}
	version := ""
	if m := osp.versionRe.FindStringSubmatch(d); m != nil {
		// Strip the trailing punctuation a capture drags along from a
		// comma-separated sysDescr ("15.2(4)E10,").
		version = strings.TrimRight(m[1], ".,;:-")
	}
	return OSIdentity{Product: product, Version: version}, true
}

// ProfileForOS resolves the PROFILE a (vendor, sysDescr) pair identifies — the
// "lookup by detected OS string" entry point. It returns false when the vendor
// is unknown or the sysDescr does not name a product this vendor declares.
func (r *Registry) ProfileForOS(vendor, sysDescr string) (Profile, bool) {
	id, ok := r.ResolveOS(vendor, sysDescr)
	if !ok || id.Product == "" {
		return Profile{}, false
	}
	return r.LookupPlatform(vendor, id.Product)
}

// ─── dialect ─────────────────────────────────────────────────────────────────

// VRFDisplayTerm returns the dialect word the vendor's own operator expects for
// the L3 isolation concept. ok=false for a vendor no profile claims — the caller
// decides what to display, the registry never invents a dialect.
func (r *Registry) VRFDisplayTerm(vendorToken string) (string, bool) {
	t, ok := r.vrfTerms[canon(vendorToken)]
	return t, ok
}

// IsVRFTerm reports whether a token names the VRF concept in ANY declared
// dialect ("routing-instance", "VPRN", "VPN instance", …).
func (r *Registry) IsVRFTerm(term string) bool {
	_, ok := r.vrfSyn[canon(term)]
	return ok
}

// ─── consumer bindings ───────────────────────────────────────────────────────

// ProfileForPlatformText resolves a free-form platform label ("Cisco IOS-XE
// 17.9", "Nokia SR Linux") onto a profile via the ranked platform_contains
// table, first match wins. It is deliberately conservative: an unrecognized
// label returns false so the caller reports the platform unassessed rather than
// evaluating it against the wrong dialect.
func (r *Registry) ProfileForPlatformText(platform string) (Profile, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return Profile{}, false
	}
	for _, rule := range r.platRules {
		for _, sub := range rule.contains {
			if strings.Contains(p, sub) {
				return r.profiles[rule.profileID].clone(), true
			}
		}
	}
	return Profile{}, false
}

// HardeningBindingForPlatform returns the hardening rule-binding dialect id a
// free-form platform label resolves to. ok=false means no profile matched, OR
// the matched profile declares no hardening bindings — either way the caller
// reports NotApplicable, never a false Pass.
func (r *Registry) HardeningBindingForPlatform(platform string) (string, bool) {
	p, ok := r.ProfileForPlatformText(platform)
	if !ok || p.Hardening.Binding == "" {
		return "", false
	}
	return p.Hardening.Binding, true
}

// HardeningDisplay returns the operator-facing label for a hardening binding id.
func (r *Registry) HardeningDisplay(binding string) (string, bool) {
	d, ok := r.hardDisp[binding]
	return d, ok
}

// AdvisoryFor returns the advisory provider binding declared for (vendor,
// platform). ErrNotFound is the honest answer for an unknown platform: the
// caller surfaces the device as UNASSESSED and applies no default provider.
func (r *Registry) AdvisoryFor(vendor, platform string) (AdvisoryBinding, error) {
	p, ok := r.LookupPlatform(vendor, platform)
	if !ok {
		return AdvisoryBinding{}, fmt.Errorf("%w: %s/%s", ErrNotFound, vendor, platform)
	}
	if p.Advisory.Provider == "" {
		return AdvisoryBinding{}, fmt.Errorf("%w: %s declares no advisory provider", ErrNotFound, p.ID)
	}
	return p.Advisory, nil
}

// ThreatFor returns the device-log detection coverage declared for (vendor,
// platform). An empty LogRuleIDs list is UNASSESSED coverage, not "no threats".
func (r *Registry) ThreatFor(vendor, platform string) (ThreatBinding, error) {
	p, ok := r.LookupPlatform(vendor, platform)
	if !ok {
		return ThreatBinding{}, fmt.Errorf("%w: %s/%s", ErrNotFound, vendor, platform)
	}
	return p.Threat, nil
}

// CaptureFor returns the read-only capture command set for a profile id. An
// empty command means the platform's command is not established — a capture
// caller reports unassessed rather than issuing a guessed command at a device.
func (r *Registry) CaptureFor(id string) (Capture, error) {
	p, ok := r.Lookup(id)
	if !ok {
		return Capture{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return p.Capture, nil
}

// ─── cli dialect ─────────────────────────────────────────────────────────────

// CLIDialectForPlatform returns the show-command dialect id a free-form platform
// label resolves to. ok=false means no profile matched the label, OR the matched
// profile declares no CLI dialect — either way the caller reports the platform's
// grammar as unknown and records any fallback it renders, never a silent guess.
func (r *Registry) CLIDialectForPlatform(platform string) (string, bool) {
	p, ok := r.ProfileForPlatformText(platform)
	if !ok || p.CLI.Dialect == "" {
		return "", false
	}
	return p.CLI.Dialect, true
}

// CLIDialectDisplay returns the operator-facing label for a CLI dialect id.
func (r *Registry) CLIDialectDisplay(dialect string) (string, bool) {
	d, ok := r.cliDisp[dialect]
	return d, ok
}

// ─── active verification ─────────────────────────────────────────────────────

// VerifyCommand resolves (vendor family, check id) to the EXACT allowlisted
// read-only command the verification engine may execute. An unknown vendor or
// an id the vendor does not declare returns ok=false: the check is skipped, and
// no command is ever composed or borrowed from another vendor's grammar.
func (r *Registry) VerifyCommand(vendor, checkID string) (string, bool) {
	fam, ok := r.verifyCmds[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return "", false
	}
	cmd, ok := fam[checkID]
	return cmd, ok
}

// VerifyCommandAllowed reports whether cmd appears VERBATIM in some vendor's
// verification allowlist. It is the runner's defense-in-depth gate: matching is
// exact, with no normalization surface to exploit.
func (r *Registry) VerifyCommandAllowed(cmd string) bool {
	_, ok := r.verifyAll[cmd]
	return ok
}

// VerifyCommands returns one vendor's whole verification allowlist as a copy,
// or nil when the vendor declares none.
func (r *Registry) VerifyCommands(vendor string) map[string]string {
	fam, ok := r.verifyCmds[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(fam))
	for k, v := range fam {
		out[k] = v
	}
	return out
}

// VerifyCommandTable returns the WHOLE verification allowlist (vendor → check id
// → command) as a deep copy, for the engine's closed-table invariant tests and
// for operator-facing documentation of what the battery may run.
func (r *Registry) VerifyCommandTable() map[string]map[string]string {
	out := make(map[string]map[string]string, len(r.verifyCmds))
	for vendor, fam := range r.verifyCmds {
		cp := make(map[string]string, len(fam))
		for k, v := range fam {
			cp[k] = v
		}
		out[vendor] = cp
	}
	return out
}
