package vendorprofile

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// osProbeRoundTripToken is the synthetic version the loader renders through a
// platform's version_render to prove the vendor's own os_version_pattern reads
// it back unchanged. Digits and dots only, so it is inside every vendor
// pattern's version character class and the check tests the PHRASING, not the
// character class.
const osProbeRoundTripToken = "9.9.9"

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

	// ── vendor-level consumer bindings ──────────────────────────────────────
	configCap   map[string]ConfigCapture      // vendor → config-capture binding
	configVol   map[string][]compiledVolatile // vendor → compiled volatile rules
	configRules []configRule                  // platform text → capture family, ascending rank
	// configFamilies is every id ConfigCaptureVendorForPlatform can return —
	// the participating vendors PLUS their sibling capture dialects. It is what
	// a consumer's closed-table test iterates so a family that gains a command
	// with no golden fails the build.
	configFamilies []string
	snmpGen        map[string]SNMPConfigGen // vendor → onboarding templates
	snmpGenIDs     []string                 // sorted vendor ids declaring one
	devTypeText    map[string][]string      // device type → text hints (union)
	devTypeVend    map[string]string        // exact vendor token → device type

	// ── packet-capture families (profile level) ─────────────────────────────
	pcapFamily map[string]string // capture family key → profile id
	pcapKeys   []string          // sorted family keys
	pcapRules  []pcapRule        // platform text → family, ascending rank
}

// configRule is one vendor's entry in the config-capture platform table.
type configRule struct {
	rank     int
	vendor   string
	contains []string
}

// compiledVolatile is a volatile-line rule with its pattern compiled once, at
// load: normalization runs on every captured line of every capture, and a
// registry that recompiled a regexp per line would make the move a performance
// regression rather than a refactor.
type compiledVolatile struct {
	name string
	re   *regexp.Regexp
}

// pcapRule is one ranked capture-family resolution rule.
type pcapRule struct {
	rank   int
	family string
	tokens []string
	joined []string
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

		configCap:   make(map[string]ConfigCapture),
		configVol:   make(map[string][]compiledVolatile),
		snmpGen:     make(map[string]SNMPConfigGen),
		devTypeText: make(map[string][]string),
		devTypeVend: make(map[string]string),
		pcapFamily:  make(map[string]string),
	}
	seenDescrRank := make(map[int]string)
	seenPlatRank := make(map[int]string)
	seenConfigRank := make(map[int]string)
	seenPcapRank := make(map[int]string)
	seenHint := make(map[string]string)

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
		// ── config-capture binding (vendor level) ────────────────────────────
		if cc := doc.ConfigCapture; cc.PlatformRank > 0 || cc.RunningConfigCmd != "" || len(cc.VolatileRules) > 0 {
			if cc.PlatformRank > 0 {
				if other, dup := seenConfigRank[cc.PlatformRank]; dup {
					return nil, fmt.Errorf("vendorprofile: config_capture platform_rank %d claimed by both %q and %q",
						cc.PlatformRank, other, doc.Vendor)
				}
				seenConfigRank[cc.PlatformRank] = doc.Vendor
				r.configRules = append(r.configRules, configRule{
					rank: cc.PlatformRank, vendor: doc.Vendor,
					contains: append([]string(nil), cc.PlatformContains...),
				})
			}
			r.configCap[doc.Vendor] = cc
			if err := r.indexConfigVolatile(doc.Vendor, cc.VolatileRules); err != nil {
				return nil, err
			}
		}
		// ── config-capture SIBLING dialects (a second OS under one vendor) ───
		for _, d := range doc.ConfigCapture.PlatformDialects {
			if _, dup := r.configCap[d.ID]; dup {
				return nil, fmt.Errorf("vendorprofile: config_capture dialect id %q collides with an existing capture family", d.ID)
			}
			if other, dup := seenConfigRank[d.PlatformRank]; dup {
				return nil, fmt.Errorf("vendorprofile: config_capture platform_rank %d claimed by both %q and %q",
					d.PlatformRank, other, d.ID)
			}
			seenConfigRank[d.PlatformRank] = d.ID
			r.configRules = append(r.configRules, configRule{
				rank: d.PlatformRank, vendor: d.ID,
				contains: append([]string(nil), d.PlatformContains...),
			})
			r.configCap[d.ID] = ConfigCapture{
				PlatformContains: append([]string(nil), d.PlatformContains...),
				PlatformRank:     d.PlatformRank,
				RunningConfigCmd: d.RunningConfigCmd,
				VolatileRules:    append([]VolatileRule(nil), d.VolatileRules...),
			}
			r.configFamilies = append(r.configFamilies, d.ID)
			if err := r.indexConfigVolatile(d.ID, d.VolatileRules); err != nil {
				return nil, err
			}
		}
		if _, participates := r.configCap[doc.Vendor]; participates {
			r.configFamilies = append(r.configFamilies, doc.Vendor)
		}
		// ── SNMP onboarding templates (vendor level) ─────────────────────────
		if doc.SNMPConfigGen.V2CTemplate != "" {
			r.snmpGen[doc.Vendor] = doc.SNMPConfigGen
			r.snmpGenIDs = append(r.snmpGenIDs, doc.Vendor)
		}
		// ── device-type hints (vendor level) ─────────────────────────────────
		for _, tok := range doc.DeviceType.VendorTokens {
			key := strings.ToLower(strings.TrimSpace(tok))
			if other, dup := r.devTypeVend[key]; dup && other != doc.DeviceType.VendorKind {
				return nil, fmt.Errorf("vendorprofile: device_type vendor token %q maps to both %q and %q", key, other, doc.DeviceType.VendorKind)
			}
			r.devTypeVend[key] = doc.DeviceType.VendorKind
		}
		for kind, hints := range doc.DeviceType.TextHints {
			for _, hint := range hints {
				lower := strings.ToLower(hint)
				key := kind + "\x00" + lower
				if other, dup := seenHint[key]; dup {
					return nil, fmt.Errorf("vendorprofile: device_type text hint %q for %q is declared by both %q and %q",
						hint, kind, other, doc.Vendor)
				}
				seenHint[key] = doc.Vendor
				r.devTypeText[kind] = append(r.devTypeText[kind], lower)
			}
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
			ConfigCapture: doc.ConfigCapture, SNMPConfigGen: doc.SNMPConfigGen,
			DeviceType: doc.DeviceType,
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
			// OS-VERSION LADDER ROUND TRIP. A probe writes its reading onto the
			// device row, and collectors.ResolveDeviceOS reads that row back
			// through THIS vendor's os_version_pattern. A rendering the vendor
			// pattern cannot re-parse would store a version the platform is
			// unable to see — the device would sit UNASSESSED with the answer
			// already in the row. Prove it here, at load, on a synthetic token:
			// rendering must produce a string the vendor pattern captures the
			// SAME token back out of.
			if p.OSVersionProbe.Declared() {
				if osp.versionRe == nil {
					return nil, fmt.Errorf("vendorprofile: %s declares os_version_probe but vendor %q has no os_version_pattern to read it back with", p.ID, doc.Vendor)
				}
				rendered := p.OSVersionProbe.Render(osProbeRoundTripToken)
				m := osp.versionRe.FindStringSubmatch(rendered)
				if m == nil || strings.TrimRight(m[1], ".,;:-") != osProbeRoundTripToken {
					got := "no match"
					if m != nil {
						got = strconv.Quote(m[1])
					}
					return nil, fmt.Errorf("vendorprofile: %s os_version_probe.version_render %q renders %q, which vendor %q's os_version_pattern reads back as %s, not %q",
						p.ID, p.OSVersionProbe.VersionRender, rendered, doc.Vendor, got, osProbeRoundTripToken)
				}
			}
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
			// packet-capture family: one profile owns a family, and the family's
			// resolution ranks are global (first match wins over one list).
			if fam := p.Capture.PcapFamily; fam != "" {
				if other, dup := r.pcapFamily[fam]; dup {
					return nil, fmt.Errorf("vendorprofile: pcap_family %q claimed by both %q and %q", fam, other, p.ID)
				}
				r.pcapFamily[fam] = p.ID
				r.pcapKeys = append(r.pcapKeys, fam)
				for _, rule := range p.Capture.PcapPlatformRules {
					if other, dup := seenPcapRank[rule.Rank]; dup {
						return nil, fmt.Errorf("vendorprofile: pcap_platform_rules rank %d claimed by both %q and %q", rule.Rank, other, p.ID)
					}
					seenPcapRank[rule.Rank] = p.ID
					r.pcapRules = append(r.pcapRules, pcapRule{
						rank: rule.Rank, family: fam,
						tokens: append([]string(nil), rule.Tokens...),
						joined: append([]string(nil), rule.Joined...),
					})
				}
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
	sort.Strings(r.snmpGenIDs)
	sort.Strings(r.pcapKeys)
	sort.Slice(r.configRules, func(i, j int) bool { return r.configRules[i].rank < r.configRules[j].rank })
	sort.Slice(r.pcapRules, func(i, j int) bool { return r.pcapRules[i].rank < r.pcapRules[j].rank })
	// The device-type hint union is assembled from a map range (non-deterministic
	// order). Matching within a type is an OR, so order cannot change an answer —
	// but a registry that reported its own contents in a different order on every
	// build could not be pinned by a test, and this registry is deterministic by
	// design.
	for kind := range r.devTypeText {
		sort.Strings(r.devTypeText[kind])
	}
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
	if p.Capture.PcapPlatformRules != nil {
		out.Capture.PcapPlatformRules = make([]PcapPlatformRule, len(p.Capture.PcapPlatformRules))
		for i, rule := range p.Capture.PcapPlatformRules {
			out.Capture.PcapPlatformRules[i] = PcapPlatformRule{
				Rank: rule.Rank, Tokens: cp(rule.Tokens), Joined: cp(rule.Joined),
			}
		}
	}
	out.OSVersionProbe.GNMIPaths = cp(p.OSVersionProbe.GNMIPaths)
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
	out.ConfigCapture = v.ConfigCapture.clone()
	out.DeviceType = v.DeviceType.clone()
	out.ProfileIDs = cp(v.ProfileIDs)
	return out
}

// clone deep-copies the config-capture binding (its slices are shared index
// state until copied).
func (c ConfigCapture) clone() ConfigCapture {
	out := c
	out.PlatformContains = cp(c.PlatformContains)
	if c.VolatileRules != nil {
		out.VolatileRules = append([]VolatileRule(nil), c.VolatileRules...)
	}
	if c.PlatformDialects != nil {
		out.PlatformDialects = make([]ConfigCaptureDialect, len(c.PlatformDialects))
		for i, d := range c.PlatformDialects {
			dc := d
			dc.PlatformContains = cp(d.PlatformContains)
			if d.VolatileRules != nil {
				dc.VolatileRules = append([]VolatileRule(nil), d.VolatileRules...)
			}
			out.PlatformDialects[i] = dc
		}
	}
	return out
}

// clone deep-copies the device-type hints, including the hint map.
func (h DeviceTypeHints) clone() DeviceTypeHints {
	out := h
	out.VendorTokens = cp(h.VendorTokens)
	if h.TextHints != nil {
		out.TextHints = make(map[string][]string, len(h.TextHints))
		for k, v := range h.TextHints {
			out.TextHints[k] = cp(v)
		}
	}
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

// ─── os-version source ladder ────────────────────────────────────────────────

// OSVersionProbeForDevice resolves the OS-VERSION PROBE data for a device from
// what an inventory row actually carries: its detected vendor and its free-form
// OS/platform label ("SR Linux", "Cisco IOS-XE 17.9", a whole sysDescr).
//
// Resolution is vendor-BOUNDED on purpose. The sysDescr route is tried first
// (ResolveOS names the product, which names the platform) because it is the
// authoritative one; the ranked platform-text table is the backstop, and its
// answer is ACCEPTED ONLY when the profile it lands on belongs to the vendor
// SNMP already detected. Without that check the label "Nokia SR Linux" on a row
// whose vendor is something else would silently hand a device another vendor's
// gNMI paths and CLI command — the ladder would then run one vendor's command
// at another vendor's device, which is precisely the "never guess at a live
// device" rule this registry exists to keep.
//
// ok=false is the honest "no established non-SNMP version source for this
// device": an unknown vendor, an unrecognized label, or a profile that declares
// no probe. The caller reports the device unassessed; it never guesses a path.
func (r *Registry) OSVersionProbeForDevice(vendor, osText string) (Profile, OSVersionProbe, bool) {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" || strings.TrimSpace(osText) == "" {
		return Profile{}, OSVersionProbe{}, false
	}
	p, ok := r.ProfileForOS(v, osText)
	if !ok {
		p, ok = r.ProfileForPlatformText(osText)
		if !ok || p.Vendor != v {
			return Profile{}, OSVersionProbe{}, false
		}
	}
	if !p.OSVersionProbe.Declared() {
		return Profile{}, OSVersionProbe{}, false
	}
	return p, p.OSVersionProbe.clone(), true
}

// clone copies the slice the caller could otherwise retain into the registry.
func (o OSVersionProbe) clone() OSVersionProbe {
	out := o
	out.GNMIPaths = cp(o.GNMIPaths)
	return out
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

// ─── config capture (vendor level) ───────────────────────────────────────────

// ConfigCaptureVendorForPlatform resolves a free-form platform label ("Cisco
// IOS-XE 17.9", "Arista EOS 4.30") onto the CAPTURE FAMILY whose config-capture
// binding applies, via the ranked config_capture.platform_contains table, first
// match wins. ok=false means nothing claimed the text: the caller REFUSES the
// capture rather than issuing another family's command at a device prompt.
//
// A capture family is usually a vendor, but not always: a vendor that ships two
// operating systems declares the second as a config_capture.platform_dialect
// and this returns the DIALECT's id ("srlinux"), because SR Linux answers a
// different command than SR OS and shares none of its volatile lines.
//
// The rank order is load-bearing and is why this is not ProfileForPlatformText:
// an EOS platform string frequently names a "Cisco-compatible" CLI, and EOS
// wants its own volatile-line rules; likewise "Nokia SR Linux" contains
// "nokia", so the srlinux dialect must rank ahead of the nokia vendor family.
func (r *Registry) ConfigCaptureVendorForPlatform(platform string) (string, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return "", false
	}
	for _, rule := range r.configRules {
		for _, sub := range rule.contains {
			if strings.Contains(p, sub) {
				return rule.vendor, true
			}
		}
	}
	return "", false
}

// indexConfigVolatile compiles and registers one family's volatile-line rules.
func (r *Registry) indexConfigVolatile(family string, rules []VolatileRule) error {
	for _, vr := range rules {
		re, err := regexp.Compile(vr.Pattern)
		if err != nil {
			return fmt.Errorf("vendorprofile: capture family %q volatile rule %q: %w", family, vr.Name, err)
		}
		r.configVol[family] = append(r.configVol[family], compiledVolatile{name: vr.Name, re: re})
	}
	return nil
}

// ConfigCaptureFamilies returns, sorted, every capture family id the resolver
// can return: the vendors that participate in config capture PLUS their sibling
// dialects (Nokia's `srlinux`). A consumer pinning the closed command table
// iterates THIS, not VendorIDs — a dialect is not a vendor and would otherwise
// gain a command with no golden behind it.
func (r *Registry) ConfigCaptureFamilies() []string {
	out := append([]string(nil), r.configFamilies...)
	sort.Strings(out)
	return out
}

// ConfigCaptureFor returns a vendor's whole config-capture binding as a copy.
func (r *Registry) ConfigCaptureFor(vendor string) (ConfigCapture, bool) {
	cc, ok := r.configCap[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return ConfigCapture{}, false
	}
	return cc.clone(), true
}

// ConfigCaptureCommand returns the EXACT read-only running-config command for a
// vendor family. ok=false is the honest "this family is not bound" answer — the
// caller refuses the capture, it never composes a command.
func (r *Registry) ConfigCaptureCommand(vendor string) (string, bool) {
	cc, ok := r.configCap[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok || cc.RunningConfigCmd == "" {
		return "", false
	}
	return cc.RunningConfigCmd, true
}

// ConfigVolatileRuleNames returns the documented volatile-rule names for a
// vendor, in declaration order. It is what lets a consumer's test pin the list
// by name so a silent deletion fails the build.
func (r *Registry) ConfigVolatileRuleNames(vendor string) []string {
	rules := r.configVol[strings.ToLower(strings.TrimSpace(vendor))]
	if len(rules) == 0 {
		return nil
	}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.name)
	}
	return out
}

// IsConfigVolatileLine reports whether one captured line matches any of a
// vendor's volatile-line rules. The patterns are compiled once at load, so this
// is a match, not a compile, on the per-line hot path of every capture.
func (r *Registry) IsConfigVolatileLine(vendor, line string) bool {
	for _, rule := range r.configVol[strings.ToLower(strings.TrimSpace(vendor))] {
		if rule.re.MatchString(line) {
			return true
		}
	}
	return false
}

// ─── SNMP onboarding templates (vendor level) ────────────────────────────────

// SNMPConfigGenVendors returns, sorted, every vendor that declares a first-class
// SNMP onboarding template. A vendor absent from this list still gets a real
// minted credential — only the ready-to-paste CLI block is generic.
func (r *Registry) SNMPConfigGenVendors() []string { return append([]string(nil), r.snmpGenIDs...) }

// SNMPConfigGenFor returns a vendor's onboarding templates.
func (r *Registry) SNMPConfigGenFor(vendor string) (SNMPConfigGen, bool) {
	g, ok := r.snmpGen[strings.ToLower(strings.TrimSpace(vendor))]
	return g, ok
}

// RenderSNMPConfig renders a vendor's onboarding CLI block for an SNMP version
// ("v2c" or "v3") with the supplied placeholder values. ok=false means the
// vendor declares no template for that version — the caller falls back to the
// generic guidance, it never renders another vendor's grammar.
//
// SECURITY: rendering is a SINGLE LEFT-TO-RIGHT PASS, never a sequence of
// strings.ReplaceAll. One of the values (the management subnet) is operator
// input; with sequential replacement an operator who submitted the literal text
// "<<auth_key>>" as their subnet would have the MINTED PRIVATE KEY substituted
// into it by the next pass. A single pass never re-examines what it has already
// emitted, so a value can never name a hole.
func (r *Registry) RenderSNMPConfig(vendor, version string, vals map[string]string) (string, bool) {
	g, ok := r.snmpGen[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return "", false
	}
	tpl := g.V2CTemplate
	if version == "v3" {
		tpl = g.V3Template
	}
	if tpl == "" {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(tpl))
	for {
		i := strings.Index(tpl, "<<")
		if i < 0 {
			break
		}
		end := strings.Index(tpl[i+2:], ">>")
		if end < 0 {
			break // validated at load; a malformed template renders literally
		}
		b.WriteString(tpl[:i])
		b.WriteString(vals[tpl[i+2:i+2+end]])
		tpl = tpl[i+2+end+2:]
	}
	b.WriteString(tpl)
	return b.String(), true
}

// ─── functional device type ──────────────────────────────────────────────────

// DeviceTypeForText infers a FUNCTIONAL device type from the free-form text an
// operator reads (vendor + model + OS + name), evaluating DeviceTypeOrder in
// order so a specific role (firewall, load balancer, WLC, AP, cloud gateway) is
// always tested before the generic switch-vs-router split. ok=false means no
// hint matched: the caller reports its own neutral default, never a guess.
func (r *Registry) DeviceTypeForText(text string) (string, bool) {
	t := strings.ToLower(text)
	if strings.TrimSpace(t) == "" {
		return "", false
	}
	for _, kind := range DeviceTypeOrder {
		for _, hint := range r.devTypeText[kind] {
			if strings.Contains(t, hint) {
				return kind, true
			}
		}
	}
	return "", false
}

// DeviceTypeForVendorToken resolves a vendor spelling that is ITSELF a role
// claim ("fortinet", "palo alto") to a device type. The match is exact, on the
// whole trimmed, lower-cased vendor token: a vendor id is an identity, not a
// substring hint.
func (r *Registry) DeviceTypeForVendorToken(vendor string) (string, bool) {
	kind, ok := r.devTypeVend[strings.ToLower(strings.TrimSpace(vendor))]
	return kind, ok
}

// DeviceTypeTextHints returns, sorted, every text hint declared for one device
// type across all vendors — the union a consumer test can pin verbatim.
func (r *Registry) DeviceTypeTextHints(kind string) []string {
	return append([]string(nil), r.devTypeText[kind]...)
}

// ─── packet-capture families ─────────────────────────────────────────────────

// PcapFamilyKeys returns every declared capture-family key, sorted. A key here
// is a family the registry can NAME; whether it has COMMANDS is a separate
// question (a profile may declare the family and establish no commands, which
// is refused honestly at the device).
func (r *Registry) PcapFamilyKeys() []string { return append([]string(nil), r.pcapKeys...) }

// PcapFamilies returns capture-family key → the profile id that declares it.
func (r *Registry) PcapFamilies() map[string]string {
	out := make(map[string]string, len(r.pcapFamily))
	for k, v := range r.pcapFamily {
		out[k] = v
	}
	return out
}

// PcapFamilyForPlatform resolves a device's free-form platform text onto a
// capture-family key: an exact family key first, then the ranked token rules,
// first match wins. ok=false means the platform is not a family this registry
// establishes — packet capture is REFUSED, never rendered from a guess.
func (r *Registry) PcapFamilyForPlatform(platform string) (string, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return "", false
	}
	if _, ok := r.pcapFamily[p]; ok {
		return p, true
	}
	tokens, joined := platformTokens(p)
	for _, rule := range r.pcapRules {
		for _, tok := range rule.tokens {
			if tokens[tok] {
				return rule.family, true
			}
		}
		for _, sub := range rule.joined {
			if strings.Contains(joined, sub) {
				return rule.family, true
			}
		}
	}
	return "", false
}

// platformTokens splits a free-form vendor/OS/model string into lower-case
// alphanumeric TOKENS plus their concatenation. Matching on tokens rather than
// substrings is deliberate: a substring rule for "eos" also matches the vendor
// string "acme-networks SomeOS", and silently rendering Arista commands at an
// unknown device is exactly the "invent an API at a live router" failure the
// design forbids. The joined form is used only for the two-part names ("ios-xe",
// "nx-os") a substring test can identify unambiguously.
func platformTokens(platform string) (map[string]bool, string) {
	set := map[string]bool{}
	var cur, joined strings.Builder
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
