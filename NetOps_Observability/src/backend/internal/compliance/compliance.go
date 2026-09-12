// Package compliance implements Compliance Monitoring (build-order #14): drift
// between the declared intent (the active Source-of-Truth provider) and the
// observed/operator inventory, plus management-plane policy baselines — all
// agentless, computed from data the platform already holds (no config pull yet;
// that's a later phase). The HTTP surface (/api/compliance) stays in package
// main; this package is the evaluation only, with its collaborators passed in.
//
// The SoT is a ROLE, not a product (docs/design/sot-provider-model.md): drift
// pairs against whichever provider is active. The active provider is the INTERNAL
// one (the platform's own SNMP-discovered inventory IS the authority), so
// DeviceRecordSource() returns "" → there are no separate declared records to
// drift device fields against, and the check reports the honest "the inventory is
// itself the source of truth" state rather than flagging discovered devices as
// "unregistered". NetBox is an automation connector, NOT a drift authority. The
// pairing stays provider-agnostic: if a future external authority were ever wired
// into activeSoT it would report its own source label and the same logic runs
// unchanged (Evaluate takes the source as a parameter).
//
// Two check classes:
//
//   - drift  — pair every SoT-declared record against the observed record(s) for
//     the same physical device (matched mgmt-IP → serial → name, the same
//     identity chain the discovery de-dup uses) and diff the fields an
//     operator declares in the SoT: registration, name, mgmt IP, serial,
//     platform (vs the OS parsed out of SNMP sysDescr).
//   - policy — baselines that need no source of truth: SNMPv1/v2c in use,
//     weak SNMPv3 parameters, fleet OS-version consensus outliers (the
//     agentless "golden version" proxy), and known-exploited CVEs present
//     (reuses the #13 advisory feed when provisioned).
//
// Checks that lack their data source are reported as INACTIVE with the reason
// (no external SoT records, no credential profiles, feed not provisioned) — an
// unrun check is "cannot assess", never "compliant". Same honesty rule as the
// Vulnerability Management board.
package compliance

import (
	"fmt"
	"sort"
	"strings"

	"netops/backend/collectors"
	"netops/backend/internal/vuln"
	"netops/backend/models"
)

// SNMPProfile is the slice of a management credential this package judges:
// the profile's identity and its cryptographic parameters. Deliberately NOT
// the platform's full credential record — community strings and keys never
// cross this boundary, so the package that reports on credentials cannot
// leak one (§3 zero trust, §8 no secrets). The caller adapts at the seam.
type SNMPProfile struct {
	Name          string
	Version       string // v1 | v2c | v3
	SecurityLevel string // noAuthNoPriv|authNoPriv|authPriv
	AuthProtocol  string
	PrivProtocol  string
}

// Finding is one device × check violation.
type Finding struct {
	Check      string `json:"check"`
	Title      string `json:"title"`
	Class      string `json:"class"`    // drift | policy
	Severity   string `json:"severity"` // high | medium | low
	Framework  string `json:"framework"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Observed   string `json:"observed,omitempty"`
	Intended   string `json:"intended,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Check describes one check's status for the board: whether it could
// run, why not, and how many findings it produced.
type Check struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Class     string `json:"class"`
	Framework string `json:"framework"`
	Active    bool   `json:"active"`
	Reason    string `json:"reason,omitempty"` // why inactive
	Findings  int    `json:"findings"`
}

// Gap is a device some checks had to skip, and why. Unassessed ≠ ok.
type Gap struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Reason     string `json:"reason"`
}

type Result struct {
	Findings []Finding
	Checks   []Check
	Gaps     []Gap
	Physical int // unique physical devices (merged records folded by identity)
}

// Check ids (stable API surface — the UI keys off these).
const (
	ckSotRegistered = "sot-registered"
	ckSotName       = "sot-name"
	ckSotMgmtIP     = "sot-mgmt-ip"
	ckSotSerial     = "sot-serial"
	ckSotPlatform   = "sot-platform"
	ckSnmpVersion   = "snmp-version"
	ckSnmpV3Weak    = "snmp-v3-strength"
	ckOSConsensus   = "os-consensus"
	ckKEV           = "kev-exposure"
)

var checkCatalog = []Check{
	{ID: ckSotRegistered, Title: "Device registered in Source of Truth", Class: "drift", Framework: "NIST CSF ID.AM-1"},
	{ID: ckSotName, Title: "Name matches Source of Truth", Class: "drift", Framework: "NIST CSF ID.AM-1"},
	{ID: ckSotMgmtIP, Title: "Management IP matches Source of Truth", Class: "drift", Framework: "NIST CSF ID.AM-1"},
	{ID: ckSotSerial, Title: "Serial matches Source of Truth", Class: "drift", Framework: "NIST CSF ID.AM-1"},
	{ID: ckSotPlatform, Title: "Running OS matches intended platform", Class: "drift", Framework: "NIST CSF ID.AM-2"},
	{ID: ckSnmpVersion, Title: "No community-based SNMP (v1/v2c)", Class: "policy", Framework: "CIS · NIST 800-53 IA-5"},
	{ID: ckSnmpV3Weak, Title: "SNMPv3 uses authPriv with strong ciphers", Class: "policy", Framework: "CIS · NIST 800-53 SC-8"},
	{ID: ckOSConsensus, Title: "OS version matches fleet baseline", Class: "policy", Framework: "Internal golden baseline"},
	{ID: ckKEV, Title: "No known-exploited vulnerabilities", Class: "policy", Framework: "CISA BOD 22-01"},
}

// sevRank orders finding severities worst-first. Duplicated from the /api/vulns
// handler's copy (one line, two owners) rather than shared — CLAUDE.md §2
// forbids a utils package, and the two surfaces rank independently.
var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// Evaluate runs every check it has data for. merged is the
// de-duplicated inventory (one record per physical device — policy checks);
// raw is the per-source inventory (drift pairing). resolveCred and vulnMatch
// are nil-able seams: nil means that data source isn't available, and the
// dependent checks report inactive instead of silently passing.
// sotSource is the active provider's declared-record Device.Source label
// (SoTProvider.DeviceRecordSource()): records carrying it are the declared intent,
// every other record is observed. "" means no declared records exist (internal
// provider, or an external one not read back) → drift checks stay inactive.
func Evaluate(
	merged, raw []models.Device,
	sotSource string,
	resolveCred func(string) (SNMPProfile, bool),
	vulnMatch func(vendor, product, version string) []vuln.Entry,
) Result {
	var findings []Finding

	// ── drift: pair SoT-declared records against the observed records ────────
	driftable := sotSource != ""
	var sot, observed []models.Device
	for _, d := range raw {
		if driftable && d.Source == sotSource {
			sot = append(sot, d)
		} else {
			observed = append(observed, d)
		}
	}
	if driftable {
		findings = append(findings, evalDrift(sot, observed)...)
	}

	// ── policy: per PHYSICAL device ──────────────────────────────────────────
	// The merged inventory can still carry two records for one device (an
	// IP-less NetBox record never merges with its IP-bearing twin — deviceKey
	// is IP-first), so aggregate the signals each record contributes under one
	// physical identity (display name) before judging. Without this a device
	// monitored via its static record would also be flagged "no credential"
	// via its NetBox twin.
	type physical struct {
		rep        models.Device // record findings/gaps are attributed to
		hasAddr    bool
		cred       *SNMPProfile // first resolvable profile across records
		credDev    models.Device
		badCredRef string             // a ref that matched no profile (only reported if no record resolved one)
		osi        *collectors.OSInfo // first parseable OS across records
		osiDev     models.Device
		vendor     string
	}
	byPhys := map[string]*physical{}
	var physOrder []string
	for _, d := range merged {
		key := strings.ToLower(deviceDisplayName(d))
		p, ok := byPhys[key]
		if !ok {
			p = &physical{rep: d}
			byPhys[key] = p
			physOrder = append(physOrder, key)
		}
		if d.Address != "" {
			p.hasAddr = true
		}
		if ref := strings.TrimSpace(d.CredentialRef); ref != "" && resolveCred != nil && p.cred == nil {
			if c, ok := resolveCred(ref); ok {
				p.cred, p.credDev = &c, d
			} else {
				p.badCredRef = ref
			}
		}
		// ParseOS keys on the lowercase vendor ids DetectVendor emits; NetBox
		// manufacturers arrive capitalized, so fold case here.
		if d.Vendor != "" {
			p.vendor = d.Vendor
			if p.osi == nil {
				if osi := collectors.ParseOS(strings.ToLower(d.Vendor), d.OS); osi.Product != "" && osi.Version != "" {
					p.osi, p.osiDev = &osi, d
				}
			}
		}
	}

	gapReasons := map[string][]string{} // physical key → reasons
	addGap := func(key, reason string) { gapReasons[key] = append(gapReasons[key], reason) }

	credAssigned := false
	type osKey struct{ vendor, product string }
	consensus := map[osKey][]osVersionSeen{}
	for _, key := range physOrder {
		p := byPhys[key]
		switch {
		case p.cred != nil:
			credAssigned = true
			findings = append(findings, evalSNMPPolicy(p.credDev, *p.cred)...)
		case p.badCredRef != "":
			addGap(key, fmt.Sprintf("credential_ref %q matches no SNMP profile — management-plane checks skipped", p.badCredRef))
		case p.hasAddr:
			addGap(key, "no SNMP credential profile assigned — management-plane checks skipped")
		}

		if p.vendor == "" {
			addGap(key, "vendor unknown (SNMP unreachable or unrecognized sysObjectID) — OS checks skipped")
			continue
		}
		if p.osi == nil {
			addGap(key, "no OS version in sysDescr — version checks skipped")
			continue
		}
		k := osKey{strings.ToLower(p.vendor), vuln.NormProduct(p.osi.Product)}
		consensus[k] = append(consensus[k], osVersionSeen{p.osiDev, p.osi.Version})

		if vulnMatch != nil {
			findings = append(findings, evalKEV(p.osiDev, *p.osi, vulnMatch)...) // feed keys are lowercase-vendor; evalKEV folds
		}
	}

	consensusRan := false
	for _, group := range consensus {
		if fs, ran := evalConsensus(group); ran {
			consensusRan = true
			findings = append(findings, fs...)
		}
	}

	// ── check status table ───────────────────────────────────────────────────
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Check]++
	}
	checks := make([]Check, 0, len(checkCatalog))
	for _, c := range checkCatalog {
		c.Findings = counts[c.ID]
		switch {
		case c.Class == "drift" && !driftable:
			c.Reason = "No declared inventory to compare against — the internal Source of Truth is itself the authority. Connect an external SoT (Automation → Source of Truth) in read or two-way mode to detect drift against declared intent."
		case (c.ID == ckSnmpVersion || c.ID == ckSnmpV3Weak) && !credAssigned:
			c.Reason = "no devices reference an SNMP credential profile"
		case c.ID == ckOSConsensus && !consensusRan:
			c.Reason = "needs ≥3 devices on the same platform with a parseable OS version"
		case c.ID == ckKEV && vulnMatch == nil:
			c.Reason = "vulnerability feed not provisioned — see Security → Vulnerability Management"
		}
		c.Active = c.Reason == ""
		checks = append(checks, c)
	}

	// Worst first: severity, then class (drift first), then device name.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] > sevRank[b.Severity]
		}
		if a.Class != b.Class {
			return a.Class == "drift"
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.DeviceName < b.DeviceName
	})

	gaps := make([]Gap, 0, len(gapReasons))
	for key, reasons := range gapReasons {
		rep := byPhys[key].rep
		gaps = append(gaps, Gap{DeviceID: rep.ID, DeviceName: deviceDisplayName(rep), Reason: strings.Join(reasons, "; ")})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].DeviceName < gaps[j].DeviceName })

	return Result{Findings: findings, Checks: checks, Gaps: gaps, Physical: len(byPhys)}
}

func deviceDisplayName(d models.Device) string {
	if n := strings.TrimSpace(d.Name); n != "" {
		return n
	}
	return d.Address
}

// evalDrift pairs each SoT-declared record to the observed/operator records for
// the same physical device and diffs the declared fields. Match precedence mirrors
// deviceKey (mgmt IP → serial → normalized name); a field is only diffed when
// the pair matched on a DIFFERENT field (a name-matched pair can't have name
// drift by construction).
func evalDrift(sot, observed []models.Device) []Finding {
	byIP, bySerial, byName := map[string]models.Device{}, map[string]models.Device{}, map[string]models.Device{}
	for _, d := range sot {
		if ip := strings.TrimSpace(d.Address); ip != "" {
			byIP[ip] = d
		}
		if sn := strings.ToLower(strings.TrimSpace(d.Labels["serial"])); sn != "" {
			bySerial[sn] = d
		}
		if n := strings.ToLower(strings.TrimSpace(d.Name)); n != "" {
			byName[n] = d
		}
	}

	var out []Finding
	for _, o := range observed {
		nb, matchedOn := matchSot(o, byIP, bySerial, byName)
		if matchedOn == "" {
			// The SoT supplies declared records (caller gates on that) — a device
			// absent from them is drift even when the SoT is otherwise empty.
			out = append(out, Finding{
				Check: ckSotRegistered, Title: "Device not registered in Source of Truth", Class: "drift",
				Severity: "medium", Framework: "NIST CSF ID.AM-1",
				DeviceID: o.ID, DeviceName: deviceDisplayName(o),
				Observed: o.Source + " inventory", Intended: "Source-of-Truth record",
				Detail: "Discovered/operator inventory has this device but the Source of Truth does not. Register it in your Source of Truth, or enable two-way sync under Automation → Source of Truth.",
			})
			continue
		}

		oName, nName := strings.TrimSpace(o.Name), strings.TrimSpace(nb.Name)
		if matchedOn != "name" && oName != "" && nName != "" && !strings.EqualFold(oName, nName) {
			out = append(out, Finding{
				Check: ckSotName, Title: "Name differs from Source of Truth", Class: "drift",
				Severity: "low", Framework: "NIST CSF ID.AM-1",
				DeviceID: o.ID, DeviceName: deviceDisplayName(o),
				Observed: oName, Intended: nName,
			})
		}
		oIP, nIP := strings.TrimSpace(o.Address), strings.TrimSpace(nb.Address)
		if matchedOn != "ip" && oIP != "" && nIP != "" && oIP != nIP {
			out = append(out, Finding{
				Check: ckSotMgmtIP, Title: "Management IP differs from Source of Truth", Class: "drift",
				Severity: "high", Framework: "NIST CSF ID.AM-1",
				DeviceID: o.ID, DeviceName: deviceDisplayName(o),
				Observed: oIP, Intended: nIP,
			})
		}
		oSN, nSN := strings.TrimSpace(o.Labels["serial"]), strings.TrimSpace(nb.Labels["serial"])
		if matchedOn != "serial" && oSN != "" && nSN != "" && !strings.EqualFold(oSN, nSN) {
			out = append(out, Finding{
				Check: ckSotSerial, Title: "Serial differs from Source of Truth", Class: "drift",
				Severity: "high", Framework: "NIST CSF ID.AM-1",
				DeviceID: o.ID, DeviceName: deviceDisplayName(o),
				Observed: oSN, Intended: nSN,
				Detail: "A serial mismatch on the same management identity usually means hardware was swapped without updating the record.",
			})
		}
		if f, drifted := platformDrift(o, nb); drifted {
			out = append(out, f)
		}
	}
	return out
}

// matchSot finds the SoT-declared counterpart for an observed record, returning
// what the pair matched on ("ip", "serial", "name") or "" when unregistered.
func matchSot(o models.Device, byIP, bySerial, byName map[string]models.Device) (models.Device, string) {
	if ip := strings.TrimSpace(o.Address); ip != "" {
		if nb, ok := byIP[ip]; ok {
			return nb, "ip"
		}
	}
	if sn := strings.ToLower(strings.TrimSpace(o.Labels["serial"])); sn != "" {
		if nb, ok := bySerial[sn]; ok {
			return nb, "serial"
		}
	}
	if n := strings.ToLower(strings.TrimSpace(o.Name)); n != "" {
		if nb, ok := byName[n]; ok {
			return nb, "name"
		}
	}
	return models.Device{}, ""
}

// platformDrift compares the OS actually running (parsed from the observed
// record's sysDescr) with the platform declared in the SoT. Platform names are
// free-form ("Cisco IOS-XE", "IOS XE 17", "Arista EOS"), so both sides reduce
// to a vendor-stripped, digit-stripped product token before comparing —
// "Cisco IOS-XE 17" and ParseOS's "ios_xe" both become "iosxe".
func platformDrift(o, nb models.Device) (Finding, bool) {
	intended := strings.TrimSpace(nb.OS) // SoT record maps Platform → OS
	vendor := o.Vendor
	if vendor == "" {
		vendor = nb.Vendor
	}
	if intended == "" || vendor == "" || o.OS == "" {
		return Finding{}, false
	}
	osi := collectors.ParseOS(strings.ToLower(vendor), o.OS)
	if osi.Product == "" {
		return Finding{}, false
	}
	want := platformToken(intended, vendor)
	got := platformToken(osi.Product, vendor)
	if want == "" || got == "" || want == got {
		return Finding{}, false
	}
	return Finding{
		Check: ckSotPlatform, Title: "Running OS differs from intended platform", Class: "drift",
		Severity: "medium", Framework: "NIST CSF ID.AM-2",
		DeviceID: o.ID, DeviceName: deviceDisplayName(o),
		Observed: osi.Product, Intended: intended,
	}, true
}

// platformToken reduces a platform/product string to a comparable token:
// lowercase, vendor name removed, digits and separators stripped, then the
// same alias fold the vulnerability matcher uses (sr_os/timos → sros) — a
// letters-only token passes through vuln.NormProduct unchanged except for
// that fold.
func platformToken(s, vendor string) string {
	low := strings.ToLower(s)
	for _, v := range []string{strings.ToLower(vendor), "cisco", "juniper", "arista", "fortinet", "nokia", "huawei", "mikrotik", "paloalto", "palo alto"} {
		if v != "" {
			low = strings.ReplaceAll(low, v, "")
		}
	}
	var b strings.Builder
	for _, r := range low {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return vuln.NormProduct(b.String())
}

// evalSNMPPolicy checks one device's management-plane credential profile.
func evalSNMPPolicy(d models.Device, c SNMPProfile) []Finding {
	var out []Finding
	switch strings.ToLower(c.Version) {
	case "v1", "v2c":
		out = append(out, Finding{
			Check: ckSnmpVersion, Title: "Community-based SNMP in use", Class: "policy",
			Severity: "medium", Framework: "CIS · NIST 800-53 IA-5",
			DeviceID: d.ID, DeviceName: deviceDisplayName(d),
			Observed: "SNMP " + c.Version + " (cleartext community)", Intended: "SNMPv3 authPriv",
			Detail: "Profile \"" + c.Name + "\" authenticates with a cleartext community string. Migrate the device to an SNMPv3 profile (Settings → SNMP Profiles).",
		})
	case "v3":
		var weak []string
		if !strings.EqualFold(c.SecurityLevel, "authPriv") {
			weak = append(weak, "security level "+c.SecurityLevel+" (unencrypted)")
		}
		if strings.EqualFold(c.AuthProtocol, "MD5") {
			weak = append(weak, "MD5 authentication")
		}
		if strings.EqualFold(c.PrivProtocol, "DES") {
			weak = append(weak, "DES privacy")
		}
		if len(weak) > 0 {
			out = append(out, Finding{
				Check: ckSnmpV3Weak, Title: "Weak SNMPv3 parameters", Class: "policy",
				Severity: "low", Framework: "CIS · NIST 800-53 SC-8",
				DeviceID: d.ID, DeviceName: deviceDisplayName(d),
				Observed: strings.Join(weak, ", "), Intended: "authPriv with SHA-2 + AES",
				Detail: "Profile \"" + c.Name + "\".",
			})
		}
	}
	return out
}

// evalKEV flags devices whose running OS matches a CISA known-exploited CVE.
// The full CVE list lives on the Vulnerability Management board; compliance
// surfaces the pass/fail with a short evidence trail.
func evalKEV(d models.Device, osi collectors.OSInfo, match func(vendor, product, version string) []vuln.Entry) []Finding {
	var kev []string
	for _, e := range match(strings.ToLower(d.Vendor), osi.Product, osi.Version) {
		if e.KEV {
			kev = append(kev, e.CVE)
		}
	}
	if len(kev) == 0 {
		return nil
	}
	sort.Strings(kev)
	shown := kev
	if len(shown) > 4 {
		shown = shown[:4]
	}
	detail := strings.Join(shown, ", ")
	if len(kev) > len(shown) {
		detail += fmt.Sprintf(" (+%d more)", len(kev)-len(shown))
	}
	return []Finding{{
		Check: ckKEV, Title: "Known-exploited vulnerability present", Class: "policy",
		Severity: "high", Framework: "CISA BOD 22-01",
		DeviceID: d.ID, DeviceName: deviceDisplayName(d),
		Observed: fmt.Sprintf("%s %s — %d KEV CVE(s)", osi.Product, osi.Version, len(kev)),
		Intended: "no known-exploited CVEs",
		Detail:   detail + " — full advisories on the Vulnerability Management board.",
	}}
}

// osVersionSeen is one device's parsed OS version within a vendor+product group.
type osVersionSeen struct {
	dev     models.Device
	version string
}

// evalConsensus flags OS-version outliers within one vendor+product group.
// The "golden" version is the strict-majority version of a group of ≥3 — an
// agentless stand-in for an operator-pinned baseline. ran reports whether the
// group was big enough to establish a baseline at all.
func evalConsensus(group []osVersionSeen) (out []Finding, ran bool) {
	if len(group) < 3 {
		return nil, false
	}
	tally := map[string]int{}
	for _, g := range group {
		tally[g.version]++
	}
	golden, best := "", 0
	for v, n := range tally {
		if n > best || (n == best && vuln.CompareVersions(v, golden) > 0) {
			golden, best = v, n
		}
	}
	if best*2 <= len(group) { // no strict majority (>50%) → no defensible baseline
		return nil, true
	}
	for _, g := range group {
		if g.version == golden {
			continue
		}
		out = append(out, Finding{
			Check: ckOSConsensus, Title: "OS version off fleet baseline", Class: "policy",
			Severity: "low", Framework: "Internal golden baseline",
			DeviceID: g.dev.ID, DeviceName: deviceDisplayName(g.dev),
			Observed: g.version, Intended: golden,
			Detail: fmt.Sprintf("%d of %d %s devices run %s.", best, len(group), g.dev.Vendor, golden),
		})
	}
	return out, true
}
