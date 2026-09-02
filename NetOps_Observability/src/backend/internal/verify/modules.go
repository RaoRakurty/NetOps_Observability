package verify

// verify_modules.go — prebuilt deterministic troubleshooting MODULES for the
// Active Verification engine (verify_engine.go). A module is a set of extra
// read-only checks that fires only when a case's seam/fault context matches
// its trigger condition — the case runs the core battery plus the modules its
// context earns, nothing more.
//
// The troubleshooting KNOWLEDGE encoded in the per-vendor command choices and
// the fault indicators the parsers look for (CRC/input errors ⇒ physical layer,
// half-duplex ⇒ duplex mismatch, carrier transitions / short up-time ⇒ flap,
// BGP session below incident age ⇒ recent reset, prefix-count collapse,
// config-change-before-incident as a top-tier "possibly because of" cause) is
// mined from the Apache-2.0 NetClaw project by John Capobianco
// (github.com/automateyournetwork/netclaw, pinned commit
// 49332542f43390955e758b69855a111b5ba0ff4c — see NOTICE): specifically its
// pyats-troubleshoot, pyats-health-check, pyats-routing and
// pyats-junos-interfaces/-routing skill procedures. NetClaw is an LLM agent;
// nothing of the agent runs here — only the distilled procedures, re-expressed
// as closed command tables and deterministic parsers. Arista EOS, Nokia SR OS
// and Huawei VRP command profiles are authored fresh from standard platform
// command knowledge (NetClaw does not cover those CLIs).
//
// Invariants (identical to the core battery):
//   - commands come ONLY from the closed module table below; read-only
//     show/display verbs; nothing composed at runtime
//   - parsers are conservative: unparseable output is SKIPPED (inconclusive),
//     never a fabricated pass/fail
//   - a failing check corroborates, a healthy one refutes, using ONLY the
//     closed evidence vocabulary mirrored by verification_producer.py

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- case context: what a run knows about the case it verifies --------------

// CaseContext carries the case attributes module triggers and parsers
// key on. Zero values are honest unknowns — modules that need a field a case
// does not carry simply do not fire (or fall back to wide, documented slack).
type CaseContext struct {
	Owner         string    // corr_current.owner — seam-ownership badge (netops/isp/carrier/…)
	TopHypothesis string    // corr_current.top_hypothesis — winning template id
	VerdictTier   string    // undetermined | suspected | confirmed
	WindowStart   time.Time // incident window start (UTC); zero ⇒ unknown
}

// ---- module registry --------------------------------------------------------

const (
	verifyModuleIfaceDeep    = "iface_deep"    // interface deep-dive (L1/L2)
	verifyModuleBGPEdge      = "bgp_edge"      // BGP/edge seam diagnosis
	verifyModuleRecentChange = "recent_change" // config-change-before-incident detector
)

// verifyModuleSpecs returns the module check specs. Same shape as the core
// battery; Module names the trigger gate that must fire for the check to run.
// Evidence vocabulary is mirrored by verification_producer.py REFUTABLE_KINDS.
func verifyModuleSpecs() []verifyCheckSpec {
	return []verifyCheckSpec{
		{ID: "ssh_iface_deep", Method: "ssh", Module: verifyModuleIfaceDeep,
			Corroborates: []string{"link_state_change", "if_errors", "if_crc"},
			Refutes:      []string{"if_errors", "if_crc"}},
		{ID: "ssh_bgp_edge", Method: "ssh", Module: verifyModuleBGPEdge,
			Corroborates: []string{"bgp_adjacency_change", "bgp_state_anomaly", "routing_adjacency_change"},
			Refutes:      []string{"bgp_adjacency_change", "bgp_state_anomaly"}},
		{ID: "ssh_config_change", Method: "ssh", Module: verifyModuleRecentChange,
			Corroborates: []string{"config_change"},
			Refutes:      []string{"config_change"}},
	}
}

// The module command allowlist is the SAME closed table the core battery reads
// (CommandFor / CommandAllowed in verify_engine.go), served by the vendor-profile
// registry's vendor-level `verify.commands` block. Core and module check ids are
// disjoint, so one table per vendor expresses both without ambiguity, and the
// helpers below simply SCOPE a lookup to the module half.
//
// Command provenance (recorded on the profile documents' authoring history):
// cisco + juniper rows mined from NetClaw skills (see file header); arista,
// huawei, nokia rows authored fresh for EOS / VRP / SR OS.
//
// Semantics per row, kept from the former in-code table:
//   - cisco   ssh_config_change "show running-config"       — only the "Last configuration change" header lines are parsed; full text is discarded
//   - arista  ssh_config_change "show running-config diffs" — any diff ⇒ unsaved (recent) change
//
// moduleCheckIDs is the set of check ids the MODULES own. It is derived from
// verifyModuleSpecs, so a module and its table half can never drift apart.
func moduleCheckIDs() map[string]bool {
	out := make(map[string]bool, 4)
	for _, s := range verifyModuleSpecs() {
		out[s.ID] = true
	}
	return out
}

// ---- trigger gates ----------------------------------------------------------

// ModulesFor decides which modules a case's context earns:
//   - iface_deep:    every case that reached target resolution at all (a run
//     only exists when the case localized at least one device)
//   - bgp_edge:      the case's seam is edge/ISP/middle-mile — by seam owner
//     (isp/carrier) or by the winning hypothesis naming an edge-family domain
//   - recent_change: the case is at the SUSPECTED tier — still hunting a
//     cause, where "a config change landed just before" is a top-tier
//     "possibly because of" signal
func ModulesFor(cc CaseContext) []string {
	mods := []string{verifyModuleIfaceDeep}
	if verifyEdgeSeamCase(cc) {
		mods = append(mods, verifyModuleBGPEdge)
	}
	if strings.EqualFold(strings.TrimSpace(cc.VerdictTier), "suspected") {
		mods = append(mods, verifyModuleRecentChange)
	}
	return mods
}

// verifyEdgeSeamCase reports whether the case sits on an edge/ISP/middle-mile
// seam. Owner is authoritative (the engine's seam-ownership attribution);
// hypothesis-id domain tokens are the fallback for cases owned by netops but
// diagnosed at the edge (e.g. sig.ent.wan-edge.routing-instability).
func verifyEdgeSeamCase(cc CaseContext) bool {
	switch strings.ToLower(strings.TrimSpace(cc.Owner)) {
	case "isp", "carrier":
		return true
	}
	th := strings.ToLower(cc.TopHypothesis)
	for _, tok := range []string{"bgp", "wan-edge", "middle-mile", "peering", "interconnect", "dia"} {
		if strings.Contains(th, tok) {
			return true
		}
	}
	return false
}

// ActiveBattery is the check set one run actually executes: the fixed
// core battery plus the checks of every module the case context fires.
func ActiveBattery(cc CaseContext) []verifyCheckSpec {
	out := verifyBattery()
	fired := map[string]bool{}
	for _, m := range ModulesFor(cc) {
		fired[m] = true
	}
	for _, s := range verifyModuleSpecs() {
		if fired[s.Module] {
			out = append(out, s)
		}
	}
	return out
}

// verifyModuleCommandFor resolves (vendor, MODULE check) → command from the
// registry-served table; same unknown ⇒ skip contract as CommandFor. A core
// check id does not resolve here — the scoping is what keeps the module half of
// the table nameable on its own.
func verifyModuleCommandFor(vendor, checkID string) (string, bool) {
	if !moduleCheckIDs()[checkID] {
		return "", false
	}
	return CommandFor(vendor, checkID)
}

// verifyModuleCommandAllowed reports whether cmd appears VERBATIM as a MODULE
// row of the closed table (defense-in-depth gate, scoped to the module half).
func verifyModuleCommandAllowed(cmd string) bool {
	if cmd == "" {
		return false
	}
	mods := moduleCheckIDs()
	for _, fam := range CommandTable() {
		for check, c := range fam {
			if c == cmd && mods[check] {
				return true
			}
		}
	}
	return false
}

// ---- shared parsing helpers -------------------------------------------------

// verifyRecentWindow is how far back from now a flap / session reset / config
// change still counts as "inside or shortly before the incident window":
// incident age plus one hour of slack; 24h when the window is unknown.
func verifyRecentWindow(now time.Time, cc CaseContext) time.Duration {
	if cc.WindowStart.IsZero() || now.Before(cc.WindowStart) {
		return 24 * time.Hour
	}
	return now.Sub(cc.WindowStart) + time.Hour
}

var (
	reDurHMS = regexp.MustCompile(`^(\d+):(\d{2})(?::(\d{2}))?$`) // 00:02:11 / 2:33
	// unit tokens classify by first letter (w/d/h/m/s covers "2d10h",
	// "00h07m34s" and "33 minutes, 20 seconds" alike)
	reDurUnits = regexp.MustCompile(`(\d+)\s*([wdhms])`)
)

// parseNetDuration parses the relative-age formats network OSes print
// (hh:mm:ss, 2d10h, 1w2d, 00h07m34s, "33 minutes, 20 seconds"). "never" and
// unrecognized text return ok=false — the caller must not guess.
func parseNetDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "ago"))
	if s == "" || strings.EqualFold(s, "never") {
		return 0, false
	}
	if m := reDurHMS.FindStringSubmatch(s); m != nil {
		h, _ := strconv.Atoi(m[1])  // discard: the regex captured digits only
		mi, _ := strconv.Atoi(m[2]) // discard: the regex captured digits only
		sec := 0
		if m[3] != "" {
			sec, _ = strconv.Atoi(m[3]) // best-effort: regex-matched digits; failure means 0
		} // else "2:33" is h:mm on summary tables — already assigned
		return time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute + time.Duration(sec)*time.Second, true
	}
	total := time.Duration(0)
	found := false
	for _, m := range reDurUnits.FindAllStringSubmatch(strings.ToLower(s), -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		found = true
		switch m[2][0] {
		case 'w':
			total += time.Duration(n) * 7 * 24 * time.Hour
		case 'd':
			total += time.Duration(n) * 24 * time.Hour
		case 'h':
			total += time.Duration(n) * time.Hour
		case 'm':
			total += time.Duration(n) * time.Minute
		case 's':
			total += time.Duration(n) * time.Second
		}
	}
	return total, found
}

// parseDeviceTime parses the absolute timestamp formats the five vendor
// families print, interpreted as UTC (device-local zones are compared with the
// slack verifyRecentWindow already carries; abbreviations like "UTC"/"MST"
// parse as offset 0 by the stdlib — documented in docs/design/verify-modules.md).
func parseDeviceTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		"2006-01-02 15:04:05",         // juniper commit / huawei commit list / huawei last-up
		"2006/01/02 15:04:05",         // nokia rollback
		"01/02/2006 15:04:05",         // nokia port "Last State Change"
		"15:04:05 MST Mon Jan 2 2006", // IOS/IOS-XE "Last configuration change at"
		"Mon Jan 2 15:04:05 2006",     // IOS-XR "Last configuration change at"
		"Mon Jan 2 15:04:05.000 2006", // IOS-XR with millis
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// (ClickHouse DateTime64 parsing: parseCHTime is shared from timeintel_api.go.)

// ---- module output parsing --------------------------------------------------

// parseVerifyModuleOutput classifies one module check's output. Device output
// is untrusted input: bounded upstream, sanitized before storage. Conservative
// by contract: unparseable ⇒ skipped.
func parseVerifyModuleOutput(checkID, vendor, output string, now time.Time, cc CaseContext) (status, observed string) {
	txt := strings.TrimSpace(output)
	if txt == "" && !(checkID == "ssh_config_change" && strings.ToLower(vendor) == "arista") {
		return StatusSkipped, "empty command output"
	}
	switch checkID {
	case "ssh_iface_deep":
		return parseIfaceDeep(txt, now, cc)
	case "ssh_bgp_edge":
		return parseBGPEdge(txt, now, cc)
	case "ssh_config_change":
		return parseConfigChange(txt, vendor, now, cc)
	default:
		return StatusSkipped, "no module parser for check " + sanitizeObserved(checkID)
	}
}

// ---- module 1: interface deep-dive ------------------------------------------

var (
	// interface section headers across the vendor families
	reIfHeadCisco = regexp.MustCompile(`^(\S+) is (up|down|administratively down)`)  // IOS/IOS-XE/NX-OS/EOS
	reIfHeadJunos = regexp.MustCompile(`^Physical interface: (\S+?),(.*)$`)          // Junos extensive
	reIfHeadVRP   = regexp.MustCompile(`^(\S+) current state\s*:\s*(\S.*)$`)         // Huawei VRP
	reIfHeadNokia = regexp.MustCompile(`^\s*(?:Interface|Port)\s*:\s*(\S+)\s*(.*)$`) // SR OS show port detail
	// fault indicators (NetClaw pyats-troubleshoot L1 checklist: CRC ⇒ cable/
	// optic/duplex, input errors ⇒ physical corruption, output drops ⇒
	// congestion, resets/transitions ⇒ flapping, half-duplex ⇒ mismatch)
	reCRCBefore   = regexp.MustCompile(`(?i)\b(\d+)\s+CRC\b`)
	reCRCAfter    = regexp.MustCompile(`(?i)\bCRC(?:/Align)?(?:\s+Errors?)?\s*:?\s+(\d+)`)
	reInErrsB     = regexp.MustCompile(`(?i)\b(\d+)\s+input errors?\b`)
	reOutErrsB    = regexp.MustCompile(`(?i)\b(\d+)\s+output errors?\b`)
	reErrsAfter   = regexp.MustCompile(`(?i)\b(?:input|output|total)\s+errors?\s*:?\s+(\d+)`)
	reJunosErrRow = regexp.MustCompile(`(?m)^\s*Errors:\s*(\d+),\s*Drops:\s*(\d+)`)
	reOutDrops    = regexp.MustCompile(`(?i)\b(?:total\s+)?output drops?\s*:?\s+(\d+)`)
	reHalfDuplex  = regexp.MustCompile(`(?i)\bhalf[- ]?duplex\b|\bduplex\s*:?\s*half\b`)
	reIfResets    = regexp.MustCompile(`(?i)\b(\d+)\s+interface resets\b`)
	reCarrierTr   = regexp.MustCompile(`(?i)\bcarrier transitions\s*:?\s+(\d+)`)
	reLinkChanges = regexp.MustCompile(`(?i)\b(\d+)\s+link status changes\b`)
	reLastFlap    = regexp.MustCompile(`(?i)\blast link flapped\s+([0-9][0-9dhmswy: ]*)`)
	reUpFor       = regexp.MustCompile(`(?im)^\s*Up\s+((?:\d+\s+(?:weeks?|days?|hours?|minutes?|seconds?),?\s*)+)$`)
	reLastPhys    = regexp.MustCompile(`(?i)last physical (?:up|down) time\s*:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
	reLastState   = regexp.MustCompile(`(?i)last state change\s*:\s*(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})`)
)

// ifaceHeader recognizes an interface section head; adminDown reports an
// intentionally disabled interface whose stale counters must not fail a case.
func ifaceHeader(line string) (name string, adminDown, ok bool) {
	if m := reIfHeadCisco.FindStringSubmatch(line); m != nil {
		return m[1], m[2] == "administratively down", true
	}
	if m := reIfHeadJunos.FindStringSubmatch(line); m != nil {
		return m[1], strings.Contains(strings.ToLower(m[2]), "administratively down"), true
	}
	if m := reIfHeadVRP.FindStringSubmatch(line); m != nil {
		return m[1], strings.Contains(strings.ToLower(m[2]), "administratively down"), true
	}
	if m := reIfHeadNokia.FindStringSubmatch(line); m != nil {
		return m[1], false, true
	}
	return "", false, false
}

func parseIfaceDeep(txt string, now time.Time, cc CaseContext) (string, string) {
	recent := verifyRecentWindow(now, cc)
	iface, adminDown := "", false
	sawHeader := false
	var faults []string
	addFault := func(reason string) {
		if adminDown {
			return // intended state — not a fault
		}
		name := iface
		if name == "" {
			name = "?"
		}
		if len(faults) < 8 {
			faults = append(faults, name+": "+reason)
		}
	}
	nonzero := func(m []string) (int64, bool) {
		if m == nil {
			return 0, false
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		return n, err == nil && n > 0
	}
	for _, line := range strings.Split(txt, "\n") {
		if name, ad, ok := ifaceHeader(line); ok {
			iface, adminDown, sawHeader = name, ad, true
			continue
		}
		if n, ok := nonzero(reCRCBefore.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d CRC errors (cumulative)", n))
		} else if n, ok := nonzero(reCRCAfter.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d CRC errors (cumulative)", n))
		}
		if n, ok := nonzero(reInErrsB.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d input errors (cumulative)", n))
		} else if n, ok := nonzero(reOutErrsB.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d output errors (cumulative)", n))
		} else if n, ok := nonzero(reErrsAfter.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d errors (cumulative)", n))
		}
		if m := reJunosErrRow.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.ParseInt(m[1], 10, 64); n > 0 { // discard: the regex captured digits only
				addFault(fmt.Sprintf("%d errors (cumulative)", n))
			}
			if n, _ := strconv.ParseInt(m[2], 10, 64); n > 0 { // discard: the regex captured digits only
				addFault(fmt.Sprintf("%d drops (cumulative)", n))
			}
		} else if n, ok := nonzero(reOutDrops.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d output drops (cumulative)", n))
		}
		if reHalfDuplex.MatchString(line) {
			addFault("half-duplex — duplex mismatch indicator")
		}
		if n, ok := nonzero(reIfResets.FindStringSubmatch(line)); ok {
			addFault(fmt.Sprintf("%d interface resets (cumulative)", n))
		}
		if m := reCarrierTr.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.ParseInt(m[1], 10, 64); n > 1 { // discard: digits-only capture; 1 = initial link-up
				addFault(fmt.Sprintf("%d carrier transitions (cumulative)", n))
			}
		}
		if m := reLinkChanges.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.ParseInt(m[1], 10, 64); n > 1 { // discard: the regex captured digits only
				addFault(fmt.Sprintf("%d link status changes (cumulative)", n))
			}
		}
		if m := reLastFlap.FindStringSubmatch(line); m != nil {
			if age, ok := parseNetDuration(m[1]); ok && age <= recent {
				addFault("flapped " + strings.TrimSpace(m[1]) + " ago — inside the incident window")
			}
		}
		if m := reUpFor.FindStringSubmatch(line); m != nil {
			if age, ok := parseNetDuration(m[1]); ok && age <= recent {
				addFault("up only " + strings.TrimSpace(m[1]) + " — link transitioned inside the incident window")
			}
		}
		if m := reLastPhys.FindStringSubmatch(line); m != nil {
			if ts, ok := parseDeviceTime(m[1]); ok && now.Sub(ts) <= recent && now.Sub(ts) >= -30*time.Minute {
				addFault("last physical state change " + m[1] + " — inside the incident window")
			}
		}
		if m := reLastState.FindStringSubmatch(line); m != nil {
			if ts, ok := parseDeviceTime(m[1]); ok && now.Sub(ts) <= recent && now.Sub(ts) >= -30*time.Minute {
				addFault("last state change " + m[1] + " — inside the incident window")
			}
		}
	}
	if len(faults) > 0 {
		return StatusFail, "interface deep-dive faults: " + sanitizeObserved(strings.Join(faults, "; "))
	}
	if !sawHeader {
		return StatusSkipped, "unrecognized interface detail output: " + sanitizeObserved(firstLine(txt))
	}
	return StatusPass, "interface counters clean — no CRC/input/output errors, drops, duplex mismatch or recent flap"
}

// ---- module 2: BGP/edge seam ------------------------------------------------

var (
	// summary-table rows ending in a non-established FSM state (cisco/arista/
	// junos summaries; optional "(Admin)" / "(Admin shut)" suffix)
	reBGPRowDownM = regexp.MustCompile(`(?m)\s(Idle|Active|Connect|OpenSent|OpenConfirm)\s*(\(Admin[^)]*\))?\s*$`)
	// state fields in detail/verbose listings ("BGP current state: Idle",
	// "State : Active"); "Last State" lines are excluded by the line scan
	reBGPStateFld = regexp.MustCompile(`(?i)\b(?:BGP current state|Peer state|State)\s*[:=]\s*(Idle|Active|Connect|OpenSent|OpenConfirm|Established)\b`)
	// cisco/arista/huawei row tail: uptime then pfx-count (established rows)
	reBGPUpPfx = regexp.MustCompile(`(?m)\s(never|\d{1,2}:\d{2}(?::\d{2})?|\d+[wdhms][\dwdhms]*|\d{2}h\d{2}m\d{2}s)\s+(?:Established\s+)?(\d+)\s*$`)
	// huawei summary row: non-established state followed by the PrefRcv column
	reBGPRowDownVRP = regexp.MustCompile(`(?m)\s(Idle|Active|Connect|OpenSent|OpenConfirm)\s*(\(Admin[^)]*\))?\s+\d+\s*$`)
	// junos row tail: uptime then Active/Received/Accepted/Damped
	reBGPJunosPfx = regexp.MustCompile(`(?m)\s(\d{1,2}:\d{2}(?::\d{2})?|\d+[wdhms][\dwdhms]*)\s+(\d+)/(\d+)/\d+/\d+\s*$`)
	// nokia row tail: "00h07m34s 10/8/50 (IPv4)" — uptime then Rcv/Act/Sent
	reBGPNokiaPfx = regexp.MustCompile(`(?m)\s(\d{2}h\d{2}m\d{2}s|\d+d\d{2}h\d{2}m)\s+(\d+)/\d+/\d+\s*\(`)
	reBGPUpFor    = regexp.MustCompile(`(?i)\bup for\s+([0-9][0-9dhms:]*)`)
	reDownPeers   = regexp.MustCompile(`(?i)\bdown peers:\s*([1-9]\d*)`)
	reRcvTotal    = regexp.MustCompile(`(?i)\breceived total routes:\s*(\d+)`)
)

func parseBGPEdge(txt string, now time.Time, cc CaseContext) (string, string) {
	low := strings.ToLower(txt)
	if strings.Contains(low, "not active") || strings.Contains(low, "not running") ||
		strings.Contains(low, "% bgp") {
		return StatusSkipped, "bgp not running on device — nothing to verify"
	}
	recent := verifyRecentWindow(now, cc)
	var reasons []string
	downCount := 0
	established := false
	addReason := func(r string) {
		if len(reasons) < 8 {
			reasons = append(reasons, r)
		}
	}

	for _, line := range strings.Split(txt, "\n") {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "last state") || strings.Contains(ll, "state/pfxrcd") ||
			strings.Contains(ll, "state|#") || strings.Contains(ll, "prefrcv") {
			continue // history fields and table headers, not live state
		}
		if reBGPRowDownM.MatchString(line) || reBGPRowDownVRP.MatchString(line) {
			downCount++
			continue
		}
		if m := reBGPStateFld.FindStringSubmatch(line); m != nil {
			if m[1] != "Established" {
				downCount++
				continue
			}
			established = true // fall through: same line may carry "Up for …"
		}
		if strings.Contains(line, "Estab") {
			established = true
		}
		// established rows: recent reset (uptime below incident age) and
		// prefix-count collapse (session up, zero prefixes)
		checkUpPfx := func(up, pfx string) {
			established = true
			if age, ok := parseNetDuration(up); ok && age <= recent {
				addReason("session up only " + up + " — reset inside the incident window")
			}
			if n, err := strconv.Atoi(pfx); err == nil && n == 0 {
				addReason("session established but 0 prefixes received — prefix-count collapse")
			}
		}
		if m := reBGPJunosPfx.FindStringSubmatch(line); m != nil {
			checkUpPfx(m[1], m[3]) // junos: Received column
		} else if m := reBGPNokiaPfx.FindStringSubmatch(line); m != nil {
			checkUpPfx(m[1], m[2]) // nokia: Rcv column
		} else if m := reBGPUpPfx.FindStringSubmatch(line); m != nil && m[1] != "never" {
			checkUpPfx(m[1], m[2])
		}
		if m := reBGPUpFor.FindStringSubmatch(line); m != nil {
			if age, ok := parseNetDuration(m[1]); ok && age <= recent {
				addReason("session up only " + m[1] + " — reset inside the incident window")
			}
		}
		if m := reRcvTotal.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.Atoi(m[1]); n == 0 { // discard: the regex captured digits only
				addReason("received total routes 0 — prefix-count collapse")
			}
		}
	}
	if m := reDownPeers.FindStringSubmatch(txt); m != nil {
		addReason(m[1] + " down peer(s) reported by the device")
	}
	if downCount > 0 {
		addReason(fmt.Sprintf("%d bgp neighbor(s) not established", downCount))
	}
	if len(reasons) > 0 {
		return StatusFail, "bgp edge faults: " + sanitizeObserved(strings.Join(reasons, "; "))
	}
	if established {
		return StatusPass, "all bgp neighbors established — no recent reset, no prefix collapse"
	}
	return StatusSkipped, "unrecognized bgp output: " + sanitizeObserved(firstLine(txt))
}

// ---- module 3: recent-change detector ---------------------------------------

var (
	reLastCfgChange = regexp.MustCompile(`(?im)last configuration change at\s+([^\r\n]+)$`)
	reNVRAMUpdated  = regexp.MustCompile(`(?im)config(?:uration)? last updated at\s+([^\r\n]+)$`)
	reISOStamp      = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	reSlashStamp    = regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`)
	reDiffMarker    = regexp.MustCompile(`(?m)^[+-]|^@@`)
)

// stripBySuffix drops trailing " by <user>[ via <method>]" from cisco/juniper
// change lines so the remainder is a bare timestamp.
func stripBySuffix(s string) string {
	if i := strings.Index(strings.ToLower(s), " by "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func parseConfigChange(txt, vendor string, now time.Time, cc CaseContext) (string, string) {
	// Arista EOS reads change evidence as a running↔startup diff: any diff
	// hunk means an UNSAVED change is present right now; empty output means
	// the configs match (EOS prints nothing when there is no difference).
	if strings.ToLower(strings.TrimSpace(vendor)) == "arista" {
		if strings.TrimSpace(txt) == "" {
			return StatusPass, "running-config matches startup-config — no unsaved configuration change"
		}
		if reDiffMarker.MatchString(txt) {
			return StatusFail, "running-config differs from startup-config — unsaved configuration change present"
		}
		return StatusSkipped, "unrecognized config-diff output: " + sanitizeObserved(firstLine(txt))
	}

	var newest time.Time
	var newestRaw string
	consider := func(raw string) {
		if ts, ok := parseDeviceTime(strings.TrimSpace(raw)); ok && ts.After(newest) {
			newest, newestRaw = ts, strings.TrimSpace(raw)
		}
	}
	for _, m := range reLastCfgChange.FindAllStringSubmatch(txt, -1) {
		consider(stripBySuffix(m[1]))
	}
	for _, m := range reNVRAMUpdated.FindAllStringSubmatch(txt, -1) {
		consider(stripBySuffix(m[1]))
	}
	for _, raw := range reISOStamp.FindAllString(txt, -1) {
		consider(raw)
	}
	for _, raw := range reSlashStamp.FindAllString(txt, -1) {
		consider(raw)
	}
	if newest.IsZero() {
		return StatusSkipped, "no configuration-change timestamp recognized: " + sanitizeObserved(firstLine(txt))
	}
	// "Inside or shortly before the incident window": window start minus 1h of
	// slack (24h lookback when the window is unknown). Device clocks are
	// compared as UTC — verifyRecentWindow's slack absorbs small zone drift.
	boundary := now.Add(-verifyRecentWindow(now, cc))
	if newest.After(boundary) {
		return StatusFail, "configuration change at " + sanitizeObserved(newestRaw) +
			" — inside or shortly before the incident window (possible cause)"
	}
	return StatusPass, "last configuration change at " + sanitizeObserved(newestRaw) +
		" — predates the incident window"
}

// ---- deterministic ordering helper ------------------------------------------

// verifyModuleNames returns the registered module names, sorted (docs/tests).
func verifyModuleNames() []string {
	seen := map[string]bool{}
	for _, s := range verifyModuleSpecs() {
		seen[s.Module] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
