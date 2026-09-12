// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Evidence is the specific captured line a signature grounds its verdict on — the
// command it came from and the line itself. A verdict without evidence is not
// allowed: every fired signature cites the exact text that tripped it.
type Evidence struct {
	Command string
	SpecID  string
	Line    string
}

// Finding is one fired signature's verdict: the plain-language conclusion, the
// likely cause, the remediation, a confidence, and the evidence line. It is the
// analyze half of the "collect → analyze" contract.
type Finding struct {
	SignatureID string
	Verdict     string
	Cause       string
	Remediation string
	Confidence  Confidence
	Evidence    Evidence
}

// AnalyzeResult is the outcome of running the signatures for a Collection's
// issue. Findings is deterministically ordered (confidence desc, then signature
// id). When it is EMPTY, Unmatched carries the honest fail-closed message and the
// caller shows the raw captured output for TAC — a verdict is NEVER invented.
type AnalyzeResult struct {
	Protocol       Protocol
	IssueID        string
	IssueTitle     string
	RulesetVersion string
	Findings       []Finding
	Unmatched      string
}

// Matched reports whether any signature fired.
func (r AnalyzeResult) Matched() bool { return len(r.Findings) > 0 }

// Signature is one hand-authored failure signature for a specific issue: a
// matcher over the collected output that, when it fires, yields a verdict + cause
// + remediation + confidence. The matcher captures its compiled regexps at
// build time (no package-level mutable state, §5), reads the Collection
// read-only, and never panics on any output.
type Signature struct {
	ID          string
	IssueID     string
	Verdict     string
	Cause       string
	Remediation string
	Confidence  Confidence
	match       func(col *Collection) (Evidence, bool)
}

// Analyzer holds the signature catalog grouped by issue. It is immutable once
// built and holds no mutable state, so Analyze is safe under -race and fully
// deterministic.
type Analyzer struct {
	byIssue map[string][]Signature
	all     []Signature
}

// NewAnalyzer groups a signature set by issue id (preserving authored order
// within an issue) and returns an immutable Analyzer.
func NewAnalyzer(sigs []Signature) *Analyzer {
	by := make(map[string][]Signature)
	cp := make([]Signature, len(sigs))
	copy(cp, sigs)
	for _, s := range cp {
		by[s.IssueID] = append(by[s.IssueID], s)
	}
	return &Analyzer{byIssue: by, all: cp}
}

// Signatures returns every signature in authored order (for self-consistency
// tests and catalog listing).
func (a *Analyzer) Signatures() []Signature {
	out := make([]Signature, len(a.all))
	copy(out, a.all)
	return out
}

// Analyze runs the signatures for col's issue over the collected output and
// returns the fired findings in a deterministic order. If none fire it returns an
// empty Findings and the honest Unmatched message (fail-closed — no invented
// cause). A command that errored during Collect is treated as absent output, so a
// capture with no usable output can never produce a verdict.
func (a *Analyzer) Analyze(col *Collection) AnalyzeResult {
	res := AnalyzeResult{
		Protocol:       col.Protocol,
		IssueID:        col.IssueID,
		IssueTitle:     col.IssueTitle,
		RulesetVersion: RulesetVersion,
	}
	for _, s := range a.byIssue[col.IssueID] {
		if ev, ok := s.match(col); ok {
			res.Findings = append(res.Findings, Finding{
				SignatureID: s.ID,
				Verdict:     s.Verdict,
				Cause:       s.Cause,
				Remediation: s.Remediation,
				Confidence:  s.Confidence,
				Evidence:    ev,
			})
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		fi, fj := res.Findings[i], res.Findings[j]
		if confidenceRank(fi.Confidence) != confidenceRank(fj.Confidence) {
			return confidenceRank(fi.Confidence) > confidenceRank(fj.Confidence)
		}
		return fi.SignatureID < fj.SignatureID
	})
	if len(res.Findings) == 0 {
		res.Unmatched = "no known signature matched — the raw captured output is attached for TAC"
	}
	return res
}

// ── Collection read helpers (used by signature matchers) ─────────────────────

// command returns the first captured command with the given spec id that ran
// WITHOUT error, and whether one exists. A command that errored is treated as
// absent — this is the fail-closed property: no usable output ⇒ no match.
func (c *Collection) command(specID string) (CollectedCommand, bool) {
	for _, cc := range c.Commands {
		if cc.SpecID == specID && cc.ok() {
			return cc, true
		}
	}
	return CollectedCommand{}, false
}

// firstMatch returns the first output line of cc matching re (trimmed), and ok.
func firstMatch(cc CollectedCommand, re *regexp.Regexp) (string, bool) {
	for _, ln := range strings.Split(cc.Output, "\n") {
		if re.MatchString(ln) {
			return strings.TrimSpace(ln), true
		}
	}
	return "", false
}

// countMatch counts output lines of cc matching re.
func countMatch(cc CollectedCommand, re *regexp.Regexp) int {
	n := 0
	for _, ln := range strings.Split(cc.Output, "\n") {
		if re.MatchString(ln) {
			n++
		}
	}
	return n
}

// evidenceOf builds an Evidence for a captured command + line.
func evidenceOf(cc CollectedCommand, line string) Evidence {
	return Evidence{Command: cc.Command, SpecID: cc.SpecID, Line: line}
}

// lineIn is the common single-command matcher: fire when specID's output has a
// line matching re, citing that line.
func lineIn(col *Collection, specID string, re *regexp.Regexp) (Evidence, bool) {
	cc, ok := col.command(specID)
	if !ok {
		return Evidence{}, false
	}
	if ln, ok := firstMatch(cc, re); ok {
		return evidenceOf(cc, ln), true
	}
	return Evidence{}, false
}

// DefaultAnalyzer builds the hand-authored signature catalog for all 15 issues.
// Every regexp is compiled ONCE here and captured in a matcher closure (not a
// package-level global, §5). Signatures are honest: a single unambiguous tell is
// Medium, a corroborated multi-condition match is High, a weak heuristic is Low;
// output that matches nothing yields no finding (fail-closed).
func DefaultAnalyzer() *Analyzer {
	// Shared compiled matchers.
	reExstart := regexp.MustCompile(`(?i)\b(EXSTART|EXCHANGE)\b`)
	reMTU := regexp.MustCompile(`(?i)\bMTU\b`)
	reInit := regexp.MustCompile(`(?i)\bINIT\b`)
	reOspfMismatch := regexp.MustCompile(`(?i)(mismatch|%OSPF-4-)`)
	reStubArea := regexp.MustCompile(`(?i)(it is a stub area|it is a nssa area|nssa)`)
	reMaxMetric := regexp.MustCompile(`(?i)originating router-lsas with maximum metric`)
	reAdjchg := regexp.MustCompile(`(?i)%?OSPF-5-ADJCHG`)
	reIfErrors := regexp.MustCompile(`(?i)([1-9]\d*)\s+(input errors|crc|runts)`)
	reRefBW := regexp.MustCompile(`(?i)reference bandwidth unit is 100 mbps`)

	reBgpIdle := regexp.MustCompile(`(?i)\bidle\b`)
	reBgpActiveConnect := regexp.MustCompile(`(?i)\b(active|connect)\b`)
	reBgpAdminShut := regexp.MustCompile(`(?i)(administratively shut|idle \(admin\)|state = idle.*admin)`)
	reRouteReachable := regexp.MustCompile(`(?i)( via |directly connected)`)
	reAdvertisedZero := regexp.MustCompile(`(?i)total number of prefixes 0\b`)
	reInaccessible := regexp.MustCompile(`(?i)\(inaccessible\)`)
	reDroppedCount := regexp.MustCompile(`(?i)dropped\s+(\d+)`)
	reDampened := regexp.MustCompile(`(?i)(dampened|suppressed)`)
	reNoExport := regexp.MustCompile(`(?i)\bno-(export|advertise)\b`)

	reIsisNotUp := regexp.MustCompile(`(?i)\b(down|init)\b`)
	reIsisUp := regexp.MustCompile(`(?i)\bup\b`)
	reIsisInit := regexp.MustCompile(`(?i)\binit\b`)
	reOverload := regexp.MustCompile(`(?i)overload`)
	reIsisAdjchg := regexp.MustCompile(`(?i)(ISIS-5-ADJCHANGE|CLNS-5-ADJCHANGE|adjacency.*(up|down))`)
	reNarrowMetric := regexp.MustCompile(`(?i)metric.?style\s*:?\s*narrow|narrow metric`)

	sigs := []Signature{
		// ── OSPF ────────────────────────────────────────────────────────────
		{
			ID: "ospf-exstart-mtu", IssueID: "ospf-neighbor-stuck",
			Verdict: "OSPF neighbor stuck in EXSTART/EXCHANGE with an MTU on the interface",
			Cause:   "IP MTU mismatch across the link — the DBD exchange cannot complete when the two ends disagree on MTU",
			Remediation: "Set a matching `ip mtu` on both ends of the link (compare the captured interface MTU with the far end). " +
				"`ip ospf mtu-ignore` only masks it — fix the MTU.",
			Confidence: ConfidenceHigh,
			match: func(col *Collection) (Evidence, bool) {
				// Multi-condition: EXSTART/EXCHANGE in the neighbor table AND an MTU
				// line captured from the interface → cite the MTU line.
				nb, ok := col.command("ospf-neighbor")
				if !ok {
					return Evidence{}, false
				}
				if _, ok := firstMatch(nb, reExstart); !ok {
					return Evidence{}, false
				}
				return lineIn(col, "ospf-interface", reMTU)
			},
		},
		{
			ID: "ospf-exstart-only", IssueID: "ospf-neighbor-stuck",
			Verdict:     "OSPF neighbor stuck in EXSTART/EXCHANGE",
			Cause:       "almost certainly an IP MTU mismatch across the link (EXSTART is the classic MTU tell); interface MTU was not captured to confirm",
			Remediation: "Capture `show ip ospf interface` on BOTH ends and compare `ip mtu`; set them equal.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				// Fire only when the interface MTU corroboration is ABSENT, so exactly
				// one of the two EXSTART signatures reports.
				if _, ok := col.command("ospf-interface"); ok {
					if ev, ok := lineIn(col, "ospf-interface", reMTU); ok {
						_ = ev
						return Evidence{}, false
					}
				}
				return lineIn(col, "ospf-neighbor", reExstart)
			},
		},
		{
			ID: "ospf-init-oneway", IssueID: "ospf-neighbor-stuck",
			Verdict:     "OSPF neighbor stuck in INIT",
			Cause:       "hellos are being heard in only one direction — a unidirectional link, an inbound ACL, or an authentication mismatch",
			Remediation: "Check for a one-way link, an ACL dropping OSPF (IP proto 89) inbound, and matching authentication on both ends.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "ospf-neighbor", reInit)
			},
		},
		{
			ID: "ospf-param-mismatch", IssueID: "ospf-adjacency-nonform",
			Verdict:     "OSPF parameter mismatch on the link",
			Cause:       "a parameter that must match across the link disagrees (hello/dead timer, area id, authentication, or network-type)",
			Remediation: "Align the mismatched parameter shown in the log; hello/dead timers, area id, auth, and network-type must match on both ends.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "ospf-logging", reOspfMismatch)
			},
		},
		{
			ID: "ospf-stub-area", IssueID: "ospf-routes-missing",
			Verdict:     "the OSPF area is a stub / NSSA",
			Cause:       "a stub or NSSA area filters the external (type-5) LSAs — the routes you expect are being suppressed by area type",
			Remediation: "Expect only a default route from the ABR in a stub area. If externals are required, use NSSA with translation or a normal area.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "ospf-summary", reStubArea)
			},
		},
		{
			ID: "ospf-max-metric", IssueID: "ospf-routes-missing",
			Verdict:     "OSPF is originating router-LSAs with maximum metric (stub-router)",
			Cause:       "the router advertises max metric, so it is avoided for transit and its transit routes are not chosen",
			Remediation: "Clear the max-metric / stub-router condition (`no max-metric router-lsa`) unless it is intentional during maintenance.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "ospf-summary", reMaxMetric)
			},
		},
		{
			ID: "ospf-flap-l1", IssueID: "ospf-flapping",
			Verdict:     "OSPF adjacency flapping, driven by L1 errors on the interface",
			Cause:       "repeated adjacency changes coincide with input/CRC errors on the interface — the physical link is unstable",
			Remediation: "Fix the L1 problem first (clean fiber/optics/cabling, check the SFP); do not tune OSPF timers over a dirty link.",
			Confidence:  ConfidenceHigh,
			match: func(col *Collection) (Evidence, bool) {
				lg, ok := col.command("ospf-logging")
				if !ok || countMatch(lg, reAdjchg) < 3 {
					return Evidence{}, false
				}
				return lineIn(col, "iface", reIfErrors)
			},
		},
		{
			ID: "ospf-flap", IssueID: "ospf-flapping",
			Verdict:     "OSPF adjacency flapping (3 or more changes)",
			Cause:       "the adjacency is repeatedly dropping and re-forming; no L1 error was captured to pin the layer",
			Remediation: "Correlate with interface flaps/errors and neighbor timers; capture `show interface` and `show logging` over a longer window.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				lg, ok := col.command("ospf-logging")
				if !ok || countMatch(lg, reAdjchg) < 3 {
					return Evidence{}, false
				}
				// Defer to ospf-flap-l1 when L1 errors are present.
				if _, ok := lineIn(col, "iface", reIfErrors); ok {
					return Evidence{}, false
				}
				if ln, ok := firstMatch(lg, reAdjchg); ok {
					return evidenceOf(lg, ln), true
				}
				return Evidence{}, false
			},
		},
		{
			ID: "ospf-refbw-default", IssueID: "ospf-suboptimal",
			Verdict:     "OSPF auto-cost reference-bandwidth is left at the default (100 Mbps)",
			Cause:       "at the default reference bandwidth every link at or above 100 Mbps shares cost 1, so SPF cannot distinguish 1G from 100G",
			Remediation: "Raise `auto-cost reference-bandwidth` (e.g. 100000 for 100G) consistently on EVERY router in the area.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "ospf-summary", reRefBW)
			},
		},

		// ── BGP ─────────────────────────────────────────────────────────────
		{
			ID: "bgp-idle-unreachable", IssueID: "bgp-session-down",
			Verdict:     "BGP peer is Idle and the peering address is unreachable",
			Cause:       "there is no route to the peer, so BGP cannot even open TCP/179 — this is an underlay/reachability problem, not a BGP one",
			Remediation: "Restore reachability to the peer address (IGP/static route, and any ACL blocking it). BGP will not leave Idle until the peer is routable.",
			Confidence:  ConfidenceHigh,
			match: func(col *Collection) (Evidence, bool) {
				// Multi-condition: the session is Idle AND the peer route lookup
				// shows no reachable route.
				//
				// TYPED FIRST (typedbridge.go): when the capture parses for this
				// device's dialect the state is read from BGPPeer.State, so the
				// word "Idle" appearing anywhere ELSE in the output — a
				// description, a log echo, another column — can no longer fire
				// this verdict. The regex below is the fallback for a platform
				// whose summary layout has no parser.
				ev, fired, typed := typedBGPStateEvidence(col, "bgp-summary",
					bgpStateIs("Idle", "Idle (Admin)"))
				if !typed {
					sm, ok := col.command("bgp-summary")
					if !ok {
						return Evidence{}, false
					}
					idleLine, ok := firstMatch(sm, reBgpIdle)
					if !ok {
						return Evidence{}, false
					}
					ev, fired = evidenceOf(sm, idleLine), true
				}
				if !fired {
					return Evidence{}, false
				}
				pr, ok := col.command("bgp-peer-route")
				if !ok {
					return Evidence{}, false
				}
				if _, reachable := firstMatch(pr, reRouteReachable); reachable {
					return Evidence{}, false
				}
				return ev, true
			},
		},
		{
			ID: "bgp-tcp-blocked", IssueID: "bgp-session-down",
			Verdict:     "BGP peer is reachable but the session stays in Active/Connect",
			Cause:       "there IS a route to the peer, yet TCP/179 never establishes — a firewall/ACL is blocking TCP 179, or the peer is not configured/listening",
			Remediation: "Permit TCP/179 both directions between the peers, and confirm the neighbor is configured on the far end.",
			Confidence:  ConfidenceHigh,
			match: func(col *Collection) (Evidence, bool) {
				// Typed first, regex fallback — see bgp-idle-unreachable. The
				// gain here is larger: "active" is an ordinary English word that
				// appears in plenty of BGP output ("Active Route", "active
				// paths"), and reading the FSM state from the parsed row removes
				// every one of those false tells.
				ev, fired, typed := typedBGPStateEvidence(col, "bgp-summary",
					bgpStateIs("Active", "Connect"))
				if !typed {
					sm, ok := col.command("bgp-summary")
					if !ok {
						return Evidence{}, false
					}
					stLine, ok := firstMatch(sm, reBgpActiveConnect)
					if !ok {
						return Evidence{}, false
					}
					ev, fired = evidenceOf(sm, stLine), true
				}
				if !fired {
					return Evidence{}, false
				}
				pr, ok := col.command("bgp-peer-route")
				if !ok {
					return Evidence{}, false
				}
				if _, reachable := firstMatch(pr, reRouteReachable); !reachable {
					return Evidence{}, false
				}
				return ev, true
			},
		},
		{
			ID: "bgp-admin-shut", IssueID: "bgp-session-down",
			Verdict:     "BGP neighbor is administratively shut down",
			Cause:       "the session is Idle because the neighbor is configured `shutdown`",
			Remediation: "Remove the shutdown on the neighbor (`no neighbor <peer> shutdown`) if the session should be up.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				if ev, ok := lineIn(col, "bgp-neighbor", reBgpAdminShut); ok {
					return ev, true
				}
				return lineIn(col, "bgp-summary", reBgpAdminShut)
			},
		},
		{
			ID: "bgp-nothing-advertised", IssueID: "bgp-prefix-not-exchanged",
			Verdict:     "BGP is advertising zero prefixes to the peer",
			Cause:       "nothing is being sent to this neighbor — an outbound route-map/prefix-list is filtering everything, or the prefix is never originated (missing `network`/redistribute)",
			Remediation: "Check the outbound policy on the neighbor and confirm the prefix is originated (a matching `network` statement or redistribution).",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "bgp-advertised", reAdvertisedZero)
			},
		},
		{
			ID: "bgp-nexthop-inaccessible", IssueID: "bgp-route-not-best",
			Verdict:     "BGP best-path fails: the next-hop is inaccessible",
			Cause:       "the path's BGP next-hop cannot be resolved in the routing table, so the path is invalid and not selected/installed",
			Remediation: "Resolve the next-hop in the IGP, or set `next-hop-self` on the iBGP session advertising the prefix.",
			Confidence:  ConfidenceHigh,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "bgp-prefix", reInaccessible)
			},
		},
		{
			ID: "bgp-session-flapped", IssueID: "bgp-flapping",
			Verdict:     "BGP session has dropped repeatedly",
			Cause:       "the neighbor shows three or more dropped connections — the session is flapping",
			Remediation: "Investigate the last reset reason on the neighbor and the underlying link; sustained flaps may trigger dampening downstream.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				nb, ok := col.command("bgp-neighbor")
				if !ok {
					return Evidence{}, false
				}
				for _, ln := range strings.Split(nb.Output, "\n") {
					m := reDroppedCount.FindStringSubmatch(ln)
					if m == nil {
						continue
					}
					if n, err := strconv.Atoi(m[1]); err == nil && n >= 3 {
						return evidenceOf(nb, strings.TrimSpace(ln)), true
					}
				}
				return Evidence{}, false
			},
		},
		{
			ID: "bgp-dampened", IssueID: "bgp-flapping",
			Verdict:     "route dampening is suppressing the prefix",
			Cause:       "the prefix has flapped enough to be dampened/suppressed, so it is withheld even though it may now be stable",
			Remediation: "Clear the dampening for the prefix once the flapping source is fixed (`clear ip bgp dampening <prefix>`) and review the dampening policy.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "bgp-dampening", reDampened)
			},
		},
		{
			ID: "bgp-community-no-export", IssueID: "bgp-wrong-path",
			Verdict:     "a well-known community (no-export / no-advertise) is on the prefix",
			Cause:       "the prefix carries no-export or no-advertise, which prevents it from propagating as expected",
			Remediation: "If propagation is intended, strip the community with an outbound route-map before advertising the prefix onward.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "bgp-prefix", reNoExport)
			},
		},

		// ── IS-IS ───────────────────────────────────────────────────────────
		{
			ID: "isis-adjacency-not-up", IssueID: "isis-adjacency-down",
			Verdict:     "IS-IS adjacency is not Up",
			Cause:       "a neighbor is listed but not Up — a level (L1/L2), area (NET), MTU, or authentication mismatch is preventing the adjacency",
			Remediation: "Verify the level, the area/NET, the interface MTU, and authentication match on both ends of the link.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				nb, ok := col.command("isis-neighbors")
				if !ok {
					return Evidence{}, false
				}
				// A neighbor line in a non-Up state, and no Up neighbor present.
				downLine, ok := firstMatch(nb, reIsisNotUp)
				if !ok {
					return Evidence{}, false
				}
				if _, up := firstMatch(nb, reIsisUp); up {
					return Evidence{}, false
				}
				return evidenceOf(nb, downLine), true
			},
		},
		{
			ID: "isis-init-stuck", IssueID: "isis-adjacency-init",
			Verdict: "IS-IS adjacency stuck in INIT",
			Cause: "one-way hellos — the analogue of OSPF EXSTART; typically an MTU / hello-padding problem or a " +
				"point-to-point-vs-broadcast network-type mismatch across the link",
			Remediation: "Compare interface MTU and hello-padding on both ends, and confirm the network-type (p2p vs broadcast) matches.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "clns-neighbors-detail", reIsisInit)
			},
		},
		{
			ID: "isis-overload-routes", IssueID: "isis-routes-missing",
			Verdict:     "the IS-IS overload bit is set",
			Cause:       "this IS advertises the overload (max-metric) bit, asking the network not to use it for transit, so its transit routes are avoided",
			Remediation: "Clear the overload condition (`no set-overload-bit`) if it is not an intentional maintenance state; check L1↔L2 leaking for inter-level routes.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "isis-database", reOverload)
			},
		},
		{
			ID: "isis-adjacency-flap", IssueID: "isis-flapping",
			Verdict:     "IS-IS adjacency flapping (3 or more changes)",
			Cause:       "the adjacency is repeatedly dropping and re-forming — an unstable link or timer instability underneath",
			Remediation: "Check the interface for errors/flaps and review IS-IS hello/hold timers; stabilize L1 before tuning timers.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				lg, ok := col.command("isis-logging")
				if !ok || countMatch(lg, reIsisAdjchg) < 3 {
					return Evidence{}, false
				}
				if ln, ok := firstMatch(lg, reIsisAdjchg); ok {
					return evidenceOf(lg, ln), true
				}
				return Evidence{}, false
			},
		},
		{
			ID: "isis-overload-suboptimal", IssueID: "isis-overload-suboptimal",
			Verdict:     "the IS-IS overload bit is set (transit avoided)",
			Cause:       "the overload bit forces maximum metric, so SPF routes around this IS for transit — a common cause of suboptimal paths",
			Remediation: "Clear the overload bit unless it is intentional; if paths are still poor, review the metric-style.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "isis-database-detail", reOverload)
			},
		},
		{
			ID: "isis-narrow-metric", IssueID: "isis-overload-suboptimal",
			Verdict:     "IS-IS is using the narrow metric-style",
			Cause:       "narrow metrics cap a link metric at 63 and the total path at 1023, and block wide-metric features — SPF cannot express real link costs, so paths are distorted",
			Remediation: "Migrate to wide metrics (`metric-style wide`) network-wide during a maintenance window.",
			Confidence:  ConfidenceMedium,
			match: func(col *Collection) (Evidence, bool) {
				return lineIn(col, "isis-summary", reNarrowMetric)
			},
		},
	}

	return NewAnalyzer(sigs)
}
