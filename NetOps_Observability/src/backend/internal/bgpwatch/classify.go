// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// classify.go — tracker row #5: the incident class per watched prefix.
//
// ONE implementation, TWO consumers: the Prefixes tab renders what Classify
// returns, and the evaluator (evaluate.go) alerts on transitions in exactly the
// same verdict. There is no second classifier and no "alerting version" of the
// rules — a divergence between what the page shows and what pages someone at
// 03:00 is the failure this file exists to prevent.
//
// ── The false-positive guards (why a class is NOT asserted) ─────────────────
//
// Route collectors disagree with each other all the time: a peer holds a stale
// path for minutes after a change, one collector's session is down, a path is
// an AS_SET. So every PATH-DERIVED class here requires CORROBORATION from at
// least MinVantages DISTINCT collector peers, and the supporting vantage points
// are named in the evidence. A single collector seeing something odd is
// recorded as a corroboration shortfall, not as an incident.
//
// The two classes that do NOT need corroboration are the two that are not
// path-derived: an RPKI verdict is one validator's answer about one
// (prefix, origin) pair, and a bogon match is arithmetic on the prefix itself.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// IncidentClass is the closed vocabulary the API promises.
type IncidentClass string

const (
	// ClassNone — measured, and nothing is wrong.
	ClassNone IncidentClass = "none"
	// ClassUnknown — NOT measured. Distinct from ClassNone on purpose: an
	// unreachable upstream must never render as a clean prefix (§10).
	ClassUnknown IncidentClass = "unknown"

	ClassVisibilityLoss IncidentClass = "visibility_loss"
	ClassOriginChange   IncidentClass = "origin_change"
	ClassRPKIInvalid    IncidentClass = "rpki_invalid"
	ClassRouteLeak      IncidentClass = "route_leak"
	ClassBogon          IncidentClass = "bogon"
)

// classRank orders the classes worst-first. The prefix's headline class is the
// worst one that fired; every other one that fired rides in Incident.Also, so
// nothing measured is thrown away.
var classRank = map[IncidentClass]int{
	ClassOriginChange:   0,
	ClassRPKIInvalid:    1,
	ClassBogon:          2,
	ClassRouteLeak:      3,
	ClassVisibilityLoss: 4,
	ClassUnknown:        5,
	ClassNone:           6,
}

// Severity tokens. They are the wire severities the notifier and the evidence
// event both carry; the engine's EVIDENCE_SEVERITY_ALIASES already maps them.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevWarning  = "warning"
	SevInfo     = "info"
)

// classSeverity is the shipped severity per class.
var classSeverity = map[IncidentClass]string{
	ClassOriginChange:   SevCritical,
	ClassRPKIInvalid:    SevHigh,
	ClassBogon:          SevHigh,
	ClassRouteLeak:      SevHigh,
	ClassVisibilityLoss: SevWarning,
	ClassUnknown:        SevInfo,
	ClassNone:           SevInfo,
}

// SeverityOf returns the shipped severity for a class ("info" for an unknown
// token — never an invented escalation).
func SeverityOf(c IncidentClass) string {
	if s, ok := classSeverity[c]; ok {
		return s
	}
	return SevInfo
}

// VantagePath is one collector peer's observed AS path for the prefix. Peer is
// the collector-side identity (RIPEstat's source_id, or a BMP peer address) —
// it is what makes "two vantage points agree" a countable thing.
type VantagePath struct {
	Peer string   `json:"peer"`
	Path []uint32 `json:"path"`
}

// Origin returns the path's origin ASN, or 0 when the path is empty.
func (v VantagePath) Origin() uint32 {
	if len(v.Path) == 0 {
		return 0
	}
	return v.Path[len(v.Path)-1]
}

// Observation is everything MEASURED about one prefix in one evaluation. It is
// pure data: the classifier does no IO and reads no clock.
type Observation struct {
	Prefix string `json:"prefix"`
	// Measured is false when the routing lookup itself failed. A false here can
	// only ever produce ClassUnknown — never ClassNone.
	Measured bool   `json:"measured"`
	Error    string `json:"error,omitempty"`

	// Announced / AnnouncedKnown: whether any collector currently sees it.
	Announced      bool `json:"announced"`
	AnnouncedKnown bool `json:"announced_known"`

	// Visibility across RIS full-feed peers.
	PeersSeeing int `json:"peers_seeing"`
	PeersTotal  int `json:"peers_total"`

	// Paths as observed, one per collector peer.
	Paths []VantagePath `json:"paths,omitempty"`

	// RPKI verdict for the announcement actually in the table.
	RPKIState  string `json:"rpki_state,omitempty"` // valid|invalid|unknown|unavailable
	RPKIOrigin string `json:"rpki_origin,omitempty"`
	RPKIReason string `json:"rpki_reason,omitempty"`

	FetchedAt time.Time `json:"fetched_at"`
}

// PolicyConfig is the tenant's DECLARED intent for a prefix — what it expects
// to be true. Everything in it is operator input and is validated/bounded at
// the API boundary before it ever reaches here.
type PolicyConfig struct {
	// ExpectedOrigins are the ASNs allowed to originate the prefix. EMPTY means
	// "not declared": origin-change detection then LEARNS the origin from the
	// first successful observation (see Incident.LearnedOrigin) and says so,
	// rather than either alerting on everything or on nothing.
	ExpectedOrigins []uint32 `json:"expected_origins,omitempty"`
	// Upstreams are the ASNs the tenant buys transit from. EMPTY disables the
	// route-leak heuristic entirely — with no declared transit set there is
	// nothing to call "unexpected", and guessing one would be fabrication.
	Upstreams []uint32 `json:"upstreams,omitempty"`
	// MinVisibility is the RIS-peer fraction below which visibility is lost.
	MinVisibility float64 `json:"min_visibility,omitempty"`
	// MinVantages is the corroboration floor for path-derived classes.
	MinVantages int `json:"min_vantages,omitempty"`
}

// Policy defaults. They are conservative on purpose: the shipped behaviour must
// not page anyone over one flaky collector.
const (
	DefaultMinVisibility = 0.50
	DefaultMinVantages   = 2
	// MaxDeclaredASNs bounds one prefix's declared origin/upstream sets.
	MaxDeclaredASNs = 32
	// MaxEvidencePaths bounds the paths copied into an incident's evidence.
	MaxEvidencePaths = 8
	// MaxEvidenceVantages bounds the named vantage points.
	MaxEvidenceVantages = 12
)

// withDefaults returns the config with unset thresholds filled in.
func (c PolicyConfig) withDefaults() PolicyConfig {
	if c.MinVisibility <= 0 || c.MinVisibility > 1 {
		c.MinVisibility = DefaultMinVisibility
	}
	if c.MinVantages < 1 {
		c.MinVantages = DefaultMinVantages
	}
	return c
}

// Evidence is WHY a class was asserted, in the operator's terms.
type Evidence struct {
	// Vantages are the collector peers that support the verdict, named.
	Vantages []string `json:"vantages,omitempty"`
	// Paths are the supporting AS paths (bounded).
	Paths [][]uint32 `json:"paths,omitempty"`
	// Detail is one sentence an operator can act on.
	Detail string `json:"detail"`
	// Origins observed, ASN → how many vantage points saw it.
	Origins map[string]int `json:"origins,omitempty"`
	// Bogon carries the matched reserved block, when the class is bogon.
	Bogon *BogonEntry `json:"bogon,omitempty"`
	// Visibility is the measured fraction, when the class is visibility_loss.
	PeersSeeing int `json:"peers_seeing,omitempty"`
	PeersTotal  int `json:"peers_total,omitempty"`
}

// Incident is ONE prefix's current verdict, with history.
type Incident struct {
	Prefix   string          `json:"prefix"`
	Class    IncidentClass   `json:"class"`
	Also     []IncidentClass `json:"also,omitempty"`
	Severity string          `json:"severity"`
	Summary  string          `json:"summary"`
	Evidence Evidence        `json:"evidence"`
	// LearnedOrigin is set when ExpectedOrigins was NOT declared and the
	// classifier is using the first observed origin as the baseline. The UI must
	// say so — a learned baseline is weaker evidence than a declared one.
	LearnedOrigin bool `json:"learned_origin,omitempty"`
	// Shortfall records a class that ALMOST fired but lacked corroboration. It
	// is the honest counterpart to a suppressed alert (§10): the operator can
	// see that something was observed and why it was not asserted.
	Shortfall string `json:"corroboration_shortfall,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Since is when the CURRENT class started (it resets when the class
	// changes); FirstSeen is when this prefix was first evaluated.
	Since time.Time `json:"since"`
	Error string    `json:"error,omitempty"`
}

// candidate is one class the rules produced, before ranking.
type candidate struct {
	class    IncidentClass
	summary  string
	evidence Evidence
}

// Classify turns one measurement plus the tenant's declared intent into one
// incident verdict. It is PURE: no IO, no clock (`now` is injected), no state.
//
// bogons may be nil — the bogon rule is then simply not evaluated.
func Classify(obs Observation, cfg PolicyConfig, bogons *BogonSet, now time.Time) Incident {
	cfg = cfg.withDefaults()
	inc := Incident{
		Prefix: obs.Prefix, Class: ClassNone, Severity: SevInfo,
		LastSeen: now, Since: now, FirstSeen: now,
		Summary: "Announced as expected; RPKI clean; visibility normal.",
	}
	if !obs.Measured {
		inc.Class, inc.Severity = ClassUnknown, SeverityOf(ClassUnknown)
		inc.Error = obs.Error
		inc.Summary = "Not measured — the routing lookup did not answer. This is an absent measurement, not a clean prefix."
		inc.Evidence.Detail = inc.Summary
		return inc
	}

	var cands []candidate
	shortfalls := []string{}

	// ── bogon (arithmetic on the prefix; no corroboration needed) ───────────
	if bogons != nil {
		if p, err := parsePrefix(obs.Prefix); err == nil {
			if e, ok := bogons.Lookup(p); ok {
				entry := e
				cands = append(cands, candidate{
					class:   ClassBogon,
					summary: fmt.Sprintf("%s falls inside the reserved block %s (%s) — it must never appear in the global table.", obs.Prefix, e.Block, e.RFC),
					evidence: Evidence{
						Bogon:  &entry,
						Detail: e.Why + ". Matched block " + e.Block + " (" + e.Reason + ").",
					},
				})
			}
		}
	}

	// ── RPKI (one validator's verdict; no corroboration needed) ────────────
	if strings.EqualFold(obs.RPKIState, "invalid") {
		reason := "the announcement violates a published ROA"
		switch obs.RPKIReason {
		case "origin_as":
			reason = "a ROA exists but names a different origin AS"
		case "max_length":
			reason = "the announcement is more specific than the ROA's maxLength allows"
		}
		cands = append(cands, candidate{
			class:   ClassRPKIInvalid,
			summary: fmt.Sprintf("RPKI INVALID for %s from %s — %s.", obs.Prefix, orDash(obs.RPKIOrigin), reason),
			evidence: Evidence{Detail: "RPKI origin validation returned invalid: " + reason +
				". A stale ROA and a hijack look identical here — check the ROA before assuming an attack."},
		})
	}

	// ── visibility (measured fraction; RIS peers ARE the corroboration) ────
	if obs.PeersTotal > 0 {
		frac := float64(obs.PeersSeeing) / float64(obs.PeersTotal)
		if frac < cfg.MinVisibility {
			cands = append(cands, candidate{
				class: ClassVisibilityLoss,
				summary: fmt.Sprintf("%s is visible from %d of %d route-collector peers (%.0f%%, threshold %.0f%%).",
					obs.Prefix, obs.PeersSeeing, obs.PeersTotal, frac*100, cfg.MinVisibility*100),
				evidence: Evidence{
					PeersSeeing: obs.PeersSeeing, PeersTotal: obs.PeersTotal,
					Detail: "Visibility below the configured threshold. A partial withdrawal is the signature of an upstream session down or a filtered announcement.",
				},
			})
		}
	} else if obs.AnnouncedKnown && !obs.Announced {
		cands = append(cands, candidate{
			class:    ClassVisibilityLoss,
			summary:  obs.Prefix + " is not seen by ANY route-collector peer — it is not in the global table.",
			evidence: Evidence{Detail: "No collector peer currently sees this prefix."},
		})
	}

	// ── origin change (path-derived → needs corroboration) ─────────────────
	originVantages := map[uint32][]string{}
	for _, vp := range obs.Paths {
		if o := vp.Origin(); o != 0 {
			originVantages[o] = appendVantage(originVantages[o], vp.Peer)
		}
	}
	expected := map[uint32]bool{}
	for _, a := range cfg.ExpectedOrigins {
		expected[a] = true
	}
	learned := false
	if len(expected) == 0 {
		// Not declared: learn the DOMINANT observed origin as the baseline and
		// say so. Learning the dominant one (not "any observed one") is what
		// makes the very next evaluation able to see a change at all.
		if dom, ok := dominantOrigin(originVantages); ok {
			expected[dom] = true
			learned = true
		}
	}
	if len(expected) > 0 {
		var unexpected []uint32
		for asn := range originVantages {
			if !expected[asn] {
				unexpected = append(unexpected, asn)
			}
		}
		sort.Slice(unexpected, func(i, j int) bool { return unexpected[i] < unexpected[j] })
		for _, asn := range unexpected {
			peers := originVantages[asn]
			if len(peers) < cfg.MinVantages {
				shortfalls = append(shortfalls, fmt.Sprintf(
					"AS%d was seen originating %s by %d vantage point(s); %d are required before an origin change is asserted (a single collector holding a stale path is not an origin change)",
					asn, obs.Prefix, len(peers), cfg.MinVantages))
				continue
			}
			cands = append(cands, candidate{
				class: ClassOriginChange,
				summary: fmt.Sprintf("%s is being originated by AS%d, which is not in the expected origin set (%s) — possible hijack.",
					obs.Prefix, asn, asnList(cfg.ExpectedOrigins, expected)),
				evidence: Evidence{
					Vantages: clipStrings(peers, MaxEvidenceVantages),
					Paths:    pathsForOrigin(obs.Paths, asn),
					Origins:  originCounts(originVantages),
					Detail: fmt.Sprintf("%d vantage point(s) agree on the unexpected origin. Compare with the RPKI verdict: an invalid alongside this is a strong hijack signal; a valid one usually means the origin legitimately changed and the expected set is stale.",
						len(peers)),
				},
			})
		}
	}

	// ── route leak (path-derived → needs corroboration AND a declared set) ──
	if leak, short := classifyLeak(obs, cfg, expected); leak != nil {
		cands = append(cands, *leak)
	} else if short != "" {
		shortfalls = append(shortfalls, short)
	}

	if len(cands) == 0 {
		inc.LearnedOrigin = learned
		inc.Shortfall = strings.Join(shortfalls, "; ")
		inc.Evidence = Evidence{
			Detail:      "Announced, RPKI not invalid, visibility above threshold, no unexpected origin or transit.",
			Origins:     originCounts(originVantages),
			PeersSeeing: obs.PeersSeeing, PeersTotal: obs.PeersTotal,
		}
		return inc
	}

	sort.SliceStable(cands, func(i, j int) bool { return classRank[cands[i].class] < classRank[cands[j].class] })
	head := cands[0]
	inc.Class, inc.Summary, inc.Evidence = head.class, head.summary, head.evidence
	inc.Severity = SeverityOf(head.class)
	inc.LearnedOrigin = learned
	inc.Shortfall = strings.Join(shortfalls, "; ")
	for _, c := range cands[1:] {
		inc.Also = append(inc.Also, c.class)
	}
	if inc.Evidence.PeersTotal == 0 {
		inc.Evidence.PeersSeeing, inc.Evidence.PeersTotal = obs.PeersSeeing, obs.PeersTotal
	}
	if inc.Evidence.Origins == nil {
		inc.Evidence.Origins = originCounts(originVantages)
	}
	return inc
}

// classifyLeak implements the route-leak heuristic.
//
// WHAT IS DERIVABLE, AND WHAT IS NOT. A full valley-free (Gao-Rexford) check
// needs the provider/customer/peer relationship of every AS on the path, and no
// free per-ASN source publishes those. What the tenant DOES declare is its own
// transit set, and two leak signatures follow from it alone:
//
//	(a) UNEXPECTED TRANSIT — the hop immediately upstream of our origin is an AS
//	    we do not buy transit from. Someone else is announcing our prefix to the
//	    world; that is the textbook leak/mis-origination signature.
//	(b) VALLEY VIA OUR OWN TRANSIT — one of our declared upstreams appears on
//	    the path but NOT adjacent to our origin, with a NON-declared AS sitting
//	    between it and us. Our provider is carrying our prefix for a third
//	    party, i.e. someone downstream of us leaked it back up.
//
// Both need MinVantages corroboration. With no declared upstream set neither is
// computable and the function says so instead of inventing one.
func classifyLeak(obs Observation, cfg PolicyConfig, expectedOrigins map[uint32]bool) (*candidate, string) {
	if len(cfg.Upstreams) == 0 {
		return nil, ""
	}
	up := map[uint32]bool{}
	for _, a := range cfg.Upstreams {
		up[a] = true
	}
	type hit struct {
		asn   uint32
		kind  string
		peers []string
		paths [][]uint32
	}
	hits := map[uint32]*hit{}
	for _, vp := range obs.Paths {
		p := vp.Path
		if len(p) < 2 {
			continue
		}
		origin := p[len(p)-1]
		if !expectedOrigins[origin] {
			continue // an unexpected ORIGIN is an origin change, not a leak
		}
		// (a) the hop adjacent to our origin must be a declared upstream.
		adj := p[len(p)-2]
		if !up[adj] && !expectedOrigins[adj] {
			h := hits[adj]
			if h == nil {
				h = &hit{asn: adj, kind: "unexpected_transit"}
				hits[adj] = h
			}
			h.peers = appendVantage(h.peers, vp.Peer)
			if len(h.paths) < MaxEvidencePaths {
				h.paths = append(h.paths, append([]uint32(nil), p...))
			}
			continue
		}
		// (b) a declared upstream at a NON-adjacent interior position, with a
		//     non-declared AS between it and us.
		for i := 0; i < len(p)-2; i++ {
			if !up[p[i]] {
				continue
			}
			mid := p[i+1]
			if up[mid] || expectedOrigins[mid] {
				continue
			}
			h := hits[mid]
			if h == nil {
				h = &hit{asn: mid, kind: "valley"}
				hits[mid] = h
			}
			h.peers = appendVantage(h.peers, vp.Peer)
			if len(h.paths) < MaxEvidencePaths {
				h.paths = append(h.paths, append([]uint32(nil), p...))
			}
			break
		}
	}
	if len(hits) == 0 {
		return nil, ""
	}
	keys := make([]uint32, 0, len(hits))
	for k := range hits {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var short []string
	for _, k := range keys {
		h := hits[k]
		if len(h.peers) < cfg.MinVantages {
			short = append(short, fmt.Sprintf(
				"AS%d appeared as unexpected transit for %s on %d vantage point(s); %d are required before a route leak is asserted",
				h.asn, obs.Prefix, len(h.peers), cfg.MinVantages))
			continue
		}
		detail := fmt.Sprintf("AS%d carries %s but is not in the declared upstream set (%s).", h.asn, obs.Prefix, asnList(cfg.Upstreams, up))
		if h.kind == "valley" {
			detail = fmt.Sprintf("AS%d sits between one of the declared upstreams and %s — our transit is carrying this prefix for a third party (a valley in the path).", h.asn, obs.Prefix)
		}
		return &candidate{
			class:   ClassRouteLeak,
			summary: fmt.Sprintf("Possible route leak: %s reaches the internet through AS%d, which is not a declared upstream.", obs.Prefix, h.asn),
			evidence: Evidence{
				Vantages: clipStrings(h.peers, MaxEvidenceVantages),
				Paths:    h.paths,
				Detail: detail + " Full valley-free validation needs AS provider/customer relationships that no free per-ASN source publishes; " +
					"this verdict is derived from the tenant's DECLARED upstream set only.",
			},
		}, ""
	}
	return nil, strings.Join(short, "; ")
}

// ── small pure helpers ──────────────────────────────────────────────────────

func appendVantage(in []string, peer string) []string {
	peer = clip(strings.TrimSpace(peer), 64)
	if peer == "" {
		peer = "(unnamed collector peer)"
	}
	for _, e := range in {
		if e == peer {
			return in
		}
	}
	if len(in) >= 64 { // bounded (§9)
		return in
	}
	return append(in, peer)
}

func dominantOrigin(m map[uint32][]string) (uint32, bool) {
	best, bestN, ok := uint32(0), -1, false
	keys := make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		if n := len(m[k]); n > bestN {
			best, bestN, ok = k, n, true
		}
	}
	return best, ok
}

func originCounts(m map[uint32][]string) map[string]int {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[fmt.Sprintf("AS%d", k)] = len(v)
	}
	return out
}

func pathsForOrigin(paths []VantagePath, origin uint32) [][]uint32 {
	out := [][]uint32{}
	for _, vp := range paths {
		if vp.Origin() != origin {
			continue
		}
		if len(out) >= MaxEvidencePaths {
			break
		}
		out = append(out, append([]uint32(nil), vp.Path...))
	}
	return out
}

// asnList renders a declared set for a message. It prefers the DECLARED slice
// (order the operator typed); an empty slice means the set was learned, and the
// message says that rather than printing an empty list.
func asnList(declared []uint32, set map[uint32]bool) string {
	src := declared
	if len(src) == 0 {
		src = make([]uint32, 0, len(set))
		for k := range set {
			src = append(src, k)
		}
		sort.Slice(src, func(i, j int) bool { return src[i] < src[j] })
		if len(src) == 0 {
			return "none declared"
		}
		return "learned: AS" + joinASNs(src)
	}
	return "AS" + joinASNs(src)
}

func joinASNs(a []uint32) string {
	parts := make([]string, 0, len(a))
	for _, v := range a {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", AS")
}

func clipStrings(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return in[:max]
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "an undetermined origin"
	}
	return s
}
