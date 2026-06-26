package appid

import (
	"sort"
	"time"
)

// pipeline.go — #81 Fusion Layer §B–J composable modules. Each is a pure, separately
// testable function; FuseObservations (fusion.go) orchestrates them in the §7A order:
// collect → alias → candidate → dedup → temporal → score → guardrail → conflict → decide.

// Evidence is a normalized, scoped observation ready for the pipeline.
type Evidence struct {
	Obs   ApplicationObservation
	App   string // canonical (set by AliasResolver)
	Scope ScopeResolution
}

// candAgg groups evidence for one candidate application (CandidateBuilder, §D).
type candAgg struct {
	app string
	ev  []Evidence
}

// ScoredCandidate is one candidate after EvidenceScorer + GuardrailEngine (§G/§H).
type ScoredCandidate struct {
	App         string         `json:"app"`
	Score       int            `json:"score"` // 0..100 evidence score (not a probability)
	Band        ConfidenceBand `json:"band"`
	BestScope   ScopeMatch     `json:"best_scope"`
	Sources     []Source       `json:"sources"`
	AppProtocol string         `json:"app_protocol,omitempty"`
	Transport   string         `json:"transport,omitempty"`
	Supporting  []Evidence     `json:"-"`
}

// ConflictType classifies an evidence conflict (§I).
type ConflictType string

const (
	ConflictNone          ConflictType = ""
	ConflictAuthoritative ConflictType = "authoritative_vs_authoritative"
)

// ConflictResult is the ConflictDetector output (§I).
type ConflictResult struct {
	Type       ConflictType `json:"type"`
	Candidates []string     `json:"candidates,omitempty"`
}

// ── §B EvidenceCollector ─────────────────────────────────────────────────────
// collectEvidence gathers observations that carry an app opinion and binds each to a
// scope. (Tenant filtering + bounded queries happen upstream; the pool is already
// tenant-scoped.) Malformed/no-opinion observations are skipped.
func collectEvidence(in FuseInput) []Evidence {
	out := make([]Evidence, 0, len(in.Observations))
	for _, o := range in.Observations {
		if o.VendorAppName == "" && o.VendorAppID == "" {
			continue
		}
		out = append(out, Evidence{Obs: o, App: o.VendorAppName, Scope: ResolveScope(o)})
	}
	return out
}

// ── §C AliasResolver ─────────────────────────────────────────────────────────
// resolveAliases canonicalizes each evidence's app via the injected catalog lookup.
// The ORIGINAL vendor value stays on Obs; only Evidence.App becomes canonical.
func resolveAliases(ev []Evidence, canon func(vendor, app string) string, codes codeSet) []Evidence {
	if canon == nil {
		canon = func(_, a string) string { return a }
	}
	for i := range ev {
		raw := ev[i].Obs.VendorAppName
		c := canon(ev[i].Obs.Vendor, raw)
		if c == "" {
			c = raw
		}
		if c != raw && raw != "" {
			codes.add(ExVendorAliasCanon)
		}
		ev[i].App = c
	}
	return ev
}

// ── §D CandidateBuilder ──────────────────────────────────────────────────────
// buildCandidates groups evidence by canonical app (protocol stays on the evidence,
// never as the app). Stable order: first-seen.
func buildCandidates(ev []Evidence) []*candAgg {
	by := map[string]*candAgg{}
	var order []*candAgg
	for _, e := range ev {
		if e.App == "" {
			continue
		}
		c := by[e.App]
		if c == nil {
			c = &candAgg{app: e.App}
			by[e.App] = c
			order = append(order, c)
		}
		c.ev = append(c.ev, e)
	}
	return order
}

// ── §E EvidenceDeduper ───────────────────────────────────────────────────────
// dedupeEvidence drops duplicate copies within a candidate (same source/device/
// session/flow/dst/content-hash) so repeated logs can't inflate score.
func dedupeEvidence(cands []*candAgg, codes codeSet) {
	for _, c := range cands {
		seen := map[string]bool{}
		kept := c.ev[:0]
		for _, e := range c.ev {
			o := e.Obs
			key := string(e.Obs.Source) + "|" + o.Device + "|" + o.SessionID + "|" + o.FlowID + "|" + o.DstIP + "|" + o.RawHash
			if seen[key] {
				codes.add(ExDuplicateIgnored)
				continue
			}
			seen[key] = true
			kept = append(kept, e)
		}
		c.ev = kept
	}
}

// ── §F TemporalValidator ─────────────────────────────────────────────────────
// validateTemporal rejects stale DNS/SNI (respecting TTL + observation time) and
// drops candidates left with no admissible evidence.
func validateTemporal(cands []*candAgg, now time.Time, ttl time.Duration, codes codeSet) []*candAgg {
	var out []*candAgg
	for _, c := range cands {
		kept := c.ev[:0]
		for _, e := range c.ev {
			if e.Obs.Source == SrcDNS || e.Obs.Source == SrcSNI {
				if !e.Obs.EventTime.IsZero() && e.Obs.EventTime.Add(ttl).Before(now) {
					codes.add(ExStaleDNS)
					continue
				}
			}
			kept = append(kept, e)
		}
		c.ev = kept
		if len(c.ev) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// ── §G EvidenceScorer ────────────────────────────────────────────────────────
// scoreEvidence assigns each candidate a deterministic 0..100 evidence score from the
// centralized policy: base(strongest source) + independent-source/fresh bonuses +
// dns-tls corroboration floor, minus the destination-only downrank for a classifier
// that lacks an exact session.
func scoreEvidence(cands []*candAgg, p ScoringPolicy, codes codeSet) []ScoredCandidate {
	out := make([]ScoredCandidate, 0, len(cands))
	for _, c := range cands {
		srcSet := map[Source]bool{}
		best := 0
		bestScope := ScopeNone
		var hasDNS, hasSNI bool
		var appProto, transport string
		for _, e := range c.ev {
			srcSet[e.Obs.Source] = true
			if b := p.base(e.Obs.Source); b > best {
				best = b
			}
			if e.Scope.Type.strength() > bestScope.strength() {
				bestScope = e.Scope.Type
			}
			hasDNS = hasDNS || e.Obs.Source == SrcDNS
			hasSNI = hasSNI || e.Obs.Source == SrcSNI
			if e.Obs.AppProtocol != "" {
				appProto = e.Obs.AppProtocol
			}
			if e.Obs.Proto != "" {
				transport = e.Obs.Proto
			}
		}
		score := best
		if n := len(srcSet); n > 1 {
			score += p.IndependentSourceBonus * (n - 1)
		}
		if hasDNS && hasSNI && score < p.DNSTLSCorroborated {
			score = p.DNSTLSCorroborated
		}
		score += p.FreshBonus // surviving evidence is fresh (temporal removed stale)
		// destination-only downrank applies to a CLASSIFIER (base>=80) that lacks an
		// exact session — inferential sources' bases already encode their coarse scope.
		if best >= 80 && !bestScope.exact() && bestScope != ScopeWorkload && bestScope != ScopeUser {
			score -= p.DestinationOnlyPenalty
			codes.add(ExDestinationDownranked)
		}
		out = append(out, ScoredCandidate{
			App: c.app, Score: clampScore(score), Band: BandForScore(clampScore(score)),
			BestScope: bestScope, Sources: sortedSources(srcSet), AppProtocol: appProto,
			Transport: transport, Supporting: c.ev,
		})
	}
	return out
}

// ── §H GuardrailEngine ───────────────────────────────────────────────────────
// applyGuardrails enforces the non-negotiable hard caps after scoring.
func applyGuardrails(scored []ScoredCandidate, in FuseInput, codes codeSet) []ScoredCandidate {
	out := make([]ScoredCandidate, 0, len(scored))
	for _, c := range scored {
		onlyIP := allInferentialIP(c.Sources)
		// shared CDN: ip/asn-only evidence on a shared CDN cannot identify a specific app.
		if in.SharedCDN && onlyIP {
			codes.add(ExSharedCDNAmbiguity)
			continue // excluded — cannot prove
		}
		// NAT ambiguity: dst-only evidence under a NAT-collapsed source can't be
		// attributed to this endpoint (an exact session / user / workload binding survives).
		if in.NATSource && c.BestScope.strength() <= ScopeDomain.strength() &&
			c.BestScope != ScopeWorkload && c.BestScope != ScopeUser {
			codes.add(ExNATAmbiguity)
			continue
		}
		cap := 100
		if len(c.Sources) == 1 {
			switch c.Sources[0] {
			case SrcPort: // port/protocol → service class, never a business app
				cap = bandCap(BandLow)
				codes.add(ExPortOnlyFallback)
			case SrcASN: // provider-only
				cap = bandCap(BandLow)
				codes.add(ExProviderOnlyIP)
			case SrcIPCatalog: // coarse prefix — provider/region, not proof of the app
				cap = bandCap(BandMedium)
				codes.add(ExProviderOnlyIP)
			}
		}
		if c.Score > cap {
			c.Score = cap
			c.Band = BandForScore(c.Score)
		}
		out = append(out, c)
	}
	return out
}

// ── §I ConflictDetector ──────────────────────────────────────────────────────
// detectConflicts flags two+ distinct apps each backed by an AUTHORITATIVE source
// (base ≥ 85: operator/sot/cloud-tag/ngfw/nbar) — incompatible strong evidence.
func detectConflicts(scored []ScoredCandidate, p ScoringPolicy) ConflictResult {
	var auth []string
	for _, c := range scored {
		for _, s := range c.Sources {
			if p.base(s) >= 85 {
				auth = append(auth, c.App)
				break
			}
		}
	}
	if d := distinct(auth); len(d) >= 2 {
		return ConflictResult{Type: ConflictAuthoritative, Candidates: d}
	}
	return ConflictResult{Type: ConflictNone}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func allInferentialIP(srcs []Source) bool {
	if len(srcs) == 0 {
		return false
	}
	for _, s := range srcs {
		if s != SrcIPCatalog && s != SrcASN {
			return false
		}
	}
	return true
}

func sortedSources(set map[Source]bool) []Source {
	out := make([]Source, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
