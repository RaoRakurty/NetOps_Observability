// Package appid is the pure (DB-free, dependency-free) contract for application
// identification (#81). It defines the verdict vocabulary and the multi-signal
// FUSION rule that turns a set of identification signals into one confidence-scored
// app label — with "unknown" as a FIRST-CLASS answer (never a false app=X).
//
// By design it reuses the correlation engine's vocabulary rather than inventing a
// parallel confidence model:
//   - Tier mirrors VerdictTier (correlation/verdicts.py): undetermined|suspected|confirmed.
//   - Role mirrors corr_evidence.role (clickhouse/init.sql): supports|contradicts|discriminates.
//   - the floor / contradiction-penalty constants mirror correlation/scoring.py.
//
// so app-identity verdicts flow into RCA / evidence bundles / replay natively.
//
// The resolver (P1) produces []Signal from the catalog LPM-trie + NGFW/IPFIX app-id
// + #69 selectors + SoT; Fuse is the seam that combines them. Pure + unit-tested.
package appid

import "sort"

// Tier mirrors the correlation engine's VerdictTier.
type Tier string

const (
	Undetermined Tier = "undetermined" // unknown / coarse-only / contradicted / below floor — FIRST-CLASS
	Suspected    Tier = "suspected"    // a single medium/strong signal, no corroboration
	Confirmed    Tier = "confirmed"    // authoritative, or strong + corroborated
)

// Role mirrors corr_evidence.role — a signal's relation to the chosen app.
type Role string

const (
	Supports      Role = "supports"
	Contradicts   Role = "contradicts"
	Discriminates Role = "discriminates"
)

// Source is an identification technique. Ordered by trust via strength(): the
// research's precedence ladder (authoritative → strong → medium → weak → hint).
type Source string

const (
	SrcNGFWAppID  Source = "ngfw_app_id"  // on-box DPI, exported in the firewall log — authoritative
	SrcIPFIXAppID Source = "ipfix_app_id" // IPFIX applicationId IE 95 / NBAR2 — authoritative
	SrcOperator   Source = "operator"     // #69 operator-declared service selector — authoritative (internal)
	SrcSoT        Source = "sot"          // SoT/NetBox IP→app mapping — authoritative (internal)
	SrcCloudTag   Source = "cloud_tag"    // cloud resource tag (operator) via the cloud inventory — authoritative
	SrcWorkload   Source = "workload"     // workload/process identity (K8s/OTel service) tied to the endpoint — authoritative
	SrcCloudGraph Source = "cloud_graph"  // cloud resource-graph name via the cloud inventory — strong
	SrcDNS        Source = "dns"          // DNS-flow correlation — strong
	SrcSNI        Source = "sni"          // TLS SNI — strong
	SrcIPCatalog  Source = "ip_catalog"   // vendor published IP/prefix range — medium (coarse on shared CDN IPs)
	SrcASN        Source = "asn"          // ASN → org — weak/context
	SrcPort       Source = "port"         // port/protocol heuristic — hint only
)

// strength buckets a source on the trust ladder.
//
//	4 authoritative · 3 strong · 2 medium · 1 weak · 0 hint
func (s Source) strength() int {
	switch s {
	case SrcNGFWAppID, SrcIPFIXAppID, SrcOperator, SrcSoT, SrcCloudTag, SrcWorkload:
		return 4
	case SrcDNS, SrcSNI, SrcCloudGraph:
		return 3
	case SrcIPCatalog:
		return 2
	case SrcASN:
		return 1
	default: // SrcPort and anything unknown
		return 0
	}
}

// baseConfidence is the standalone confidence a source contributes, before
// agreement boosts and contradiction penalties.
func (s Source) baseConfidence() float64 {
	switch s.strength() {
	case 4:
		return 0.95
	case 3:
		return 0.80
	case 2:
		return 0.55
	case 1:
		return 0.35
	default:
		return 0.20
	}
}

// Signal is one identification opinion. App=="" means the source had no opinion
// (it still counts toward evidence_missing reasoning, never toward a candidate).
type Signal struct {
	Source     Source  `json:"source"`
	App        string  `json:"app"`
	Confidence float64 `json:"confidence"`     // 0..1 the source's own confidence (0 ⇒ use baseConfidence)
	Role       Role    `json:"role,omitempty"` // assigned by Fuse relative to the winning app
	Detail     string  `json:"detail,omitempty"`
}

// Verdict is the fused result. App is "unknown" when undetermined.
type Verdict struct {
	App             string   `json:"app"`
	Tier            Tier     `json:"tier"`
	Confidence      float64  `json:"confidence"`
	Contradicted    bool     `json:"contradicted"`
	Signals         []Signal `json:"signals"`          // contributing signals, roles assigned
	EvidenceMissing []string `json:"evidence_missing"` // honest gaps that would raise confidence
}

const (
	confidenceFloor      = 0.30 // mirrors scoring.py CONFIDENCE_FLOOR
	contradictionPenalty = 0.20 // mirrors scoring.py CONTRADICTION_PENALTY
)

// Unknown is the honest first-class verdict for no admissible signal.
func unknown(missing []string, signals []Signal) Verdict {
	return Verdict{App: "unknown", Tier: Undetermined, Confidence: 0, Signals: signals, EvidenceMissing: missing}
}

// Fuse combines signals into one confidence-scored verdict. Precedence by source
// strength; agreement promotes; a credible competing claim (another app backed by a
// medium-or-stronger signal) contradicts → demote + penalty; coarse-only or
// below-floor → undetermined ("unknown" is first class, never a guessed app).
func Fuse(signals []Signal) Verdict {
	// Index candidates by app, tracking the strongest backing per app.
	type cand struct {
		app     string
		best    int     // max source strength backing this app
		conf    float64 // max base/own confidence backing this app
		sources int     // distinct contributing signals
	}
	byApp := map[string]*cand{}
	var order []string
	for _, sig := range signals {
		if sig.App == "" {
			continue
		}
		c := byApp[sig.App]
		if c == nil {
			c = &cand{app: sig.App}
			byApp[sig.App] = c
			order = append(order, sig.App)
		}
		c.sources++
		if st := sig.Source.strength(); st > c.best {
			c.best = st
		}
		cf := sig.Confidence
		if cf <= 0 {
			cf = sig.Source.baseConfidence()
		}
		if cf > c.conf {
			c.conf = cf
		}
	}

	missing := missingEvidence(signals)
	if len(byApp) == 0 {
		return unknown(missing, signals)
	}

	// Winner: strongest backing, then highest confidence, then stable by first-seen.
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byApp[order[i]], byApp[order[j]]
		if a.best != b.best {
			return a.best > b.best
		}
		return a.conf > b.conf
	})
	win := byApp[order[0]]

	// Contradiction: any OTHER app backed by a medium-or-stronger signal (strength ≥ 2)
	// is a credible competing claim.
	contradicted := false
	for _, app := range order {
		if app == win.app {
			continue
		}
		if byApp[app].best >= 2 {
			contradicted = true
			break
		}
	}

	// Tier from the winner's strength + corroboration.
	tier := Undetermined
	switch {
	case win.best >= 4: // authoritative — alone is enough
		tier = Confirmed
	case win.best == 3: // strong — confirmed only if corroborated
		if win.sources >= 2 {
			tier = Confirmed
		} else {
			tier = Suspected
		}
	case win.best == 2: // medium — at best suspected
		tier = Suspected
	default: // weak / hint only
		tier = Undetermined
	}

	conf := win.conf
	if win.sources >= 2 && tier != Undetermined {
		conf = minF(0.99, conf+0.10) // agreement boost
	}
	if contradicted {
		conf *= contradictionPenalty
		tier = demote(tier)
	}
	if conf < confidenceFloor {
		tier = Undetermined
	}

	if tier == Undetermined {
		// keep the contributing signals + reason, but do not assert an app.
		v := unknown(missing, assignRoles(signals, win.app))
		v.Confidence = round2(conf)
		v.Contradicted = contradicted
		return v
	}

	return Verdict{
		App:             win.app,
		Tier:            tier,
		Confidence:      round2(conf),
		Contradicted:    contradicted,
		Signals:         assignRoles(signals, win.app),
		EvidenceMissing: missing,
	}
}

// assignRoles labels each signal relative to the winning app.
func assignRoles(signals []Signal, winApp string) []Signal {
	out := make([]Signal, 0, len(signals))
	for _, sig := range signals {
		if sig.App != "" {
			if sig.App == winApp {
				sig.Role = Supports
			} else {
				sig.Role = Contradicts
			}
		}
		out = append(out, sig)
	}
	return out
}

// missingEvidence reports which higher-value sources were absent — the honest
// "this would raise confidence" hint, mirroring the engine's evidence_missing.
func missingEvidence(signals []Signal) []string {
	present := map[Source]bool{}
	for _, s := range signals {
		if s.App != "" {
			present[s.Source] = true
		}
	}
	var miss []string
	if !present[SrcDNS] {
		miss = append(miss, "no dns-flow correlation source")
	}
	if !present[SrcSNI] {
		miss = append(miss, "no tls-sni source")
	}
	if !present[SrcNGFWAppID] && !present[SrcIPFIXAppID] {
		miss = append(miss, "no on-box app-id (ngfw/ipfix) on this path")
	}
	if !present[SrcOperator] && !present[SrcSoT] && !present[SrcCloudTag] {
		miss = append(miss, "no operator-declared service, SoT, or cloud-tag mapping")
	}
	return miss
}

func demote(t Tier) Tier {
	switch t {
	case Confirmed:
		return Suspected
	default:
		return Undetermined
	}
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
