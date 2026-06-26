package appid

// scoring.go — #81 Fusion Layer §G EvidenceScorer policy. ALL fusion weights,
// adjustments and bands live here (centralized, versioned) — no magic numbers
// scattered through the pipeline. The result is an EVIDENCE SCORE (0..100), NOT a
// statistical probability. Bumping ScoringPolicy.Version yields a new fusion result
// version (replay) rather than silently rewriting history.
type ScoringPolicy struct {
	Version string

	// Base evidence weight per source (the §G base table). A source absent here
	// scores 0 (unknown).
	Base map[Source]int

	// Adjustments (§G).
	IndependentSourceBonus int // + per extra independent compatible source
	FreshBonus             int // + fresh evidence
	OnPathBonus            int // + source device confirmed on the affected path
	StaleDNSPenalty        int // - stale DNS
	NATPenalty             int // - NAT ambiguity
	SharedCDNPenalty       int // - shared CDN ambiguity
	DestinationOnlyPenalty int // - destination-only match
	ContradictionPenalty   int // - strong contradiction
	DNSTLSCorroborated     int // floor when DNS + TLS-SNI corroborate the same app
}

// DefaultScoringPolicy is the §G policy (version "score-1").
func DefaultScoringPolicy() ScoringPolicy {
	return ScoringPolicy{
		Version: "score-1",
		Base: map[Source]int{
			SrcOperator:   100, // customer/operator exact mapping
			SrcSoT:        100,
			SrcCloudTag:   100,
			SrcNGFWAppID:  95, // ngfw exact session
			SrcIPFIXAppID: 90, // nbar exact flow
			SrcWorkload:   80, // workload identity
			SrcCloudGraph: 75,
			SrcDNS:        65, // specific domain
			SrcSNI:        65,
			SrcIPCatalog:  45, // specific ip-prefix (with context)
			SrcASN:        25, // provider/asn only
			SrcPort:       10, // port/protocol only
		},
		IndependentSourceBonus: 10,
		FreshBonus:             5,
		OnPathBonus:            5,
		StaleDNSPenalty:        20,
		NATPenalty:             25,
		SharedCDNPenalty:       30,
		DestinationOnlyPenalty: 40,
		ContradictionPenalty:   50,
		DNSTLSCorroborated:     75,
	}
}

// base returns the source's base weight (0 when unmapped).
func (p ScoringPolicy) base(s Source) int { return p.Base[s] }

// clampScore bounds a raw score to 0..100.
func clampScore(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// BandForScore maps a 0..100 evidence score to a confidence band (§G).
//
//	authoritative 95-100 · high 75-94 · medium 50-74 · low 20-49 · unresolved 0-19
func BandForScore(score int) ConfidenceBand {
	switch {
	case score >= 95:
		return BandAuthoritative
	case score >= 75:
		return BandHigh
	case score >= 50:
		return BandMedium
	case score >= 20:
		return BandLow
	default:
		return BandUnresolved
	}
}

// bandCap returns the maximum score a band allows (used by the GuardrailEngine to
// enforce "can never exceed <band>" hard caps).
func bandCap(b ConfidenceBand) int {
	switch b {
	case BandAuthoritative:
		return 100
	case BandHigh:
		return 94
	case BandMedium:
		return 74
	case BandLow:
		return 49
	default:
		return 19
	}
}
