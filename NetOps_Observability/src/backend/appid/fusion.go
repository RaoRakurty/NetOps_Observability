// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// fusion.go — #81 Fusion Layer §7A orchestrator + §J FusionDecisionEngine + §K
// ExplanationBuilder. FuseObservations runs the composable modules (pipeline.go) in
// the prescribed order; each module is separately unit-tested. Deterministic: same
// (observations, Now, catalog version, policy) → identical result + fusion id.
//
//   collect → alias → candidate → dedup → temporal → score → guardrail → conflict → decide

const defaultDNSTTL = 5 * time.Minute

// FuseInput is the pure input to the fusion pipeline (no IO — the caller supplies the
// catalog/ambiguity context so the engine stays testable).
type FuseInput struct {
	Scope          IdentityScope
	Observations   []ApplicationObservation
	Now            time.Time
	CatalogVersion int
	DNSTTL         time.Duration                   // dns/sni freshness window (0 ⇒ 5m)
	SharedCDN      bool                            // dst is a shared CDN/cloud IP
	NATSource      bool                            // src is NAT-collapsed
	Policy         ScoringPolicy                   // 0-value ⇒ DefaultScoringPolicy()
	Canon          func(vendor, app string) string // vendor alias → canonical (nil ⇒ identity)
}

// FuseObservations is the deterministic fusion pipeline (§7A).
func FuseObservations(in FuseInput) FusedIdentity {
	p := in.Policy
	if p.Version == "" {
		p = DefaultScoringPolicy()
	}
	ttl := in.DNSTTL
	if ttl <= 0 {
		ttl = defaultDNSTTL
	}
	codes := codeSet{}
	codes.add(ExCatalogVersionUsed) // always record which catalog version produced this (replay)

	ev := collectEvidence(in)
	ev = resolveAliases(ev, in.Canon, codes)
	cands := buildCandidates(ev)
	dedupeEvidence(cands, codes)
	cands = validateTemporal(cands, in.Now, ttl, codes)
	scored := scoreEvidence(cands, p, codes)
	scored = applyGuardrails(scored, in, codes)
	conflict := detectConflicts(scored, p)
	fi := decideIdentity(scored, conflict, codes)

	fi.TenantID = firstTenant(in.Observations)
	fi.Scope = in.Scope
	fi.CatalogVersion = in.CatalogVersion
	fi.FusionVersion = FusionEngineVersion
	fi.FusedAt = in.Now.UTC()
	fi.FusionID = fusionID(in.Scope, in.CatalogVersion)
	fi.Explanations = codes.sorted()
	return fi
}

// ── §J FusionDecisionEngine ──────────────────────────────────────────────────
func decideIdentity(scored []ScoredCandidate, conflict ConflictResult, codes codeSet) FusedIdentity {
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		return scored[i].App < scored[j].App
	})

	if conflict.Type == ConflictAuthoritative {
		codes.add(ExAuthoritativeConflict)
		return FusedIdentity{
			Verdict: Verdict{App: "unknown", Tier: Undetermined, Confidence: 0},
			Band:    BandUnresolved, State: StateConflicted, EvidenceScore: 0,
			Alternatives: candidatesFrom(scored),
		}
	}

	if len(scored) == 0 || scored[0].Band == BandUnresolved {
		// honest unknown — name why if the guardrails/temporal already did; else insufficient.
		if !codes.has(ExPortOnlyFallback) && !codes.has(ExProviderOnlyIP) &&
			!codes.has(ExSharedCDNAmbiguity) && !codes.has(ExNATAmbiguity) && !codes.has(ExStaleDNS) {
			codes.add(ExInsufficient)
		}
		fi := FusedIdentity{Verdict: Verdict{App: "unknown", Tier: Undetermined}, Band: BandUnresolved, State: StateUnknown}
		if len(scored) > 0 {
			fi.Alternatives = candidatesFrom(scored)
		}
		return fi
	}

	win := scored[0]
	addWinnerExplain(codes, win)
	return FusedIdentity{
		Verdict: Verdict{
			App: win.App, Tier: tierForBand(win.Band),
			Confidence: round2(float64(win.Score) / 100), Signals: signalsFrom(win),
		},
		EvidenceScore:     win.Score,
		Band:              win.Band,
		State:             stateFor(win),
		AppProtocol:       win.AppProtocol,
		TransportProtocol: win.Transport,
		Alternatives:      candidatesFrom(scored[1:]),
	}
}

func tierForBand(b ConfidenceBand) Tier {
	switch b {
	case BandAuthoritative, BandHigh:
		return Confirmed
	case BandMedium, BandLow:
		return Suspected
	default:
		return Undetermined
	}
}

func stateFor(win ScoredCandidate) ResolutionState {
	if len(win.Sources) >= 2 {
		return StateFused
	}
	if win.Sources[0].strength() >= 4 && win.BestScope.exact() {
		return StateObserved // a single authoritative upstream classification on the exact session
	}
	return StateInferred
}

func addWinnerExplain(codes codeSet, win ScoredCandidate) {
	has := func(s Source) bool {
		for _, w := range win.Sources {
			if w == s {
				return true
			}
		}
		return false
	}
	authClassifier := has(SrcNGFWAppID) || has(SrcIPFIXAppID) || has(SrcOperator) || has(SrcSoT) || has(SrcCloudTag)
	if authClassifier && win.BestScope.exact() {
		codes.add(ExSessionUpstream)
	}
	if has(SrcWorkload) {
		codes.add(ExWorkloadMatch)
	}
	if has(SrcDNS) && has(SrcSNI) {
		codes.add(ExDNSTLSCorroboration)
	}
	if len(win.Sources) >= 2 {
		codes.add(ExMultiIndependent)
	}
}

func candidatesFrom(scored []ScoredCandidate) []Candidate {
	out := make([]Candidate, 0, len(scored))
	for _, c := range scored {
		out = append(out, Candidate{App: c.App, Confidence: round2(float64(c.Score) / 100), Band: c.Band, Sources: c.Sources})
	}
	return out
}

func signalsFrom(win ScoredCandidate) []Signal {
	out := make([]Signal, 0, len(win.Supporting))
	for _, e := range win.Supporting {
		out = append(out, Signal{Source: e.Obs.Source, App: win.App, Role: Supports, Detail: e.Obs.Vendor})
	}
	return out
}

// ── §K ExplanationBuilder ────────────────────────────────────────────────────
// Explanation is the machine + human readable account of a fused decision.
type Explanation struct {
	Conclusion      string            `json:"conclusion"`
	Resolution      ResolutionState   `json:"resolution"`
	Confidence      ConfidenceBand    `json:"confidence"`
	EvidenceScore   int               `json:"evidence_score"`
	Codes           []ExplanationCode `json:"codes"`
	Reasons         []string          `json:"reasons"` // human-readable (code descriptions)
	Alternatives    []Candidate       `json:"alternatives,omitempty"`
	EvidenceMissing []string          `json:"evidence_missing,omitempty"`
	CatalogVersion  int               `json:"catalog_version"`
	FusionVersion   string            `json:"fusion_version"`
}

// BuildExplanation renders the fused identity's reasoning (§K).
func BuildExplanation(fi FusedIdentity) Explanation {
	reasons := make([]string, 0, len(fi.Explanations))
	for _, c := range fi.Explanations {
		if d := c.Description(); d != "" {
			reasons = append(reasons, d)
		}
	}
	concl := fi.App
	if concl == "" {
		concl = "unknown"
	}
	return Explanation{
		Conclusion: concl, Resolution: fi.State, Confidence: fi.Band, EvidenceScore: fi.EvidenceScore,
		Codes: fi.Explanations, Reasons: reasons, Alternatives: fi.Alternatives,
		EvidenceMissing: fi.EvidenceMissing, CatalogVersion: fi.CatalogVersion, FusionVersion: fi.FusionVersion,
	}
}

// ── shared ───────────────────────────────────────────────────────────────────
type codeSet map[ExplanationCode]bool

func (c codeSet) add(x ExplanationCode)      { c[x] = true }
func (c codeSet) has(x ExplanationCode) bool { return c[x] }
func (c codeSet) sorted() []ExplanationCode {
	out := make([]ExplanationCode, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func firstTenant(obs []ApplicationObservation) string {
	for _, o := range obs {
		if o.TenantID != "" {
			return o.TenantID
		}
	}
	return ""
}

// fusionID is deterministic per (scope, catalog version) + engine version — re-fusing
// the same scope at the same versions yields the same id (idempotent replace on replay).
func fusionID(s IdentityScope, catVer int) string {
	parts := strings.Join([]string{
		s.SessionID, s.FlowID, s.WorkloadID, s.CorrelationID, s.SrcIP, s.DstIP,
		itoa(s.DstPort), s.Proto, "cat" + itoa(catVer), FusionEngineVersion,
	}, "|")
	h := sha256.Sum256([]byte(parts))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}
