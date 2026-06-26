package appid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// fusion.go — #81 Fusion Layer Phase 3. FuseObservations deepens Fuse over a SET of
// provenance-bearing observations for ONE scope. It adds, AROUND the existing
// strength-ladder confidence math (which it reuses via Fuse — not replaced):
//   - duplicate-evidence dedup (copies never inflate confidence)
//   - evidence freshness / DNS-TTL (stale DNS/SNI rejected)
//   - exact-session > destination-only weighting
//   - NAT-source ambiguity (dst-only inferential evidence not attributed under NAT)
//   - shared-CDN ambiguity (a shared IP can't prove the app alone)
//   - authoritative-source CONFLICT → state=conflicted, identity NOT asserted
//   - vendor-alias canonicalization (original value preserved on the observation)
//   - confidence bands, resolution state, alternative candidates, stable explanation
//     codes, and catalog/fusion versioning for deterministic, idempotent replay.
//
// Deterministic: same (observations, Now, catalog version, options) → same result.

const defaultDNSTTL = 5 * time.Minute

// FuseInput is everything FuseObservations needs — pure (no IO); the catalog/ambiguity
// context is supplied by the caller (the resolver/catalog layer), so fusion stays testable.
type FuseInput struct {
	Scope          IdentityScope
	Observations   []ApplicationObservation
	Now            time.Time
	CatalogVersion int
	DNSTTL         time.Duration                   // freshness window for dns/sni (0 ⇒ default 5m)
	SharedCDN      bool                            // dst is a shared CDN/cloud IP → ip/asn can't prove alone
	NATSource      bool                            // src is NAT-collapsed → dst-only inferential evidence unattributable
	Canon          func(vendor, app string) string // vendor alias → canonical display name (nil ⇒ identity)
}

// FuseObservations fuses a scope's observations into one explainable FusedIdentity.
func FuseObservations(in FuseInput) FusedIdentity {
	ttl := in.DNSTTL
	if ttl <= 0 {
		ttl = defaultDNSTTL
	}
	canon := in.Canon
	if canon == nil {
		canon = func(_, app string) string { return app }
	}

	codes := map[ExplanationCode]bool{}
	var signals []Signal
	seen := map[string]bool{} // dedup key → already counted

	for _, o := range in.Observations {
		if o.VendorAppName == "" && o.VendorAppID == "" {
			continue // no app opinion (still informs evidence-missing via Fuse)
		}
		// canonicalize (original vendor value stays on the observation, untouched).
		app := canon(o.Vendor, o.VendorAppName)
		if app == "" {
			app = o.VendorAppName
		}
		if app != o.VendorAppName && o.VendorAppName != "" {
			codes[ExVendorAliasCanon] = true
		}

		// freshness: stale DNS/SNI evidence is rejected (respect TTL + observation time).
		if o.Source == SrcDNS || o.Source == SrcSNI {
			if !o.EventTime.IsZero() && o.EventTime.Add(ttl).Before(in.Now) {
				codes[ExStaleDNS] = true
				continue
			}
		}
		// NAT ambiguity: under a NAT-collapsed source, dst-only inferential evidence
		// (no exact session) can't be attributed to THIS endpoint — drop it.
		if in.NATSource && o.SessionID == "" && o.Source.strength() < 4 {
			codes[ExNATAmbiguity] = true
			continue
		}
		// shared-CDN ambiguity: a shared CDN/cloud IP can't independently prove an
		// app — ip/asn evidence on it becomes context only (excluded from candidates).
		if in.SharedCDN && (o.Source == SrcIPCatalog || o.Source == SrcASN) {
			codes[ExSharedCDNAmbiguity] = true
			continue
		}

		// dedup: same source + same canonical app + same session/tuple = one copy.
		key := string(o.Source) + "|" + app + "|" + o.SessionID + "|" + o.DstIP
		if seen[key] {
			codes[ExDuplicateIgnored] = true
			continue
		}
		seen[key] = true

		conf := o.Confidence
		if conf <= 0 {
			conf = o.Source.baseConfidence()
		}
		// exact-session evidence outranks destination-only: a small edge so the Fuse
		// tiebreak prefers it among equally-strong sources (never crosses a tier).
		if o.SessionID != "" || o.FlowID != "" || in.Scope.ExactSession() {
			conf = minF(0.99, conf+0.02)
		}
		signals = append(signals, Signal{Source: o.Source, App: app, Confidence: conf, Detail: o.Vendor})
	}

	// authoritative conflict: two+ DISTINCT apps each backed by an authoritative
	// (strength-4) source — we do NOT pick a winner; the identity is conflicted.
	authApps := map[string]bool{}
	for _, s := range signals {
		if s.Source.strength() >= 4 {
			authApps[s.App] = true
		}
	}
	conflicted := len(authApps) >= 2

	base := Fuse(signals)
	winStrength, winSources := backingFor(signals, base.App)

	fi := FusedIdentity{
		FusionID:       fusionID(in.Scope, in.CatalogVersion),
		TenantID:       firstTenant(in.Observations),
		Scope:          in.Scope,
		CatalogVersion: in.CatalogVersion,
		FusionVersion:  FusionEngineVersion,
		FusedAt:        in.Now.UTC(),
		Verdict:        base,
		Alternatives:   alternatives(signals, base.App),
	}

	if conflicted {
		// authoritative sources disagree — assert NOTHING (honest), surface candidates.
		fi.App = "unknown"
		fi.Tier = Undetermined
		fi.Confidence = 0
		fi.Band = BandUnresolved
		fi.State = StateConflicted
		codes[ExAuthoritativeConflict] = true
	} else {
		fi.Band = BandFor(base.Tier, winStrength)
		fi.State = resolutionState(base, winStrength, len(winSources))
	}

	addWinnerCodes(codes, base, winSources, signals, in.Scope, conflicted)
	fi.Explanations = sortedCodes(codes)
	return fi
}

// backingFor returns the strongest source strength and the distinct sources backing app.
func backingFor(signals []Signal, app string) (int, []Source) {
	best := 0
	set := map[Source]bool{}
	for _, s := range signals {
		if s.App == app && app != "" && app != "unknown" {
			if st := s.Source.strength(); st > best {
				best = st
			}
			set[s.Source] = true
		}
	}
	out := make([]Source, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return best, out
}

// resolutionState classifies the (non-conflicted) outcome into the lifecycle state.
func resolutionState(v Verdict, winStrength, distinctSources int) ResolutionState {
	if v.App == "" || v.App == "unknown" || v.Tier == Undetermined {
		return StateUnknown
	}
	if distinctSources >= 2 {
		return StateFused
	}
	if winStrength >= 4 { // a single authoritative source reported it
		return StateObserved
	}
	return StateInferred // single inferential source (dns/sni/ip/asn) — derived, not asserted by an authority
}

// alternatives lists the non-winning candidate apps for transparency.
func alternatives(signals []Signal, winApp string) []Candidate {
	type agg struct {
		conf int // strength
		c    float64
		srcs map[Source]bool
	}
	by := map[string]*agg{}
	var order []string
	for _, s := range signals {
		if s.App == "" || s.App == winApp {
			continue
		}
		a := by[s.App]
		if a == nil {
			a = &agg{srcs: map[Source]bool{}}
			by[s.App] = a
			order = append(order, s.App)
		}
		if st := s.Source.strength(); st > a.conf {
			a.conf = st
		}
		cf := s.Confidence
		if cf <= 0 {
			cf = s.Source.baseConfidence()
		}
		if cf > a.c {
			a.c = cf
		}
		a.srcs[s.Source] = true
	}
	sort.SliceStable(order, func(i, j int) bool { return by[order[i]].conf > by[order[j]].conf })
	out := make([]Candidate, 0, len(order))
	for _, app := range order {
		a := by[app]
		srcs := make([]Source, 0, len(a.srcs))
		for s := range a.srcs {
			srcs = append(srcs, s)
		}
		sort.Slice(srcs, func(i, j int) bool { return srcs[i] < srcs[j] })
		out = append(out, Candidate{App: app, Confidence: round2(a.c), Band: BandFor(tierForStrength(a.conf), a.conf), Sources: srcs})
	}
	return out
}

// tierForStrength is the standalone tier a single source of this strength implies.
func tierForStrength(strength int) Tier {
	switch {
	case strength >= 4:
		return Confirmed
	case strength >= 2:
		return Suspected
	default:
		return Undetermined
	}
}

// addWinnerCodes appends the explanation codes implied by the winning evidence.
func addWinnerCodes(codes map[ExplanationCode]bool, v Verdict, winSources []Source, signals []Signal, scope IdentityScope, conflicted bool) {
	if conflicted {
		return
	}
	if v.App == "" || v.App == "unknown" {
		// business app unknown — name WHY (a port/provider hint is still service-class info).
		switch {
		case anySource(signals, SrcPort):
			codes[ExPortOnlyFallback] = true
		case anySource(signals, SrcIPCatalog) || anySource(signals, SrcASN):
			codes[ExProviderOnlyIP] = true
		default:
			codes[ExInsufficient] = true
		}
		return
	}
	has := func(s Source) bool {
		for _, w := range winSources {
			if w == s {
				return true
			}
		}
		return false
	}
	auth := has(SrcNGFWAppID) || has(SrcIPFIXAppID) || has(SrcOperator) || has(SrcSoT) || has(SrcCloudTag)
	if auth && scope.ExactSession() {
		codes[ExSessionUpstream] = true
	}
	if has(SrcWorkload) {
		codes[ExWorkloadMatch] = true
	}
	if has(SrcDNS) && has(SrcSNI) {
		codes[ExDNSTLSCorroboration] = true
	}
	if len(winSources) >= 2 {
		codes[ExMultiIndependent] = true
	}
	// single-source-only weak cases:
	if len(winSources) == 1 {
		switch winSources[0] {
		case SrcIPCatalog, SrcASN:
			codes[ExProviderOnlyIP] = true
		case SrcPort:
			codes[ExPortOnlyFallback] = true
		}
	}
}

func anySource(signals []Signal, s Source) bool {
	for _, x := range signals {
		if x.Source == s {
			return true
		}
	}
	return false
}

func sortedCodes(set map[ExplanationCode]bool) []ExplanationCode {
	out := make([]ExplanationCode, 0, len(set))
	for c := range set {
		out = append(out, c)
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

// fusionID is deterministic per (scope, catalog version) + engine version, so re-fusing
// the same scope at the same versions yields the same id (idempotent replace on replay).
func fusionID(s IdentityScope, catVer int) string {
	parts := []string{
		s.SessionID, s.FlowID, s.WorkloadID, s.CorrelationID, s.SrcIP, s.DstIP,
		fmt.Sprintf("%d/%s", s.DstPort, s.Proto), fmt.Sprintf("cat%d", catVer), FusionEngineVersion,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}
