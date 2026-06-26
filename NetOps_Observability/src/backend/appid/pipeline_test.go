package appid

import (
	"testing"
	"time"
)

func TestModule_CollectEvidence_SkipsNoApp(t *testing.T) {
	in := FuseInput{Observations: []ApplicationObservation{
		{Source: SrcNGFWAppID, VendorAppName: "Teams", SessionID: "s1"},
		{Source: SrcDNS, DstIP: "1.2.3.4"}, // no app opinion
	}}
	ev := collectEvidence(in)
	if len(ev) != 1 || ev[0].Obs.VendorAppName != "Teams" {
		t.Fatalf("collectEvidence should skip no-app observations, got %d", len(ev))
	}
	if ev[0].Scope.Type == ScopeNone {
		t.Error("collected evidence must be scoped")
	}
}

func TestModule_ResolveAliases(t *testing.T) {
	codes := codeSet{}
	ev := resolveAliases([]Evidence{{Obs: ApplicationObservation{Vendor: "paloalto", VendorAppName: "ms-teams"}}},
		func(_, a string) string {
			if a == "ms-teams" {
				return "Microsoft Teams"
			}
			return a
		}, codes)
	if ev[0].App != "Microsoft Teams" || !codes.has(ExVendorAliasCanon) {
		t.Fatalf("alias not canonicalized: app=%q codes=%v", ev[0].App, codes.sorted())
	}
	// original vendor value preserved on the observation.
	if ev[0].Obs.VendorAppName != "ms-teams" {
		t.Error("original vendor value must be preserved")
	}
}

func TestModule_BuildCandidatesGroups(t *testing.T) {
	c := buildCandidates([]Evidence{{App: "A"}, {App: "A"}, {App: "B"}, {App: ""}})
	if len(c) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(c))
	}
	if c[0].app != "A" || len(c[0].ev) != 2 {
		t.Errorf("grouping wrong: %+v", c[0])
	}
}

func TestModule_DedupeEvidence(t *testing.T) {
	e := Evidence{Obs: ApplicationObservation{Source: SrcNGFWAppID, SessionID: "s", DstIP: "d", RawHash: "h"}, App: "A"}
	c := []*candAgg{{app: "A", ev: []Evidence{e, e, e}}}
	codes := codeSet{}
	dedupeEvidence(c, codes)
	if len(c[0].ev) != 1 || !codes.has(ExDuplicateIgnored) {
		t.Fatalf("dedup failed: kept=%d codes=%v", len(c[0].ev), codes.sorted())
	}
}

func TestModule_TemporalValidator(t *testing.T) {
	stale := Evidence{Obs: ApplicationObservation{Source: SrcDNS, EventTime: fuseNow.Add(-10 * time.Minute)}, App: "A"}
	fresh := Evidence{Obs: ApplicationObservation{Source: SrcDNS, EventTime: fuseNow}, App: "A"}
	codes := codeSet{}
	if out := validateTemporal([]*candAgg{{app: "A", ev: []Evidence{stale}}}, fuseNow, 5*time.Minute, codes); len(out) != 0 || !codes.has(ExStaleDNS) {
		t.Fatalf("stale-only candidate should drop, got %d codes=%v", len(out), codes.sorted())
	}
	if out := validateTemporal([]*candAgg{{app: "A", ev: []Evidence{fresh}}}, fuseNow, 5*time.Minute, codeSet{}); len(out) != 1 {
		t.Fatalf("fresh candidate should survive, got %d", len(out))
	}
}

func TestModule_ScoreEvidence(t *testing.T) {
	c := []*candAgg{{app: "Teams", ev: []Evidence{
		{Obs: ApplicationObservation{Source: SrcNGFWAppID, SessionID: "s"}, App: "Teams", Scope: ScopeResolution{Type: ScopeSession}},
	}}}
	sc := scoreEvidence(c, DefaultScoringPolicy(), codeSet{})
	if sc[0].Score != 100 || sc[0].Band != BandAuthoritative { // 95 base + 5 fresh
		t.Fatalf("ngfw-session score=%d band=%s want 100/authoritative", sc[0].Score, sc[0].Band)
	}
	// two independent sources add the bonus.
	c2 := []*candAgg{{app: "Teams", ev: []Evidence{
		{Obs: ApplicationObservation{Source: SrcDNS}, App: "Teams", Scope: ScopeResolution{Type: ScopeDomain}},
		{Obs: ApplicationObservation{Source: SrcSNI}, App: "Teams", Scope: ScopeResolution{Type: ScopeDomain}},
	}}}
	sc2 := scoreEvidence(c2, DefaultScoringPolicy(), codeSet{})
	if sc2[0].Score < 75 { // dns+sni corroboration floor + bonus
		t.Errorf("dns+sni score too low: %d", sc2[0].Score)
	}
}

func TestModule_GuardrailCaps(t *testing.T) {
	p := FuseInput{}
	// port-only capped at low
	if out := applyGuardrails([]ScoredCandidate{{App: "HTTPS", Score: 80, Sources: []Source{SrcPort}, BestScope: ScopePort}}, p, codeSet{}); out[0].Score > 49 {
		t.Errorf("port-only not capped at low: %d", out[0].Score)
	}
	// ip-catalog-only capped at medium
	if out := applyGuardrails([]ScoredCandidate{{App: "X", Score: 99, Sources: []Source{SrcIPCatalog}, BestScope: ScopeDstIP}}, p, codeSet{}); out[0].Score > 74 {
		t.Errorf("ip-only not capped at medium: %d", out[0].Score)
	}
	// shared-CDN ip-only excluded entirely
	if out := applyGuardrails([]ScoredCandidate{{App: "X", Score: 50, Sources: []Source{SrcIPCatalog}, BestScope: ScopeDstIP}}, FuseInput{SharedCDN: true}, codeSet{}); len(out) != 0 {
		t.Errorf("shared-CDN ip-only should be excluded, got %d", len(out))
	}
	// NAT dst-only excluded
	if out := applyGuardrails([]ScoredCandidate{{App: "X", Score: 50, Sources: []Source{SrcIPCatalog}, BestScope: ScopeDstIP}}, FuseInput{NATSource: true}, codeSet{}); len(out) != 0 {
		t.Errorf("NAT dst-only should be excluded, got %d", len(out))
	}
}

func TestModule_DetectConflicts(t *testing.T) {
	p := DefaultScoringPolicy()
	authVsAuth := []ScoredCandidate{
		{App: "Teams", Sources: []Source{SrcNGFWAppID}},
		{App: "Zoom", Sources: []Source{SrcIPFIXAppID}},
	}
	if detectConflicts(authVsAuth, p).Type != ConflictAuthoritative {
		t.Error("two authoritative sources disagreeing should conflict")
	}
	authVsWeak := []ScoredCandidate{
		{App: "Teams", Sources: []Source{SrcNGFWAppID}},
		{App: "Zoom", Sources: []Source{SrcIPCatalog}},
	}
	if detectConflicts(authVsWeak, p).Type != ConflictNone {
		t.Error("authoritative vs weak is not an authoritative conflict")
	}
}
