// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"testing"
	"time"
)

var fuseNow = time.Unix(1782460000, 0).UTC()

func ob(src Source, app string, mut ...func(*ApplicationObservation)) ApplicationObservation {
	o := ApplicationObservation{Source: src, VendorAppName: app, TenantID: "acme", EventTime: fuseNow, DstIP: "203.0.113.9"}
	for _, m := range mut {
		m(&o)
	}
	return o
}

func fin(obs []ApplicationObservation, mut ...func(*FuseInput)) FuseInput {
	f := FuseInput{Observations: obs, Now: fuseNow, CatalogVersion: 1,
		Scope: IdentityScope{DstIP: "203.0.113.9", DstPort: 443, Proto: "tcp"}}
	for _, m := range mut {
		m(&f)
	}
	return f
}

func hasCode(fi FusedIdentity, c ExplanationCode) bool {
	for _, x := range fi.Explanations {
		if x == c {
			return true
		}
	}
	return false
}

// #1 FortiGate identifies Teams on the exact session → authoritative.
func TestFuse_AuthoritativeSessionTeams(t *testing.T) {
	o := ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" })
	r := FuseObservations(fin([]ApplicationObservation{o}, func(f *FuseInput) { f.Scope.SessionID = "s1" }))
	if r.App != "Microsoft Teams" || r.Tier != Confirmed || r.Band != BandAuthoritative {
		t.Fatalf("want authoritative Teams, got app=%q tier=%s band=%s", r.App, r.Tier, r.Band)
	}
	if r.State != StateObserved || !hasCode(r, ExSessionUpstream) {
		t.Errorf("state=%s codes=%v", r.State, r.Explanations)
	}
}

// #2 Palo Alto ms-teams canonicalizes to the same business application.
func TestFuse_VendorAliasCanonicalized(t *testing.T) {
	o := ob(SrcNGFWAppID, "ms-teams", func(o *ApplicationObservation) { o.SessionID = "s1"; o.Vendor = "paloalto" })
	canon := func(_, a string) string {
		if a == "ms-teams" {
			return "Microsoft Teams"
		}
		return a
	}
	r := FuseObservations(fin([]ApplicationObservation{o}, func(f *FuseInput) { f.Canon = canon; f.Scope.SessionID = "s1" }))
	if r.App != "Microsoft Teams" || !hasCode(r, ExVendorAliasCanon) {
		t.Fatalf("alias not canonicalized: app=%q codes=%v", r.App, r.Explanations)
	}
}

// #3 Cisco reports a protocol; DNS identifies the app — protocol ≠ application.
// (the protocol-only Cisco event produced no observation; only DNS reaches fusion.)
func TestFuse_ProtocolSeparateFromApp(t *testing.T) {
	r := FuseObservations(fin([]ApplicationObservation{ob(SrcDNS, "YouTube")}))
	if r.App != "YouTube" {
		t.Fatalf("DNS should identify YouTube, got %q", r.App)
	}
	if r.App == "QUIC" || r.App == "HTTPS" {
		t.Error("a protocol must never be the business app")
	}
	if r.State != StateInferred {
		t.Errorf("dns-only should be inferred, got %s", r.State)
	}
}

// #4 TCP/443 with no other evidence → HTTPS service class, business app UNKNOWN.
func TestFuse_PortOnlyIsNotABusinessApp(t *testing.T) {
	r := FuseObservations(fin([]ApplicationObservation{ob(SrcPort, "HTTPS")}))
	if r.App != "unknown" {
		t.Fatalf("port-only must NOT assert a business app, got %q", r.App)
	}
	if !hasCode(r, ExPortOnlyFallback) || r.Band != BandUnresolved {
		t.Errorf("want port-only-fallback/unresolved, codes=%v band=%s", r.Explanations, r.Band)
	}
}

// #5 A provider IP range does not become the provider's flagship app.
func TestFuse_ProviderIPIsNotTheApp(t *testing.T) {
	r := FuseObservations(fin([]ApplicationObservation{ob(SrcIPCatalog, "Microsoft")}))
	if r.App != "Microsoft" {
		t.Fatalf("provider-IP should resolve to the provider, got %q", r.App)
	}
	if r.App == "Microsoft Teams" {
		t.Error("a Microsoft IP must not become Microsoft Teams")
	}
	if !hasCode(r, ExProviderOnlyIP) || r.State != StateInferred {
		t.Errorf("want provider-only/inferred, codes=%v state=%s", r.Explanations, r.State)
	}
}

// #6 Expired DNS evidence is rejected.
func TestFuse_StaleDNSRejected(t *testing.T) {
	old := ob(SrcDNS, "YouTube", func(o *ApplicationObservation) { o.EventTime = fuseNow.Add(-10 * time.Minute) })
	r := FuseObservations(fin([]ApplicationObservation{old})) // default TTL 5m
	if r.App != "unknown" || !hasCode(r, ExStaleDNS) {
		t.Fatalf("stale DNS should be rejected → unknown, got app=%q codes=%v", r.App, r.Explanations)
	}
}

// #7 Two authoritative sources disagree → conflicted; identity NOT asserted.
func TestFuse_AuthoritativeConflict(t *testing.T) {
	a := ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" })
	b := ob(SrcIPFIXAppID, "Zoom", func(o *ApplicationObservation) { o.SessionID = "s1" })
	r := FuseObservations(fin([]ApplicationObservation{a, b}, func(f *FuseInput) { f.Scope.SessionID = "s1" }))
	if r.State != StateConflicted || r.App != "unknown" {
		t.Fatalf("want conflicted/unknown, got state=%s app=%q", r.State, r.App)
	}
	if !hasCode(r, ExAuthoritativeConflict) || len(r.Alternatives) == 0 {
		t.Errorf("conflict should surface code + alternatives, codes=%v alts=%d", r.Explanations, len(r.Alternatives))
	}
}

// #8 Duplicate firewall logs do not inflate confidence.
func TestFuse_DuplicateEvidenceIgnored(t *testing.T) {
	mk := func() ApplicationObservation {
		return ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" })
	}
	one := FuseObservations(fin([]ApplicationObservation{mk()}, func(f *FuseInput) { f.Scope.SessionID = "s1" }))
	two := FuseObservations(fin([]ApplicationObservation{mk(), mk()}, func(f *FuseInput) { f.Scope.SessionID = "s1" }))
	if two.Confidence != one.Confidence {
		t.Errorf("duplicate inflated confidence: %v vs %v", two.Confidence, one.Confidence)
	}
	if !hasCode(two, ExDuplicateIgnored) || two.State != StateObserved {
		t.Errorf("duplicate should be ignored + stay single-source, codes=%v state=%s", two.Explanations, two.State)
	}
}

// #9 NAT-collapsed source: dst-only inferential evidence is not attributed.
func TestFuse_NATAmbiguity(t *testing.T) {
	o := ob(SrcIPCatalog, "Salesforce") // dst-only, no session
	r := FuseObservations(fin([]ApplicationObservation{o}, func(f *FuseInput) { f.NATSource = true }))
	if r.App != "unknown" || !hasCode(r, ExNATAmbiguity) {
		t.Fatalf("NAT dst-only should not attribute, got app=%q codes=%v", r.App, r.Explanations)
	}
}

// #10 Shared CDN evidence cannot independently prove an application.
func TestFuse_SharedCDNAmbiguity(t *testing.T) {
	o := ob(SrcIPCatalog, "SomeSaaS")
	r := FuseObservations(fin([]ApplicationObservation{o}, func(f *FuseInput) { f.SharedCDN = true }))
	if r.App != "unknown" || !hasCode(r, ExSharedCDNAmbiguity) {
		t.Fatalf("shared CDN ip should not prove the app, got app=%q codes=%v", r.App, r.Explanations)
	}
}

// independent corroboration: NGFW session + DNS agree → fused, multi-source.
func TestFuse_MultipleIndependentSources(t *testing.T) {
	a := ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" })
	b := ob(SrcDNS, "Microsoft Teams")
	r := FuseObservations(fin([]ApplicationObservation{a, b}, func(f *FuseInput) { f.Scope.SessionID = "s1" }))
	if r.State != StateFused || !hasCode(r, ExMultiIndependent) || !hasCode(r, ExSessionUpstream) {
		t.Fatalf("want fused + multi-independent + session, state=%s codes=%v", r.State, r.Explanations)
	}
}

// DNS + SNI corroboration.
func TestFuse_DNSTLSCorroboration(t *testing.T) {
	r := FuseObservations(fin([]ApplicationObservation{ob(SrcDNS, "Slack"), ob(SrcSNI, "Slack")}))
	if !hasCode(r, ExDNSTLSCorroboration) || r.App != "Slack" {
		t.Fatalf("want dns+tls corroboration for Slack, app=%q codes=%v", r.App, r.Explanations)
	}
}

// determinism / replay: same inputs (incl. Now + catalog version) → identical id + result.
func TestFuse_DeterministicReplay(t *testing.T) {
	build := func() FuseInput {
		return fin([]ApplicationObservation{ob(SrcNGFWAppID, "Zoom", func(o *ApplicationObservation) { o.SessionID = "s9" })},
			func(f *FuseInput) { f.Scope.SessionID = "s9" })
	}
	a := FuseObservations(build())
	b := FuseObservations(build())
	if a.FusionID != b.FusionID || a.App != b.App || a.Band != b.Band || a.FusionVersion != FusionEngineVersion {
		t.Fatalf("fusion not deterministic: %+v vs %+v", a, b)
	}
	if a.FusionID == "" {
		t.Error("fusion id must be set")
	}
}

// empty / no-opinion observations → honest unknown.
func TestFuse_NoEvidenceUnknown(t *testing.T) {
	r := FuseObservations(fin(nil))
	if r.App != "unknown" || r.State != StateUnknown || !hasCode(r, ExInsufficient) {
		t.Fatalf("no evidence must be unknown/insufficient, got app=%q state=%s codes=%v", r.App, r.State, r.Explanations)
	}
}
