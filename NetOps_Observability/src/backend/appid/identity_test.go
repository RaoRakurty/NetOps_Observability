package appid

import (
	"encoding/json"
	"testing"
	"time"
)

// Contract tests (#81 fusion P1) — pin the explanation-code set, band/state vocab,
// model projections and JSON shape so downstream (API/UI/runbooks) can rely on them.

func TestExplanationCodeRegistryComplete(t *testing.T) {
	// every required code (the spec's list) must be present + valid.
	required := []ExplanationCode{
		ExSessionUpstream, ExVendorAliasCanon, ExWorkloadMatch, ExDNSTLSCorroboration,
		ExMultiIndependent, ExProviderOnlyIP, ExPortOnlyFallback, ExAuthoritativeConflict,
		ExStaleDNS, ExNATAmbiguity, ExSharedCDNAmbiguity, ExDuplicateIgnored, ExInsufficient,
	}
	for _, c := range required {
		if !c.Valid() {
			t.Errorf("required explanation code %q not in registry", c)
		}
		if c.Description() == "" {
			t.Errorf("explanation code %q has no description", c)
		}
	}
	// ExplanationCodes() returns exactly the registry, sorted, no dups.
	all := ExplanationCodes()
	if len(all) != len(required) {
		t.Fatalf("ExplanationCodes()=%d, required=%d — set drifted", len(all), len(required))
	}
	seen := map[ExplanationCode]bool{}
	for i, c := range all {
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		if i > 0 && all[i-1] >= c {
			t.Errorf("ExplanationCodes() not sorted at %d: %q >= %q", i, all[i-1], c)
		}
	}
	if ExplanationCode("NOT_A_CODE").Valid() {
		t.Error("unknown code reported valid")
	}
}

func TestConfidenceBandOrderingAndMapping(t *testing.T) {
	if !(BandUnresolved.rank() < BandLow.rank() &&
		BandLow.rank() < BandMedium.rank() &&
		BandMedium.rank() < BandHigh.rank() &&
		BandHigh.rank() < BandAuthoritative.rank()) {
		t.Fatal("band ranks not strictly ordered")
	}
	cases := []struct {
		tier     Tier
		strength int
		want     ConfidenceBand
	}{
		{Confirmed, 4, BandAuthoritative}, // authoritative source, confirmed
		{Confirmed, 3, BandHigh},          // strong corroborated, confirmed but not authoritative
		{Suspected, 2, BandMedium},        // medium
		{Suspected, 1, BandLow},           // weak
		{Undetermined, 4, BandUnresolved}, // tier wins: undetermined → unresolved regardless of strength
	}
	for _, c := range cases {
		if got := BandFor(c.tier, c.strength); got != c.want {
			t.Errorf("BandFor(%s,%d)=%s want %s", c.tier, c.strength, got, c.want)
		}
	}
}

func TestIdentityScopeExactSession(t *testing.T) {
	if !(IdentityScope{SessionID: "s1"}).ExactSession() {
		t.Error("session scope should be exact-session")
	}
	if !(IdentityScope{FlowID: "f1"}).ExactSession() {
		t.Error("flow scope should be exact-session")
	}
	if (IdentityScope{DstIP: "1.2.3.4", DstPort: 443}).ExactSession() {
		t.Error("destination-only scope must NOT be exact-session")
	}
}

func TestObservationToSignalPreservesProvenance(t *testing.T) {
	o := ApplicationObservation{
		Source: SrcNGFWAppID, Vendor: "fortinet", Method: "app-control",
		VendorAppName: "Microsoft.Teams", Confidence: 0.9,
	}
	s := o.ToSignal()
	if s.Source != SrcNGFWAppID || s.App != "Microsoft.Teams" || s.Confidence != 0.9 {
		t.Fatalf("ToSignal projection wrong: %+v", s)
	}
	if s.Detail != "fortinet app-control" {
		t.Errorf("detail=%q", s.Detail)
	}
	// no app opinion → empty candidate (counts toward evidence-missing, not a candidate)
	if (ApplicationObservation{Source: SrcDNS}).ToSignal().App != "" {
		t.Error("empty vendor app should project to empty signal app")
	}
}

func TestFusedIdentityJSONEmbedsVerdict(t *testing.T) {
	fi := FusedIdentity{
		FusionID: "fz1", TenantID: "acme",
		Scope:          IdentityScope{SessionID: "s1", DstIP: "13.107.6.152"},
		Band:           BandAuthoritative,
		State:          StateFused,
		Explanations:   []ExplanationCode{ExSessionUpstream, ExMultiIndependent},
		CatalogVersion: 7, FusionVersion: FusionEngineVersion,
		FusedAt: time.Unix(0, 0).UTC(),
		Verdict: Verdict{App: "Microsoft Teams", Tier: Confirmed, Confidence: 0.95},
	}
	b, err := json.Marshal(fi)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	// embedded Verdict fields are promoted to top level (backward-compatible shape).
	for _, k := range []string{"app", "tier", "confidence", "fusion_id", "band", "state", "explanations", "fusion_version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("FusedIdentity JSON missing %q", k)
		}
	}
	if m["app"] != "Microsoft Teams" || m["band"] != "authoritative" || m["state"] != "fused" {
		t.Errorf("unexpected json values: app=%v band=%v state=%v", m["app"], m["band"], m["state"])
	}
}

func TestFusionEngineVersionSet(t *testing.T) {
	if FusionEngineVersion == "" {
		t.Fatal("FusionEngineVersion must be set for replay/versioning")
	}
}
