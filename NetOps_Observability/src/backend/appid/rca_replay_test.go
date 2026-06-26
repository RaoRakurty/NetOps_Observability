package appid

import (
	"testing"
	"time"
)

// #11 a tenant-defined application mapping is applied (tenant override precedence).
// Cross-tenant ISOLATION is enforced by the store (which tenant's catalog/canon is
// supplied) + app_aliases RLS; the engine simply applies the tenant's mapping.
func TestFuse_TenantOverrideApplied(t *testing.T) {
	o := ob(SrcOperator, "internal-payroll", func(o *ApplicationObservation) { o.SessionID = "s1"; o.TenantID = "acme" })
	canon := func(_, a string) string {
		if a == "internal-payroll" {
			return "Payroll" // acme's tenant-defined name
		}
		return a
	}
	r := FuseObservations(fin([]ApplicationObservation{o}, func(f *FuseInput) { f.Canon = canon; f.Scope.SessionID = "s1" }))
	if r.App != "Payroll" || r.Band != BandAuthoritative {
		t.Fatalf("tenant override not applied: app=%q band=%s", r.App, r.Band)
	}
}

// #14 multiple unrelated apps failing on the same seam → shared-infrastructure evidence.
func TestSeamImpact_SharedInfrastructure(t *testing.T) {
	if k := AnalyzeSeamImpact([]string{"Teams", "Zoom", "Salesforce"}, nil); k != ImpactSharedInfra {
		t.Errorf("multiple apps on one seam should read shared-infra, got %s", k)
	}
}

// #15 one app fails while others stay healthy → app/provider-specific evidence.
func TestSeamImpact_AppSpecific(t *testing.T) {
	if k := AnalyzeSeamImpact([]string{"Teams"}, []string{"Zoom", "Slack"}); k != ImpactAppSpecific {
		t.Errorf("one-fails-others-healthy should read app-specific, got %s", k)
	}
}

func TestEmitRCAEvidenceRoles(t *testing.T) {
	confirmed := FusedIdentity{Verdict: Verdict{App: "Microsoft Teams"}, Band: BandAuthoritative, State: StateObserved, FusionID: "f1"}
	if e := EmitRCAEvidence(confirmed, "corr-1"); e.Role != RoleSupporting || e.CorrelationID != "corr-1" || e.App != "Microsoft Teams" {
		t.Errorf("confirmed identity should support: %+v", e)
	}
	conflicted := FusedIdentity{Verdict: Verdict{App: "unknown"}, State: StateConflicted}
	if EmitRCAEvidence(conflicted, "corr-1").Role != RoleContradicting {
		t.Error("conflicted identity should contradict")
	}
	unknown := FusedIdentity{Verdict: Verdict{App: "unknown"}, State: StateUnknown}
	if EmitRCAEvidence(unknown, "corr-1").Role != RoleConcurrent {
		t.Error("unknown identity should be concurrent context")
	}
}

// #12 late DNS evidence → a NEW versioned fused result; the old result is preserved.
func TestReplay_LateEvidenceNewVersionOldPreserved(t *testing.T) {
	scope := IdentityScope{SessionID: "s1", DstIP: "203.0.113.9"}
	// v1: ngfw only.
	v1 := FuseObservations(FuseInput{Scope: scope, CatalogVersion: 1, Now: fuseNow,
		Observations: []ApplicationObservation{ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" })}})
	// late DNS arrives → replay at catalog v2 with both observations.
	res := ReplayFusion(v1, FuseInput{Scope: scope, CatalogVersion: 2, Now: fuseNow.Add(time.Minute),
		Observations: []ApplicationObservation{
			ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" }),
			ob(SrcDNS, "Microsoft Teams"),
		}}, ReplayLateEvidence)
	if res.New.FusionID == res.Old.FusionID {
		t.Error("replay at a new catalog version must yield a new fusion id (old preserved)")
	}
	if res.Old.FusionID != v1.FusionID || res.Old.State != v1.State {
		t.Error("old result must be preserved verbatim")
	}
	if !codeContains(res.New.Explanations, ExLateEvidenceReplay) {
		t.Error("late-evidence replay should be flagged")
	}
	if res.New.State != StateFused { // ngfw + dns now corroborate
		t.Errorf("new result should be fused, got %s", res.New.State)
	}
}

// #13 a catalog version change preserves reproducibility of the historical decision.
func TestReplay_HistoricalReproducible(t *testing.T) {
	build := func(cat int) FuseInput {
		return FuseInput{Scope: IdentityScope{SessionID: "s1"}, CatalogVersion: cat, Now: fuseNow,
			Observations: []ApplicationObservation{ob(SrcNGFWAppID, "Zoom", func(o *ApplicationObservation) { o.SessionID = "s1" })}}
	}
	// same catalog version → identical (historical decision reproducible).
	a := FuseObservations(build(1))
	b := FuseObservations(build(1))
	if a.FusionID != b.FusionID || a.App != b.App || a.Band != b.Band {
		t.Fatal("same catalog version must reproduce the historical decision bit-for-bit")
	}
	// new catalog version → new id, but the old (v1) id is still reproducible above.
	if FuseObservations(build(2)).FusionID == a.FusionID {
		t.Error("a new catalog version must produce a distinct versioned id")
	}
}
