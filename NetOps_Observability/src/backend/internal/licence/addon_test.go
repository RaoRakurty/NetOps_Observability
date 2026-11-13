// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package licence_test

import (
	"strings"
	"testing"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
)

// The AI add-on (owner decision 2026-11-12, confirmed 2026-11-13): model-backed
// Iris is `iris_model`. Enterprise INCLUDES it whether or not the file lists it;
// Team and Community have it only when the file carries the add-on line.

func TestTeamLicenceWithoutTheAddOnHasNoModelIris(t *testing.T) {
	kp := testKey(t)
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(signDoc(t, teamDoc(), kp), issued.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if st.Has(entitlement.FeatureIrisModel) {
		t.Fatal("a Team licence that does not carry the add-on line must not grant model-backed Iris")
	}
	svc := licence.NewService(licence.NewStaticStore(st))
	e, ok := entitlement.As(entitlement.Require(svc, entitlement.FeatureIrisModel))
	if !ok {
		t.Fatal("the refusal must be a structured *ErrLicence")
	}
	if e.LiftedBy != entitlement.TierEnterprise {
		t.Fatalf("Enterprise includes the add-on; lifted_by = %q", e.LiftedBy)
	}
	if !strings.Contains(e.Message, "add-on") {
		t.Fatalf("the refusal must say the add-on can be bought without upgrading: %q", e.Message)
	}
}

func TestTeamLicenceWithTheAddOnLineHasModelIris(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.Features = append(d.Features, entitlement.FeatureIrisModel)
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(signDoc(t, d, kp), issued.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Has(entitlement.FeatureIrisModel) || !st.Has(entitlement.FeatureSecurityFindings) {
		t.Fatalf("the add-on line must grant iris_model beside the tier's own features: %v", st.Features)
	}
}

// TestEnterpriseIncludesTheAddOnUnlisted is the lab's case: an Enterprise
// licence issued before `iris_model` existed lists the seven older features and
// must gain the add-on WITHOUT being re-issued (an old binary would refuse a
// licence naming the new feature).
func TestEnterpriseIncludesTheAddOnUnlisted(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.Tier = entitlement.TierEnterprise
	d.Ceilings, _ = entitlement.TierCeilings(entitlement.TierEnterprise)
	d.Features = []entitlement.Feature{
		entitlement.FeatureLDAP, entitlement.FeatureMSPManagement, entitlement.FeatureSAML, entitlement.FeatureSCIM,
		entitlement.FeatureSecurityDialects, entitlement.FeatureSecurityFindings, entitlement.FeatureSIEMExport,
	}
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(signDoc(t, d, kp), issued.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Has(entitlement.FeatureIrisModel) {
		t.Fatalf("Enterprise includes the AI add-on: %v", st.Features)
	}
	// Inclusion adds exactly the included set — nothing the file did not grant
	// and the tier does not include.
	if len(st.Features) != len(d.Features)+1 {
		t.Fatalf("features = %v", st.Features)
	}
	svc := licence.NewService(licence.NewStaticStore(st))
	if err := entitlement.Require(svc, entitlement.FeatureIrisModel); err != nil {
		t.Fatalf("Require must admit the included add-on: %v", err)
	}
}

// TestEnterpriseListingTheAddOnIsNotDoubled: a new Enterprise licence that does
// list it carries it once.
func TestEnterpriseListingTheAddOnIsNotDoubled(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.Tier = entitlement.TierEnterprise
	d.Ceilings, _ = entitlement.TierCeilings(entitlement.TierEnterprise)
	d.Features = []entitlement.Feature{entitlement.FeatureIrisModel}
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(signDoc(t, d, kp), issued.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Features) != 1 || st.Features[0] != entitlement.FeatureIrisModel {
		t.Fatalf("features = %v", st.Features)
	}
}

// TestIncludedAddOnLapsesLikeAnyFeature: past grace the included add-on moves
// to the lapsed set with everything else — no new model calls, and the
// read-only half (EntitledForRead) still admits existing AI findings.
func TestIncludedAddOnLapsesLikeAnyFeature(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.Tier = entitlement.TierEnterprise
	d.Ceilings, _ = entitlement.TierCeilings(entitlement.TierEnterprise)
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(signDoc(t, d, kp), expires.AddDate(0, 3, 0))
	if err != nil {
		t.Fatal(err)
	}
	svc := licence.NewService(licence.NewStaticStore(st))
	if entitlement.Entitled(svc, entitlement.FeatureIrisModel) {
		t.Fatal("past grace the add-on is not entitled for new use")
	}
	if !entitlement.EntitledForRead(svc, entitlement.FeatureIrisModel) {
		t.Fatal("past grace what the add-on produced stays readable")
	}
}

// TestCommunityHasNoModelIris: no file, no add-on.
func TestCommunityHasNoModelIris(t *testing.T) {
	svc := licence.NewService(licence.NewStaticStore(licence.Community()))
	if entitlement.Entitled(svc, entitlement.FeatureIrisModel) {
		t.Fatal("Community without the add-on line must not grant model-backed Iris")
	}
}
