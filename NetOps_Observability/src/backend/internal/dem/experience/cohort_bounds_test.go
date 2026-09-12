// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// cohort_bounds_test.go — the cohort dimensions are WIRE fields (review
// 2026-09-08, 3.2-09).
//
// They arrive on the operator change route and on the beacon ingest route,
// whose credential ingest.go itself says must be assumed public, and before
// this they were the only wire fields in the package that no Validate ever
// clipped or charset-bound. A cohort dimension is rendered into Cohort.Key(),
// which is a grouping key and a rendered label, so an unbounded one is both an
// unbounded allocation per event and a control-character injection into
// everything downstream that prints a cohort.

import (
	"strings"
	"testing"
	"time"
)

// hostileCohort is one cohort with every dimension over the cap and carrying
// characters a grouping key must never hold: NULs, newlines, the Key()
// separator and a fabricated second dimension.
func hostileCohort() Cohort {
	long := strings.Repeat("A", 4000)
	return Cohort{
		Site:        long,
		ISP:         "evil\x00isp\nSet-Cookie: x=1",
		Region:      long,
		DeviceType:  "phone · flag=admin",
		Browser:     long,
		AppVersion:  strings.Repeat("9.", 500),
		NetworkType: long,
		FeatureFlag: "flag\r\nflag",
	}
}

// assertBounded fails when any dimension is over the cap or still carries a
// character labelSafe refuses.
func assertBounded(t *testing.T, what string, c Cohort) {
	t.Helper()
	dims := map[string]string{
		"site": c.Site, "isp": c.ISP, "region": c.Region, "device_type": c.DeviceType,
		"browser": c.Browser, "app_version": c.AppVersion, "network_type": c.NetworkType,
		"feature_flag": c.FeatureFlag,
	}
	for name, v := range dims {
		if len(v) > MaxCohortDimensionsLen {
			t.Errorf("%s: cohort dimension %s is %d bytes, over the %d-byte cap",
				what, name, len(v), MaxCohortDimensionsLen)
		}
		if v != labelSafe(v) {
			t.Errorf("%s: cohort dimension %s kept characters no other label in this package may carry: %q",
				what, name, v)
		}
	}
	if strings.ContainsAny(c.Key(), "\x00\r\n") {
		t.Errorf("%s: the cohort key carries a control character: %q", what, c.Key())
	}
}

func TestCohortDimensionsAreBoundedOnEveryWireShape(t *testing.T) {
	wire := func() Provenance { return prov(SourceRUM, -time.Minute) }

	t.Run("experience event (public ingest route)", func(t *testing.T) {
		e := ExperienceEvent{
			ID: "ev1", TenantID: "acme", App: "shop", Type: EventPageView,
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "experience event", e.Cohort)
	})

	t.Run("experience session", func(t *testing.T) {
		s := ExperienceSession{
			ID: "s1", TenantID: "acme", App: "shop", StartedAt: testNow.Add(-time.Hour),
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "experience session", s.Cohort)
	})

	t.Run("business event (public ingest route)", func(t *testing.T) {
		b := BusinessEvent{
			ID: "b1", TenantID: "acme", Type: "purchase",
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := b.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "business event", b.Cohort)
	})

	t.Run("change event (operator change route)", func(t *testing.T) {
		c := ChangeEvent{
			ID: "c1", TenantID: "acme", Type: ChangeApplicationDeploy, Object: "shop", Summary: "deploy",
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "change event", c.Cohort)
	})

	t.Run("journey observation", func(t *testing.T) {
		now := testNow.Add(-time.Hour)
		o := JourneyObservation{
			ID: "o1", TenantID: "acme", JourneyID: "j1", JourneyVersion: 1,
			StartedAt: now, EndedAt: now.Add(time.Second), Success: true,
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "journey observation", o.Cohort)
	})

	t.Run("evidence item", func(t *testing.T) {
		it := EvidenceItem{
			ID: "e1", TenantID: "acme", Kind: KindCohortComparison, Entity: "shop",
			Summary: "cohort moved", IndependenceGroup: ModalityRealUser,
			Cohort: hostileCohort(), Provenance: wire(),
		}
		if err := it.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		assertBounded(t, "evidence item", it.Cohort)
	})
}

// A dimension inside the cap is left exactly as the producer sent it: bounding
// must not rewrite honest data, or two cohorts that are the same stop matching.
func TestCohortNormalizeLeavesOrdinaryDimensionsAlone(t *testing.T) {
	c := Cohort{
		Site: "amsterdam-dc1", ISP: "Deutsche Telekom", Region: "eu-west",
		DeviceType: "phone", Browser: "chrome-mobile", AppVersion: "4.12.3",
		NetworkType: "cellular", FeatureFlag: "new-checkout",
	}
	want := c
	c.normalize()
	if c != want {
		t.Errorf("normalize rewrote an ordinary cohort:\n got %+v\nwant %+v", c, want)
	}
}
