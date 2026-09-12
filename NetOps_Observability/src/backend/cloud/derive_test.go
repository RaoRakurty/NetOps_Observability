// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

import (
	"context"
	"testing"
)

func loadFixture(t *testing.T) []CloudResource {
	t.Helper()
	res, err := NewFixtureProvider("testdata").ListResources(context.Background(), "org-a", "")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDeriveApps(t *testing.T) {
	apps := DeriveApps(loadFixture(t))
	byID := map[string]CloudApp{}
	for _, a := range apps {
		byID[a.AppID] = a
	}
	// billing: ALB+ECS+RDS = 3 resources, confirmed by tag
	b, ok := byID["billing"]
	if !ok || b.Resources != 3 || b.Confidence != Confirmed || b.Source != SrcCloudTag {
		t.Fatalf("billing should be 3 resources / confirmed-tag, got %+v", b)
	}
	if b.Owner != "payments" {
		t.Fatalf("billing owner should be payments, got %q", b.Owner)
	}
	// legacy-reports-worker: NAME-derived → a guess, not an app. It must not
	// appear as an application at all (audit P0-1).
	if _, ok := byID["legacy-reports-worker"]; ok {
		t.Fatal("a name-only guess must NOT be derived into an application")
	}
	// the untagged EC2 has no app_id → not an app
	if _, ok := byID[""]; ok {
		t.Fatal("unattributed resource must NOT become an app")
	}
}

func TestCoverage(t *testing.T) {
	c := Coverage(loadFixture(t))
	// billing alb/ecs/rds = 3 tag-confirmed. The name-only worker and the fully
	// untagged EC2 are BOTH unattributed — a name is a guess, not attribution, so
	// coverage reports 2 gaps, not 1 (audit 2026-07-13, P0-1). No resource may be
	// counted as strong resource-graph attribution without a STRUCTURAL relation.
	if c.Total != 5 {
		t.Fatalf("total = %d, want 5", c.Total)
	}
	if c.ConfirmedTag != 3 || c.StrongGraph != 0 || c.Unknown != 2 {
		t.Fatalf("coverage wrong: %+v", c)
	}
}

func TestTopUnknown(t *testing.T) {
	u := TopUnknown(loadFixture(t), 10)
	// BOTH the name-only guess and the untagged resource must surface for
	// remediation — the funnel must never report false coverage.
	if len(u) != 2 {
		t.Fatalf("expected 2 unattributed resources, got %d", len(u))
	}
	for _, r := range u {
		if r.AppID != "" {
			t.Fatalf("unattributed resource must carry no app identity: %+v", r)
		}
	}
}
