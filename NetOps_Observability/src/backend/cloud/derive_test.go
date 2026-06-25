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
	// legacy-reports-worker: graph-derived → strong
	if g, ok := byID["legacy-reports-worker"]; !ok || g.Confidence != Strong || g.Source != SrcCloudGraph {
		t.Fatalf("graph app should be strong, got %+v", g)
	}
	// the untagged EC2 has no app_id → not an app
	if _, ok := byID[""]; ok {
		t.Fatal("unattributed resource must NOT become an app")
	}
}

func TestCoverage(t *testing.T) {
	c := Coverage(loadFixture(t))
	// 3 billing (tag) + others... compute from the fixture: billing alb/ecs/rds = 3 tag,
	// graph worker = 1, untagged = 1 unknown.
	if c.Total != 5 {
		t.Fatalf("total = %d, want 5", c.Total)
	}
	if c.ConfirmedTag != 3 || c.StrongGraph != 1 || c.Unknown != 1 {
		t.Fatalf("coverage wrong: %+v", c)
	}
}

func TestTopUnknown(t *testing.T) {
	u := TopUnknown(loadFixture(t), 10)
	if len(u) != 1 || u[0].AppID != "" {
		t.Fatalf("expected 1 unattributed resource, got %+v", u)
	}
}
