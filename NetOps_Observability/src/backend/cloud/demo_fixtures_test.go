package cloud

import (
	"testing"
	"time"
)

// demo_fixtures_test.go — the committed cloud demo fixtures are a PRODUCT
// SURFACE, not sample data: they are what an evaluator sees on the Cloud tab
// before connecting a real account, and they are how the region/VPC nesting is
// demonstrated at all.
//
// This guards them the way any other contract is guarded. A fixture renamed off
// the `*-topology.json` pattern, or one that loses its region, silently returns
// the Cloud tab to "No cloud network discovered yet" — which is exactly how it
// was found empty in the first place.
func TestDemoFixturesProduceNestedGroups(t *testing.T) {
	topos, err := LoadTopologies("../../../deployment/docker/demo-fixtures/cloud")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(topos) == 0 {
		t.Fatal("no *-topology.json fixtures found")
	}
	v := BuildTopologyView(topos, "", time.Now())
	t.Logf("nodes=%d edges=%d groups=%d", len(v.Nodes), len(v.Edges), len(v.Groups))
	regions, vpcs, nested := 0, 0, 0
	for _, g := range v.Groups {
		switch g.GroupType {
		case "region":
			regions++
		case "vpc":
			vpcs++
			if g.ParentID != "" {
				nested++
			}
		}
		t.Logf("  %-7s %-28s parent=%-24s children=%d", g.GroupType, g.ID, g.ParentID, len(g.Children))
	}
	if regions < 2 {
		t.Errorf("want >=2 regions (multi-region demo), got %d", regions)
	}
	if vpcs < 3 {
		t.Errorf("want >=3 vpcs, got %d", vpcs)
	}
	if nested != vpcs {
		t.Errorf("every VPC must nest under a region: %d/%d nested", nested, vpcs)
	}
}
