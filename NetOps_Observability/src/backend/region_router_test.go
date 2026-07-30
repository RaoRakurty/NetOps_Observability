package backend

import "testing"

// TestEffectiveTenantRegion: explicit tenant region wins; blank inherits the
// org's home_region; otherwise the platform default.
func TestEffectiveTenantRegion(t *testing.T) {
	s := newPBACTestServer(t)
	if _, err := s.orgs.Create("Acme Corp", "acme-corp", "", "eu-central", ""); err != nil {
		t.Fatal(err)
	}
	// tenant inherits org region
	inh, err := s.tenants.Create("Acme Prod", "", "", "", "acme-corp")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.effectiveTenantRegion(inh); got != "eu-central" {
		t.Errorf("inherited region = %q, want eu-central", got)
	}
	// explicit tenant region overrides the org
	ov, err := s.tenants.SetRegion(inh.ID, "us-west")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.effectiveTenantRegion(ov); got != "us-west" {
		t.Errorf("explicit region = %q, want us-west", got)
	}
	// unknown region rejected
	if _, err := s.tenants.SetRegion(inh.ID, "atlantis"); err == nil {
		t.Error("unknown region should be rejected")
	}
	// a tenant in the global org (default region) inherits the default
	g, _ := s.tenants.Get(TenantGlobal)
	if got := s.effectiveTenantRegion(g); got != RegionDefault {
		t.Errorf("global tenant region = %q, want %q", got, RegionDefault)
	}
}

// TestDataPlaneRouting: every region resolves to the LOCAL stack by default; an
// env override re-points a region (the multi-region seam, config not code).
func TestDataPlaneRouting(t *testing.T) {
	// default → local
	dp := dataPlaneFor("eu-central")
	if !dp.Local || dp.ClickHouse == "" {
		t.Errorf("default region should resolve to the local stack, got %+v", dp)
	}
	// env override re-points the region
	t.Setenv(dataPlaneEnvKey("eu-central"), "ch=https://ch.eu;os=https://os.eu;vm=https://vm.eu;kafka=eu:9092")
	dp = dataPlaneFor("eu-central")
	if dp.Local || dp.ClickHouse != "https://ch.eu" || dp.OpenSearch != "https://os.eu" || dp.Kafka != "eu:9092" {
		t.Errorf("override not applied: %+v", dp)
	}
	// a different region still resolves local
	if !dataPlaneFor("us-east").Local {
		t.Error("unconfigured region should stay local")
	}
}

// TestTenantDataPlane: the routing layer maps a tenant through its region to a
// data plane.
func TestTenantDataPlane(t *testing.T) {
	s := newPBACTestServer(t)
	if _, err := s.tenants.Create("Euro", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.SetRegion("euro", "eu-west"); err != nil {
		t.Fatal(err)
	}
	if dp := s.tenantDataPlane("euro"); dp.Region != "eu-west" {
		t.Errorf("tenant data plane region = %q, want eu-west", dp.Region)
	}
}
