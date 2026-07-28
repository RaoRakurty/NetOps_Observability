package main

import "testing"

// Administratively-configurable default landing (Increment 2): sanitization, the
// per-tenant setter, and the resolution order (tenant → global default → none).

func TestSetDefaultLandingPersistsAndValidates(t *testing.T) {
	s, err := newTenantStore(t.TempDir() + "/tenants.json")
	if err != nil {
		t.Fatal(err)
	}
	acme, err := s.Create("Acme", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// A valid route persists.
	if _, err := s.SetDefaultLanding(acme.ID, "#/incident/overview"); err != nil {
		t.Fatalf("set landing: %v", err)
	}
	got, _ := s.Get(acme.ID)
	if got.DefaultLanding != "#/incident/overview" {
		t.Fatalf("landing not persisted, got %q", got.DefaultLanding)
	}

	// An invalid route is rejected and leaves the stored value unchanged.
	if _, err := s.SetDefaultLanding(acme.ID, "https://evil.com"); err == nil {
		t.Fatal("invalid landing should be rejected")
	}
	got, _ = s.Get(acme.ID)
	if got.DefaultLanding != "#/incident/overview" {
		t.Fatalf("rejected write must not mutate, got %q", got.DefaultLanding)
	}

	// Blank clears back to inherit.
	if _, err := s.SetDefaultLanding(acme.ID, ""); err != nil {
		t.Fatalf("clear landing: %v", err)
	}
	if got, _ = s.Get(acme.ID); got.DefaultLanding != "" {
		t.Fatalf("blank should clear, got %q", got.DefaultLanding)
	}
}

// The resolution order: a tenant's own value wins; a blank tenant inherits the
// global tenant's value (the platform default); neither set → empty (SPA home).
func TestDefaultLandingResolutionOrder(t *testing.T) {
	s, err := newTenantStore(t.TempDir() + "/tenants.json")
	if err != nil {
		t.Fatal(err)
	}
	acme, _ := s.Create("Acme", "", "", "", "")

	// Platform default via the global tenant.
	if _, err := s.SetDefaultLanding(TenantGlobal, "#/dashboards/home"); err != nil {
		t.Fatalf("set global default: %v", err)
	}
	resolve := func(tenant string) string {
		if tenant != "" && tenant != TenantGlobal {
			if tt, ok := s.Get(tenant); ok && tt.DefaultLanding != "" {
				return tt.DefaultLanding
			}
		}
		if g, ok := s.Get(TenantGlobal); ok {
			return g.DefaultLanding
		}
		return ""
	}

	if got := resolve(acme.ID); got != "#/dashboards/home" {
		t.Fatalf("blank tenant should inherit platform default, got %q", got)
	}
	// Tenant override wins.
	if _, err := s.SetDefaultLanding(acme.ID, "#/incident/overview"); err != nil {
		t.Fatal(err)
	}
	if got := resolve(acme.ID); got != "#/incident/overview" {
		t.Fatalf("tenant override should win, got %q", got)
	}
}
