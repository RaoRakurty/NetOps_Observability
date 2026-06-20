package main

import (
	"path/filepath"
	"testing"
)

func newTestOrgStore(t *testing.T) *orgStore {
	t.Helper()
	s, err := newOrgStore(filepath.Join(t.TempDir(), "orgs.json"))
	if err != nil {
		t.Fatalf("newOrgStore: %v", err)
	}
	return s
}

func TestOrgStoreSeedsGlobal(t *testing.T) {
	s := newTestOrgStore(t)
	g, ok := s.Get(OrgGlobal)
	if !ok {
		t.Fatal("global org not seeded")
	}
	if g.HomeRegion != RegionDefault {
		t.Errorf("global home_region = %q, want %q", g.HomeRegion, RegionDefault)
	}
	// Global must sort first.
	if list := s.List(); len(list) == 0 || list[0].ID != OrgGlobal {
		t.Errorf("Global should sort first, got %+v", list)
	}
}

func TestOrgCreateValidatesRegion(t *testing.T) {
	s := newTestOrgStore(t)
	if _, err := s.Create("Acme", "", "", "atlantis", ""); err == nil {
		t.Error("unknown region should be rejected")
	}
	o, err := s.Create("Acme Corp", "", "note", "eu-central", "acme-okta")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// id is opaque (not the slugified name); slug is the human handle.
	if o.Slug != "acme-corp" || o.HomeRegion != "eu-central" || o.SSOConnection != "acme-okta" {
		t.Errorf("unexpected org: %+v", o)
	}
	if o.ID == "acme-corp" || !isOrgID(o.ID) {
		t.Errorf("org id = %q, want an opaque org_ id (not the slug)", o.ID)
	}
	// blank region defaults
	d, err := s.Create("Default Co", "", "", "", "")
	if err != nil || d.HomeRegion != RegionDefault {
		t.Errorf("blank region should default, got %q (err %v)", d.HomeRegion, err)
	}
	// duplicate slug rejected
	if _, err := s.Create("Acme Corp", "", "", "", ""); err == nil {
		t.Error("duplicate org should be rejected")
	}
}

func TestOrgUpdateAndDelete(t *testing.T) {
	s := newTestOrgStore(t)
	o, err := s.Create("Globex", "", "", "us-east", "")
	if err != nil {
		t.Fatal(err)
	}
	region := "us-west"
	note := "moved west"
	got, err := s.Update(o.ID, orgUpdate{HomeRegion: &region, Note: &note})
	if err != nil || got.HomeRegion != "us-west" || got.Note != "moved west" {
		t.Fatalf("Update: %+v err=%v", got, err)
	}
	// bad region on update rejected
	bad := "nowhere"
	if _, err := s.Update(o.ID, orgUpdate{HomeRegion: &bad}); err == nil {
		t.Error("bad region on update should be rejected")
	}
	// global cannot be deleted
	if err := s.Delete(OrgGlobal); err == nil {
		t.Error("global org delete should be refused")
	}
	if err := s.Delete(o.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Get(o.ID); ok {
		t.Error("org should be gone after delete")
	}
}

func TestOrgStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orgs.json")
	s1, err := newOrgStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Create("Persisted Inc", "", "", "ap-southeast", ""); err != nil {
		t.Fatal(err)
	}
	s2, err := newOrgStore(path)
	if err != nil {
		t.Fatal(err)
	}
	o, ok := s2.Get("persisted-inc")
	if !ok || o.HomeRegion != "ap-southeast" {
		t.Errorf("org did not persist/reload: %+v ok=%v", o, ok)
	}
}

func TestTenantOrgMembership(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	// global tenant belongs to global org
	if g, _ := ts.Get(TenantGlobal); orgOf(g) != OrgGlobal {
		t.Errorf("global tenant org = %q, want %q", orgOf(g), OrgGlobal)
	}
	a, err := ts.Create("Acme Prod", "", "", "", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if a.OrgID != "acme" {
		t.Errorf("tenant org = %q, want acme", a.OrgID)
	}
	if _, err := ts.Create("Acme Dev", "", "", "", "acme"); err != nil {
		t.Fatal(err)
	}
	if n := ts.CountByOrg("acme"); n != 2 {
		t.Errorf("CountByOrg(acme) = %d, want 2", n)
	}
	if got := ts.ListByOrg("acme"); len(got) != 2 {
		t.Errorf("ListByOrg(acme) = %d tenants, want 2", len(got))
	}
	// a tenant created with no org counts under global
	if _, err := ts.Create("Orphan", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if got := ts.ListByOrg(OrgGlobal); len(got) != 2 { // global tenant + Orphan
		t.Errorf("ListByOrg(global) = %d, want 2", len(got))
	}
}
