package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/models"
)

func TestSiteSlug(t *testing.T) {
	cases := map[string]string{
		"Dallas Branch":   "dallas-branch",
		"  DC-East / 1  ": "dc-east-1",
		"HQ__Campus":      "hq-campus",
		"Frankfurt.POP":   "frankfurt-pop",
		"a   b":           "a-b", // collapse runs of separators
		"---":             "",
		"München 9":       "mnchen-9", // non-ascii dropped (ascii-only slug)
	}
	for in, want := range cases {
		if got := siteSlug(in); got != want {
			t.Errorf("siteSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSiteValidate(t *testing.T) {
	bad := []Site{
		{Slug: "", Name: "x"},                                          // no slug
		{Slug: "x", Name: ""},                                          // no name
		{Slug: "x", Name: "y", HasCoords: true, Lat: 91},               // lat OOB
		{Slug: "x", Name: "y", HasCoords: true, Lng: -181},             // lng OOB
		{Slug: "x", Name: string(make([]byte, 121)), HasCoords: false}, // name too long
	}
	for i, b := range bad {
		if err := b.validate(); err == nil {
			t.Errorf("case %d: validate(%+v) = nil, want error", i, b)
		}
	}
	// A coordless site is valid (surfaces as "not placed").
	if err := (Site{Slug: "den", Name: "Denver"}).validate(); err != nil {
		t.Errorf("coordless site rejected: %v", err)
	}
	// 0,0 is a valid coordinate when explicitly flagged.
	if err := (Site{Slug: "null", Name: "Null Island", HasCoords: true}).validate(); err != nil {
		t.Errorf("0,0 rejected: %v", err)
	}
}

func newTestSitesStore(t *testing.T) *sitesStore {
	t.Helper()
	s, err := newSitesStore(filepath.Join(t.TempDir(), "sites.json"))
	if err != nil {
		t.Fatalf("newSitesStore: %v", err)
	}
	return s
}

func TestSitesStoreCRUD(t *testing.T) {
	s := newTestSitesStore(t)
	if !s.Empty() {
		t.Fatal("new store should be empty")
	}

	if _, err := s.Upsert(Site{Slug: "nyc", Name: "New York", Lat: 40.7, Lng: -74, HasCoords: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := s.Upsert(Site{Slug: "lon", Name: "London"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if s.Empty() {
		t.Fatal("store should not be empty after upsert")
	}

	got, ok := s.Get("nyc")
	if !ok || got.Name != "New York" || !got.HasCoords || got.Lat != 40.7 {
		t.Fatalf("get nyc = %+v ok=%v", got, ok)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not stamped")
	}

	// All is sorted by slug.
	all := s.All()
	if len(all) != 2 || all[0].Slug != "lon" || all[1].Slug != "nyc" {
		t.Fatalf("All not sorted by slug: %+v", all)
	}

	// Upsert replaces in place (no duplicate).
	if _, err := s.Upsert(Site{Slug: "nyc", Name: "NYC DC"}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if all := s.All(); len(all) != 2 {
		t.Fatalf("re-upsert created a duplicate: %d rows", len(all))
	}

	// Persistence: a fresh store at the same path reloads the rows.
	reloaded, err := newSitesStore(s.path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if g, ok := reloaded.Get("nyc"); !ok || g.Name != "NYC DC" {
		t.Fatalf("reload lost data: %+v ok=%v", g, ok)
	}

	if err := s.Delete("nyc"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.Get("nyc"); ok {
		t.Fatal("nyc still present after delete")
	}
	if err := s.Delete("nope"); err == nil {
		t.Fatal("delete of missing slug should error")
	}
}

func TestInternalProviderSites(t *testing.T) {
	s := newTestSitesStore(t)
	s.Upsert(Site{Slug: "nyc", Name: "New York", Lat: 40.7, Lng: -74, HasCoords: true})
	s.Upsert(Site{Slug: "den", Name: "Denver"}) // no coords

	p := &internalProvider{sites: s}
	if p.Name() != "internal" || !p.Configured() {
		t.Fatalf("internal provider name/configured wrong")
	}
	if ds, _ := p.DeviceSites(context.Background()); ds != nil {
		t.Fatalf("internal DeviceSites should be nil (placement via labels), got %+v", ds)
	}
	sites, err := p.Sites(context.Background())
	if err != nil || len(sites) != 2 {
		t.Fatalf("Sites = %+v err=%v", sites, err)
	}
	for _, st := range sites {
		if st.Source != "internal" {
			t.Errorf("site %s source = %q, want internal", st.Slug, st.Source)
		}
	}
}

// buildGeomap must carry the provider source onto each row so the geo projection
// attaches the right evidence source; operator annotations are "manual".
func TestBuildGeomapCarriesSource(t *testing.T) {
	now := time.Now()
	sites := []SoTSite{{Slug: "nyc", Name: "NYC", Lat: 40.7, Lng: -74, HasCoords: true, Source: "internal"}}
	devices := []models.Device{
		{ID: "a", Labels: map[string]string{"site": "nyc"}, LastSeen: now}, // internal-sited
		{ID: "b", Name: "edge1", Address: "10.0.0.9", LastSeen: now},       // annotated below
	}
	lookup := func(toks []string) (DeviceLocation, bool) {
		for _, tok := range toks {
			if tok == "ip:10.0.0.9" {
				return DeviceLocation{Site: "Edge", Lat: 1, Lng: 2}, true
			}
		}
		return DeviceLocation{}, false
	}
	rows, _, _ := buildGeomap(sites, devices, nil, lookup, now)
	bySlug := map[string]geoSite{}
	for _, r := range rows {
		bySlug[r.Slug] = r
	}
	if bySlug["nyc"].Source != "internal" {
		t.Errorf("nyc source = %q, want internal", bySlug["nyc"].Source)
	}
	if bySlug["loc:edge"].Source != "manual" {
		t.Errorf("annotation source = %q, want manual", bySlug["loc:edge"].Source)
	}
}
