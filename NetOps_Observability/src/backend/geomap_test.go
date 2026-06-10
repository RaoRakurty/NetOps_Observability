package main

import (
	"testing"
	"time"

	"netops/backend/models"
)

func TestBuildGeomap(t *testing.T) {
	now := time.Now()
	f := func(v float64) *float64 { return &v }
	sites := []netboxSite{
		{Name: "Dallas DC", Slug: "dallas", Latitude: f(32.78), Longitude: f(-96.80),
			Status: &struct {
				Value string `json:"value"`
			}{Value: "active"}},
		{Name: "Discovered", Slug: "discovered"}, // no coordinates
		{Slug: ""},                               // malformed — skipped
	}
	devices := []models.Device{
		{ID: "a", Labels: map[string]string{"site": "dallas"}, LastSeen: now.Add(-time.Minute)},     // up
		{ID: "b", Labels: map[string]string{"site": "dallas"}, LastSeen: now.Add(-time.Hour)},       // down
		{ID: "c", Labels: map[string]string{"site": "discovered"}, LastSeen: now.Add(-time.Minute)}, // sited, no coords
		{ID: "d", Labels: map[string]string{}, LastSeen: now},                                       // unplaced
		{ID: "e", Labels: map[string]string{"site": "ghost"}, LastSeen: now},                        // site absent from SoT
	}
	rows, unplaced := buildGeomap(sites, devices, now)
	if len(rows) != 2 {
		t.Fatalf("expected 2 site rows, got %d: %+v", len(rows), rows)
	}
	dal := rows[0]
	if dal.Slug != "dallas" || !dal.HasCoords || dal.Lat != 32.78 || dal.Lng != -96.80 {
		t.Errorf("dallas row wrong: %+v", dal)
	}
	if dal.Devices != 2 || dal.Up != 1 || dal.Down != 1 {
		t.Errorf("dallas counts wrong: %+v", dal)
	}
	if dal.Status != "active" {
		t.Errorf("status not carried: %+v", dal)
	}
	disc := rows[1]
	if disc.HasCoords || disc.Devices != 1 || disc.Up != 1 {
		t.Errorf("discovered row wrong: %+v", disc)
	}
	if unplaced != 2 { // d (no label) + e (unknown site)
		t.Errorf("unplaced = %d, want 2", unplaced)
	}
}

func TestBuildGeomapEmpty(t *testing.T) {
	rows, unplaced := buildGeomap(nil, nil, time.Now())
	if len(rows) != 0 || unplaced != 0 {
		t.Fatalf("expected empty result, got %v / %d", rows, unplaced)
	}
}
