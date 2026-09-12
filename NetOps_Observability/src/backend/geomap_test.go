// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"
	"time"

	"netops/backend/models"
)

func TestBuildGeomap(t *testing.T) {
	now := time.Now()
	sites := []SoTSite{
		{Name: "Dallas DC", Slug: "dallas", Lat: 32.78, Lng: -96.80, HasCoords: true, Status: "active", Source: "netbox"},
		{Name: "Discovered", Slug: "discovered", Source: "netbox"}, // no coordinates
		{Slug: ""}, // malformed — skipped
	}
	devices := []models.Device{
		{ID: "a", Labels: map[string]string{"site": "dallas"}, LastSeen: now.Add(-time.Minute)},     // up
		{ID: "b", Labels: map[string]string{"site": "dallas"}, LastSeen: now.Add(-time.Hour)},       // down
		{ID: "c", Labels: map[string]string{"site": "discovered"}, LastSeen: now.Add(-time.Minute)}, // sited, no coords
		{ID: "d", Labels: map[string]string{}, LastSeen: now},                                       // unplaced
		{ID: "e", Labels: map[string]string{"site": "ghost"}, LastSeen: now},                        // site absent from SoT
	}
	rows, unplaced, _ := buildGeomap(sites, devices, nil, nil, now)
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
	rows, unplaced, _ := buildGeomap(nil, nil, nil, nil, time.Now())
	if len(rows) != 0 || unplaced != 0 {
		t.Fatalf("expected empty result, got %v / %d", rows, unplaced)
	}
}

// Write-only sync mode: inventory devices carry NO `site` label (NetBox isn't
// read back), so placement comes from the NetBox device→site assignment map
// keyed by identity token.
func TestBuildGeomapWriteOnlyAssignment(t *testing.T) {
	now := time.Now()
	sites := []SoTSite{{Name: "Dallas", Slug: "dallas", Lat: 32.78, Lng: -96.80, HasCoords: true, Source: "netbox"}}
	devices := []models.Device{
		{ID: "snmp-leaf1", Name: "leaf1", Address: "10.70.0.1", LastSeen: now}, // no site label
	}
	assign := map[string]string{"ip:10.70.0.1": "dallas"} // from NetBox device assignment
	rows, unplaced, _ := buildGeomap(sites, devices, assign, nil, now)
	if len(rows) != 1 || rows[0].Devices != 1 || rows[0].Up != 1 {
		t.Fatalf("assignment-based placement failed: %+v", rows)
	}
	if unplaced != 0 {
		t.Errorf("device should be placed via assignment, unplaced=%d", unplaced)
	}
}

// TestBuildGeomapManualAnnotations — devices without an SoT placement fall
// back to the operator location layer: shared site labels fold into one
// bubble, label-less annotations pin under the device name, SoT still wins.
func TestBuildGeomapManualAnnotations(t *testing.T) {
	now := time.Now()
	sites := []SoTSite{{Name: "HQ", Slug: "hq", Lat: 32.7, Lng: -96.8, HasCoords: true, Source: "netbox"}}
	devices := []models.Device{
		{ID: "a", Name: "leaf1", Address: "10.0.0.1", Labels: map[string]string{"site": "hq"}, LastSeen: now},
		{ID: "b", Name: "leaf2", Address: "10.0.0.2", LastSeen: now},
		{ID: "c", Name: "leaf3", Address: "10.0.0.3", LastSeen: now.Add(-time.Hour)},
		{ID: "d", Name: "lonely", Address: "10.0.0.4", LastSeen: now},
		{ID: "e", Name: "nowhere", Address: "10.0.0.5", LastSeen: now},
	}
	locs := map[string]DeviceLocation{
		"ip:10.0.0.1": {Site: "ShouldNotWin", Lat: 1, Lng: 1}, // SoT placement must win for leaf1
		"ip:10.0.0.2": {Site: "Branch-A", Lat: 40.7, Lng: -74.0},
		"ip:10.0.0.3": {Site: "Branch-A", Lat: 40.7, Lng: -74.0},
		"ip:10.0.0.4": {Lat: 51.5, Lng: -0.1}, // no label → pins by device name
	}
	lookup := func(tokens []string) (DeviceLocation, bool) {
		for _, tok := range tokens {
			if l, ok := locs[tok]; ok {
				return l, true
			}
		}
		return DeviceLocation{}, false
	}
	rows, unplaced, _ := buildGeomap(sites, devices, nil, lookup, now)
	if unplaced != 1 {
		t.Fatalf("unplaced = %d, want 1 (only 'nowhere')", unplaced)
	}
	byName := map[string]geoSite{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if g := byName["HQ"]; g.Devices != 1 || g.Up != 1 {
		t.Fatalf("HQ = %+v, want 1 device up (SoT wins over annotation)", g)
	}
	g := byName["Branch-A"]
	if !g.HasCoords || g.Devices != 2 || g.Up != 1 || g.Down != 1 {
		t.Fatalf("Branch-A = %+v, want 2 devices (1 up, 1 down) with coords", g)
	}
	if g.Status != "manual" {
		t.Fatalf("Branch-A status = %q, want manual", g.Status)
	}
	if g := byName["lonely"]; !g.HasCoords || g.Devices != 1 {
		t.Fatalf("lonely = %+v, want a single-device pin", g)
	}
}

// TestDeviceLocationValidate — coordinate and label bounds.
func TestDeviceLocationValidate(t *testing.T) {
	for _, bad := range []DeviceLocation{
		{Lat: 91}, {Lat: -91}, {Lng: 181}, {Lng: -181},
		{Site: string(make([]byte, 121))},
	} {
		if err := bad.validate(); err == nil {
			t.Fatalf("validate(%+v) = nil, want error", bad)
		}
	}
	if err := (DeviceLocation{Site: "HQ", Lat: 32.7, Lng: -96.8}).validate(); err != nil {
		t.Fatalf("valid location rejected: %v", err)
	}
}
