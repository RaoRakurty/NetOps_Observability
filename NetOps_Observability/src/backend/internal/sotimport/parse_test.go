// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package sotimport

import (
	"testing"
)

func TestParseImportSites(t *testing.T) {
	// CSV with aliased headers + a coordinate-less row.
	csv := "name,slug,status,owner,latitude,longitude\n" +
		"New York,nyc,active,NetEng,40.71,-74.01\n" +
		"Backup,,planned,,,\n"
	rows, err := ParseSites("csv", []byte(csv))
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	if len(rows) != 2 || rows[0].Slug != "nyc" || !rows[0].HasCoords || rows[0].Lat != 40.71 || rows[0].Lng != -74.01 {
		t.Fatalf("csv row0 = %+v", rows[0])
	}
	if rows[1].HasCoords {
		t.Fatalf("csv row1 should have no coords: %+v", rows[1])
	}

	// JSON array.
	jrows, err := ParseSites("json", []byte(`[{"name":"LA","slug":"lax","lat":34.05,"lng":-118.24}]`))
	if err != nil || len(jrows) != 1 || !jrows[0].HasCoords || jrows[0].Lat != 34.05 {
		t.Fatalf("json: %v %+v", err, jrows)
	}

	// GeoJSON — coordinates are [lng, lat] (lng FIRST); we must not swap them.
	geo := `{"type":"FeatureCollection","features":[
	  {"type":"Feature","geometry":{"type":"Point","coordinates":[-74.01,40.71]},
	   "properties":{"name":"New York","slug":"nyc","owner":"NetEng"}}]}`
	grows, err := ParseSites("geojson", []byte(geo))
	if err != nil || len(grows) != 1 {
		t.Fatalf("geojson: %v %+v", err, grows)
	}
	if grows[0].Lat != 40.71 || grows[0].Lng != -74.01 {
		t.Fatalf("geojson lng/lat order wrong: lat=%v lng=%v (want 40.71/-74.01)", grows[0].Lat, grows[0].Lng)
	}
	if grows[0].Owner != "NetEng" {
		t.Fatalf("geojson properties not read: %+v", grows[0])
	}
}

func TestParseImportBindings(t *testing.T) {
	csv := "device,site\nleaf1,nyc\n10.0.0.2,lax\n"
	rows, err := ParseBindings("csv", []byte(csv))
	if err != nil || len(rows) != 2 || rows[0].Device != "leaf1" || rows[0].Site != "nyc" || rows[1].Device != "10.0.0.2" {
		t.Fatalf("csv: %v %+v", err, rows)
	}
	jrows, err := ParseBindings("json", []byte(`[{"device":"SN1","site":"nyc"}]`))
	if err != nil || len(jrows) != 1 || jrows[0].Device != "SN1" {
		t.Fatalf("json: %v %+v", err, jrows)
	}
}
