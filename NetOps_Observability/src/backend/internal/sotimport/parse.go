// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package sotimport parses external Source-of-Truth exports into site and
// device-site-binding rows (Phase-2 W1.7, extracted from package main): CSV
// with header aliases, JSON arrays, and RFC 7946 GeoJSON FeatureCollections
// (coordinate order [lng, lat]). Pure: no I/O, no env. The IDENTIFY/RECONCILE
// planners, the device resolver and the HTTP handler stay in main — they hold
// srv and the Site/DeviceSiteBinding domain types.
package sotimport

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxBody bounds an import upload — 1 MiB of file text is thousands of rows.
const MaxBody = 1 << 20

// ── parsed rows ─────────────────────────────────────────────────────────────

type Site struct {
	Slug      string
	Name      string
	Status    string
	Owner     string
	Lat       float64
	Lng       float64
	HasCoords bool
}

type Binding struct {
	Device string // free identifier: device id | hostname | mgmt-IP | serial
	Site   string // site slug (or name → slugified)
}

// ── results ─────────────────────────────────────────────────────────────────

type RowResult struct {
	Line   int    `json:"line"`             // 1-based source row (header = line 1)
	Key    string `json:"key"`              // site slug / device identifier
	Action string `json:"action"`           // create|update|skip|conflict|unchanged|error
	Detail string `json:"detail,omitempty"` // what would change, or why it failed
}

type Result struct {
	Kind    string         `json:"kind"`
	DryRun  bool           `json:"dry_run"`
	Summary map[string]int `json:"summary"`
	Rows    []RowResult    `json:"rows"`
}

func NewResult(kind string, dryRun bool) *Result {
	return &Result{Kind: kind, DryRun: dryRun, Summary: map[string]int{}, Rows: []RowResult{}}
}

func (r *Result) Add(line int, key, action, detail string) {
	r.Summary[action]++
	r.Rows = append(r.Rows, RowResult{Line: line, Key: key, Action: action, Detail: detail})
}

// ── parsers (pure, unit-tested) ─────────────────────────────────────────────

// csvIndex maps lower-cased header names → column index, accepting common aliases.
func csvIndex(header []string) map[string]int {
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return idx
}

func cell(rec []string, idx map[string]int, names ...string) string {
	for _, n := range names {
		if i, ok := idx[n]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
	}
	return ""
}

// parseCoords resolves an optional lat/lng pair: both blank → no coords (valid);
// either present → both must parse as finite decimals.
func parseCoords(latS, lngS string) (lat, lng float64, has bool, err error) {
	latS, lngS = strings.TrimSpace(latS), strings.TrimSpace(lngS)
	if latS == "" && lngS == "" {
		return 0, 0, false, nil
	}
	if latS == "" || lngS == "" {
		return 0, 0, false, errors.New("both latitude and longitude are required (or leave both blank)")
	}
	if lat, err = strconv.ParseFloat(latS, 64); err != nil {
		return 0, 0, false, fmt.Errorf("bad latitude %q", latS)
	}
	if lng, err = strconv.ParseFloat(lngS, 64); err != nil {
		return 0, 0, false, fmt.Errorf("bad longitude %q", lngS)
	}
	return lat, lng, true, nil
}

func ParseSites(format string, data []byte) ([]Site, error) {
	switch format {
	case "csv":
		return parseSitesCSV(data)
	case "json":
		return parseSitesJSON(data)
	case "geojson":
		return parseSitesGeoJSON(data)
	default:
		return nil, fmt.Errorf("unsupported format %q for sites (use csv, json or geojson)", format)
	}
}

func parseSitesCSV(data []byte) ([]Site, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV parse: %w", err)
	}
	if len(rows) < 1 {
		return nil, errors.New("empty CSV")
	}
	idx := csvIndex(rows[0])
	out := make([]Site, 0, len(rows)-1)
	for _, rec := range rows[1:] {
		lat, lng, has, cerr := parseCoords(
			cell(rec, idx, "lat", "latitude"), cell(rec, idx, "lng", "lon", "longitude"))
		if cerr != nil {
			return nil, cerr
		}
		out = append(out, Site{
			Slug:   cell(rec, idx, "slug"),
			Name:   cell(rec, idx, "name", "site", "site_name"),
			Status: cell(rec, idx, "status"),
			Owner:  cell(rec, idx, "owner", "team", "owner_team"),
			Lat:    lat, Lng: lng, HasCoords: has,
		})
	}
	return out, nil
}

func parseSitesJSON(data []byte) ([]Site, error) {
	var raw []struct {
		Slug   string   `json:"slug"`
		Name   string   `json:"name"`
		Status string   `json:"status"`
		Owner  string   `json:"owner"`
		Lat    *float64 `json:"lat"`
		Lng    *float64 `json:"lng"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON parse (expected an array of site objects): %w", err)
	}
	out := make([]Site, 0, len(raw))
	for _, s := range raw {
		si := Site{Slug: strings.TrimSpace(s.Slug), Name: strings.TrimSpace(s.Name),
			Status: strings.TrimSpace(s.Status), Owner: strings.TrimSpace(s.Owner)}
		if s.Lat != nil && s.Lng != nil {
			si.Lat, si.Lng, si.HasCoords = *s.Lat, *s.Lng, true
		} else if (s.Lat == nil) != (s.Lng == nil) {
			return nil, errors.New("each site needs both lat and lng, or neither")
		}
		out = append(out, si)
	}
	return out, nil
}

// parseSitesGeoJSON reads an RFC 7946 FeatureCollection of Point features.
// IMPORTANT: GeoJSON coordinate order is [longitude, latitude] (lng first).
func parseSitesGeoJSON(data []byte) ([]Site, error) {
	var fc struct {
		Type     string `json:"type"`
		Features []struct {
			Geometry struct {
				Type        string    `json:"type"`
				Coordinates []float64 `json:"coordinates"`
			} `json:"geometry"`
			Properties map[string]any `json:"properties"`
		} `json:"features"`
	}
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("GeoJSON parse: %w", err)
	}
	if !strings.EqualFold(fc.Type, "FeatureCollection") {
		return nil, errors.New("GeoJSON must be a FeatureCollection")
	}
	prop := func(p map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := p[k]; ok {
				if s, ok := v.(string); ok {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	out := make([]Site, 0, len(fc.Features))
	for _, f := range fc.Features {
		si := Site{
			Slug:   prop(f.Properties, "slug"),
			Name:   prop(f.Properties, "name", "site", "site_name"),
			Status: prop(f.Properties, "status"),
			Owner:  prop(f.Properties, "owner", "team"),
		}
		if strings.EqualFold(f.Geometry.Type, "Point") && len(f.Geometry.Coordinates) >= 2 {
			si.Lng, si.Lat, si.HasCoords = f.Geometry.Coordinates[0], f.Geometry.Coordinates[1], true
		}
		out = append(out, si)
	}
	return out, nil
}

func ParseBindings(format string, data []byte) ([]Binding, error) {
	switch format {
	case "csv":
		r := csv.NewReader(strings.NewReader(string(data)))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("CSV parse: %w", err)
		}
		if len(rows) < 1 {
			return nil, errors.New("empty CSV")
		}
		idx := csvIndex(rows[0])
		out := make([]Binding, 0, len(rows)-1)
		for _, rec := range rows[1:] {
			out = append(out, Binding{
				Device: cell(rec, idx, "device", "device_id", "host", "hostname", "name", "ip", "address", "serial"),
				Site:   cell(rec, idx, "site", "site_slug", "slug"),
			})
		}
		return out, nil
	case "json":
		var raw []struct {
			Device string `json:"device"`
			Site   string `json:"site"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("JSON parse (expected an array of {device, site}): %w", err)
		}
		out := make([]Binding, 0, len(raw))
		for _, b := range raw {
			out = append(out, Binding{Device: strings.TrimSpace(b.Device), Site: strings.TrimSpace(b.Site)})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported format %q for device_sites (use csv or json)", format)
	}
}
