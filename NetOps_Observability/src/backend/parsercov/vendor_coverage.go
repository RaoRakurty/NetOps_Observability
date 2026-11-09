// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// vendor_coverage.go — the per-vendor scorecard behind /api/admin/parser/stats
// (tracker 387 PR 14, plan §6a).
//
// Two halves, kept apart because they answer different questions:
//
//   - WHAT WE CAN READ is static: vendor_coverage.json, generated from the catalogue
//     by scripts/gen-vendor-coverage.py and embedded, so the binary and the
//     catalogue it shipped with cannot disagree.
//   - WHAT WE READ TODAY is live: the router's netops_parse_status_events, through
//     Deps.QueryByVendor. An unreachable metric store is "no reading", never zero.
//
// The rows are platform-global catalogue facts and vendor-level counters. No device,
// site or tenant value exists in either half, so the route's platform-admin gate
// stays what it was (§3a rule 3).

import (
	"context"
	_ "embed" // the scorecard ships inside the binary
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed vendor_coverage.json
var vendorCoverageJSON []byte

// Lane names, the same `lane` label the router's metric carries.
const (
	laneSyslog = "syslog"
	laneTrap   = "snmptrap"
)

// liveWindow is what "today" means on the scorecard.
const liveWindow = "24h"

type (
	// LiveParse is one vendor's records on one lane over the live window. Read
	// counts a record a parser understood, including a partly decoded trap.
	LiveParse struct {
		Total int64 `json:"total"`
		Read  int64 `json:"read"`
	}

	// VendorLane is one vendor on one lane. Every count is explicit: 0 is a fact
	// about the catalogue. Live nil means no reading was available.
	VendorLane struct {
		Grammars        int            `json:"grammars"`
		MIBNodes        int            `json:"mib_nodes"`
		MIBs            int            `json:"mibs"`
		TrapDefinitions int            `json:"trap_definitions"`
		Fixtures        int            `json:"fixtures"`
		Rules           map[string]int `json:"rules"`
		Live            *LiveParse     `json:"live"`
	}

	// VendorScore is one row of the scorecard.
	VendorScore struct {
		Vendor      string `json:"vendor"`
		DisplayName string `json:"display_name"`
		// Standard marks the row for what holds for every sender.
		Standard bool `json:"standard,omitempty"`
		// Unidentified marks the row collecting records with no known vendor.
		Unidentified bool                  `json:"unidentified,omitempty"`
		Lanes        map[string]VendorLane `json:"lanes"`
	}
)

// embeddedVendorCoverage parses the scorecard. Each call returns a fresh copy, so
// a request can add its live readings without touching anything shared.
func embeddedVendorCoverage() ([]VendorScore, error) {
	var doc struct {
		Schema  int           `json:"schema"`
		Vendors []VendorScore `json:"vendors"`
	}
	if err := json.Unmarshal(vendorCoverageJSON, &doc); err != nil {
		return nil, fmt.Errorf("vendor_coverage.json: %w", err)
	}
	if doc.Schema != 1 {
		return nil, fmt.Errorf("vendor_coverage.json: schema %d, want 1", doc.Schema)
	}
	return doc.Vendors, nil
}

// readLive asks for each lane's totals by vendor. ok=false when any answer is
// missing: half a reading would show a lane as empty that is not.
func readLive(ctx context.Context, query func(context.Context, string) map[string]float64) (map[string]map[string]LiveParse, bool) {
	if query == nil {
		return nil, false
	}
	selectors := []struct{ lane, all, read string }{
		{laneSyslog, `lane="syslog"`, `lane="syslog",parser_status="parsed"`},
		{laneTrap, `lane="snmptrap"`, `lane="snmptrap",parser_status=~"decoded|partially_decoded"`},
	}
	expr := func(sel string) string {
		return fmt.Sprintf("sum by (vendor) (increase(netops_parse_status_events{%s}[%s]))", sel, liveWindow)
	}
	out := map[string]map[string]LiveParse{}
	for _, s := range selectors {
		all, read := query(ctx, expr(s.all)), query(ctx, expr(s.read))
		if all == nil || read == nil {
			return nil, false
		}
		for vendor, n := range all {
			if out[vendor] == nil {
				out[vendor] = map[string]LiveParse{}
			}
			out[vendor][s.lane] = LiveParse{Total: int64(n), Read: int64(read[vendor])}
		}
	}
	return out, true
}

// vendorScores joins the two halves. With a reading, every lane of every row gets a
// Live value (no records is {0,0}, which reads as "no lines yet"), and a vendor
// outside the scorecard folds into one row, so records from an unidentified sender
// are shown rather than lost. Without a reading every Live stays nil.
func vendorScores(rows []VendorScore, live map[string]map[string]LiveParse, ok bool) []VendorScore {
	if !ok {
		return rows
	}
	known := make(map[string]bool, len(rows))
	for i := range rows {
		known[rows[i].Vendor] = true
		if rows[i].Standard {
			continue // a row of rules, not of senders: nothing is ever attributed to it
		}
		for lane, stats := range rows[i].Lanes {
			reading := live[rows[i].Vendor][lane]
			stats.Live = &reading
			rows[i].Lanes[lane] = stats
		}
	}
	strangers := make([]string, 0, 2)
	for vendor := range live {
		if !known[vendor] {
			strangers = append(strangers, vendor)
		}
	}
	if len(strangers) == 0 {
		return rows
	}
	sort.Strings(strangers)
	total := map[string]LiveParse{}
	for _, vendor := range strangers {
		for lane, r := range live[vendor] {
			t := total[lane]
			t.Total += r.Total
			t.Read += r.Read
			total[lane] = t
		}
	}
	row := VendorScore{Vendor: "unidentified", DisplayName: "Not identified", Unidentified: true, Lanes: map[string]VendorLane{}}
	for _, lane := range []string{laneSyslog, laneTrap} {
		reading := total[lane]
		row.Lanes[lane] = VendorLane{Rules: map[string]int{}, Live: &reading}
	}
	return append(rows, row)
}
