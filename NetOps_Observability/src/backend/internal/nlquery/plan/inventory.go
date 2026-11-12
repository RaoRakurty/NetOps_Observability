// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// inventory.go — entity_count / entity_list (hybrid NLU plan A4): "how many
// devices can you see", "list the circuits at Dallas". The answer is the
// caller's OWN visible inventory, read through the same Scope chokepoints as
// every other query (Devices / Circuits are the root's visibility sets) — no
// new backend reach, and another tenant's entity can never be counted.

import (
	"context"
	"fmt"
	"sort"

	"netops/backend/internal/nlquery/ast"
)

// SourceInventory is the provenance of an inventory answer.
const SourceInventory = "inventory"

// NoteSitesFromDevices is said with every site count or list: sites are the
// sites of the devices the caller can see, so a site with no visible device
// is not counted.
const NoteSitesFromDevices = "Sites are counted from the devices you can see; a site with no visible device is not included."

func (p Planner) inventory(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	var sites, devIDs []string
	for _, r := range q.Refs {
		switch r.Type {
		case "site":
			sites = append(sites, stripPrefix(r.ID))
		case "device":
			devIDs = append(devIDs, stripPrefix(r.ID))
		}
	}
	rs.Provenance.Source = SourceInventory
	var items []Row
	switch q.Target {
	case "device":
		devs, err := sc.Devices(ctx, DeviceFilter{IDs: devIDs, Sites: sites})
		if err != nil {
			return err
		}
		devs = keepTypes(devs, filterValues(q, ast.FilterDeviceType))
		reach := map[string]string{}
		wantReach := filterValues(q, ast.FilterReachability)
		if wantReach != nil || q.Type == ast.EntityList {
			reach = p.reachability(ctx, sc, devs, rs)
		}
		for _, d := range devs {
			row := Row{"device": firstNonEmpty(d.Name, d.ID), "id": "device:" + d.ID, "site": d.Site}
			if wantReach != nil || q.Type == ast.EntityList {
				r := firstNonEmpty(reach[d.ID], ReachUnknown)
				if wantReach != nil && !wantReach[r] {
					continue
				}
				row["reachability"] = r
			}
			if d.Type != "" && filterValues(q, ast.FilterDeviceType) != nil {
				row["type"] = d.Type
			}
			items = append(items, row)
		}
	case "circuit":
		cs, err := sc.Circuits(ctx, CircuitFilter{Sites: sites, Devices: devIDs})
		if err != nil {
			return err
		}
		for _, c := range cs {
			items = append(items, Row{"circuit": c.ID, "id": "circuit:" + c.ID, "device": c.LocalDevice, "site": c.Site})
		}
	case "site":
		devs, err := sc.Devices(ctx, DeviceFilter{IDs: devIDs, Sites: sites})
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, d := range devs {
			if d.Site != "" && !seen[d.Site] {
				seen[d.Site] = true
				items = append(items, Row{"site": d.Site, "id": "site:" + d.Site})
			}
		}
		rs.Notes = append(rs.Notes, NoteSitesFromDevices)
	default:
		return fmt.Errorf("plan: %s cannot be counted", q.Target)
	}
	key := q.Target
	sort.SliceStable(items, func(i, j int) bool { return fmt.Sprint(items[i][key]) < fmt.Sprint(items[j][key]) })
	if q.Type == ast.EntityCount {
		rs.Rows = countRows(items, q.GroupBy)
		return nil
	}
	limit := q.LimitOr(len(items))
	if len(items) > limit {
		items, rs.Truncated = items[:limit], true
	}
	rs.Rows = items
	return nil
}

// ReachUnknown is the verdict of a device no collector has polled recently, or
// whose reachability could not be read: never "down".
const ReachUnknown = "unknown"

// NoteReachabilityNow is said with every reachability answer: it is the live
// verdict, not a history.
const NoteReachabilityNow = "Reachability is the collectors' current verdict (their last 3 minutes of polls), not a history."

// NoteReachabilityUnread is said when the reachability could not be read.
const NoteReachabilityUnread = "Device reachability could not be read just now, so every device shows as unknown."

// reachability reads the verdict of devs through the optional
// ReachabilityScope; on any failure every device is unknown and the answer
// says why.
func (p Planner) reachability(ctx context.Context, sc Scope, devs []DeviceRef, rs *ResultSet) map[string]string {
	rs.Notes = append(rs.Notes, NoteReachabilityNow)
	rsc, ok := sc.(ReachabilityScope)
	if !ok || len(devs) == 0 {
		if !ok {
			rs.Notes = append(rs.Notes, NoteReachabilityUnread)
		}
		return map[string]string{}
	}
	ids := make([]string, 0, len(devs))
	for _, d := range devs {
		ids = append(ids, d.ID)
	}
	m, err := rsc.DeviceReachability(ctx, ids)
	if err != nil {
		rs.Notes = append(rs.Notes, NoteReachabilityUnread)
		return map[string]string{}
	}
	return m
}

// filterValues is the value set of the query's filter on field (nil = none).
func filterValues(q *ast.AST, field string) map[string]bool {
	for _, f := range q.Filters {
		if f.Field == field {
			out := map[string]bool{}
			for _, v := range f.Values {
				out[v] = true
			}
			return out
		}
	}
	return nil
}

// keepTypes keeps the devices of the wanted types (nil = all).
func keepTypes(devs []DeviceRef, want map[string]bool) []DeviceRef {
	if want == nil {
		return devs
	}
	var out []DeviceRef
	for _, d := range devs {
		if want[d.Type] {
			out = append(out, d)
		}
	}
	return out
}

// countRows is the count, or one count per group (largest first, then by
// name), as rows: [{count: n}] or [{site: s, count: n}, …].
func countRows(items []Row, groupBy []string) []Row {
	if len(groupBy) == 0 {
		return []Row{{"count": len(items)}}
	}
	g := groupBy[0]
	by := map[string]int{}
	for _, it := range items {
		k := fmt.Sprint(it[g])
		if k == "" {
			k = "(none)"
		}
		by[k]++
	}
	out := make([]Row, 0, len(by))
	for k, n := range by {
		out = append(out, Row{g: k, "count": n})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i]["count"].(int) != out[j]["count"].(int) {
			return out[i]["count"].(int) > out[j]["count"].(int)
		}
		return fmt.Sprint(out[i][g]) < fmt.Sprint(out[j][g])
	})
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
