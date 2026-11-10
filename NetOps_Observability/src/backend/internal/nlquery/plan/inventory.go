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
		for _, d := range devs {
			items = append(items, Row{"device": firstNonEmpty(d.Name, d.ID), "id": "device:" + d.ID, "site": d.Site})
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
