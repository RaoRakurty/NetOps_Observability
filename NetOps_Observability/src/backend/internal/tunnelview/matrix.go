// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tunnelview

import (
	"sort"
	"strconv"
	"time"
)

// Site is a device's resolved site (internal/siteres in the root): Key groups
// devices within ONE tenant; a manual slug or label is not tenant-qualified,
// so the matrix keys a site by (tenant, Key).
type Site struct {
	Key    string `json:"-"`
	Label  string `json:"label"`
	Source string `json:"source"`
}

// SiteOf resolves a visible device id to its site; ok=false when unplaced.
type SiteOf func(deviceID string) (Site, bool)

// MaxMatrixSites caps the sites a matrix returns (worst first).
const MaxMatrixSites = 50

// MatrixSite is one site row/column of the matrix. Key is an opaque id local
// to this response ("s1", "s2", …), never a tenant's slug.
type MatrixSite struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Source  string `json:"source"`
	Devices int    `json:"devices"`
}

// Transport is one colour (or colour pair) within a cell.
type Transport struct {
	Color   string `json:"color"`
	State   string `json:"state"`
	Tunnels int    `json:"tunnels"`
}

// Cell is the tunnels between two sites (A <= B; A == B is intra-site).
type Cell struct {
	A              string      `json:"a"`
	B              string      `json:"b"`
	State          string      `json:"state"`
	Tunnels        int         `json:"tunnels"`
	Up             int         `json:"up"`
	Down           int         `json:"down"`
	Disagree       int         `json:"disagree"`
	Transports     []Transport `json:"transports"`
	Measured       int         `json:"measured"`
	WorstLossPct   *float64    `json:"worst_loss_pct"`
	WorstLatencyMs *float64    `json:"worst_latency_ms"`
	QualityAsOf    *time.Time  `json:"quality_as_of"`
	Cases          []string    `json:"cases"`
}

// Matrix is the site × site view.
type Matrix struct {
	Sites           []MatrixSite `json:"sites"`
	Cells           []Cell       `json:"cells"`
	SitesTotal      int          `json:"sites_total"`
	UnplacedTunnels int          `json:"unplaced_tunnels"`
	Truncated       bool         `json:"truncated"`
}

type siteKey struct{ tenant, key string }

type siteAcc struct {
	site    Site
	devices map[string]bool
	worst   int
	tunnels int
}

type cellAcc struct {
	cell  Cell
	trans map[string]*Transport
	cases map[string]bool
}

// BuildMatrix builds the matrix over the caller's visible tunnels (after
// Visible, BEFORE any status filter or limit, so the grid never lies about
// what a truncated list left out).
func BuildMatrix(ts []Tunnel, siteOf SiteOf, quality QualityIndex, cases CaseIndex) Matrix {
	sites := map[siteKey]*siteAcc{}
	type placed struct {
		t    Tunnel
		a, b siteKey
	}
	var all []placed
	m := Matrix{Sites: []MatrixSite{}, Cells: []Cell{}}
	for _, t := range ts {
		sa, okA := endSite(t.A, siteOf)
		sb, okB := endSite(t.B, siteOf)
		if !okA || !okB {
			m.UnplacedTunnels++
			continue
		}
		ka, kb := siteKey{t.Tenant, sa.Key}, siteKey{t.Tenant, sb.Key}
		rank := stateRank(t.State())
		for _, x := range []struct {
			k   siteKey
			s   Site
			dev string
		}{{ka, sa, t.A.DeviceID}, {kb, sb, t.B.DeviceID}} {
			acc := sites[x.k]
			if acc == nil {
				acc = &siteAcc{site: x.s, devices: map[string]bool{}}
				sites[x.k] = acc
			}
			acc.devices[x.dev] = true
			acc.tunnels++
			if rank > acc.worst {
				acc.worst = rank
			}
		}
		all = append(all, placed{t, ka, kb})
	}
	order := make([]siteKey, 0, len(sites))
	for k := range sites {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := sites[order[i]], sites[order[j]]
		if a.worst != b.worst {
			return a.worst > b.worst
		}
		if a.tunnels != b.tunnels {
			return a.tunnels > b.tunnels
		}
		if a.site.Label != b.site.Label {
			return a.site.Label < b.site.Label
		}
		if order[i].tenant != order[j].tenant {
			return order[i].tenant < order[j].tenant
		}
		return order[i].key < order[j].key
	})
	m.SitesTotal = len(order)
	if len(order) > MaxMatrixSites {
		order, m.Truncated = order[:MaxMatrixSites], true
	}
	idx := map[siteKey]int{}
	for i, k := range order {
		idx[k] = i
		acc := sites[k]
		m.Sites = append(m.Sites, MatrixSite{Key: "s" + strconv.Itoa(i+1), Label: acc.site.Label,
			Source: acc.site.Source, Devices: len(acc.devices)})
	}
	cells := map[[2]int]*cellAcc{}
	for _, p := range all {
		ia, okA := idx[p.a]
		ib, okB := idx[p.b]
		if !okA || !okB {
			continue // a site the cap left out
		}
		ca, cb := p.t.A.Color, p.t.B.Color
		if ia > ib {
			ia, ib = ib, ia
			ca, cb = cb, ca
		}
		k := [2]int{ia, ib}
		c := cells[k]
		if c == nil {
			c = &cellAcc{cell: Cell{A: m.Sites[ia].Key, B: m.Sites[ib].Key, Transports: []Transport{}, Cases: []string{}},
				trans: map[string]*Transport{}, cases: map[string]bool{}}
			cells[k] = c
		}
		st := p.t.State()
		c.cell.Tunnels++
		switch st {
		case StateUp:
			c.cell.Up++
		case StateDown:
			c.cell.Down++
		case StateDisagree:
			c.cell.Disagree++
		}
		if stateRank(st) > stateRank(c.cell.State) {
			c.cell.State = st
		}
		color := ca
		if cb != ca {
			color = ca + " ↔ " + cb
		}
		tr := c.trans[color]
		if tr == nil {
			tr = &Transport{Color: color}
			c.trans[color] = tr
		}
		tr.Tunnels++
		if stateRank(st) > stateRank(tr.State) {
			tr.State = st
		}
		if q := quality.For(p.t); q != nil {
			c.cell.Measured++
			if c.cell.WorstLossPct == nil || q.LossPct > *c.cell.WorstLossPct {
				v := q.LossPct
				c.cell.WorstLossPct = &v
			}
			if c.cell.WorstLatencyMs == nil || q.LatencyMs > *c.cell.WorstLatencyMs {
				v := q.LatencyMs
				c.cell.WorstLatencyMs = &v
			}
			if !q.AsOf.IsZero() && (c.cell.QualityAsOf == nil || q.AsOf.Before(*c.cell.QualityAsOf)) {
				v := q.AsOf
				c.cell.QualityAsOf = &v
			}
		}
		if cs := cases.For(p.t); cs != nil {
			c.cases[cs.ID] = true
		}
	}
	keys := make([][2]int, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		c := cells[k]
		colors := make([]string, 0, len(c.trans))
		for col := range c.trans {
			colors = append(colors, col)
		}
		sort.Strings(colors)
		for _, col := range colors {
			c.cell.Transports = append(c.cell.Transports, *c.trans[col])
		}
		for id := range c.cases {
			c.cell.Cases = append(c.cell.Cases, id)
		}
		sort.Strings(c.cell.Cases)
		m.Cells = append(m.Cells, c.cell)
	}
	return m
}

func endSite(e End, siteOf SiteOf) (Site, bool) {
	if e.DeviceID == "" || siteOf == nil {
		return Site{}, false
	}
	s, ok := siteOf(e.DeviceID)
	if !ok || s.Key == "" {
		return Site{}, false
	}
	return s, true
}
