// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"math"
	"strings"
)

// Text-aware ego geometry (P-7EE84E, 2026-11-24) — the twin of pathModel.ts
// egoGeometry; the shared golden testdata/topoctx/ego_layout.golden.json pins
// that both produce the same positions.
//
// The old layout put nodes on FIXED slots (760×250/330, an ellipse or two
// rows) sized for this document's 9px labels. The screen draws the same slots
// with 14px bold labels, so on a busy context the labels ran into each other
// there ("crammed on screen, fine in the PDF").
//
// Rule: every node has a FOOTPRINT — its circle plus the text drawn around it
// (anomalous mark above; label and role line below), measured with the LARGER
// renderer's metrics (the screen: 14px bold label, 12.5px role, 12.5px bold
// mark) at the screen's truncation limits. This document's text (9/7.5px,
// tighter offsets, its own truncation limits) always fits inside that
// footprint, so ONE geometry is clean at both scales. Width stays 760 so no
// renderer shrinks its text; a context that needs more room gets more ROWS
// (height grows), never tighter spacing. The ellipse (≤ 1 anchor) is kept
// only when every footprint fits on it without touching another or leaving
// the picture; otherwise neighbours pack into rows above and below the anchor
// row, alternating as before.

const (
	topoEgoW       = 760.0
	topoEgoMarginX = 20.0
	topoEgoGapX    = 16.0
	topoEgoGapMax  = 64.0
	topoEgoGapY    = 18.0
	topoEgoPadY    = 14.0
	topoEgoBoxGap  = 4.0

	// Conservative per-character advance for the screen text (the larger scale)
	// and the screen's truncation limits.
	topoEgoLabelCh  = 8.7
	topoEgoMetaCh   = 7.0
	topoEgoMarkCh   = 7.8
	topoEgoLabelMax = 22
	topoEgoRoleMax  = 24
	topoEgoMarkMax  = 36
)

type topoFootprint struct {
	halfW, above, below float64
}

type topoBox struct {
	x0, y0, x1, y1 float64
}

func topoRuneCount(s string, max int) int {
	n := len([]rune(s))
	if n > max {
		return max
	}
	return n
}

// topoEgoRole is the role line under a node (also used by the footprint).
func topoEgoRole(n TopoCtxNode) string {
	sub := strings.ReplaceAll(n.Role, "_", " ")
	if !n.Managed && sub == "" {
		sub = "not in inventory"
	}
	return sub
}

// topoEgoMarkText is the "anomalous: …" mark drawn above a node; an interface
// without a port name is named by its target id (as the screen does).
func topoEgoMarkText(tc TopologyContext, id string) string {
	ports := topoIfaceFaults(tc, id)
	if len(ports) == 0 {
		return ""
	}
	names := make([]string, 0, len(ports))
	for _, f := range ports {
		name := f.Port
		if name == "" {
			name = f.TargetID
		}
		names = append(names, name)
	}
	return "anomalous: " + strings.Join(names, " · ")
}

// topoEgoFootprint: half a node's width, and how far its drawing reaches above
// and below its centre (circle radius 18 for an anchor, 14 otherwise).
func topoEgoFootprint(label, role, mark string, anchor bool) topoFootprint {
	r := 14.0
	if anchor {
		r = 18
	}
	halfW := math.Max(r, topoEgoLabelCh*float64(topoRuneCount(label, topoEgoLabelMax))/2)
	if role != "" {
		halfW = math.Max(halfW, topoEgoMetaCh*float64(topoRuneCount(role, topoEgoRoleMax))/2)
	}
	if mark != "" {
		halfW = math.Max(halfW, topoEgoMarkCh*float64(topoRuneCount(mark, topoEgoMarkMax))/2)
	}
	f := topoFootprint{halfW: halfW, above: r, below: r + 20}
	if mark != "" {
		f.above = r + 20
	}
	if role != "" {
		f.below = r + 35
	}
	return f
}

func topoEgoBox(p [2]float64, f topoFootprint) topoBox {
	return topoBox{x0: p[0] - f.halfW, y0: p[1] - f.above, x1: p[0] + f.halfW, y1: p[1] + f.below}
}

func topoBoxesOverlap(a, b topoBox, gap float64) bool {
	return a.x0 < b.x1+gap && b.x0 < a.x1+gap && a.y0 < b.y1+gap && b.y0 < a.y1+gap
}

func topoEgoFits(ids []string, pos map[string][2]float64, fp map[string]topoFootprint, w, h float64) bool {
	boxes := make([]topoBox, len(ids))
	for i, id := range ids {
		boxes[i] = topoEgoBox(pos[id], fp[id])
	}
	for i, a := range boxes {
		if a.x0 < 0 || a.y0 < 0 || a.x1 > w || a.y1 > h {
			return false
		}
		for j := i + 1; j < len(boxes); j++ {
			if topoBoxesOverlap(a, boxes[j], topoEgoBoxGap) {
				return false
			}
		}
	}
	return true
}

func topoEgoPackRows(ids []string, fp map[string]topoFootprint) [][]string {
	usable := topoEgoW - 2*topoEgoMarginX
	var rows [][]string
	var cur []string
	width := 0.0
	for _, id := range ids {
		nw := 2 * fp[id].halfW
		need := nw
		if len(cur) > 0 {
			need = width + topoEgoGapX + nw
		}
		if len(cur) > 0 && need > usable {
			rows = append(rows, cur)
			cur = []string{id}
			width = nw
		} else {
			cur = append(cur, id)
			width = need
		}
	}
	if len(cur) > 0 {
		rows = append(rows, cur)
	}
	return rows
}

// topoEgoGeometry returns the ego-graph's width, height and every node's
// centre. Pure and deterministic.
func topoEgoGeometry(tc TopologyContext) (w, h float64, pos map[string][2]float64) {
	var anchors, neigh []TopoCtxNode
	for _, n := range tc.Nodes {
		if n.Anchor {
			anchors = append(anchors, n)
		} else {
			neigh = append(neigh, n)
		}
	}
	fp := map[string]topoFootprint{}
	for _, n := range tc.Nodes {
		fp[n.ID] = topoEgoFootprint(n.Label, topoEgoRole(n), topoEgoMarkText(tc, n.ID), n.Anchor)
	}
	all := make([]string, 0, len(tc.Nodes))
	for _, n := range anchors {
		all = append(all, n.ID)
	}
	for _, n := range neigh {
		all = append(all, n.ID)
	}

	if len(anchors) <= 1 {
		// The original picture: one centre, its neighbours on an ellipse —
		// kept only when it is clean.
		eh := 250.0
		if len(neigh) > 8 {
			eh = 330
		}
		cx, cy := topoEgoW/2, eh/2
		ep := map[string][2]float64{}
		for _, a := range anchors {
			ep[a.ID] = [2]float64{cx, cy}
		}
		rx, ry := topoEgoW/2-70, eh/2-38
		for i, n := range neigh {
			ang := -math.Pi/2 + 2*math.Pi*float64(i)/float64(len(neigh))
			if len(neigh) == 1 {
				ang = 0
			}
			ep[n.ID] = [2]float64{cx + rx*math.Cos(ang), cy + ry*math.Sin(ang)}
		}
		if topoEgoFits(all, ep, fp, topoEgoW, eh) {
			return topoEgoW, eh, ep
		}
	}

	// Rows: neighbours alternate above / below the anchor row (so no link is
	// drawn through another anchor), each band packed into as many rows as
	// its footprints need; every row is centred.
	var top, bottom, anc []string
	for i, n := range neigh {
		if i%2 == 0 {
			top = append(top, n.ID)
		} else {
			bottom = append(bottom, n.ID)
		}
	}
	for _, a := range anchors {
		anc = append(anc, a.ID)
	}
	var rows [][]string
	rows = append(rows, topoEgoPackRows(top, fp)...)
	rows = append(rows, topoEgoPackRows(anc, fp)...)
	rows = append(rows, topoEgoPackRows(bottom, fp)...)
	pos = map[string][2]float64{}
	cursor := topoEgoPadY
	usable := topoEgoW - 2*topoEgoMarginX
	for _, row := range rows {
		above, below, base := 0.0, 0.0, 0.0
		for _, id := range row {
			f := fp[id]
			above = math.Max(above, f.above)
			below = math.Max(below, f.below)
			base += 2 * f.halfW
		}
		// Spread the row into its spare width (never below topoEgoGapX —
		// packing guaranteed that — and never more than topoEgoGapMax), then
		// centre it.
		k := float64(len(row))
		gap := 0.0
		if len(row) > 1 {
			gap = math.Min(topoEgoGapMax, (usable-base)/(k-1))
		}
		total := base + gap*(k-1)
		y := cursor + above
		x := (topoEgoW - total) / 2
		for _, id := range row {
			f := fp[id]
			pos[id] = [2]float64{x + f.halfW, y}
			x += 2*f.halfW + gap
		}
		cursor = y + below + topoEgoGapY
	}
	return topoEgoW, cursor - topoEgoGapY + topoEgoPadY, pos
}
