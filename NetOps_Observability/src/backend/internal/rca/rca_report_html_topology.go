// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_report_html_topology.go — the document's "Network topology & causality"
// partial (RCA document v2 §2/§4 section 6). It renders the ONE
// TopologyContext the report and the path view share, in its four states:
//
//	topology_with_path — the measured spine, then the known topology around the
//	                     affected devices with the fault and causal overlays;
//	topology_only      — the known topology; the causal path marked unverified;
//	device_only        — a device diagnostic card (device, role, source, last
//	                     seen, evidence interfaces, which neighbour sources were
//	                     read and came back empty, remediation);
//	no_asset_mapping   — an explicit data-availability error with remediation.
//
// Two named templates are added to rcaReportTmpl:
//
//	{{template "topologyContext" .TopologyContext}}       the full section body
//	{{template "topologyContextBrief" .TopologyContext}}  the at-a-glance picture
//
// No script (Gotenberg prints with JavaScript disabled), no external resource,
// no element id (the picture appears twice in one document). The SVG is drawn
// in Go from escaped fields only. State is always carried by a WORD; colour only
// reinforces it, so the page reads in grayscale print. Colours are the report's
// existing palette (rca_report_html.go: green #0f7a3d, amber #b45309, red
// #b42318, gray #475467/#94a3b8/#cbd5e1, ink #172033).

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"
)

// registerTopologyContextTemplates adds the partials (and their funcs) to the report
// template set at package initialisation — before any Execute, which is the
// only time html/template accepts new definitions. Referencing rcaReportTmpl
// orders this initialiser after it.
var _ = registerTopologyContextTemplates()

func registerTopologyContextTemplates() bool {
	template.Must(rcaReportTmpl.Funcs(template.FuncMap{
		"topologyContextSVG": topologyContextSVG,
		"topoSpineSVG":       topoSpineSVG,
		"topoStateLabel":     topoStateLabel,
		"topoSourcesLine":    topoSourcesLine,
		"topoSourceLabel":    topoCtxSourceLabel,
		"topoTS":             topoHumanTS,
		"topoKind":           topoHumanKind,
		"topoKinds":          topoHumanKinds,
		"topoRelTone":        topoRelTone,
		"topoSevTone":        topoSevTone,
		"topoLabel":          topoNodeLabel,
		"topoAnchorNodes":    topoAnchorNodes,
		"topoIfaceFaults":    topoIfaceFaults,
		"topoEmptySources":   topoSourcesWithStatus(TopoReadOK, true),
		"topoUnreadSources":  topoSourcesWithStatus(TopoReadUnavailable, false),
		"topoCausalRows":     topoCausalRows,
		"topoCausalMore":     topoCausalMore,
	}).New("topologyContext").Parse(topologyContextTmplSrc))
	template.Must(rcaReportTmpl.New("topologyContextBrief").Parse(topologyContextBriefTmplSrc))
	return true
}

// topoCtxCausalTableCap bounds the causal table; the rest is counted.
const topoCtxCausalTableCap = 30

const topologyContextBriefTmplSrc = `{{if .State}}{{with .Spine}}{{topoSpineSVG .}}{{end}}{{topologyContextSVG .}}
<div class="note">Network topology &amp; causality — <b>{{topoStateLabel .State}}</b>. {{.Reason}} Detail in the topology section.</div>{{end}}`

const topologyContextTmplSrc = `{{if not .State}}<h2>Network topology &amp; causality</h2>
<div class="note">The topology context was not built for this document.</div>
{{else}}<h2>Network topology &amp; causality — sources: {{topoSourcesLine .}}</h2>
<div class="note" style="margin-bottom:4px">State: <b>{{topoStateLabel .State}}</b> — {{.Reason}}</div>
{{if eq .State "no_asset_mapping"}}
<div class="decision red"><b>Data-availability error</b> — the affected entity could not be placed in the network topology. This is a gap in the data, not a finding about the network.{{if .Unmapped}} Not in the inventory: {{commaJoin .Unmapped}}.{{end}}</div>
{{else}}
{{with .Spine}}
<div class="note" style="margin:6px 0 2px"><b>Measured path</b> — vantage {{.VantageID}} · observed {{.ObservedAt}}{{if .RelationToIncident}} · temporal role: <b>{{humanState .RelationToIncident}}</b>{{end}}{{if .Stale}} · <b style="color:#b45309">STALE — measured before/after the incident window; treat as context, not live state</b>{{end}}</div>
{{if .TemporalNote}}<div class="note" style="color:#b45309;font-weight:600">{{.TemporalNote}}</div>{{end}}
{{topoSpineSVG .}}
<table><thead><tr><th style="width:32px">#</th><th>Hop</th><th>Address</th><th>Zone</th><th>State</th><th>Boundary</th></tr></thead><tbody>
{{range .Hops}}<tr>
  <td style="font-family:ui-monospace,monospace">{{.Index}}</td>
  <td><b>{{if .Label}}{{.Label}}{{else}}(no response — unknown hop){{end}}</b>{{if .Provider}} <span class="pill blue" style="font-size:9px">{{upper .Provider}}</span>{{end}}{{if respondingMark .}} <span class="pill gray">◍ last responding hop — boundary after</span>{{else if eq .Fault "broken"}} <span class="pill red">✕ failed hop</span>{{else if eq .Fault "suspected"}} <span class="pill amber">✕ suspected failed hop</span>{{end}}</td>
  <td style="font-family:ui-monospace,monospace">{{.Address}}</td>
  <td>{{title .Kind}}</td>
  <td><span class="pill {{if eq .State "down"}}red{{else if eq .State "degraded"}}amber{{else if eq .State "unknown"}}gray{{else}}green{{end}}">{{title .State}}</span></td>
  <td>{{if .SeamID}}provider boundary ({{.Boundary}}){{else}}{{.Boundary}}{{end}}</td>
</tr>{{end}}
</tbody></table>
{{if .DropPoint}}<div class="note" style="font-weight:600">{{.DropPoint}}</div>{{end}}
<div class="note">Only the measured path is drawn as a path. An unknown hop is preserved as unknown — never bridged. A probe source→target relationship does not by itself imply physical causality.</div>
{{end}}
{{topologyContextSVG .}}
{{if .Edges}}
<div class="note">Legend: grey line = known link (dotted = stale) · amber/red device or port = anomalous evidence observed there (no causation implied) · <b>solid arrow</b> = verified causal link · <b>dashed arrow</b> = suspected · <b>?</b> = relationship unknown.{{if eq .State "topology_only"}} No measured path is attached: the causal path across this topology is <b>unverified</b>.{{end}}{{if .MoreNodes}} {{.MoreNodes}} more neighbour(s) not drawn.{{end}}</div>
<table><thead><tr><th style="width:22%">Device</th><th style="width:22%">Neighbour</th><th style="width:18%">Ports</th><th style="width:14%">Link</th><th style="width:12%">First seen</th><th>Freshness</th></tr></thead><tbody>
{{range .Edges}}<tr>
  <td>{{topoLabel $ .A}}</td>
  <td>{{topoLabel $ .B}}</td>
  <td style="font-family:ui-monospace,monospace">{{if .APort}}{{.APort}}{{else}}—{{end}} → {{if .BPort}}{{.BPort}}{{else}}—{{end}}</td>
  <td>{{humanState .Relationship}}{{if .Protocol}}<div class="note">{{.Protocol}} · {{range $i, $s := .Sources}}{{if $i}}, {{end}}{{topoSourceLabel $s}}{{end}}</div>{{end}}</td>
  <td>{{if .FirstSeen}}{{topoTS .FirstSeen}}{{else}}—{{end}}</td>
  <td><span class="pill {{if eq .Freshness "current"}}green{{else if eq .Freshness "after_incident"}}blue{{else}}gray{{end}}" style="font-size:10px">{{humanState .Freshness}}</span></td>
</tr>{{end}}
</tbody></table>
<div class="note">Known topology as the sources state it when this report was generated; "first seen" says whether a link was already known at incident time ("after incident" = first seen after the case window).</div>
{{end}}
{{if eq .State "device_only"}}
{{range topoAnchorNodes .}}
<div class="decision" style="margin-top:6px">
  <b>Device diagnostic — {{.Label}}</b>
  <div class="kv" style="margin-top:4px">
    <span class="k">Device</span><span class="v">{{.Label}}{{if ne .Label .ID}} <span style="font-weight:400;color:#64748b">({{.ID}})</span>{{end}}</span>
    <span class="k">Role</span><span class="v">{{if .Role}}{{humanState .Role}}{{else}}not classified{{end}}</span>
    <span class="k">Source</span><span class="v">{{topoSourceLabel .Source}}</span>
    <span class="k">Last seen</span><span class="v">{{if .Stale}}<span class="pill gray" style="font-size:9px">stale</span>{{if .LastSeen}} last seen {{topoTS .LastSeen}}{{end}}{{else if .LastSeen}}current — seen by its inventory source{{if .FirstSeen}} (known since {{topoTS .FirstSeen}}){{end}}{{else}}not recorded{{end}}</span>
    <span class="k">Evidence interfaces</span><span class="v">{{with topoIfaceFaults $ .ID}}{{range $i, $f := .}}{{if $i}} · {{end}}{{$f.Port}} <span style="font-weight:400;color:#64748b">({{topoKinds $f.Kinds}})</span>{{end}}{{else}}none{{end}}</span>
    <span class="k">Read and empty</span><span class="v" style="font-weight:400">{{with topoEmptySources $}}{{range $i, $s := .}}{{if $i}}, {{end}}{{topoSourceLabel $s.Kind}}{{end}}{{else}}—{{end}}</span>
    <span class="k">Could not be read</span><span class="v" style="font-weight:400">{{with topoUnreadSources $}}{{range $i, $s := .}}{{if $i}}, {{end}}{{topoSourceLabel $s.Kind}}{{end}}{{else}}none{{end}}</span>
  </div>
</div>
{{end}}
{{end}}
{{if .Faults}}
<table style="margin-top:6px"><thead><tr><th style="width:30%">Where (measured)</th><th>Evidence kinds</th><th style="width:14%">Peak severity</th><th style="width:12%">Observations</th></tr></thead><tbody>
{{range .Faults}}<tr>
  <td>{{if eq .TargetType "interface"}}{{.Device}} · <span style="font-family:ui-monospace,monospace">{{.Port}}</span>{{else}}{{.Device}} (device){{end}}</td>
  <td>{{topoKinds .Kinds}}</td>
  <td><span class="pill {{topoSevTone .PeakSeverity}}" style="font-size:10px">{{upper .PeakSeverity}}</span></td>
  <td>{{len .EvidenceRefs}}</td>
</tr>{{end}}
</tbody></table>
<div class="note">Measured fault overlay: where anomalous evidence was observed. It never implies causation on its own.</div>
{{end}}
{{if .Causal}}
<table style="margin-top:6px"><thead><tr><th style="width:44%">From → to</th><th style="width:12%">Causal link</th><th>Basis</th></tr></thead><tbody>
{{range topoCausalRows .}}<tr>
  <td>{{.From}}{{if .FromKind}} <span class="note">({{topoKind .FromKind}})</span>{{end}} {{if .Directed}}→{{else}}—{{end}} {{.To}}{{if .ToKind}} <span class="note">({{topoKind .ToKind}})</span>{{end}}</td>
  <td><span class="pill {{topoRelTone .Relation}}" style="font-size:10px">{{if eq .Relation "unknown"}}? unknown{{else}}{{.Relation}}{{end}}</span></td>
  <td style="font-size:10.5px;color:#475467">{{.Basis}}</td>
</tr>{{end}}
</tbody></table>
{{with topoCausalMore .}}<div class="note">{{.}} more causal link(s) are in the JSON report.</div>{{end}}
<div class="note">Causal overlay from the engine's evidence graph: verified = authoritative grounding, a direction vote and a confirmed verdict; suspected = a direction vote or a suspected verdict; unknown = no direction (co-occurrence only), or a known link the engine joined no evidence across.</div>
{{end}}
{{end}}
{{if .Remediation}}
<div class="note" style="margin-top:6px;color:#172033"><b>What would complete this picture</b></div>
<ol class="actions">{{range .Remediation}}<li>{{.}}</li>{{end}}</ol>
{{end}}
{{end}}`

// ── template funcs ──────────────────────────────────────────────────────────

func topoStateLabel(s string) string {
	switch s {
	case TopoStateWithPath:
		return "topology with measured path"
	case TopoStateTopologyOnly:
		return "known topology, no measured path"
	case TopoStateDeviceOnly:
		return "device only — no neighbour or path data"
	case TopoStateNoAssetMapping:
		return "no asset mapping"
	}
	return "unknown"
}

// topoSourcesLine names the sources that contributed rows; when none did, it
// says so in words ("inventory only", "none readable").
func topoSourcesLine(tc TopologyContext) string {
	var with []string
	inv := false
	for _, s := range tc.Sources {
		if s.Status != TopoReadOK || s.Rows == 0 {
			continue
		}
		if s.Kind == TopoSrcInventory {
			inv = true
			continue
		}
		label := topoCtxSourceLabel(s.Kind)
		label = strings.TrimPrefix(label, "the ")
		if s.Freshness == "stale" {
			label += " (stale)"
		}
		with = append(with, label)
	}
	if tc.Spine != nil {
		with = append([]string{"measured path"}, with...)
	}
	switch {
	case len(with) > 0 && inv:
		return strings.Join(with, ", ") + ", inventory"
	case len(with) > 0:
		return strings.Join(with, ", ")
	case inv:
		return "inventory only"
	}
	return "none readable"
}

func topoHumanTS(rfc string) string {
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	return t.UTC().Format("2006-01-02 15:04") + " UTC"
}

func topoHumanKind(k string) string { return strings.ReplaceAll(k, "_", " ") }

func topoHumanKinds(ks []string) string {
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, topoHumanKind(k))
	}
	return strings.Join(out, ", ")
}

func topoRelTone(r string) string {
	switch r {
	case CausalVerified:
		return "red"
	case CausalSuspected:
		return "amber"
	}
	return "gray"
}

func topoSevTone(s string) string {
	switch s {
	case "crit":
		return "red"
	case "high", "warn":
		return "amber"
	}
	return "gray"
}

func topoNodeLabel(tc TopologyContext, id string) string {
	for _, n := range tc.Nodes {
		if n.ID == id {
			return n.Label
		}
	}
	return id
}

func topoAnchorNodes(tc TopologyContext) []TopoCtxNode {
	var out []TopoCtxNode
	for _, n := range tc.Nodes {
		if n.Anchor {
			out = append(out, n)
		}
	}
	return out
}

func topoIfaceFaults(tc TopologyContext, device string) []FaultMark {
	var out []FaultMark
	for _, f := range tc.Faults {
		if f.TargetType == "interface" && f.Device == device {
			out = append(out, f)
		}
	}
	return out
}

func topoSourcesWithStatus(status string, emptyOnly bool) func(TopologyContext) []TopologySource {
	return func(tc TopologyContext) []TopologySource {
		var out []TopologySource
		for _, s := range tc.Sources {
			if s.Kind == TopoSrcInventory || s.Status != status {
				continue
			}
			if emptyOnly && s.Rows != 0 {
				continue
			}
			out = append(out, s)
		}
		return out
	}
}

func topoCausalRows(tc TopologyContext) []CausalMark {
	if len(tc.Causal) > topoCtxCausalTableCap {
		return tc.Causal[:topoCtxCausalTableCap]
	}
	return tc.Causal
}

func topoCausalMore(tc TopologyContext) int {
	if n := len(tc.Causal) - topoCtxCausalTableCap; n > 0 {
		return n
	}
	return 0
}

func topoSpineSVG(t *TopologyView) template.HTML {
	if t == nil {
		return ""
	}
	return rcaPathGraphSVG(*t)
}

// ── the picture ─────────────────────────────────────────────────────────────

// SVG palette — the report's existing colours.
const (
	topoInk      = "#172033"
	topoMuted    = "#64748b"
	topoLink     = "#94a3b8"
	topoLinkDim  = "#cbd5e1"
	topoNodeFill = "#f8fafc"
	topoAmber    = "#b45309"
	topoAmberBg  = "#fff4e8"
	topoRed      = "#b42318"
	topoRedBg    = "#fff0ee"
	topoUnknown  = "#475467"
)

// topologyContextSVG draws what the context holds: the ego-graph when there is
// known topology, and a detail panel for each affected device that carries
// evidence (device ↔ interface causal marks live there — they are inside one
// box and cannot be drawn on the ego-graph's links). no_asset_mapping draws
// nothing: there is nothing placed to draw.
func topologyContextSVG(tc TopologyContext) template.HTML {
	if tc.State == TopoStateNoAssetMapping {
		return ""
	}
	var b strings.Builder
	if len(tc.Edges) > 0 {
		topoEgoSVG(&b, tc)
	}
	drawn := 0
	for _, n := range tc.Nodes {
		if !n.Anchor {
			continue
		}
		if len(topoIfaceFaults(tc, n.ID)) == 0 && !topoDeviceFaulted(tc, n.ID) && tc.State != TopoStateDeviceOnly {
			continue
		}
		if drawn == 3 {
			fmt.Fprintf(&b, `<div class="note">Detail panels are drawn for the first 3 affected devices; the tables list every one.</div>`)
			break
		}
		topoDeviceSVG(&b, tc, n)
		drawn++
	}
	return template.HTML(b.String()) // #nosec G203 -- built from constants and template.HTMLEscapeString'd fields only
}

func topoDeviceFaulted(tc TopologyContext, id string) bool {
	for _, f := range tc.Faults {
		if f.Device == id {
			return true
		}
	}
	return false
}

// topoDevicePeak is the device's peak severity across its own and its
// interfaces' fault marks ("" when nothing anomalous was observed there).
func topoDevicePeak(tc TopologyContext, id string) string {
	peak := -1
	for _, f := range tc.Faults {
		if f.Device == id {
			if r := topoCtxSevRank(f.PeakSeverity); r > peak {
				peak = r
			}
		}
	}
	if peak < 0 {
		return ""
	}
	return topoCtxSevName(peak)
}

func topoFaultColours(sev string) (fill, stroke string) {
	switch sev {
	case "":
		return topoNodeFill, topoMuted
	case "crit":
		return topoRedBg, topoRed
	}
	return topoAmberBg, topoAmber
}

func topoEsc(s string) string { return template.HTMLEscapeString(s) }

func topoShort(s string, max int) string {
	r := []rune(s)
	if len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

// topoArrowHead draws a filled arrowhead at (x2,y2) pointing along x1,y1→x2,y2.
// A polygon, not a <marker>: markers need element ids, and this picture is
// rendered twice in one document.
func topoArrowHead(b *strings.Builder, x1, y1, x2, y2 float64, colour string) {
	dx, dy := x2-x1, y2-y1
	l := math.Hypot(dx, dy)
	if l == 0 {
		return
	}
	ux, uy := dx/l, dy/l
	const size = 7.0
	bx, by := x2-ux*size, y2-uy*size
	px, py := -uy*size*0.5, ux*size*0.5
	fmt.Fprintf(b, `<polygon points="%.1f,%.1f %.1f,%.1f %.1f,%.1f" fill="%s"/>`, x2, y2, bx+px, by+py, bx-px, by-py, colour)
}

// topoCausalLine draws one causal mark between two points in the overlay
// style of its relation: verified solid red with an arrow, suspected dashed
// amber with an arrow, unknown dotted grey with a "?".
func topoCausalLine(b *strings.Builder, x1, y1, x2, y2 float64, rel string, directed bool) {
	colour, dash := topoUnknown, ` stroke-dasharray="1.5 3"`
	switch rel {
	case CausalVerified:
		colour, dash = topoRed, ""
	case CausalSuspected:
		colour, dash = topoAmber, ` stroke-dasharray="6 4"`
	}
	fmt.Fprintf(b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1.8"%s/>`, x1, y1, x2, y2, colour, dash)
	if directed && rel != CausalUnknown {
		topoArrowHead(b, x1, y1, x2, y2, colour)
	}
	if rel == CausalUnknown {
		mx, my := (x1+x2)/2, (y1+y2)/2
		fmt.Fprintf(b, `<circle cx="%.1f" cy="%.1f" r="6.5" fill="#fff" stroke="%s" stroke-width="1"/><text x="%.1f" y="%.1f" text-anchor="middle" font-size="9" font-weight="800" fill="%s">?</text>`,
			mx, my, colour, mx, my+3.2, colour)
	}
}

// topoEgoSVG draws the 1-hop ego-graph: anchors on the centre line, their
// neighbours on an ellipse around them, known links grey (dotted when stale),
// faulted devices amber/red, cross-device causal marks overlaid.
func topoEgoSVG(b *strings.Builder, tc TopologyContext) {
	const w = 760.0
	var anchors, neigh []TopoCtxNode
	for _, n := range tc.Nodes {
		if n.Anchor {
			anchors = append(anchors, n)
		} else {
			neigh = append(neigh, n)
		}
	}
	h := 250.0
	if len(neigh) > 8 {
		h = 330
	}
	cx, cy := w/2, h/2
	pos := map[string][2]float64{}
	spacing := math.Min(140, 560/math.Max(1, float64(len(anchors))))
	for i, a := range anchors {
		x := cx + (float64(i)-float64(len(anchors)-1)/2)*spacing
		pos[a.ID] = [2]float64{x, cy}
	}
	if len(anchors) <= 1 {
		// one centre: neighbours on an ellipse around it.
		rx, ry := w/2-70, h/2-38
		for i, n := range neigh {
			ang := -math.Pi/2 + 2*math.Pi*float64(i)/float64(len(neigh))
			if len(neigh) == 1 {
				ang = 0
			}
			pos[n.ID] = [2]float64{cx + rx*math.Cos(ang), cy + ry*math.Sin(ang)}
		}
	} else {
		// several anchors share the centre line: neighbours go to a row above
		// and a row below, so no link is drawn through another anchor.
		var top, bottom []TopoCtxNode
		for i, n := range neigh {
			if i%2 == 0 {
				top = append(top, n)
			} else {
				bottom = append(bottom, n)
			}
		}
		for _, row := range []struct {
			nodes []TopoCtxNode
			y     float64
		}{{top, 40}, {bottom, h - 52}} {
			for j, n := range row.nodes {
				pos[n.ID] = [2]float64{50 + (w-100)*(float64(j)+0.5)/float64(len(row.nodes)), row.y}
			}
		}
	}
	fmt.Fprintf(b, `<svg viewBox="0 0 %.0f %.0f" width="100%%" style="max-width:760px;display:block;margin:8px auto 2px" role="img" aria-label="Known topology around the affected devices with fault and causal overlays">`, w, h)
	// known links under everything.
	causalOnLink := map[string]bool{}
	for _, m := range tc.Causal {
		if m.FromType == "node" && m.ToType == "node" && m.FromKind == "" && m.ToKind == "" {
			causalOnLink[topoCtxPair(m.From, m.To)] = true
		}
	}
	for _, e := range tc.Edges {
		pa, okA := pos[e.A]
		pb, okB := pos[e.B]
		if !okA || !okB {
			continue
		}
		style := fmt.Sprintf(`stroke="%s" stroke-width="1.5"`, topoLink)
		if e.Stale {
			style = fmt.Sprintf(`stroke="%s" stroke-width="1.5" stroke-dasharray="2 3"`, topoLinkDim)
		}
		fmt.Fprintf(b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" %s/>`, pa[0], pa[1], pb[0], pb[1], style)
		if causalOnLink[topoCtxPair(e.A, e.B)] {
			// a known link the engine joined no evidence across: relationship unknown.
			topoCausalLine(b, pa[0]+(pb[0]-pa[0])*0.35, pa[1]+(pb[1]-pa[1])*0.35, pa[0]+(pb[0]-pa[0])*0.65, pa[1]+(pb[1]-pa[1])*0.65, CausalUnknown, false)
		}
	}
	// cross-device engine edges (evidence on two different drawn devices).
	type pairMark struct {
		from, to string
		rel      string
		directed bool
	}
	best := map[string]pairMark{}
	for _, m := range tc.Causal {
		if m.FromKind == "" && m.ToKind == "" {
			continue // a topology-link mark, drawn above
		}
		da, db := topoCtxDeviceOf(topoEntityType(m.FromType), m.From), topoCtxDeviceOf(topoEntityType(m.ToType), m.To)
		if da == "" || db == "" || da == db {
			continue
		}
		if _, ok := pos[da]; !ok {
			continue
		}
		if _, ok := pos[db]; !ok {
			continue
		}
		k := topoCtxPair(da, db)
		cur, ok := best[k]
		if !ok || topoCtxRelRank(m.Relation) < topoCtxRelRank(cur.rel) {
			best[k] = pairMark{from: da, to: db, rel: m.Relation, directed: m.Directed}
		}
	}
	for _, k := range topoSortedPairKeys(best) {
		pm := best[k]
		pa, pb := pos[pm.from], pos[pm.to]
		dx, dy := pb[0]-pa[0], pb[1]-pa[1]
		l := math.Hypot(dx, dy)
		if l == 0 {
			continue
		}
		ox, oy := -dy/l*6, dx/l*6 // offset off the grey link
		sx, sy := pa[0]+dx/l*20+ox, pa[1]+dy/l*20+oy
		ex, ey := pb[0]-dx/l*20+ox, pb[1]-dy/l*20+oy
		topoCausalLine(b, sx, sy, ex, ey, pm.rel, pm.directed)
	}
	// nodes on top.
	for _, n := range append(append([]TopoCtxNode{}, anchors...), neigh...) {
		p := pos[n.ID]
		fill, stroke := topoFaultColours(topoDevicePeak(tc, n.ID))
		r := 14.0
		if n.Anchor {
			r = 18
		}
		dash := ""
		if !n.Managed {
			dash = ` stroke-dasharray="3 2"`
		}
		fmt.Fprintf(b, `<circle cx="%.1f" cy="%.1f" r="%.0f" fill="%s" stroke="%s" stroke-width="2"%s/>`, p[0], p[1], r, fill, stroke, dash)
		if n.Stale {
			fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="7.5" fill="%s">stale</text>`, p[0], p[1]+3, topoMuted)
		}
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="9" font-weight="700" fill="%s">%s</text>`, p[0], p[1]+r+11, topoInk, topoEsc(topoShort(n.Label, 22)))
		sub := strings.ReplaceAll(n.Role, "_", " ")
		if !n.Managed && sub == "" {
			sub = "not in inventory"
		}
		if sub != "" {
			fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="7.5" fill="%s">%s</text>`, p[0], p[1]+r+21, topoMuted, topoEsc(topoShort(sub, 26)))
		}
		if ports := topoIfaceFaults(tc, n.ID); len(ports) > 0 {
			names := make([]string, 0, len(ports))
			for _, f := range ports {
				names = append(names, f.Port)
			}
			_, pc := topoFaultColours(topoDevicePeak(tc, n.ID))
			fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="7.5" font-weight="700" fill="%s">anomalous: %s</text>`, p[0], p[1]-r-5, pc, topoEsc(topoShort(strings.Join(names, " · "), 40)))
		}
	}
	b.WriteString(`</svg>`)
}

// topoDeviceSVG draws one affected device with its evidence interfaces and the
// engine's device ↔ interface causal marks (collapsed per interface to the
// strongest relation). Interface ↔ interface marks are drawn only when they
// carry a direction; undirected co-occurrence between interfaces is counted
// under the picture and listed in the causal table.
func topoDeviceSVG(b *strings.Builder, tc TopologyContext, n TopoCtxNode) {
	ports := topoIfaceFaults(tc, n.ID)
	const maxPorts = 12
	more := 0
	if len(ports) > maxPorts {
		more = len(ports) - maxPorts
		ports = ports[:maxPorts]
	}
	const w = 760.0
	h := math.Max(110, 40+30*float64(len(ports)))
	devX, devW := 40.0, 220.0
	portX, portW := 470.0, 190.0
	devY := h / 2
	portY := func(i int) float64 {
		if len(ports) == 1 {
			return devY
		}
		return 30 + float64(i)*(h-60)/float64(len(ports)-1)
	}
	idx := map[string]int{}
	for i, p := range ports {
		idx[p.TargetID] = i
	}
	fmt.Fprintf(b, `<svg viewBox="0 0 %.0f %.0f" width="100%%" style="max-width:760px;display:block;margin:8px auto 2px" role="img" aria-label="Affected device, its evidence interfaces and the causal marks between them">`, w, h)
	// device ↔ port marks, collapsed per port to the strongest relation.
	type pm struct {
		rel        string
		directed   bool
		devToPort  bool
		hasMark    bool
		portToPort []CausalMark
	}
	per := map[int]*pm{}
	undirectedPP := 0
	var directedPP []CausalMark
	for _, m := range tc.Causal {
		fi, fIsPort := idx[m.From]
		ti, tIsPort := idx[m.To]
		fIsDev := m.FromType == "node" && m.From == n.ID && m.FromKind != ""
		tIsDev := m.ToType == "node" && m.To == n.ID && m.ToKind != ""
		switch {
		case fIsDev && tIsPort, fIsPort && tIsDev:
			i, d2p := ti, true
			if fIsPort {
				i, d2p = fi, false
			}
			cur := per[i]
			if cur == nil {
				cur = &pm{}
				per[i] = cur
			}
			if !cur.hasMark || topoCtxRelRank(m.Relation) < topoCtxRelRank(cur.rel) {
				cur.rel, cur.directed, cur.devToPort, cur.hasMark = m.Relation, m.Directed, d2p, true
			}
		case fIsPort && tIsPort && fi != ti:
			if m.Directed && m.Relation != CausalUnknown {
				directedPP = append(directedPP, m)
			} else {
				undirectedPP++
			}
		}
	}
	// device box.
	dfill, dstroke := topoFaultColours(topoDevicePeak(tc, n.ID))
	fmt.Fprintf(b, `<rect x="%.0f" y="%.1f" width="%.0f" height="54" rx="8" fill="%s" stroke="%s" stroke-width="2"/>`, devX, devY-27, devW, dfill, dstroke)
	fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="10.5" font-weight="800" fill="%s">%s</text>`, devX+devW/2, devY-9, topoInk, topoEsc(topoShort(n.Label, 30)))
	sub := orDefault(strings.ReplaceAll(n.Role, "_", " "), "device")
	fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="8" fill="%s">%s</text>`, devX+devW/2, devY+4, topoMuted, topoEsc(topoShort(sub, 36)))
	var devKinds []string
	for _, f := range tc.Faults {
		if f.TargetType == "node" && f.Device == n.ID {
			devKinds = append(devKinds, f.Kinds...)
		}
	}
	if len(devKinds) > 0 {
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="7.5" font-weight="700" fill="%s">%s</text>`, devX+devW/2, devY+17, dstroke, topoEsc(topoShort("device: "+topoHumanKinds(devKinds), 44)))
	}
	// connectors first, boxes on top.
	for i := range ports {
		y := portY(i)
		x1, y1, x2, y2 := devX+devW, devY, portX, y
		m := per[i]
		if m == nil {
			fmt.Fprintf(b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>`, x1, y1, x2, y2, topoLinkDim)
			continue
		}
		if !m.devToPort {
			x1, y1, x2, y2 = x2, y2, x1, y1
		}
		topoCausalLine(b, x1, y1, x2, y2, m.rel, m.directed)
	}
	for _, m := range directedPP {
		i, j := idx[m.From], idx[m.To]
		y1, y2 := portY(i), portY(j)
		x := portX + portW
		bulge := x + 30 + 6*math.Abs(float64(j-i))
		colour := topoAmber
		dash := ` stroke-dasharray="6 4"`
		if m.Relation == CausalVerified {
			colour, dash = topoRed, ""
		}
		fmt.Fprintf(b, `<path d="M %.1f %.1f C %.1f %.1f %.1f %.1f %.1f %.1f" fill="none" stroke="%s" stroke-width="1.6"%s/>`, x, y1, bulge, y1, bulge, y2, x+2, y2, colour, dash)
		topoArrowHead(b, bulge, y2, x+2, y2, colour)
	}
	for i, p := range ports {
		y := portY(i)
		fill, stroke := topoFaultColours(p.PeakSeverity)
		fmt.Fprintf(b, `<rect x="%.0f" y="%.1f" width="%.0f" height="22" rx="5" fill="%s" stroke="%s" stroke-width="1.6"/>`, portX, y-11, portW, fill, stroke)
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" font-size="9" font-weight="800" font-family="ui-monospace,monospace" fill="%s">%s</text>`, portX+8, y+3.5, topoInk, topoEsc(topoShort(p.Port, 14)))
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="end" font-size="7.5" fill="%s">%s</text>`, portX+portW-7, y+3.5, stroke, topoEsc(topoShort(topoHumanKinds(p.Kinds)+" · "+strings.ToUpper(p.PeakSeverity), 30)))
	}
	if len(ports) == 0 {
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" font-size="9" fill="%s">No interface carries attached evidence.</text>`, portX, devY+3, topoMuted)
	}
	b.WriteString(`</svg>`)
	var notes []string
	if more > 0 {
		notes = append(notes, fmt.Sprintf("%d more evidence interface(s) are listed in the table.", more))
	}
	if undirectedPP > 0 {
		notes = append(notes, fmt.Sprintf("%d undirected interface ↔ interface co-occurrence(s) (relationship unknown) are listed in the causal table.", undirectedPP))
	}
	if len(notes) > 0 {
		fmt.Fprintf(b, `<div class="note">%s</div>`, topoEsc(strings.Join(notes, " ")))
	}
}

// topoEntityType maps a mark's target type back to the engine entity type.
func topoEntityType(t string) string {
	if t == "node" {
		return "device"
	}
	return t
}

func topoSortedPairKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
