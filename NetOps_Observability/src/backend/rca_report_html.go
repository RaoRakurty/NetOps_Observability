package main

// rca_report_html.go — server-side HTML rendering of the canonical RCA report
// (rca_report.go). Phase 2 of the postmortem spec (docs/design/
// rca-postmortem-enhancements-spec.md §1): the document follows the approved
// 12-section postmortem order — Executive Summary · Impact · What Happened ·
// Trigger · Root Cause and Contributing Factors · Detection and Response ·
// Mitigation and Service Recovery · Corrective Actions · Lessons Learned ·
// Detailed Timeline · Evidence Appendix · Glossary. A section with no data
// renders its honest absence ("not determined" / "not measured") — it is
// never omitted silently and never filled. The Google-SRE-like masthead stays
// on page 1; artifact-class watermarking is preserved (a validation document
// never resembles a production postmortem).
//
// Print-safe: A4, grayscale-legible (state is always carried by a WORD,
// colour only reinforces), no scripts, no external resources (renders
// identically under the Gotenberg sidecar's Chromium and in a browser tab).
// Colour rules (§18): green = healthy/recovered, amber = suspected/monitoring,
// red = active confirmed fault, gray = unknown/absent, blue = informational.

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

var rcaReportTmpl = template.Must(template.New("rca-report").Funcs(template.FuncMap{
	"stateTone":  rcaStateTone,
	"humanState": func(v string) string { return strings.ReplaceAll(v, "_", " ") },
	"upper":      strings.ToUpper,
	"title":      rcaTitleCase,
	"midSent":    rcaMidSentence,
	"dur":        func(ms int64) string { return fmtDur(time.Duration(ms) * time.Millisecond) },
	"f1": func(f *float64) string {
		if f == nil {
			return ""
		}
		return fmt.Sprintf("%.1f", *f)
	},
	"deltaHuman": func(d *int64) string {
		if d == nil {
			return "unknown"
		}
		if *d <= 0 {
			return fmtDur(time.Duration(-*d)*time.Second) + " before onset"
		}
		return fmtDur(time.Duration(*d)*time.Second) + " after onset"
	},
	"relLabel": func(rel string) string {
		return map[string]string{
			"same_resource": "Same resource", "same_service": "Same service (correlated)",
			"same_account_region": "Same account/region only", "temporal_only": "Temporal correlation only",
		}[rel]
	},
	"pathGraph":      rcaPathGraphSVG,
	"densityBar":     rcaDensityBarHTML,
	"respondingMark": rcaHopRespondingWithMark,
	"commaJoin":      func(ss []string) string { return strings.Join(ss, ", ") },
	// coverage-assessment renderers (Phase D) — the table consumes the canonical
	// CoverageAssessment; it never recomputes a coverage number.
	"covQuality": func(a *CoverageAssessment) string {
		if a == nil {
			return ""
		}
		return rcaTitleCase(string(a.Quality))
	},
	"covStrategy": func(a *CoverageAssessment) string {
		if a == nil {
			return ""
		}
		return strings.ReplaceAll(string(a.Strategy), "_", " ")
	},
	"covPct": func(a *CoverageAssessment) string {
		if a == nil || !a.RatioKnown {
			return ""
		}
		return fmt.Sprintf("%.0f%%", a.CoverageRatio*100)
	},
	"triLabel": func(t coverageTri) string {
		switch t {
		case triYes:
			return "yes"
		case triNo:
			return "no"
		}
		return "unknown"
	},
	// Phase 2 (postmortem layout) helpers.
	"msLabel": func(key string) string { return rcaMilestoneLabels[key] },
	"impactVal": func(m rcaImpactMeasure) string {
		if m.Status == impactNotMeasured || m.Value == nil {
			return "Not measured"
		}
		v := strings.TrimSuffix(fmt.Sprintf("%.1f", *m.Value), ".0")
		if m.Unit == "%" {
			return v + "%"
		}
		if m.Unit != "" {
			return v + " " + m.Unit
		}
		return v
	},
	"hasLessons": func(l rcaLessonsLearned) bool {
		return len(l.WhatWorkedWell)+len(l.WhatDidNotWorkAsIntended)+len(l.WhereDefensesLimitedImpact)+
			len(l.AssumptionsProvedIncorrect)+len(l.DetectionGaps)+len(l.ResponseGaps) > 0
	},
}).Parse(rcaReportTmplSrc))

// rcaDensityBarHTML renders one symptom's bucketed observation density as a
// print-safe inline bar: NEUTRAL ink whose opacity tracks recurrence — volume
// is never a health state (design §7) and never a number posing as evidence.
func rcaDensityBarHTML(buckets []int) template.HTML {
	max := 0
	for _, b := range buckets {
		if b > max {
			max = b
		}
	}
	var sb strings.Builder
	sb.WriteString(`<span style="display:inline-flex;gap:1px;vertical-align:middle" role="img" aria-label="observation recurrence over the incident window">`)
	for _, b := range buckets {
		bg := "#e9edf3" // empty bucket — visibly quiet, never invisible
		if max > 0 && b > 0 {
			switch q := float64(b) / float64(max); {
			case q > 0.75:
				bg = "#334155"
			case q > 0.5:
				bg = "#64748b"
			case q > 0.25:
				bg = "#94a3b8"
			default:
				bg = "#cbd5e1"
			}
		}
		fmt.Fprintf(&sb, `<span style="width:6px;height:10px;border-radius:1px;background:%s"></span>`, bg)
	}
	sb.WriteString(`</span>`)
	return template.HTML(sb.String()) // #nosec G203 — built above from constants only
}

// rcaPathGraphSVG draws the measured path as the same causal picture the
// workspace canvas shows — nodes left→right, provider boundaries named, the
// verdict-gated break point red — so the exported document carries the path's
// causality VISUALLY, not only as a table. Only measured hops are drawn; an
// unknown hop renders dashed-grey, never bridged.
func rcaPathGraphSVG(t rcaTopologyView) template.HTML {
	n := len(t.Hops)
	if n == 0 {
		return ""
	}
	const step, x0, cy = 148, 74, 52
	w := x0*2 + step*(n-1)
	var b strings.Builder
	esc := func(s string) string { return template.HTMLEscapeString(s) }
	short := func(s string, max int) string {
		if len(s) > max {
			return s[:max-1] + "…"
		}
		return s
	}
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d 132" width="100%%" style="max-width:%dpx;display:block;margin:8px auto 2px" role="img" aria-label="Network path causality">`, w, min(w, 760))
	// edges first (under the nodes); an edge into/after a dark hop is dashed.
	for i := 1; i < n; i++ {
		x1, x2 := x0+step*(i-1), x0+step*i
		dark := t.Hops[i].State == "down" || t.Hops[i].State == "unknown" ||
			t.Hops[i-1].State == "down" || t.Hops[i-1].State == "unknown"
		style := `stroke="#94a3b8" stroke-width="1.6"`
		if dark {
			style = `stroke="#cbd5e1" stroke-width="1.6" stroke-dasharray="5 4"`
		}
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" %s/>`, x1+15, cy, x2-15, cy, style)
	}
	for i, h := range t.Hops {
		x := x0 + step*i
		// Node colour is carried by the hop's OWN response STATE — never by the
		// case's fault verdict. A responding object is drawn responding even when
		// the case's fault is on the path; the failure/visibility boundary is drawn
		// AFTER it (P1 path-boundary rendering: no red on a responding hop).
		fill, stroke, dash := "#ecfdf5", "#0f9f4f", ""
		switch h.State {
		case "down", "missing":
			fill, stroke = "#fee2e2", "#dc2626"
		case "degraded":
			fill, stroke = "#fef3c7", "#b45309"
		case "unknown":
			fill, stroke, dash = "#f1f5f9", "#94a3b8", ` stroke-dasharray="4 3"`
		}
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="13" fill="%s" stroke="%s" stroke-width="2"%s/>`, x, cy, fill, stroke, dash)
		respondingMark := rcaHopRespondingWithMark(h)
		faultedFailedNode := (h.Fault == "broken" || h.Fault == "suspected") && !respondingMark
		switch {
		case respondingMark:
			// last responding hop: a fact, not a failure. Label it, and draw the
			// failure/visibility boundary on the outgoing edge (after this hop).
			fmt.Fprintf(&b, `<text x="%d" y="18" text-anchor="middle" font-size="8" font-weight="700" letter-spacing=".06em" fill="#475569">LAST RESPONDING HOP</text>`, x)
			bx := x + step/2
			if i == n-1 {
				bx = x + 34
			}
			bcolor := "#dc2626"
			blabel := "✕ failure boundary"
			if h.Fault == "suspected" || h.Fault == "last_response" {
				bcolor, blabel = "#b45309", "✕ visibility boundary"
			}
			// The tick drops into the empty bottom band and carries its label
			// there — the label row (y=122) is otherwise unused, so it can never
			// collide with the hop name/address/seam rows (y=82/94/106).
			fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.8" stroke-dasharray="4 3"/>`, bx, cy-11, bx, 112, bcolor)
			fmt.Fprintf(&b, `<text x="%d" y="122" text-anchor="middle" font-size="8" font-weight="800" fill="%s">%s</text>`, bx, bcolor, blabel)
		case faultedFailedNode:
			// a genuinely non-responding hop the case blames — red is warranted.
			fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="13" font-weight="800" fill="%s">✕</text>`, x, cy+5, stroke)
			fmt.Fprintf(&b, `<text x="%d" y="18" text-anchor="middle" font-size="8.5" font-weight="800" letter-spacing=".08em" fill="%s">FAILED HOP</text>`, x, stroke)
		}
		if !respondingMark && !faultedFailedNode && h.Provider != "" {
			prov := strings.ToUpper(h.Provider)
			if uri := cloudIconDataURI(h.Provider); uri != "" {
				// official provider mark + name (the icon terms recommend the
				// name near the icon). Centered as one group above the node.
				tw := 5 * len(prov) // ≈ bold 8px glyph width
				left := x - (14+4+tw)/2
				fmt.Fprintf(&b, `<image href="%s" x="%d" y="4" width="14" height="14"/>`, uri, left)
				fmt.Fprintf(&b, `<text x="%d" y="14" font-size="8" font-weight="700" letter-spacing=".08em" fill="#475569">%s</text>`, left+18, esc(prov))
			} else {
				fmt.Fprintf(&b, `<text x="%d" y="18" text-anchor="middle" font-size="8" font-weight="700" letter-spacing=".08em" fill="#475569">%s</text>`, x, esc(prov))
			}
		}
		// zone above, name + boundary below — the same reading order as the table.
		fmt.Fprintf(&b, `<text x="%d" y="32" text-anchor="middle" font-size="8" fill="#64748b">%s</text>`, x, esc(rcaTitleCase(h.Kind)))
		name := h.Label
		if name == "" {
			name = "unknown hop"
		}
		fmt.Fprintf(&b, `<text x="%d" y="82" text-anchor="middle" font-size="9.5" font-weight="700" fill="#0f172a">%s</text>`, x, esc(short(name, 20)))
		if h.Address != "" && h.Address != h.Label {
			fmt.Fprintf(&b, `<text x="%d" y="94" text-anchor="middle" font-size="8" font-family="ui-monospace,monospace" fill="#64748b">%s</text>`, x, esc(short(h.Address, 22)))
		}
		if h.SeamID != "" || (h.Boundary != "" && h.Boundary != "LAN" && h.Boundary != "WAN") {
			fmt.Fprintf(&b, `<text x="%d" y="106" text-anchor="middle" font-size="8" font-weight="600" fill="#7c3aed">%s</text>`, x, esc(short(h.Boundary+" boundary", 24)))
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) // #nosec G203 — built above from escaped fields only
}

// rcaHopRespondingWithMark reports whether a hop is the last RESPONDING hop that
// carries the case's causal/visibility mark. Such a hop is a fact ("this is the
// last hop that answered"), never a failed object — it is never styled red, and
// the failure/visibility boundary is drawn AFTER it (P1 path-boundary rendering).
func rcaHopRespondingWithMark(h rcaSpineHopView) bool {
	if h.Fault != "broken" && h.Fault != "suspected" && h.Fault != "last_response" {
		return false
	}
	switch h.State {
	case "responding", "up", "healthy", "":
		return true
	}
	return false
}

// rcaStateTone — badge tone per state WORD (§18 colour rules). The word always
// renders; the tone only reinforces it (grayscale-safe).
func rcaStateTone(kind, val string) string {
	v := strings.ToLower(val)
	switch kind {
	case "incident":
		switch v {
		case "active":
			return "red"
		case "recovering":
			return "amber"
		case "recovered", "closed":
			return "green"
		case "no_longer_observed":
			// signals stopped without recovery evidence — neutral, not green:
			// absence of data must never render as health (§17).
			return "gray"
		case "merged", "superseded":
			// a merged source is neither healthy nor active — informational.
			return "blue"
		}
	case "recovery":
		switch v {
		case "explicitly_confirmed":
			return "green"
		}
		return "gray"
	case "analysis":
		switch v {
		case "confirmed":
			return "green"
		case "probable", "suspected":
			return "amber"
		case "inconclusive":
			return "gray"
		}
		return "blue" // observed
	case "impact":
		switch v {
		case "confirmed", "detected":
			return "red"
		case "none_detected":
			return "green"
		}
		return "gray"
	case "ticket":
		switch v {
		case "opened":
			return "blue"
		case "held":
			return "amber"
		case "resolved":
			return "green"
		case "failed":
			return "red"
		}
		return "gray"
	case "severity":
		switch v {
		case "crit":
			return "red"
		case "high":
			return "amber"
		case "warn":
			return "amber"
		case "info":
			return "blue"
		}
		return "gray"
	case "lane":
		switch v {
		case "anomalous":
			return "red"
		case "normal":
			return "green"
		case "inconclusive":
			// partial coverage — observed cleanly but not across the full relevant
			// phase; never green (P1 evidence-coverage quality).
			return "amber"
		}
		return "gray"
	}
	return "gray"
}

func rcaTitleCase(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// rcaReportTemplateVersion identifies the document template for the
// immutability block (postmortem Phase 1): bump on ANY change to
// rcaReportTmplSrc so a stored revision names the template that rendered it.
const rcaReportTemplateVersion = "tmpl-2026.07.19-p2"

func renderRcaReportHTML(rep rcaReport) ([]byte, error) {
	var buf bytes.Buffer
	if err := rcaReportTmpl.Execute(&buf, rep); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const rcaReportTmplSrc = `<!doctype html><html><head><meta charset="utf-8">
<title>{{.ReportType}} — {{.Title}}</title>
<style>
  @page { size: A4; margin: 14mm 12mm; }
  * { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  /* This is a light paper document: pin the color-scheme + canvas so a dark
     browser/OS preference (or a dark-themed embedder) can never restyle it. */
  html { color-scheme: light; background: #fff; }
  body { font: 12.5px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #172033; margin: 0; background: #fff; }
  .doc { max-width: 760px; margin: 0 auto; padding: 4px 0 24px; }
  header.rpt { display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid #172033; padding-bottom:9px; margin-bottom:14px; }
  header.rpt .brand { font-weight:800; letter-spacing:.5px; font-size:13px; color:#334155; }
  header.rpt .doctype { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#64748b; text-align:right; }
  h1 { font-size:20px; margin:0 0 8px; break-after: avoid; page-break-after: avoid; }
  h2 { font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#64748b; margin:0 0 6px; border-bottom:1px solid #e2e8f0; padding-bottom:3px; break-after: avoid; page-break-after: avoid; }
  /* a second heading inside one section needs air above */
  table + h2, div + h2, p + h2, ol + h2 { margin-top: 16px; }
  /* Postmortem section band (Phase 2, spec §1): the 12 numbered sections. */
  .pmh { margin:24px 0 6px; padding:6px 10px; background:#172033; color:#fff; font-size:11px; font-weight:800; letter-spacing:1.2px; text-transform:uppercase; border-radius:4px; break-after: avoid; page-break-after: avoid; }
  /* Print hygiene: long sections are ALLOWED to break across pages — a blanket
     break-inside:avoid on <section> pushed whole sections to the next page and
     left half-empty pages behind. Instead the atomic units (heading+first rows
     via break-after on h2, each row, each card) stay whole. */
  section { margin: 14px 0; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; page-break-inside: avoid; }
  svg { break-inside: avoid; page-break-inside: avoid; }
  .badges { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
  .pill { font-size:10.5px; font-weight:800; padding:3px 9px; border-radius:7px; border:1px solid; white-space:nowrap; }
  .pill.green { color:#0f7a3d; background:#eafaf1; border-color:#bfeccf; }
  .pill.amber { color:#b45309; background:#fff4e8; border-color:#ffd3a9; }
  .pill.red   { color:#b42318; background:#fff0ee; border-color:#ffd0cc; }
  .pill.blue  { color:#1d4ed8; background:#eef4ff; border-color:#c9dbff; }
  .pill.gray  { color:#475467; background:#eef1f6; border-color:#d8dee8; }
  .meta { font-size:11px; color:#64748b; margin-bottom:10px; }
  .meta b { color:#172033; font-family: ui-monospace, monospace; }
  .mgmt { border:1px solid #e2e8f0; border-left:3px solid #2563eb; border-radius:6px; padding:10px 13px; background:#f8fafc; break-inside: avoid; page-break-inside: avoid; }
  .decision { border:1px solid #fed7aa; border-left:3px solid #b45309; border-radius:6px; padding:9px 12px; background:#fff7ed; margin-bottom:6px; break-inside: avoid; page-break-inside: avoid; }
  .decision.green { border-color:#bfeccf; border-left-color:#0f7a3d; background:#f2fbf6; }
  .decision.red   { border-color:#ffd0cc; border-left-color:#b42318; background:#fff5f4; }
  table { width:100%; border-collapse:collapse; font-size:11.5px; table-layout:fixed; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; overflow-wrap:break-word; word-break:break-word; }
  th { color:#64748b; font-weight:700; font-size:10px; text-transform:uppercase; letter-spacing:.5px; background:#f8fafc; }
  /* kv grids may be tall (NOC quick read); they MUST be allowed to fragment
     between rows — an atomic kv block taller than the space left on a page
     pushes wholesale and leaves the page half-empty. */
  .kv { display:grid; grid-template-columns: 190px 1fr; gap:2px 12px; }
  .kv .k { color:#64748b; }
  .kv .v { color:#172033; font-weight:600; }
  .note { font-size:11px; color:#64748b; margin-top:4px; }
  ol.actions { margin:4px 0; padding-left:20px; } ol.actions li { margin:5px 0; break-inside: avoid; page-break-inside: avoid; }
  .divider { display:flex; align-items:center; gap:12px; margin:26px 0 4px; color:#94a3b8; font-size:9.5px; font-weight:800; letter-spacing:1.4px; text-transform:uppercase; break-after: avoid; page-break-after: avoid; }
  .divider::before, .divider::after { content:""; flex:1; border-top:1px solid #d5dce6; }
  .why b { font-size:11.5px; }
  footer.doc-end { margin-top:18px; border-top:1px solid #e2e8f0; padding-top:7px; font-size:10px; color:#94a3b8; display:flex; justify-content:space-between; }
</style></head><body><div class="doc">

<!-- ============================ MASTHEAD — PAGE 1 ============================ -->
<header class="rpt">
  <span class="brand">CORRELIX</span>
  <span class="doctype">{{.ReportType}}<br><span style="letter-spacing:0">{{.DisplayID}}</span></span>
</header>

<h1>{{.Title}}</h1>
<div class="badges">
  {{if .Validation}}<span class="pill red" style="font-weight:800;letter-spacing:.4px">VALIDATION SCENARIO — NOT A PRODUCTION INCIDENT</span>{{end}}
  <span class="pill {{if .Maturity.Watermark}}red{{else}}blue{{end}}">Artifact class: {{.Maturity.Label}}</span>
  {{if .Merge}}<span class="pill blue" style="font-weight:800">Incident: Merged{{if .Merge.SurvivorResolved}} into {{.Merge.SurvivingDisplayID}}{{end}}</span>{{else}}<span class="pill {{stateTone "incident" .States.Incident}}">Incident: {{title (humanState .States.Incident)}}</span>{{end}}
  <span class="pill {{stateTone "recovery" .States.Recovery}}">Recovery: {{title (humanState .States.Recovery)}}</span>
  <span class="pill {{stateTone "analysis" .States.FaultDomain}}">Fault domain: {{title (humanState .States.FaultDomain)}}</span>
  <span class="pill {{stateTone "analysis" .States.RootCauseState}}">Root cause: {{title (humanState .States.RootCauseState)}}</span>
  <span class="pill blue">Confidence: {{.States.Confidence}}</span>
  <span class="pill {{stateTone "impact" .States.Impact}}">Impact: {{title .States.Impact}}</span>
  <span class="pill {{stateTone "ticket" .States.Ticket}}">Ticket: {{title .States.Ticket}}</span>
  <span class="pill {{stateTone "severity" .States.SeverityIncident}}">Severity: {{upper (humanState .States.SeverityIncident)}}</span>
</div>
<div class="meta">Report <b>{{.ReportID}}</b> · Case <b>{{.DisplayID}}</b> · Generated <b>{{.GeneratedAt}}</b>{{if .Subtitle}} · {{.Subtitle}}{{end}}</div>
{{if .Maturity.WithheldSections}}<div class="note">Withheld for this artifact class ({{.Maturity.Label}}): {{range $i, $s := .Maturity.WithheldSections}}{{if $i}} · {{end}}{{humanState $s}}{{end}}. {{.Maturity.Basis}}</div>{{end}}

{{if .Merge}}
<section>
  <div class="decision blue">
    <b>Merged case</b> — {{.Merge.Statement}}
  </div>
  <div class="kv">
    <span class="k">Source case</span><span class="v">{{.Merge.SourceDisplayID}}</span>
    <span class="k">Surviving incident</span><span class="v">{{if .Merge.SurvivorResolved}}{{.Merge.SurvivingDisplayID}}{{else}}Unresolved — see consistency review{{end}}</span>
    <span class="k">Service recovery at merge</span><span class="v">{{title (humanState .Merge.ServiceRecoveryAtMerge)}}</span>
    <span class="k">Lifecycle owner</span><span class="v">Surviving incident (lifecycle, monitoring, ticketing, restoration)</span>
    <span class="k">Ticket responsibility</span><span class="v">{{humanState .Merge.TicketResponsibility}}</span>
    <span class="k">Monitoring responsibility</span><span class="v">{{humanState .Merge.MonitoringResponsibility}}</span>
    <span class="k">Escalation responsibility</span><span class="v">{{humanState .Merge.EscalationResponsibility}}</span>
  </div>
</section>
{{end}}

<!-- ============================ 1 · EXECUTIVE SUMMARY ============================ -->
<div class="pmh">1 · Executive summary</div>

<!-- #113 point 2 — the FIRST content: where · what possibly happened ·
     possible owner(s) · the causality path with broken areas in red. -->
<section>
  <h2>Incident at a glance</h2>
  <div class="kv">
    <span class="k">Where it happened</span><span class="v">{{.AtAGlance.Where}}</span>
    <span class="k">What possibly happened</span><span class="v">{{.AtAGlance.What}}</span>
    <span class="k">{{.AtAGlance.OwnersLabel}}</span><span class="v">{{range $i, $o := .AtAGlance.Owners}}{{if $i}} · {{end}}{{$o}}{{end}}</span>
    {{if .AtAGlance.OwnersReason}}<span class="k">Why</span><span class="v" style="font-weight:400">{{.AtAGlance.OwnersReason}}</span>{{end}}
  </div>
  {{if .Topology.Available}}
  {{pathGraph .Topology}}
  <div class="note">Network causality path (measured) — a red boundary or hop marks where the path broke; hop-by-hop detail in the evidence appendix.</div>
  {{else}}
  <div class="note">{{.Topology.Reason}}</div>
  {{end}}
</section>

<section>
  <h2>Management summary</h2>
  <div class="mgmt">{{.Summary.Management}}</div>
  <div class="note">Confidence basis: {{.States.ConfidenceBasis}}. Incident severity: {{.States.SeverityIncidentBasis}} <span style="color:#94a3b8">(evidence-peak severity: {{.States.SeverityBasis}})</span></div>
</section>

<section>
  <h2>Key facts</h2>
  <div class="kv">
    {{if .Times.FirstObserved}}<span class="k">First observed</span><span class="v">{{.Times.FirstObserved}}</span>{{end}}
    {{if .Times.ComponentRecoveredAt}}<span class="k">Component recovered</span><span class="v">{{.Times.ComponentRecoveredAt}} (component scope only)</span>{{end}}
    {{if .Times.RecoveredCaptured}}<span class="k">Recovered at</span><span class="v">{{.Times.RecoveredAt}}</span>
    {{else if or (eq .States.Incident "recovered") (eq .States.Incident "closed")}}<span class="k">Recovered at</span><span class="v">Not captured</span>{{end}}
    {{if .Times.DurationMS}}<span class="k">Duration</span><span class="v">{{dur .Times.DurationMS}}{{if eq .Times.DurationBasis "elapsed_still_active"}} (elapsed — still active){{end}}{{if eq .Times.DurationBasis "to_last_observation"}} (to last observation){{end}}</span>{{end}}
    {{if .Times.MonitoringUntil}}<span class="k">Monitoring until</span><span class="v">{{.Times.MonitoringUntil}}</span>{{end}}
    {{if .Scope.Services}}<span class="k">Service / application</span><span class="v">{{range $i, $s := .Scope.Services}}{{if $i}}, {{end}}{{$s}}{{end}}</span>{{end}}
    {{if .Scope.Regions}}<span class="k">Region</span><span class="v">{{range $i, $s := .Scope.Regions}}{{if $i}}, {{end}}{{$s}}{{end}}</span>{{end}}
    <span class="k">Root cause</span><span class="v">{{if .RootCause.Identified}}{{.RootCause.Object}}{{else if .RootCause.PossibleCause}}Not confirmed — possibly because of {{midSent .RootCause.PossibleCause}}{{else}}Not identified — no cause hypothesis has supporting evidence yet{{end}}</span>
  </div>
</section>

<!-- ============================ 2 · IMPACT ============================ -->
<div class="pmh">2 · Impact</div>
<section>
  <p style="margin:4px 0 8px;font-weight:600">{{.Semantics.Impact.Statement}}</p>
  <div class="kv">
    <span class="k">Synthetic-transaction axis</span><span class="v">{{title (humanState .States.ImpactSynthetic)}}</span>
    <span class="k">Real-user axis</span><span class="v">{{title (humanState .States.ImpactRealUser)}}</span>
    {{if .Semantics.Impact.SourceLineage}}<span class="k">Determination source</span><span class="v" style="font-weight:400">{{.Semantics.Impact.SourceLineage}}</span>{{end}}
  </div>
  <h2>Quantified impact — every value with provenance</h2>
  <table><thead><tr><th style="width:21%">Measure</th><th style="width:17%">Value</th><th style="width:13%">Basis</th><th>Provenance</th></tr></thead><tbody>
  {{range .ImpactProvenance.Measures}}<tr>
    <td><b>{{.Label}}</b>{{if .Scope}}<div class="note">{{.Scope}}</div>{{end}}</td>
    <td>{{if eq .Status "not_measured"}}<b>Not measured</b>{{else}}<b>{{impactVal .}}</b>{{end}}{{if .Denominator}}<div class="note">of {{.Denominator}}</div>{{end}}</td>
    <td>{{if eq .Status "not_measured"}}—{{else}}{{title (humanState .Status)}}{{end}}{{if .Confidence}}<div class="note">confidence: {{.Confidence}}</div>{{end}}</td>
    <td>{{if .Source}}{{.Source}}{{if .Coverage}}<div class="note">coverage: {{.Coverage}}</div>{{end}}<div class="note">{{.Basis}}</div>{{else}}{{.Basis}}{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">{{.ImpactProvenance.Rule}}</div>
</section>

<!-- ============================ 3 · WHAT HAPPENED ============================ -->
<div class="pmh">3 · What happened</div>
{{if .Phases}}
<section>
  <h2>Incident phases</h2>
  <table><thead><tr><th style="width:22%">Phase</th><th style="width:30%">When</th><th>What happened</th></tr></thead><tbody>
  {{range .Phases}}<tr>
    <td><b>{{title (humanState .Type)}}</b></td>
    <td>{{.StartAt}}{{if .EndAt}} → {{.EndAt}}{{end}}</td>
    <td>{{.Summary}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">Component recovery and service recovery are tracked separately; a component coming back never closes a service that is still failing.</div>
</section>
{{end}}

<section>
  <h2>How the failure propagated</h2>
  {{if .CausalChain.Available}}
  <div class="note" style="color:#172033;font-weight:600">{{.CausalChain.Note}}</div>
  <table><thead><tr><th style="width:4%">#</th><th style="width:28%">Step</th><th style="width:20%">When</th><th style="width:15%">Evidence state</th><th>Evidence</th></tr></thead><tbody>
  {{range .CausalChain.Steps}}<tr>
    <td style="font-family:ui-monospace,monospace;font-weight:800">{{.Number}}</td>
    <td><b>{{.Claim}}</b><div class="note">{{.CausalRole}}{{if .Link}} · {{.Link}} the previous step{{end}}</div></td>
    <td>{{.Interval}}</td>
    <td>{{title (humanState .EpistemicState)}}<div class="note">{{.EpistemicBasis}}</div></td>
    <td>{{if .Evidence}}{{range $i, $e := .Evidence}}{{if $i}}; {{end}}{{$e}}{{end}}{{else}}—{{end}}
      {{if .Contradictions}}<div class="note" style="color:#b42318">contradicted by: {{range $i, $c := .Contradictions}}{{if $i}}; {{end}}{{$c}}{{end}}</div>{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">{{.CausalChain.LanguageRule}}</div>
  {{else}}
  <div class="note">{{.CausalChain.Note}}</div>
  {{end}}
  {{if .CausalChain.Branches}}
  <h2>Alternative hypotheses — branches</h2>
  <table><thead><tr><th style="width:30%">Alternative</th><th style="width:15%">Evidence state</th><th style="width:13%">Verdict tier</th><th>Evidence / contradictions</th></tr></thead><tbody>
  {{range .CausalChain.Branches}}<tr>
    <td><b>{{.Claim}}</b><div class="note">{{.CausalRole}}</div></td>
    <td>{{title (humanState .EpistemicState)}}</td>
    <td>{{if .Tier}}{{title .Tier}}{{else}}—{{end}}</td>
    <td>{{if .Evidence}}{{range $i, $e := .Evidence}}{{if $i}}; {{end}}{{$e}}{{end}}{{end}}{{if .Contradictions}}<div class="note" style="color:#b42318">contradicted by: {{range $i, $c := .Contradictions}}{{if $i}}; {{end}}{{$c}}{{end}}</div>{{end}}{{if and (not .Evidence) (not .Contradictions)}}—{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  {{end}}
  <div class="note">{{.CausalChain.BranchNote}}</div>
</section>

<!-- ============================ 4 · TRIGGER ============================ -->
<div class="pmh">4 · Trigger</div>
<section>
  <p style="margin:4px 0 8px">{{.Semantics.Trigger.Statement}}</p>
  {{with .Semantics.TriggeringObservation}}
  <div class="kv">
    <span class="k">Case-opening observation</span><span class="v">{{.TS}}</span>
    <span class="k">Source</span><span class="v" style="font-weight:400">{{.SourceLineage}}</span>
  </div>
  <div class="note">The observation that opened this case is a detection fact — it is not the incident trigger. The trigger is the event or change that set the failure off, and it is stated only when causally established.</div>
  {{end}}
  {{if .CloudChanges}}
  <h2>Change events near onset</h2>
  {{range .CloudChanges}}<div class="note" style="color:#172033">{{.Explanation}}</div>{{end}}
  <div class="note">A change is never labelled the trigger or root cause from timing alone (correlated is not caused). Full change detail in the evidence appendix.</div>
  {{end}}
</section>

<!-- ============================ 5 · ROOT CAUSE AND CONTRIBUTING FACTORS ============================ -->
<div class="pmh">5 · Root cause and contributing factors</div>
<section class="why">
  <h2>Analysis reasoning</h2>
  {{if .Summary.WhySuspected}}<p><b style="color:#b45309">{{if eq .States.Analysis "confirmed"}}Evidence pattern:{{else}}Why suspected:{{end}}</b> {{.Summary.WhySuspected}}</p>{{end}}
  {{range .Summary.WhyNotConfirmed}}<p><b style="color:#475467">Why not confirmed:</b> {{.}}</p>{{end}}
  {{if .Summary.RequiredConfirm}}<p><b style="color:#1d4ed8">Required confirmation:</b> {{.Summary.RequiredConfirm}}</p>{{end}}
</section>

<section>
  <h2>Fault localization</h2>
  <p>{{.FaultLocalization.Statement}}</p>
  {{if .FaultLocalization.Localized}}
  <div class="kv">
    <span class="k">Localization boundary</span><span class="v" style="font-family:ui-monospace,monospace">{{.FaultLocalization.Object}}</span>
    <span class="k">Boundary type</span><span class="v">{{.FaultLocalization.ObjectType}}</span>
  </div>
  {{if .FaultLocalization.Evidence}}<div class="note">Localizing evidence: {{range $i, $s := .FaultLocalization.Evidence}}{{if $i}}; {{end}}{{$s}}{{end}}</div>{{end}}
  {{end}}
</section>

<section>
  <h2>Root cause</h2>
  <p>{{.RootCause.Statement}}</p>
  {{if .RootCause.Identified}}
  <div class="kv">
    <span class="k">Mechanism</span><span class="v">{{.RootCause.Mechanism}}</span>
    <span class="k">Object</span><span class="v" style="font-family:ui-monospace,monospace">{{.RootCause.Object}}</span>
    {{if .RootCause.Owner}}<span class="k">Owner</span><span class="v">{{.RootCause.Owner}}</span>{{end}}
  </div>
  {{if .RootCause.Evidence}}<div class="note">Causality evidence: {{range $i, $s := .RootCause.Evidence}}{{if $i}}; {{end}}{{$s}}{{end}}</div>{{end}}
  {{else if .RootCause.PossibleCause}}
  <!-- #113 point 4 — cause honesty: the best hypothesis and its evidence STATE,
       never a bare "not identified". -->
  <div class="kv">
    <span class="k">Possible cause (unconfirmed)</span><span class="v">{{.RootCause.PossibleCause}}</span>
    {{if .RootCause.EvidenceKnown}}<span class="k">Evidence in hand</span><span class="v" style="font-weight:400">{{range $i, $s := .RootCause.EvidenceKnown}}{{if $i}}; {{end}}{{$s}}{{end}}</span>{{end}}
    {{if .RootCause.EvidenceMissing}}<span class="k">Evidence still missing</span><span class="v" style="font-weight:400">{{range $i, $s := .RootCause.EvidenceMissing}}{{if $i}}; {{end}}{{$s}}{{end}}</span>{{end}}
  </div>
  {{end}}
  <h2>Contributing factors</h2>
  {{if .Semantics.ContributingFactors}}
  <ol class="actions">{{range .Semantics.ContributingFactors}}<li>{{.Statement}} <span class="note">({{.SourceLineage}})</span></li>{{end}}</ol>
  {{else}}<div class="note">{{.Semantics.ContributingNote}}</div>{{end}}
</section>

<section>
  <h2>{{if .SingleHypothesis}}Current hypothesis{{else}}Hypothesis ranking{{end}}</h2>
  {{if .Hypotheses}}
  <table><thead><tr><th style="width:4%">#</th><th style="width:32%">Hypothesis</th><th style="width:13%">Confidence</th><th style="width:27%">Supporting</th><th>Missing / to confirm</th></tr></thead><tbody>
  {{range .Hypotheses}}<tr{{if .Contradicted}} style="opacity:.62"{{end}}>
    <td style="font-family:ui-monospace,monospace;font-weight:800">{{.Rank}}</td>
    <td><b>{{.Title}}</b> <span class="pill {{if eq .Type "symptom classification"}}gray{{else}}blue{{end}}" style="font-size:9px">{{.Type}}</span>{{if .Contradicted}} <span class="pill gray">ruled out</span>{{end}}
        {{if .Problem}}<div class="note" style="color:#334155">{{.Problem}}</div>{{end}}
        <div class="note">condition: {{humanState .ObservationState}} · causal role: {{humanState .CausalRole}}</div>
        {{if .Owner}}<div class="note">candidate owner: {{.Owner}}</div>{{end}}</td>
    <td>{{title .Label}}</td>
    <td>{{range $i, $s := .Supporting}}{{if $i}}; {{end}}{{$s}}{{end}}{{if .Contradicting}}<div class="note">contradicted by: {{range $i, $s := .Contradicting}}{{if $i}}; {{end}}{{$s}}{{end}}</div>{{end}}</td>
    <td>{{range $i, $s := .ConfirmWhen}}{{if $i}}; {{end}}{{$s}}{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  {{else}}<div class="note">No hypothesis has evidence in this window.</div>{{end}}
</section>

<!-- ============================ 6 · DETECTION AND RESPONSE ============================ -->
<div class="pmh">6 · Detection and response</div>
<section>
  <h2>Detection milestones</h2>
  {{if .Semantics.Milestones}}
  <table><thead><tr><th style="width:28%">Milestone</th><th style="width:24%">When</th><th>Source of this timestamp</th></tr></thead><tbody>
  {{range .Semantics.Milestones}}<tr>
    <td><b>{{.Label}}</b></td>
    <td style="font-family:ui-monospace,monospace">{{.TS}}</td>
    <td>{{.SourceLineage}}</td>
  </tr>{{end}}
  </tbody></table>
  {{else}}<div class="note">No detection milestone carries both a timestamp and its source lineage yet — nothing is listed until both exist.</div>{{end}}
  {{if .Semantics.MilestonesAbsent}}<div class="note">Not recorded: {{range $i, $k := .Semantics.MilestonesAbsent}}{{if $i}} · {{end}}{{msLabel $k}}{{end}} — a milestone without a sourced timestamp is stated as absent, never estimated.</div>{{end}}
  {{if .Semantics.Comparisons}}
  <h2>Comparative durations</h2>
  <div class="kv">
    {{range .Semantics.Comparisons}}<span class="k">{{title .Name}}</span><span class="v">{{dur .DurationMS}} <span style="font-weight:400;color:#64748b">({{.Basis}})</span></span>
    {{end}}
  </div>
  <div class="note">Computed only between milestones whose timestamps AND source lineage are both present — never otherwise.</div>
  {{end}}
</section>

<section>
  <h2>Decision</h2>
  <div class="decision {{if eq .Decision.Decision "Open incident"}}red{{else if eq .Decision.Decision "Monitor"}}green{{end}}">
    <b>{{.Decision.Decision}}</b> — {{.Decision.Reason}}
  </div>
  <div class="kv">
    <span class="k">Policy</span><span class="v">{{.Decision.PolicyName}}</span>
    <span class="k">Ticket-open threshold</span><span class="v">{{.Decision.OpenThreshold}}</span>
    <span class="k">Monitoring window</span><span class="v">{{.Decision.MonitoringWindow}}</span>
    <span class="k">Auto-close</span><span class="v">{{.Decision.AutoCloseWhen}}</span>
    <span class="k">Reopen</span><span class="v">{{.Decision.ReopenWhen}}</span>
    <span class="k">Escalation</span><span class="v">{{if eq .Decision.EscalationState "triggered"}}TRIGGERED at {{.Decision.EscalationAt}} — further escalate if {{.Decision.EscalateWhen}}{{else}}armed — triggers when {{.Decision.EscalateWhen}}{{end}}</span>
    <span class="k">Ticket recommendation</span><span class="v">{{title .Decision.TicketRecommended}} — {{.Decision.TicketRecommendReason}}</span>
    {{if .Decision.TicketExecutionNote}}<span class="k">Ticket execution</span><span class="v" style="font-weight:400">{{.Decision.TicketExecutionNote}}</span>{{end}}
  {{if .Decision.AutoCloseEligible}}<span class="k">Auto-close</span><span class="v">eligible now — monitoring completed with no recurrence (historical impact stays recorded)</span>{{end}}
  </div>
</section>

<section>
  <h2>Ownership</h2>
  <div class="kv">
    <span class="k">Triage owner</span><span class="v">{{.Ownership.TriageOwner}}</span>
    <span class="k">Why</span><span class="v" style="font-weight:400">{{.Ownership.TriageReason}}</span>
    <span class="k">Suspected fault domain</span><span class="v">{{.Ownership.SuspectedDomain}}</span>
    {{if .Ownership.TechnicalOwner}}<span class="k">Technical owner</span><span class="v">{{.Ownership.TechnicalOwner}}</span>{{end}}
    {{if .Ownership.ExternalCandidate}}<span class="k">External provider candidate</span><span class="v">{{.Ownership.ExternalCandidate}} — accountability pending demarcation</span>
    <span class="k">Demarcation</span><span class="v">{{title (humanState .Ownership.Demarcation)}}</span>
    <span class="k">Why</span><span class="v" style="font-weight:400">{{.Ownership.DemarcationBasis}}</span>{{end}}
    <span class="k">Escalation owner</span><span class="v">{{.Ownership.EscalationOwner}}</span>
    <span class="k">Why</span><span class="v" style="font-weight:400">{{.Ownership.EscalationReason}}</span>
  </div>
  {{if .Ownership.Candidates}}
  <table style="margin-top:6px"><thead><tr><th>Candidate team</th><th>Basis</th></tr></thead><tbody>
  {{range .Ownership.Candidates}}<tr><td>{{.Team}}</td><td>{{.Reason}}</td></tr>{{end}}
  </tbody></table>{{end}}
</section>

<!-- ============================ 7 · MITIGATION AND SERVICE RECOVERY ============================ -->
<div class="pmh">7 · Mitigation and service recovery</div>
<section>
  <div class="kv">
    <span class="k">Recovery</span><span class="v">{{title (humanState .States.Recovery)}}</span>
    <span class="k">Why</span><span class="v" style="font-weight:400">{{.States.RecoveryBasis}}</span>
    <span class="k">Component recovery</span><span class="v">{{title (humanState .States.RecoveryComponent.State)}}{{if .States.RecoveryComponent.At}} · {{.States.RecoveryComponent.At}}{{end}}</span>
    {{if .States.RecoveryComponent.Basis}}<span class="k">Why</span><span class="v" style="font-weight:400">{{.States.RecoveryComponent.Basis}}</span>{{end}}
    <span class="k">Service recovery</span><span class="v">{{title (humanState .States.RecoveryService.State)}}{{if .States.RecoveryService.At}} · {{.States.RecoveryService.At}}{{end}}</span>
    {{if .States.RecoveryService.Basis}}<span class="k">Why</span><span class="v" style="font-weight:400">{{.States.RecoveryService.Basis}}</span>{{end}}
    <span class="k">Monitoring</span><span class="v">{{title (humanState .States.Monitoring)}}{{if .Times.MonitoringUntil}} · until {{.Times.MonitoringUntil}}{{end}}</span>
  </div>
  <div class="note">Component recovery and service recovery are assessed separately. Mitigation steps appear in the detection milestones only when an operator or ITSM lifecycle stamp records them — they are never assumed.</div>
</section>

<!-- ============================ 8 · CORRECTIVE ACTIONS ============================ -->
<div class="pmh">8 · Corrective actions</div>
<section>
  <h2>Immediate next actions</h2>
  <ol class="actions">
  {{range .Actions}}<li><span class="pill {{if eq .OperationalPriority "P1"}}red{{else}}blue{{end}}" style="font-size:9px">{{.OperationalPriority}}</span> <b>{{.Action}}</b> — owner: {{.Owner}}{{if .ExpectedResult}}<div class="note">Expected output: {{.ExpectedResult}}</div>{{end}}{{if .EscalateWhen}}<div class="note">Escalate when: {{.EscalateWhen}}</div>{{end}}</li>
  {{end}}
  </ol>
  <div class="note">Durable corrective-action commitments (accountable owner, due date, success criteria, verification) are managed in the case's action register; a printed document is a status snapshot as of generation time.{{if .Validation}} Validation scenario: this document makes no production corrective-action commitments.{{end}}</div>
</section>

<!-- ============================ 9 · LESSONS LEARNED ============================ -->
<div class="pmh">9 · Lessons learned</div>
<section>
  {{if hasLessons .LessonsLearned}}
  {{with .LessonsLearned}}
  {{if .WhatWorkedWell}}<h2>What worked well</h2><ol class="actions">{{range .WhatWorkedWell}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{if .WhatDidNotWorkAsIntended}}<h2>What did not work as intended</h2><ol class="actions">{{range .WhatDidNotWorkAsIntended}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{if .WhereDefensesLimitedImpact}}<h2>Where defenses limited impact</h2><ol class="actions">{{range .WhereDefensesLimitedImpact}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{if .AssumptionsProvedIncorrect}}<h2>Assumptions that proved incorrect</h2><ol class="actions">{{range .AssumptionsProvedIncorrect}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{if .DetectionGaps}}<h2>Detection / observability gaps</h2><ol class="actions">{{range .DetectionGaps}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{if .ResponseGaps}}<h2>Response / coordination gaps</h2><ol class="actions">{{range .ResponseGaps}}<li>{{.}}</li>{{end}}</ol>{{end}}
  {{end}}
  <div class="note">{{.LessonsLearned.Note}}</div>
  {{else if .LessonsLearned.Editable}}
  <div class="note">No lessons have been recorded yet. {{.LessonsLearned.Note}}</div>
  {{else}}
  <div class="note">{{.LessonsLearned.Note}}</div>
  {{end}}
</section>

<!-- ============================ 10 · DETAILED TIMELINE ============================ -->
<div class="pmh">10 · Detailed timeline</div>
<section>
  {{if .Timeline}}
  <table><thead><tr><th style="width:22%">When</th><th style="width:46%">Event</th><th>Source of this entry</th></tr></thead><tbody>
  {{range .Timeline}}<tr>
    <td style="font-family:ui-monospace,monospace">{{.TS}}</td>
    <td>{{.Event}}</td>
    <td>{{.Source}}</td>
  </tr>{{end}}
  </tbody></table>
  {{else}}<div class="note">No timestamped events with source lineage are available for this case.</div>{{end}}
  <div class="note">Every row names the source of its timestamp; an event lacking either is not listed — never estimated.</div>
</section>

<!-- ============================ 11 · EVIDENCE APPENDIX ============================ -->
<div class="divider">11 · Evidence appendix — measurements &amp; coverage</div>

<section>
  <h2>NOC quick read</h2>
  <div class="kv">
    {{range .Summary.Noc}}<span class="k">{{.K}}</span><span class="v">{{.V}}</span>
    {{end}}
  </div>
</section>

<section>
  <h2>Evidence summary</h2>
  <!-- Owner directive 2026-07-18 (rca-evidence-summary.md): symptoms ·
       independent sources · duration are THE evidence headline; repetition
       renders as per-symptom time density, never as a count posing as
       evidence; the raw observation total is the muted last line. -->
  <div style="display:flex;gap:26px;align-items:baseline;margin:2px 0 8px">
    <span style="font-size:17px;font-weight:800">{{.Evidence.SymptomCount}} <span style="font-size:10.5px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.5px">distinct symptom{{if ne .Evidence.SymptomCount 1}}s{{end}}</span></span>
    <span style="font-size:17px;font-weight:800">{{.Evidence.IndependentSources}} <span style="font-size:10.5px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.5px">independent source{{if ne .Evidence.IndependentSources 1}}s{{end}}</span></span>
    {{if .Times.DurationMS}}<span style="font-size:17px;font-weight:800">{{dur .Times.DurationMS}} <span style="font-size:10.5px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.5px">{{if eq .Times.DurationBasis "elapsed_still_active"}}ongoing{{else}}duration{{end}}</span></span>{{end}}
  </div>
  <div class="note" style="color:#172033;font-weight:600;margin-bottom:6px">{{.Evidence.VerdictReason}}</div>
  {{if .Evidence.Symptoms}}
  <table><thead><tr><th style="width:24%">Symptom</th><th style="width:20%">Seen by</th><th style="width:12%">First</th><th style="width:13%">Latest</th><th>Recurrence over the window</th></tr></thead><tbody>
  {{range .Evidence.Symptoms}}<tr>
    <td><b>{{.Label}}</b></td>
    <td>{{.Source}}</td>
    <td style="font-family:ui-monospace,monospace">{{.First}}</td>
    <td>{{.Last}}</td>
    <td>{{densityBar .Buckets}}</td>
  </tr>{{end}}
  </tbody></table>
  {{end}}
  <div class="kv" style="margin-top:6px">
    {{with .Signals.Probe}}
    <span class="k">Check observations</span><span class="v">{{.Failed}} failed of {{.Observations}}</span>
    {{if .AffectedVantages}}<span class="k">Reporting sources</span><span class="v">{{range $i, $s := .AffectedVantages}}{{if $i}}, {{end}}{{$s}}{{end}}</span>{{end}}
    {{with .LastTransaction}}
    <span class="k">Last failed check</span><span class="v">{{if .Method}}{{.Method}} {{end}}{{.Target}}{{if .StatusCode}} → HTTP {{.StatusCode}}{{end}}{{if .FailClass}} ({{.FailClass}}){{end}} · {{.At}}</span>
    <span class="k">Phase timings</span><span class="v">{{if .DNSMs}}DNS {{f1 .DNSMs}} ms · {{end}}{{if .TCPMs}}TCP {{f1 .TCPMs}} ms · {{end}}{{if .TLSMs}}TLS {{f1 .TLSMs}} ms · {{end}}{{if .TTFBMs}}TTFB {{f1 .TTFBMs}} ms · {{end}}{{if .TotalMs}}total {{f1 .TotalMs}} ms{{end}}</span>
    {{end}}
    {{if .FailureStages}}<span class="k">Failure stages / symptoms</span><span class="v">{{range $i, $s := .FailureStages}}{{if $i}}, {{end}}{{$s}}{{end}}</span>{{end}}
    {{if .PeakLossPct}}<span class="k">Packet loss (peak)</span><span class="v">{{f1 .PeakLossPct}}%</span>{{end}}
    {{if .PeakRttMs}}<span class="k">Latency</span><span class="v">{{if .BaselineRttMs}}baseline {{f1 .BaselineRttMs}} ms · {{end}}peak {{f1 .PeakRttMs}} ms</span>{{end}}
    {{if .FirstFailed}}<span class="k">First failed sample</span><span class="v">{{.FirstFailed}}</span>{{end}}
    {{if .LastFailed}}<span class="k">Last failed sample</span><span class="v">{{.LastFailed}}</span>{{end}}
    {{if .IndependenceNote}}<span class="k">Vantage independence</span><span class="v">{{.IndependenceNote}}</span>{{end}}
    {{end}}
  </div>
  <div class="note">Only measured values are shown; an absent metric was not observed — it is not zero.</div>
  <div class="note" style="color:#94a3b8">{{.Evidence.Observations}} raw observations collected{{if .Evidence.LastObservation}} · last {{.Evidence.LastObservation}}{{end}} · repetition shows persistence, not additional evidence</div>
</section>

<section>
  <h2>Evidence accounting</h2>
  <div class="kv">
    <span class="k">Evidence groups</span><span class="v">{{.Accounting.EvidenceGroups}} <span style="font-weight:400;color:#64748b">— distinct measurement source × entity; many observations from one source count once</span></span>
    <span class="k">Logical vantages</span><span class="v">{{if .Accounting.LogicalVantages}}{{commaJoin .Accounting.LogicalVantages}}{{else}}none classified{{end}}</span>
    <span class="k">Control-plane sources</span><span class="v">{{if .Accounting.ControlPlaneSources}}{{commaJoin .Accounting.ControlPlaneSources}}{{else}}none{{end}}</span>
    {{if .Accounting.Collectors}}<span class="k">Collectors (not vantages)</span><span class="v">{{commaJoin .Accounting.Collectors}}</span>{{end}}
    {{if .Accounting.UnknownSources}}<span class="k">Unclassified sources</span><span class="v">{{commaJoin .Accounting.UnknownSources}} <span style="font-weight:400;color:#64748b">— kind not established; never counted as a vantage</span></span>{{end}}
    <span class="k">Independent confirming sources</span><span class="v">{{.Accounting.IndependentConfirmingSources}}{{if .Accounting.IndependentSourceIDs}} ({{commaJoin .Accounting.IndependentSourceIDs}}){{end}}</span>
    <span class="k">Configured tests</span><span class="v">{{.Accounting.ConfiguredTests}}</span>
    <span class="k">Test executions</span><span class="v">{{.Accounting.TestExecutions}}{{if .Accounting.FailedExecutionsBrief}} · {{.Accounting.FailedExecutionsBrief}} failed{{end}}</span>
  </div>
  <div class="note">Reconciliation (operator detail) — each layer is a subset of the one above; the verdict rests on the bottom rows.</div>
  <table><thead><tr><th style="width:58%">Layer</th><th>Count</th></tr></thead><tbody>
  {{range .Accounting.Ladder}}<tr><td>{{.Label}}</td><td>{{.Value}}</td></tr>{{end}}
  </tbody></table>
</section>

<section>
  <h2>Evidence coverage</h2>
  <table><thead><tr><th style="width:15%">Evidence class</th><th style="width:12%">Quality</th><th style="width:15%">State</th><th style="width:10%">Obs.</th><th>Coverage &amp; gaps</th><th style="width:15%">Contributes</th></tr></thead><tbody>
  {{range .Coverage}}<tr>
    <td><b>{{.Label}}</b>{{with .Assessment}}<div class="note">{{covStrategy .}}</div>{{end}}</td>
    <td>{{covQuality .Assessment}}{{with .Assessment}}{{if .RatioKnown}}<div class="note">{{covPct .}} covered</div>{{end}}{{end}}</td>
    <td><span class="pill {{stateTone "lane" .State}}" style="font-size:10px">{{title .State}}</span></td>
    <td>{{if .Observations}}{{.Observations}}{{else}}—{{end}}{{if .Anomalous}}<div class="note">{{.Anomalous}} anomalous</div>{{end}}</td>
    <td>{{.Finding}}
      {{if .From}}<div class="note">observed {{.From}} → {{.To}}</div>{{end}}
      {{with .Assessment}}{{if .LeadingGap}}<div class="note" style="color:#b45309">leading gap: {{.LeadingGap}}</div>{{end}}{{if .TrailingGap}}<div class="note" style="color:#b45309">trailing gap: {{.TrailingGap}}</div>{{end}}{{if .InternalGapTotal}}<div class="note" style="color:#b45309">internal gaps: {{.InternalGapTotal}}</div>{{end}}{{end}}
      {{if not .Assessment}}{{if .MissingInterval}}<div class="note" style="color:#b45309">missing: {{.MissingInterval}}</div>{{end}}{{end}}</td>
    <td>{{with .Assessment}}<div class="note">confidence: {{if .ConfidenceEligible}}<b style="color:#0f7a3d">yes</b>{{else}}<b style="color:#b45309">no</b>{{end}}</div>
      <div class="note">impact: {{if .ImpactEligible}}<b style="color:#0f7a3d">yes</b>{{else}}<b style="color:#b45309">no</b>{{end}}</div>
      <div class="note">scope: {{triLabel .Scope}}</div>{{end}}
      {{if .CountsTowardConfidence}}<div class="note">counts toward confidence</div>{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">“No data” is a coverage gap, not evidence of health. A lane reads full/Normal only when its covered intervals span the incident at the expected cadence; a point-in-time control-plane event is never scored as continuous coverage. Missing telemetry never supports or contradicts a hypothesis.</div>
</section>

<section>
  <h2>Network path &amp; causality (measured)</h2>
  {{if .Topology.Available}}
  <div class="note" style="margin-bottom:4px">Vantage {{.Topology.VantageID}} · observed {{.Topology.ObservedAt}}{{if .Topology.RelationToIncident}} · temporal role: <b>{{humanState .Topology.RelationToIncident}}</b>{{end}}{{if .Topology.Stale}} · <b style="color:#b45309">STALE — measured before/after the incident window; treat as context, not live state</b>{{end}}</div>
  {{if .Topology.TemporalNote}}<div class="note" style="color:#b45309;font-weight:600">{{.Topology.TemporalNote}}</div>{{end}}
  {{pathGraph .Topology}}
  <table><thead><tr><th style="width:32px">#</th><th>Hop</th><th>Address</th><th>Zone</th><th>State</th><th>Boundary</th></tr></thead><tbody>
  {{range .Topology.Hops}}<tr>
    <td style="font-family:ui-monospace,monospace">{{.Index}}</td>
    <td><b>{{if .Label}}{{.Label}}{{else}}(no response — unknown hop){{end}}</b>{{if .Provider}} <span class="pill blue" style="font-size:9px">{{upper .Provider}}</span>{{end}}{{if respondingMark .}} <span class="pill gray">◍ last responding hop — boundary after</span>{{else if eq .Fault "broken"}} <span class="pill red">✕ failed hop</span>{{else if eq .Fault "suspected"}} <span class="pill amber">✕ suspected failed hop</span>{{end}}</td>
    <td style="font-family:ui-monospace,monospace">{{.Address}}</td>
    <td>{{title .Kind}}</td>
    <td><span class="pill {{if eq .State "down"}}red{{else if eq .State "degraded"}}amber{{else if eq .State "unknown"}}gray{{else}}green{{end}}">{{title .State}}</span></td>
    <td>{{if .SeamID}}provider boundary ({{.Boundary}}){{else}}{{.Boundary}}{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  {{if .Topology.DropPoint}}<div class="note" style="font-weight:600">{{.Topology.DropPoint}}</div>{{end}}
  <div class="note">Only the measured path is drawn. An unknown hop is preserved as unknown — never bridged. A probe source→target relationship does not by itself imply physical causality.</div>
  {{else}}
  <div class="note">{{.Topology.Reason}}</div>
  {{end}}
</section>

{{if .CloudChanges}}
<section>
  <h2>Cloud change events</h2>
  <table><thead><tr><th style="width:14%">When</th><th style="width:18%">Provider / source</th><th style="width:18%">Resource</th><th style="width:13%">Actor</th><th style="width:12%">Δ vs onset</th><th>Relationship</th><th style="width:8%">In case</th></tr></thead><tbody>
  {{range .CloudChanges}}<tr>
    <td>{{.At}}</td>
    <td>{{if .Provider}}{{.Provider}}{{end}}{{if .EventSource}} · {{.EventSource}}{{end}}</td>
    <td style="font-family:ui-monospace,monospace">{{.Resource}}{{if .Region}}<div class="note">{{.Region}}{{if .Account}} · {{.Account}}{{end}}</div>{{end}}</td>
    <td>{{if .Actor}}{{.Actor}}{{else}}—{{end}}</td>
    <td>{{deltaHuman .DeltaSeconds}}</td>
    <td>{{relLabel .Relationship}}</td>
    <td>{{if .Attached}}yes{{else}}no{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">A change is never labelled the root cause from timing alone (correlated is not caused).</div>
</section>
{{end}}

<!-- ============================ 12 · GLOSSARY ============================ -->
<div class="pmh">12 · Glossary</div>
<section>
  {{if .Glossary}}
  {{range .Glossary}}<div style="margin:5px 0"><b>{{title .Term}}</b> — {{.Definition}}</div>
  {{end}}
  {{else}}<div class="note">No specialized report terms are used in this document.</div>{{end}}
  <div class="note">The glossary is dynamic: it defines only the terms this report instance actually uses, as they are meant in this document.</div>
</section>

{{if .Integrity}}
<footer class="doc-end">
  <span>Analysis snapshot {{.Integrity.AnalysisSnapshotHash}} · policy {{.Integrity.PolicyVersion}} · template {{.Integrity.TemplateVersion}}</span>
  <span>Status as of generation: {{.Integrity.StatusAsOf}}</span>
</footer>
{{end}}

</div></body></html>`
