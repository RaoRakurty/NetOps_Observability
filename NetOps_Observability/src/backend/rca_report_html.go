package main

// rca_report_html.go — server-side HTML rendering of the canonical RCA report
// (rca_report.go). Two layers (§17): page 1 = management & decision view,
// page 2+ = NOC & technical view. Print-safe: A4, grayscale-legible (state is
// always carried by a WORD, colour only reinforces), no scripts, no external
// resources (renders identically under the Gotenberg sidecar's Chromium and in
// a browser tab). Colour rules (§18): green = healthy/recovered, amber =
// suspected/monitoring, red = active confirmed fault, gray = unknown/absent,
// blue = informational.

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
	"pathGraph": rcaPathGraphSVG,
}).Parse(rcaReportTmplSrc))

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
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d 128" width="100%%" style="max-width:%dpx;display:block;margin:8px auto 2px" role="img" aria-label="Network path causality">`, w, min(w, 760))
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
		fill, stroke, dash := "#ecfdf5", "#0f9f4f", ""
		switch {
		case h.Fault == "broken" || h.State == "down":
			fill, stroke = "#fee2e2", "#dc2626"
		case h.Fault == "suspected" || h.State == "degraded":
			fill, stroke = "#fef3c7", "#b45309"
		case h.State == "unknown":
			fill, stroke, dash = "#f1f5f9", "#94a3b8", ` stroke-dasharray="4 3"`
		}
		fmt.Fprintf(&b, `<circle cx="%d" cy="%d" r="13" fill="%s" stroke="%s" stroke-width="2"%s/>`, x, cy, fill, stroke, dash)
		if h.Fault == "broken" || h.Fault == "suspected" {
			fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="13" font-weight="800" fill="%s">✕</text>`, x, cy+5, stroke)
			label := "BREAK POINT"
			if h.Fault == "suspected" {
				label = "SUSPECTED BREAK"
			}
			fmt.Fprintf(&b, `<text x="%d" y="18" text-anchor="middle" font-size="8.5" font-weight="800" letter-spacing=".08em" fill="%s">%s</text>`, x, stroke, label)
		} else if h.Provider != "" {
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
  @page { size: A4; margin: 16mm 12mm; }
  * { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font: 12.5px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #172033; margin: 0; }
  .doc { max-width: 760px; margin: 0 auto; padding: 4px 0 24px; }
  header.rpt { display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid #172033; padding-bottom:9px; margin-bottom:14px; }
  header.rpt .brand { font-weight:800; letter-spacing:.5px; font-size:13px; color:#334155; }
  header.rpt .doctype { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#64748b; text-align:right; }
  h1 { font-size:20px; margin:0 0 8px; }
  h2 { font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#64748b; margin:0 0 6px; border-bottom:1px solid #e2e8f0; padding-bottom:3px; }
  section { margin: 12px 0; break-inside: avoid; }
  .badges { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
  .pill { font-size:10.5px; font-weight:800; padding:3px 9px; border-radius:7px; border:1px solid; white-space:nowrap; }
  .pill.green { color:#0f7a3d; background:#eafaf1; border-color:#bfeccf; }
  .pill.amber { color:#b45309; background:#fff4e8; border-color:#ffd3a9; }
  .pill.red   { color:#b42318; background:#fff0ee; border-color:#ffd0cc; }
  .pill.blue  { color:#1d4ed8; background:#eef4ff; border-color:#c9dbff; }
  .pill.gray  { color:#475467; background:#eef1f6; border-color:#d8dee8; }
  .meta { font-size:11px; color:#64748b; margin-bottom:10px; }
  .meta b { color:#172033; font-family: ui-monospace, monospace; }
  .mgmt { border:1px solid #e2e8f0; border-left:3px solid #2563eb; border-radius:6px; padding:10px 13px; background:#f8fafc; }
  .decision { border:1px solid #fed7aa; border-left:3px solid #b45309; border-radius:6px; padding:9px 12px; background:#fff7ed; margin-bottom:6px; }
  .decision.green { border-color:#bfeccf; border-left-color:#0f7a3d; background:#f2fbf6; }
  .decision.red   { border-color:#ffd0cc; border-left-color:#b42318; background:#fff5f4; }
  table { width:100%; border-collapse:collapse; font-size:11.5px; table-layout:fixed; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; overflow-wrap:break-word; word-break:break-word; }
  th { color:#64748b; font-weight:700; font-size:10px; text-transform:uppercase; letter-spacing:.5px; background:#f8fafc; }
  .kv { display:grid; grid-template-columns: 190px 1fr; gap:2px 12px; }
  .kv .k { color:#64748b; }
  .kv .v { color:#172033; font-weight:600; }
  .note { font-size:11px; color:#64748b; margin-top:4px; }
  ol.actions { margin:4px 0; padding-left:20px; } ol.actions li { margin:5px 0; }
  .pagebreak { break-before: page; page-break-before: always; }
  .why b { font-size:11.5px; }
  footer.doc-end { margin-top:18px; border-top:1px solid #e2e8f0; padding-top:7px; font-size:10px; color:#94a3b8; display:flex; justify-content:space-between; }
</style></head><body><div class="doc">

<!-- ============================ PAGE 1 — MANAGEMENT & DECISION ============================ -->
<header class="rpt">
  <span class="brand">CORRELIX</span>
  <span class="doctype">{{.ReportType}}<br><span style="letter-spacing:0">{{.DisplayID}}</span></span>
</header>

<h1>{{.Title}}</h1>
<div class="badges">
  {{if .Validation}}<span class="pill red" style="font-weight:800;letter-spacing:.4px">VALIDATION SCENARIO — NOT A PRODUCTION INCIDENT</span>{{end}}
  <span class="pill {{stateTone "incident" .States.Incident}}">Incident: {{title (humanState .States.Incident)}}</span>
  <span class="pill {{stateTone "recovery" .States.Recovery}}">Recovery: {{title (humanState .States.Recovery)}}</span>
  <span class="pill {{stateTone "analysis" .States.FaultDomain}}">Fault domain: {{title (humanState .States.FaultDomain)}}</span>
  <span class="pill {{stateTone "analysis" .States.RootCauseState}}">Root cause: {{title (humanState .States.RootCauseState)}}</span>
  <span class="pill blue">Confidence: {{.States.Confidence}}</span>
  <span class="pill {{stateTone "impact" .States.Impact}}">Impact: {{title .States.Impact}}</span>
  <span class="pill {{stateTone "ticket" .States.Ticket}}">Ticket: {{title .States.Ticket}}</span>
  <span class="pill {{stateTone "severity" .States.SeverityIncident}}">Severity: {{upper (humanState .States.SeverityIncident)}}</span>
</div>
<div class="meta">Report <b>{{.ReportID}}</b> · Case <b>{{.DisplayID}}</b> · Generated <b>{{.GeneratedAt}}</b>{{if .Subtitle}} · {{.Subtitle}}{{end}}</div>

<section>
  <h2>Management summary</h2>
  <div class="mgmt">{{.Summary.Management}}</div>
  <div class="note">Confidence basis: {{.States.ConfidenceBasis}}. Severity basis: {{.States.SeverityBasis}}.</div>
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
    <span class="k">Root cause</span><span class="v">{{if .RootCause.Identified}}{{.RootCause.Object}}{{else}}Not identified{{end}}</span>
  </div>
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

{{if .CloudChanges}}
<section>
  <h2>Change correlation summary</h2>
  {{range .CloudChanges}}<div class="note" style="color:#172033">{{.Explanation}}</div>{{end}}
</section>
{{end}}

<!-- ============================ PAGE 2 — NOC & TECHNICAL ============================ -->
<div class="pagebreak"></div>
<section>
  <h2>NOC quick read</h2>
  <div class="kv">
    {{range .Summary.Noc}}<span class="k">{{.K}}</span><span class="v">{{.V}}</span>
    {{end}}
  </div>
</section>

<section class="why">
  <h2>Analysis reasoning</h2>
  {{if .Summary.WhySuspected}}<p><b style="color:#b45309">{{if eq .States.Analysis "confirmed"}}Evidence pattern:{{else}}Why suspected:{{end}}</b> {{.Summary.WhySuspected}}</p>{{end}}
  {{range .Summary.WhyNotConfirmed}}<p><b style="color:#475467">Why not confirmed:</b> {{.}}</p>{{end}}
  {{if .Summary.RequiredConfirm}}<p><b style="color:#1d4ed8">Required confirmation:</b> {{.Summary.RequiredConfirm}}</p>{{end}}
</section>

<section>
  <h2>Signal measurements</h2>
  <div class="kv">
    <span class="k">Observations (window)</span><span class="v">{{.Signals.Total}} total · {{.Signals.Attached}} tied to this case · {{.Signals.Clears}} recovery signals</span>
    <span class="k">Independent observers</span><span class="v">{{.Signals.UniqueObservers}}</span>
    {{with .Signals.Probe}}
    <span class="k">Check observations</span><span class="v">{{.Failed}} failed of {{.Observations}}</span>
    {{if .AffectedVantages}}<span class="k">Affected vantages</span><span class="v">{{range $i, $s := .AffectedVantages}}{{if $i}}, {{end}}{{$s}}{{end}}</span>{{end}}
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
</section>

<section>
  <h2>Evidence coverage</h2>
  <table><thead><tr><th>Evidence class</th><th>Coverage</th><th>State</th><th>Obs.</th><th>Finding</th><th>Time coverage</th></tr></thead><tbody>
  {{range .Coverage}}<tr>
    <td><b>{{.Label}}</b>{{if .CountsTowardConfidence}}<div class="note">counts toward confidence</div>{{end}}</td>
    <td>{{title .Availability}}</td>
    <td><span class="pill {{stateTone "lane" .State}}">{{title .State}}</span></td>
    <td>{{if .Observations}}{{.Observations}}{{else}}—{{end}}</td>
    <td>{{.Finding}}</td>
    <td>{{if .From}}{{.From}} → {{.To}}{{else}}—{{end}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">“No data” is a coverage gap, not evidence of health. Missing telemetry never supports or contradicts a hypothesis.</div>
</section>

<section>
  <h2>Network path &amp; causality (measured)</h2>
  {{if .Topology.Available}}
  <div class="note" style="margin-bottom:4px">Vantage {{.Topology.VantageID}} · observed {{.Topology.ObservedAt}}{{if .Topology.Stale}} · <b style="color:#b45309">STALE — measured before/after the incident window; treat as context, not live state</b>{{end}}</div>
  {{pathGraph .Topology}}
  <table><thead><tr><th style="width:32px">#</th><th>Hop</th><th>Address</th><th>Zone</th><th>State</th><th>Boundary</th></tr></thead><tbody>
  {{range .Topology.Hops}}<tr>
    <td style="font-family:ui-monospace,monospace">{{.Index}}</td>
    <td><b>{{if .Label}}{{.Label}}{{else}}(no response — unknown hop){{end}}</b>{{if .Provider}} <span class="pill blue" style="font-size:9px">{{upper .Provider}}</span>{{end}}{{if eq .Fault "broken"}} <span class="pill red">✕ BREAK POINT</span>{{else if eq .Fault "suspected"}} <span class="pill amber">✕ suspected break</span>{{else if eq .Fault "last_response"}} <span class="pill gray">◍ last response</span>{{end}}</td>
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
  <table><thead><tr><th>When</th><th>Provider / source</th><th>Resource</th><th>Actor</th><th>Δ vs onset</th><th>Relationship</th><th>In case</th></tr></thead><tbody>
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

<section>
  {{if .Cascade}}
  <h2>How the failure propagated</h2>
  <table><thead><tr><th style="width:26%">Stage</th><th style="width:16%">Observed</th><th>Evidence</th></tr></thead><tbody>
  {{range .Cascade}}<tr{{if not .Witnessed}} style="opacity:.62"{{end}}>
    <td><b>{{.Stage}}</b>{{if .Root}} <span class="pill red">likely origin</span>{{end}}</td>
    <td>{{if .Witnessed}}<span class="pill green">witnessed</span>{{else}}<span class="pill gray">not observed</span>{{end}}</td>
    <td>{{.Note}}</td>
  </tr>{{end}}
  </tbody></table>
  <div class="note">A failure at the highlighted origin propagates downward. A stage marked
  not observed is part of the known propagation path but carried no evidence in this window
  and is not claimed.</div>
  {{end}}
  <h2>{{if .SingleHypothesis}}Current hypothesis{{else}}Hypothesis ranking{{end}}</h2>
  {{if .Hypotheses}}
  <table><thead><tr><th>#</th><th>Hypothesis</th><th>Confidence</th><th>Supporting</th><th>Missing / to confirm</th></tr></thead><tbody>
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
  {{end}}
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

<section>
  <h2>Next actions</h2>
  <ol class="actions">
  {{range .Actions}}<li><span class="pill {{if eq .OperationalPriority "P1"}}red{{else}}blue{{end}}" style="font-size:9px">{{.OperationalPriority}}</span> <b>{{.Action}}</b> — owner: {{.Owner}}{{if .ExpectedResult}}<div class="note">Expected output: {{.ExpectedResult}}</div>{{end}}{{if .EscalateWhen}}<div class="note">Escalate when: {{.EscalateWhen}}</div>{{end}}</li>
  {{end}}
  </ol>
</section>

</div></body></html>`
