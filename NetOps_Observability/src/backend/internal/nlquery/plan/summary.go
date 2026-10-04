// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// summary.go — the plain-language answer for a ResultSet, written without a
// model (tracker 337 N-G4: the router's data arm works key-free). Numbers come
// from the result only; nothing is inferred. Two honesty rules:
//   - unmeasured is not zero: an empty metric answer says nothing was
//     measured, never that the value was 0;
//   - a truncated list says so.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

const summaryItems = 5

// Summarize returns a short plain-language summary of rs for the query q.
func Summarize(cat *catalog.Catalog, q *ast.AST, rs *ResultSet) string {
	if rs == nil || q == nil {
		return ""
	}
	var b strings.Builder
	switch {
	case q.Type.IsMetric():
		summarizeMetric(&b, cat, q, rs)
	case q.Type == ast.ChangeList:
		summarizeList(&b, rs, "change", changeLine)
	case q.Type == ast.IncidentList:
		summarizeList(&b, rs, "incident", incidentLine)
	default:
		summarizeList(&b, rs, "row", genericLine)
	}
	return strings.TrimSpace(b.String())
}

func metricLabel(cat *catalog.Catalog, name string) (label, unit string) {
	label = strings.ReplaceAll(name, "_", " ")
	if cat == nil {
		return label, ""
	}
	if m, ok := cat.Metric(name); ok {
		if len(m.Aliases) > 0 {
			label = m.Aliases[0]
		}
		unit = m.Unit
	}
	return label, unit
}

// fmtValue renders a number with its unit ("91.2%", "34 ms", "1,203").
func fmtValue(v float64, unit string) string {
	s := fmt.Sprintf("%.1f", v)
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		s = fmt.Sprintf("%.0f", v)
	}
	switch unit {
	case "percent", "pct", "%":
		return s + "%"
	case "", "count", "score", "state", "bool":
		return s
	default:
		return s + " " + unit
	}
}

func entityName(e map[string]string) string {
	for _, k := range []string{"device", "circuit", "site", "provider", "probe_target", "application"} {
		if v := e[k]; v != "" {
			if itf := e["interface"]; itf != "" && k == "device" {
				return v + " " + itf
			}
			if peer := e["bgp_peer"]; peer != "" && k == "device" {
				return v + " → " + peer
			}
			return v
		}
	}
	var parts []string
	for k, v := range e {
		if k != "members" && v != "" {
			parts = append(parts, v)
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

func rowEntity(r Row) map[string]string {
	e := map[string]string{}
	for k, v := range r {
		if s, ok := v.(string); ok {
			e[k] = s
		}
	}
	return e
}

func summarizeMetric(b *strings.Builder, cat *catalog.Catalog, q *ast.AST, rs *ResultSet) {
	label, unit := metricLabel(cat, rs.Metric)
	if rs.Unit != "" {
		unit = rs.Unit
	}
	if len(rs.Series) == 0 && len(rs.Rows) == 0 {
		fmt.Fprintf(b, "No %s data was measured for that selection in this window — nothing was recorded, which is not the same as a value of zero.", label)
		writeNotes(b, rs)
		return
	}
	if len(rs.Series) > 0 {
		type stat struct {
			name           string
			max, avg, last float64
		}
		var stats []stat
		for _, s := range rs.Series {
			if len(s.Points) == 0 {
				continue
			}
			st := stat{name: entityName(s.Entity), max: math.Inf(-1)}
			sum := 0.0
			for _, p := range s.Points {
				st.max = math.Max(st.max, p.V)
				sum += p.V
			}
			st.avg, st.last = sum/float64(len(s.Points)), s.Points[len(s.Points)-1].V
			stats = append(stats, st)
		}
		if len(stats) == 0 {
			fmt.Fprintf(b, "No %s data was measured for that selection in this window — nothing was recorded, which is not the same as a value of zero.", label)
			writeNotes(b, rs)
			return
		}
		sort.SliceStable(stats, func(i, j int) bool { return stats[i].max > stats[j].max })
		if len(stats) == 1 {
			st := stats[0]
			fmt.Fprintf(b, "%s on %s: latest %s, peak %s, average %s.", capitalizeFirst(label), st.name,
				fmtValue(st.last, unit), fmtValue(st.max, unit), fmtValue(st.avg, unit))
		} else {
			fmt.Fprintf(b, "%s for %d series, highest peak first:", capitalizeFirst(label), len(stats))
			for i, st := range stats {
				if i == summaryItems {
					fmt.Fprintf(b, " … and %d more.", len(stats)-summaryItems)
					break
				}
				fmt.Fprintf(b, " %s peak %s (avg %s);", st.name, fmtValue(st.max, unit), fmtValue(st.avg, unit))
			}
		}
	} else {
		n := len(rs.Rows)
		if q.Type == ast.MetricFilter {
			fmt.Fprintf(b, "%d match%s for %s:", n, plural(n, "", "es"), label)
		} else {
			fmt.Fprintf(b, "%s — %d result%s:", capitalizeFirst(label), n, plural(n, "", "s"))
		}
		for i, r := range rs.Rows {
			if i == summaryItems {
				fmt.Fprintf(b, " … and %d more.", n-summaryItems)
				break
			}
			line := " " + entityName(rowEntity(r))
			if v, ok := r["value"].(float64); ok { // no value → no number, never a 0
				line += " " + fmtValue(v, unit)
			}
			if d, ok := r["delta"].(float64); ok {
				sign := "+"
				if d < 0 {
					sign = "-"
				}
				line += " (" + sign + fmtValue(math.Abs(d), unit) + " vs before)"
			}
			b.WriteString(line + ";")
		}
	}
	if rs.Truncated {
		b.WriteString(" More results exist than are shown.")
	}
	writeNotes(b, rs)
}

type lineFunc func(Row) string

func summarizeList(b *strings.Builder, rs *ResultSet, noun string, line lineFunc) {
	n := len(rs.Rows)
	if n == 0 {
		fmt.Fprintf(b, "No %ss match in this window.", noun)
		writeNotes(b, rs)
		return
	}
	more := ""
	if rs.Truncated {
		more = " (more exist; showing the newest)"
	}
	fmt.Fprintf(b, "%d %s%s%s:", n, noun, plural(n, "", "s"), more)
	for i, r := range rs.Rows {
		if i == summaryItems {
			fmt.Fprintf(b, "\n… and %d more.", n-summaryItems)
			break
		}
		b.WriteString("\n• " + line(r))
	}
	writeNotes(b, rs)
}

func changeLine(r Row) string {
	var parts []string
	if t, ok := r["time"].(time.Time); ok && !t.IsZero() {
		parts = append(parts, t.UTC().Format("Jan 2 15:04 UTC"))
	}
	what := str(r["type"])
	if o := str(r["object"]); o != "" {
		what += " on " + o
	}
	parts = append(parts, strings.TrimSpace(what))
	if a := str(r["actor"]); a != "" {
		parts = append(parts, "by "+a)
	}
	s := strings.Join(parts, " · ")
	if sum := str(r["summary"]); sum != "" {
		s += " — " + sum
	}
	return s
}

func incidentLine(r Row) string {
	id := firstStr(str(r["display_id"]), str(r["incident_id"]))
	s := id
	if t := str(r["title"]); t != "" {
		s += " " + t
	}
	var tags []string
	for _, k := range []string{"state", "verdict_tier", "owner"} {
		if v := str(r[k]); v != "" {
			tags = append(tags, v)
		}
	}
	if len(tags) > 0 {
		s += " (" + strings.Join(tags, ", ") + ")"
	}
	return s
}

func genericLine(r Row) string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, r[k]))
	}
	return strings.Join(parts, " ")
}

func writeNotes(b *strings.Builder, rs *ResultSet) {
	for _, n := range rs.Notes {
		b.WriteString("\n" + n)
	}
}

func str(v any) string {
	s, _ := v.(string) // a non-string cell has no text form here
	return s
}

func firstStr(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
