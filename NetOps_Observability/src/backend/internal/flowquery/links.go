// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Column expressions shared by every statement. Totals are scaled by the
// sampling rate the exporter REPORTED and by nothing else: a sampling exporter
// that reports no rate reads as 1:1, and the basis says so (tracker 387: "do
// not multiply"; declared sampling is tracker 401).
//
// No output is ever aliased `bytes`, `packets` or `ts`: ClickHouse resolves a
// SELECT alias inside the same statement and the alias wins over the column, so
// `sumIf(bytes …) AS bytes` fails with code 184 (ILLEGAL_AGGREGATION).
const (
	ScaledBytes   = "bytes * if(sampling_rate = 0, 1, sampling_rate)"
	ScaledPackets = "packets * if(sampling_rate = 0, 1, sampling_rate)"
	// RateReported is true for a record whose exporter reported its sampling
	// rate (the same expression /api/flows/coverage counts).
	RateReported = "(sampling_status = 'reported' OR (sampling_status = '' AND sampling_rate > 0))"
)

// Basis says how far a figure can be trusted, field by field.
type Basis string

const (
	// Measured: every record from the exporter carries the field.
	Measured Basis = "measured"
	// PartlyExported: some records name no interface for this direction, so the
	// figure reads low by about the share given beside it.
	PartlyExported Basis = "partly_exported"
	// NotExported: no record from the exporter names an interface for this
	// direction; the figure is absent (null), never zero.
	NotExported Basis = "not_exported"
)

// Sampling summarises whether the records behind a figure reported a rate.
const (
	SamplingReported    = "reported"
	SamplingNotReported = "not_reported"
	SamplingMixed       = "mixed"
	SamplingNoFlows     = "no_flows"
)

// ResponseBasis rides on every response.
type ResponseBasis struct {
	Flows             float64 `json:"flows"`
	FlowsRateReported float64 `json:"flows_rate_reported"`
	// Sampling: reported | not_reported (the exporter samples or not, but says
	// nothing, so totals read as 1:1) | mixed | no_flows.
	Sampling string `json:"sampling"`
	// BucketTime: which clock places a record in a bucket. `ts` is stamped when
	// the record is received, not when the flow started, so a long flow lands
	// whole in the bucket it was exported in (flow start/end columns: tracker 401).
	BucketTime string `json:"bucket_time"`
}

// SamplingOf derives the sampling label from two counts.
func SamplingOf(flows, reported float64) string {
	switch {
	case flows <= 0:
		return SamplingNoFlows
	case reported <= 0:
		return SamplingNotReported
	case reported >= flows:
		return SamplingReported
	}
	return SamplingMixed
}

// NewResponseBasis builds the response-level basis.
func NewResponseBasis(flows, reported float64) ResponseBasis {
	return ResponseBasis{Flows: flows, FlowsRateReported: reported, Sampling: SamplingOf(flows, reported), BucketTime: "received"}
}

// ExportBasis classifies one direction of one exporter from how many of its
// current-window records name no interface for that direction.
func ExportBasis(flows, missing float64) Basis {
	switch {
	case flows > 0 && missing >= flows:
		return NotExported
	case missing > 0:
		return PartlyExported
	}
	return Measured
}

// ── statements ──────────────────────────────────────────────────────────────

// LinksSQL is the busiest-links statement: ONE scan over the current and the
// previous window, each record counted once per direction it names an
// interface for (ARRAY JOIN over (in_if,'in') and (out_if,'out')), grouped per
// (row tenant, exporter, ifIndex) so two tenants behind one exporter address
// are never merged. Interface names are LEFT JOINed from netops.iface_names on
// the ROW's own tenant (the flows.go flowIfaceTopNSQL contract).
//
// scope is the caller's tenant clause plus the filter bar (" AND …", already
// safe). A link is listed when it carried traffic in the current window.
func LinksSQL(w Window, scope string, limit int) string {
	cur := w.CurCond()
	in, out := "d.2 = 'in'", "d.2 = 'out'"
	return `
SELECT a.tid AS tid, a.exporter AS exporter, a.ifx AS ifx,
       n.ifname AS if_name,
       if(n.ifname != '', 'resolved', 'absent') AS if_name_basis,
       a.in_b AS in_b, a.out_b AS out_b, a.prev_in_b AS prev_in_b, a.prev_out_b AS prev_out_b,
       a.in_p AS in_p, a.out_p AS out_p, a.fl AS fl
  FROM (
    SELECT tenant_id AS tid, sampler_address AS exporter, d.1 AS ifx,
           sumIf(` + ScaledBytes + `, ` + in + ` AND ` + cur + `)        AS in_b,
           sumIf(` + ScaledBytes + `, ` + out + ` AND ` + cur + `)       AS out_b,
           sumIf(` + ScaledBytes + `, ` + in + ` AND NOT ` + cur + `)    AS prev_in_b,
           sumIf(` + ScaledBytes + `, ` + out + ` AND NOT ` + cur + `)   AS prev_out_b,
           sumIf(` + ScaledPackets + `, ` + in + ` AND ` + cur + `)      AS in_p,
           sumIf(` + ScaledPackets + `, ` + out + ` AND ` + cur + `)     AS out_p,
           countIf(` + cur + `) AS fl
      FROM netops.flows
     ARRAY JOIN [(in_if, 'in'), (out_if, 'out')] AS d
     WHERE ` + w.ScanPredicate() + scope + `
       AND d.1 NOT IN ` + IfSentinels + `
     GROUP BY tid, exporter, ifx
    HAVING fl > 0
     ORDER BY in_b + out_b DESC, exporter, ifx
     LIMIT ` + strconv.Itoa(limit) + `
  ) AS a
  LEFT JOIN (
    SELECT tenant_id, exporter_addr, ifindex, argMax(ifname, updated) AS ifname
      FROM netops.iface_names
     GROUP BY tenant_id, exporter_addr, ifindex
  ) AS n ON n.tenant_id = a.tid AND n.exporter_addr = a.exporter AND n.ifindex = a.ifx
 ORDER BY a.in_b + a.out_b DESC, a.exporter, a.ifx
 FORMAT JSON`
}

// CoverageSQL counts, per (row tenant, exporter), what the exporter exports:
// records in each window, records that reported a sampling rate, and records
// (and their bytes) that name no interface per direction. It feeds the
// per-direction basis. exporters (from the links answer) bound the scan; an
// empty list means "every exporter the scope admits".
func CoverageSQL(w Window, scope string, exporters []string) string {
	cur := w.CurCond()
	noIn, noOut := "in_if IN "+IfSentinels, "out_if IN "+IfSentinels
	only := ""
	if len(exporters) > 0 {
		only = " AND sampler_address IN (" + QuoteList(exporters) + ")"
	}
	return `
SELECT tenant_id AS tid, sampler_address AS exporter,
       countIf(` + cur + `) AS fl,
       countIf(NOT ` + cur + `) AS prev_fl,
       countIf(` + cur + ` AND ` + RateReported + `) AS fl_rr,
       countIf(` + cur + ` AND ` + noIn + `) AS fl_no_in,
       countIf(` + cur + ` AND ` + noOut + `) AS fl_no_out,
       sumIf(` + ScaledBytes + `, ` + cur + `) AS b_all,
       sumIf(` + ScaledBytes + `, ` + cur + ` AND ` + noIn + `) AS b_no_in,
       sumIf(` + ScaledBytes + `, ` + cur + ` AND ` + noOut + `) AS b_no_out
  FROM netops.flows
 WHERE ` + w.ScanPredicate() + scope + only + `
 GROUP BY tid, exporter
 FORMAT JSON`
}

// ── shaping ─────────────────────────────────────────────────────────────────

// Num reads a ClickHouse JSON value: UInt64 and Int64 arrive as strings,
// smaller integers and floats as numbers. Anything unreadable is 0.
func Num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case json.Number:
		f, _ := x.Float64() // best-effort: an unreadable number is 0, like every other unreadable value here
		return f
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0
		}
		return f
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint32:
		return float64(x)
	}
	return 0
}

// Str reads a ClickHouse JSON string value.
func Str(v any) string {
	s, _ := v.(string) // a non-string is "", which every caller treats as absent
	return s
}

// CovKey identifies one exporter of one tenant.
type CovKey struct{ Tenant, Exporter string }

// Coverage is one exporter's export profile over the current window.
type Coverage struct {
	Flows, PrevFlows, RateReported float64
	NoIn, NoOut                    float64
	Bytes, BytesNoIn, BytesNoOut   float64
}

// InBasis and OutBasis classify the two directions.
func (c Coverage) InBasis() Basis  { return ExportBasis(c.Flows, c.NoIn) }
func (c Coverage) OutBasis() Basis { return ExportBasis(c.Flows, c.NoOut) }

// unnamedPct is the share of the exporter's bytes that name no interface for a
// direction, in percent; nil when nothing is missing or nothing was carried.
func unnamedPct(missing, all float64) *float64 {
	if missing <= 0 || all <= 0 {
		return nil
	}
	p := round1(missing * 100 / all)
	return &p
}

// ParseCoverage indexes a CoverageSQL answer.
func ParseCoverage(rows []map[string]any) map[CovKey]Coverage {
	out := make(map[CovKey]Coverage, len(rows))
	for _, r := range rows {
		out[CovKey{Str(r["tid"]), Str(r["exporter"])}] = Coverage{
			Flows: Num(r["fl"]), PrevFlows: Num(r["prev_fl"]), RateReported: Num(r["fl_rr"]),
			NoIn: Num(r["fl_no_in"]), NoOut: Num(r["fl_no_out"]),
			Bytes: Num(r["b_all"]), BytesNoIn: Num(r["b_no_in"]), BytesNoOut: Num(r["b_no_out"]),
		}
	}
	return out
}

// Totals sums a coverage map into a response basis.
func Totals(cov map[CovKey]Coverage) ResponseBasis {
	var fl, rr float64
	for _, c := range cov {
		fl += c.Flows
		rr += c.RateReported
	}
	return NewResponseBasis(fl, rr)
}

// LinkRow is one link in a /api/flows/links answer. A null byte figure means
// "not exported by this router" (current) or "not known" (previous) — never 0.
type LinkRow struct {
	TenantID     string   `json:"tenant_id,omitempty"`
	Exporter     string   `json:"exporter"`
	IfIndex      uint32   `json:"ifindex"`
	IfName       string   `json:"if_name"`
	IfNameBasis  string   `json:"if_name_basis"`
	DeviceID     string   `json:"device_id,omitempty"`
	DeviceName   string   `json:"device_name,omitempty"`
	Site         string   `json:"site,omitempty"`
	InBytes      *float64 `json:"in_bytes"`
	OutBytes     *float64 `json:"out_bytes"`
	PrevInBytes  *float64 `json:"prev_in_bytes"`
	PrevOutBytes *float64 `json:"prev_out_bytes"`
	InPackets    float64  `json:"in_packets"`
	OutPackets   float64  `json:"out_packets"`
	Flows        float64  `json:"flows"`
	InBasis      Basis    `json:"in_basis"`
	OutBasis     Basis    `json:"out_basis"`
	// InUnnamedPct / OutUnnamedPct: the share of this router's flow bytes that
	// name no interface for that direction (the figure reads low by about that).
	InUnnamedPct  *float64 `json:"in_unnamed_pct,omitempty"`
	OutUnnamedPct *float64 `json:"out_unnamed_pct,omitempty"`
	Sampling      string   `json:"sampling"`
}

func ptr(v float64) *float64 { return &v }

// BuildLinks shapes a LinksSQL answer with its exporters' coverage.
// prevKnown is false when the previous window reaches past retention, in which
// case no previous figure is given for any link.
func BuildLinks(rows []map[string]any, cov map[CovKey]Coverage, prevKnown bool) []LinkRow {
	out := make([]LinkRow, 0, len(rows))
	for _, r := range rows {
		ix := Num(r["ifx"])
		if ix <= 0 || ix >= 4294967295 {
			continue // a sentinel never reaches here; belt and braces
		}
		row := LinkRow{
			TenantID: Str(r["tid"]), Exporter: Str(r["exporter"]), IfIndex: uint32(ix),
			IfName: strings.TrimSpace(Str(r["if_name"])), IfNameBasis: Str(r["if_name_basis"]),
			InPackets: Num(r["in_p"]), OutPackets: Num(r["out_p"]), Flows: Num(r["fl"]),
		}
		if row.IfName == "" {
			row.IfNameBasis = "absent"
		}
		c, ok := cov[CovKey{row.TenantID, row.Exporter}]
		if !ok {
			// No coverage row (it raced the links read): say nothing stronger
			// than what the links answer itself shows.
			c = Coverage{Flows: row.Flows}
		}
		row.InBasis, row.OutBasis = c.InBasis(), c.OutBasis()
		row.InUnnamedPct, row.OutUnnamedPct = unnamedPct(c.BytesNoIn, c.Bytes), unnamedPct(c.BytesNoOut, c.Bytes)
		row.Sampling = SamplingOf(c.Flows, c.RateReported)
		prevOK := prevKnown && c.PrevFlows > 0
		if row.InBasis != NotExported {
			row.InBytes = ptr(Num(r["in_b"]))
			if prevOK {
				row.PrevInBytes = ptr(Num(r["prev_in_b"]))
			}
		}
		if row.OutBasis != NotExported {
			row.OutBytes = ptr(Num(r["out_b"]))
			if prevOK {
				row.PrevOutBytes = ptr(Num(r["prev_out_b"]))
			}
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool { return total(out[i]) > total(out[j]) })
	return out
}

func total(r LinkRow) float64 {
	var t float64
	if r.InBytes != nil {
		t += *r.InBytes
	}
	if r.OutBytes != nil {
		t += *r.OutBytes
	}
	return t
}

// Exporters lists the distinct exporters of a links answer, sorted.
func Exporters(rows []map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if e := Str(r["exporter"]); e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

func round1(v float64) float64 {
	if v < 0 {
		return -float64(int64(-v*10+0.5)) / 10
	}
	return float64(int64(v*10+0.5)) / 10
}
