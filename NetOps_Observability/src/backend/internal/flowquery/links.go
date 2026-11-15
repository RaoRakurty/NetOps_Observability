// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Column expressions shared by the raw-record statements. Totals are scaled by
// the sampling rate the exporter REPORTED; a record whose exporter reported
// none is multiplied only by a rate an operator DECLARED for that exporter
// (tracker 401 (c), applied in source.go) and otherwise reads as 1:1, with the
// basis saying which (tracker 387: never guess a rate).
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
	// SamplingDeclared: every record lacked a reported rate and an operator
	// declared the exporter's rate (tracker 401 (c)); totals are multiplied by
	// the declared rate — "declared, not reported".
	SamplingDeclared = "declared"
	SamplingNoFlows     = "no_flows"
)

// ResponseBasis rides on every response.
type ResponseBasis struct {
	Flows             float64 `json:"flows"`
	FlowsRateReported float64 `json:"flows_rate_reported"`
	// FlowsRateDeclared: records with no reported rate whose rate an operator
	// declared, so their totals are scaled by the declared rate.
	FlowsRateDeclared float64 `json:"flows_rate_declared"`
	// Sampling: reported | declared (no rate reported; an operator declared it)
	// | not_reported (the exporter samples or not, but says nothing, so totals
	// read as 1:1) | mixed | no_flows.
	Sampling string `json:"sampling"`
	// BucketTime: how a record is placed in time. "flow": spread over its flow
	// duration, ending when it was received (source.go); a record with no usable
	// duration is placed in the minute it was received. Windows are whole minutes.
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

// SamplingOfDeclared derives the sampling label when some records lacking a
// reported rate carry an operator-declared one.
func SamplingOfDeclared(flows, reported, declared float64) string {
	switch {
	case flows <= 0:
		return SamplingNoFlows
	case declared <= 0:
		return SamplingOf(flows, reported)
	case reported <= 0 && declared >= flows:
		return SamplingDeclared
	}
	return SamplingMixed
}

// NewResponseBasis builds the response-level basis.
func NewResponseBasis(flows, reported float64) ResponseBasis {
	return NewResponseBasisDeclared(flows, reported, 0)
}

// NewResponseBasisDeclared builds the response-level basis with declared
// sampling counted.
func NewResponseBasisDeclared(flows, reported, declared float64) ResponseBasis {
	return ResponseBasis{Flows: flows, FlowsRateReported: reported, FlowsRateDeclared: declared,
		Sampling: SamplingOfDeclared(flows, reported, declared), BucketTime: "flow"}
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

// LinksSQL is the busiest-links statement over raw records only (no rollup,
// no declared sampling). Kept for callers that have no Source.
func LinksSQL(w Window, scope string, limit int) string {
	return LinksSourceSQL(w, Source{RawScope: scope}, limit)
}

// LinksSourceSQL is the busiest-links statement: ONE pass over the current and
// the previous window's unified rows (source.go), each record counted once per
// direction it names an interface for, grouped per (row tenant, exporter,
// ifIndex) so two tenants behind one exporter address are never merged.
// Interface names are LEFT JOINed from netops.iface_names on the ROW's own
// tenant (the flows.go flowIfaceTopNSQL contract). A link is listed when it
// carried traffic in the current window. doms counts the exporter's
// observation domains (ODIDs, tracker 401 (b)) seen on the link.
func LinksSourceSQL(w Window, src Source, limit int) string {
	cur := curCond(w)
	in, out := "dir = 'in'", "dir = 'out'"
	sb, sp := scaledB(src.Declared), scaledP(src.Declared)
	return `
SELECT a.tid AS tid, a.exporter AS exporter, a.ifx AS ifx,
       n.ifname AS if_name,
       if(n.ifname != '', 'resolved', 'absent') AS if_name_basis,
       a.in_b AS in_b, a.out_b AS out_b, a.prev_in_b AS prev_in_b, a.prev_out_b AS prev_out_b,
       a.in_p AS in_p, a.out_p AS out_p, a.fl AS fl, a.doms AS doms
  FROM (
    SELECT tid, exporter, ifx,
           sumIf(` + sb + `, ` + in + ` AND ` + cur + `)        AS in_b,
           sumIf(` + sb + `, ` + out + ` AND ` + cur + `)       AS out_b,
           sumIf(` + sb + `, ` + in + ` AND NOT ` + cur + `)    AS prev_in_b,
           sumIf(` + sb + `, ` + out + ` AND NOT ` + cur + `)   AS prev_out_b,
           sumIf(` + sp + `, ` + in + ` AND ` + cur + `)        AS in_p,
           sumIf(` + sp + `, ` + out + ` AND ` + cur + `)       AS out_p,
           sumIf(rec, ` + cur + `) AS fl,
           uniqExactIf(odid, ` + cur + ` AND rec > 0) AS doms
      FROM ` + sourceSQL(src, w.PrevFrom(), w.To) + `
     WHERE ifx NOT IN ` + IfSentinels + `
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

// CoverageSQL counts, over raw records only, what each exporter exports.
func CoverageSQL(w Window, scope string, exporters []string) string {
	return CoverageSourceSQL(w, Source{RawScope: scope}, exporters)
}

// CoverageSourceSQL counts, per (row tenant, exporter), what the exporter
// exports: records in each window, records that reported a sampling rate,
// records whose missing rate was DECLARED by an operator, records (and their
// bytes) that name no interface per direction, and its observation domains. It
// feeds the per-direction basis. exporters (from the links answer) bound the
// scan; an empty list means "every exporter the scope admits".
//
// Each record has exactly one 'in' row, so record and byte totals are read off
// the 'in' rows; "names no output interface" is read off the 'out' rows.
func CoverageSourceSQL(w Window, src Source, exporters []string) string {
	cur := curCond(w)
	if len(exporters) > 0 {
		only := " AND sampler_address IN (" + QuoteList(exporters) + ")"
		src.RawScope += only
		src.RollupScope += only
	}
	sb := scaledB(src.Declared)
	sent := "ifx IN " + IfSentinels
	inC, outC := "dir = 'in' AND "+cur, "dir = 'out' AND "+cur
	return `
SELECT tid, exporter,
       sumIf(rec, ` + inC + `) AS fl,
       sumIf(rec, dir = 'in' AND NOT ` + cur + `) AS prev_fl,
       sumIf(rec, ` + inC + ` AND rr = 1) AS fl_rr,
       sumIf(rec, ` + inC + ` AND rr = 0 AND ` + DeclaredExpr(src.Declared) + ` > 1) AS fl_decl,
       sumIf(rec, ` + inC + ` AND ` + sent + `) AS fl_no_in,
       sumIf(rec, ` + outC + ` AND ` + sent + `) AS fl_no_out,
       sumIf(` + sb + `, ` + inC + `) AS b_all,
       sumIf(` + sb + `, ` + inC + ` AND ` + sent + `) AS b_no_in,
       sumIf(` + sb + `, ` + outC + ` AND ` + sent + `) AS b_no_out,
       uniqExactIf(odid, ` + inC + ` AND rec > 0) AS doms
  FROM ` + sourceSQL(src, w.PrevFrom(), w.To) + `
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
	// RateDeclared: records whose exporter reported no rate and whose rate an
	// operator declared (tracker 401 (c)) — their totals are multiplied by it.
	RateDeclared                 float64
	NoIn, NoOut                  float64
	Bytes, BytesNoIn, BytesNoOut float64
	// Domains: observation domains (ODIDs) the exporter used in the window.
	Domains float64
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
			Flows: Num(r["fl"]), PrevFlows: Num(r["prev_fl"]), RateReported: Num(r["fl_rr"]), RateDeclared: Num(r["fl_decl"]),
			Domains: Num(r["doms"]),
			NoIn: Num(r["fl_no_in"]), NoOut: Num(r["fl_no_out"]),
			Bytes: Num(r["b_all"]), BytesNoIn: Num(r["b_no_in"]), BytesNoOut: Num(r["b_no_out"]),
		}
	}
	return out
}

// Totals sums a coverage map into a response basis.
func Totals(cov map[CovKey]Coverage) ResponseBasis {
	var fl, rr, decl float64
	for _, c := range cov {
		fl += c.Flows
		rr += c.RateReported
		decl += c.RateDeclared
	}
	return NewResponseBasisDeclared(fl, rr, decl)
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
	// Domains: observation domains (ODIDs) seen on the link in the window. More
	// than one means the exporter reported this interface from several domains
	// (line cards, monitors); the figures add them up.
	Domains float64 `json:"domains"`
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
			Domains: Num(r["doms"]),
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
		row.Sampling = SamplingOfDeclared(c.Flows, c.RateReported, c.RateDeclared)
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
