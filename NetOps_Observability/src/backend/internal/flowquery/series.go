// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"strconv"
	"time"
)

// SeriesSQL is one link's in/out traffic per bucket over [from, to) — the
// window already Snapped to whole buckets. "In" is traffic that entered the
// device on the interface (in_if), "out" traffic that left on it (out_if).
// Buckets are UTC-aligned (toStartOfInterval over whole seconds). Empty buckets
// are absent here and filled with zeros in Go: WITH FILL fails on DateTime64
// bounds in ClickHouse 24.8 (code 475).
func SeriesSQL(l Link, from, to time.Time, step int64, scope string) string {
	ix := strconv.FormatUint(uint64(l.IfIndex), 10)
	st := strconv.FormatInt(step, 10)
	return `
SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL ` + st + ` SECOND)) AS t,
       sumIf(` + ScaledBytes + `, in_if = ` + ix + `)    AS in_b,
       sumIf(` + ScaledBytes + `, out_if = ` + ix + `)   AS out_b,
       sumIf(` + ScaledPackets + `, in_if = ` + ix + `)  AS in_p,
       sumIf(` + ScaledPackets + `, out_if = ` + ix + `) AS out_p
  FROM netops.flows
 WHERE ts >= ` + TSLit(from) + ` AND ts < ` + TSLit(to) + `
   AND ` + l.Cond(DirBoth) + scope + `
 GROUP BY t
 ORDER BY t
 FORMAT JSON`
}

// Served is the window a series actually covers, after snapping.
type Served struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// SeriesBody is the /api/flows/links/series answer.
type SeriesBody struct {
	Window      WindowEcho `json:"window"`
	Served      Served     `json:"served"`
	StepSeconds int64      `json:"step_seconds"`
	T           []int64    `json:"t"`
	// InBytes / OutBytes are nil (JSON null) when the exporter does not export
	// that direction's interface at all.
	InBytes    []float64 `json:"in_bytes"`
	OutBytes   []float64 `json:"out_bytes"`
	InPackets  []float64 `json:"in_packets"`
	OutPackets []float64 `json:"out_packets"`
	// LastBucketComplete is false when the final bucket reaches past now, so its
	// figure is still growing and must not read as a drop.
	LastBucketComplete bool          `json:"last_bucket_complete"`
	InBasis            Basis         `json:"in_basis"`
	OutBasis           Basis         `json:"out_basis"`
	InUnnamedPct       *float64      `json:"in_unnamed_pct,omitempty"`
	OutUnnamedPct      *float64      `json:"out_unnamed_pct,omitempty"`
	Basis              ResponseBasis `json:"basis"`
}

// BuildSeries zero-fills a SeriesSQL answer over [from, to) at step and attaches
// the exporter's coverage. A bucket ClickHouse did not return carried nothing
// for this link: zero is the measured value there, not a guess. Rows outside
// the range, or off the bucket grid, are ignored.
func BuildSeries(rows []map[string]any, from, to time.Time, step int64, now time.Time, c Coverage) SeriesBody {
	n := int((to.Unix() - from.Unix()) / step)
	if n < 0 {
		n = 0
	}
	b := SeriesBody{
		Served:      Served{From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339)},
		StepSeconds: step,
		T:           make([]int64, n),
		InBytes:     make([]float64, n), OutBytes: make([]float64, n),
		InPackets: make([]float64, n), OutPackets: make([]float64, n),
		LastBucketComplete: !to.After(now),
		InBasis:            c.InBasis(), OutBasis: c.OutBasis(),
		InUnnamedPct: unnamedPct(c.BytesNoIn, c.Bytes), OutUnnamedPct: unnamedPct(c.BytesNoOut, c.Bytes),
		Basis: NewResponseBasis(c.Flows, c.RateReported),
	}
	for i := range b.T {
		b.T[i] = from.Unix() + int64(i)*step
	}
	for _, r := range rows {
		t := int64(Num(r["t"]))
		off := t - from.Unix()
		if off < 0 || off%step != 0 || off/step >= int64(n) {
			continue
		}
		i := off / step
		b.InBytes[i] += Num(r["in_b"])
		b.OutBytes[i] += Num(r["out_b"])
		b.InPackets[i] += Num(r["in_p"])
		b.OutPackets[i] += Num(r["out_p"])
	}
	if b.InBasis == NotExported {
		b.InBytes, b.InPackets = nil, nil
	}
	if b.OutBasis == NotExported {
		b.OutBytes, b.OutPackets = nil, nil
	}
	return b
}
