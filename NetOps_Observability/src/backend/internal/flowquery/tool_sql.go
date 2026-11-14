// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"strconv"
)

// The allowlisted flow statements behind Iris (tracker 406, tracker 337 N-C4):
// the three flow tools and the NL `flow_top` query read through exactly these,
// never through text a model wrote. scope is the caller's ClickHouse clause,
// already built by the server from the principal (" AND (…)"), plus the link
// and platform-traffic conditions; the window is a parsed Window.
//
// Same rules as every other statement here: totals scale only by the rate the
// exporter reported, and no output is aliased bytes, packets or ts.

// Tool statement kinds.
const (
	ToolTalkers  = "talkers"  // heaviest conversations (unordered address pair)
	ToolServices = "services" // busiest destination ports
	ToolTotals   = "totals"   // one row of totals
)

// MaxToolRows bounds a talkers/services answer.
const MaxToolRows = 25

func toolLimit(limit int) string {
	if limit <= 0 || limit > MaxToolRows {
		limit = 8
	}
	return strconv.Itoa(limit)
}

// TalkersSQL ranks conversations: the unordered address pair, its scaled
// bytes and flow count, and how many of its records reported a sampling rate.
func TalkersSQL(w Window, scope string, limit int) string {
	return `
SELECT least(src_addr, dst_addr)    AS a,
       greatest(src_addr, dst_addr) AS b,
       sum(` + ScaledBytes + `)      AS bytes_total,
       count()                       AS flows,
       countIf(` + RateReported + `) AS rate_reported
  FROM netops.flows
 WHERE ` + w.Predicate() + scope + `
 GROUP BY a, b
 ORDER BY bytes_total DESC
 LIMIT ` + toolLimit(limit) + `
 FORMAT JSON`
}

// ServicesSQL ranks destination ports by scaled bytes.
func ServicesSQL(w Window, scope string, limit int) string {
	return `
SELECT dst_port                      AS port,
       sum(` + ScaledBytes + `)      AS bytes_total,
       count()                       AS flows,
       countIf(` + RateReported + `) AS rate_reported
  FROM netops.flows
 WHERE ` + w.Predicate() + ` AND dst_port > 0` + scope + `
 GROUP BY port
 ORDER BY bytes_total DESC
 LIMIT ` + toolLimit(limit) + `
 FORMAT JSON`
}

// TotalsSQL is one row: scaled bytes and packets, flows, distinct sources and
// how many records reported a sampling rate.
func TotalsSQL(w Window, scope string) string {
	return `
SELECT sum(` + ScaledBytes + `)      AS bytes_total,
       sum(` + ScaledPackets + `)    AS packets_total,
       count()                       AS flows,
       uniqExact(src_addr)           AS sources,
       countIf(` + RateReported + `) AS rate_reported
  FROM netops.flows
 WHERE ` + w.Predicate() + scope + `
 FORMAT JSON`
}

// SamplingNote is the sentence an answer carries for a basis other than
// reported; "" when every record reported its rate or there were none.
func SamplingNote(basis string) string {
	switch basis {
	case SamplingNotReported:
		return "the exporters did not report a sampling rate, so these totals read 1:1 and are low if they sample"
	case SamplingMixed:
		return "some exporters did not report a sampling rate, so part of these totals reads 1:1"
	}
	return ""
}
