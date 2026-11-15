// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

// source.go — tracker 401 (a)(b)(c): where the link figures come from.
//
// Every link figure (busiest links, coverage, per-link series) is now computed
// over ONE row shape, produced either from the per-interface rollup
// netops.flow_iface_1m (closed, already-rolled minutes) or from raw
// netops.flows (everything the rollup does not hold yet), never both for the
// same record:
//
//	tid, exporter, odid, ifx, dir, minute, rr, b, p, rec
//
// Placement in time (tracker 401 (b)). A record is placed by its flow
// DURATION, anchored on when it was RECEIVED: it covers
// [received − (flow_end − flow_start), received] and its bytes and packets are
// split across the minutes it overlaps, in proportion to the overlap, with
// integer arithmetic whose parts always add up to the record's total exactly.
// Anchoring on receipt (not on the exporter's flow_start/flow_end clock) means
// an exporter whose clock is off still lands where Correlix saw it; only the
// duration is taken from the exporter. A record with no usable duration (no
// start/end exported — sFlow, NetFlow v5 without them, a zero or negative span,
// or one longer than an hour) is placed whole in the minute it was received,
// exactly as before. `rec` (the record count) is always counted once, in the
// received minute, so "flows" stays "records received in the window".
//
// Windows are whole minutes: a minute belongs to a window when its START lies
// in [from, to). Adjacent windows (the current one and the previous one) can
// therefore never count the same minute twice.
//
// HARD RULE (init.sql, svc_rollup_schema.go): no materialized view may read
// netops.flows — its row policy is re-evaluated on every INSERT in the
// inserting connection's context and breaks ingestion. The rollup is written by
// the Roller (rollup.go) with INSERT … SELECT at the platform scope, keeping the
// ROW's own tenant_id and sampler_address, so every read predicate that works
// on raw rows works on rollup rows unchanged.

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxSpread is the longest flow duration that is spread across minutes. A
// longer span is not believed (an exporter clock reset, a never-timed-out
// cache entry) and the record is placed whole in its received minute.
const MaxSpread = time.Hour

// spreadLookahead is how far after a window's end the source still reads
// records: a record received up to MaxSpread (plus the minute it lands in)
// after the window can carry bytes back into it.
const spreadLookahead = MaxSpread + time.Minute

// DeclKey identifies one exporter as one tenant sees it: declared sampling is
// per (row tenant, exporter address), so two tenants behind one exporter
// address never share a declaration.
type DeclKey = CovKey

// Source says where the rows for one statement come from.
type Source struct {
	// RawScope is the caller's predicate on raw netops.flows columns (" AND …",
	// already safe): tenant clause, tenant narrow, flow type, the filter bar and
	// the platform-traffic exclusion.
	RawScope string
	// RollupScope is the same predicate expressed on rollup columns. Only set
	// when the predicate is expressible there (see the handlers): tenant_id,
	// sampler_address and flow_type keep their names in the rollup, and the
	// platform-traffic exclusion becomes `platform = 0`.
	RollupScope string
	// RollupLo and RollupHi bound the received minutes the rollup holds,
	// complete, at the current platform signature: [RollupLo, RollupHi). A zero
	// RollupHi means "do not read the rollup" — everything comes from raw rows.
	RollupLo, RollupHi time.Time
	// PlatformSig is the signature of the platform-address set the rollup rows
	// were classified with; rows classified under another set are never read.
	PlatformSig uint64
	// Declared is the operator-declared sampling rate per (tenant, exporter),
	// applied ONLY to records whose exporter reported no rate.
	Declared map[DeclKey]uint32
}

// UsesRollup reports whether the source reads rollup rows at all.
func (s Source) UsesRollup() bool { return !s.RollupHi.IsZero() && s.RollupHi.After(s.RollupLo) }

// PlatformSignature fingerprints the platform-traffic condition the rollup
// classifies `platform` with. A change of the platform-address set changes the
// signature, so rows classified under the old set are no longer read (and the
// Roller re-rolls them).
func PlatformSignature(platformCond string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(platformCond))) // discard: hash.Hash.Write never returns an error
	return h.Sum64()
}

func minuteLit(t time.Time) string {
	return "toDateTime(" + strconv.FormatInt(t.UTC().Truncate(time.Minute).Unix(), 10) + ", 'UTC')"
}

func floorMinute(t time.Time) time.Time { return t.UTC().Truncate(time.Minute) }

// DeclaredExpr is the per-row declared rate over the unified columns (tid,
// exporter), 1 where nothing is declared. Keys and rates are literals.
func DeclaredExpr(decl map[DeclKey]uint32) string {
	if len(decl) == 0 {
		return "1"
	}
	keys := make([]string, 0, len(decl))
	for k := range decl {
		keys = append(keys, k.Tenant+"|"+k.Exporter)
	}
	sort.Strings(keys)
	var ks, vs []string
	for _, k := range keys {
		i := strings.Index(k, "|")
		r := decl[DeclKey{Tenant: k[:i], Exporter: k[i+1:]}]
		if r < 1 {
			r = 1
		}
		ks = append(ks, Quote(k))
		vs = append(vs, strconv.FormatUint(uint64(r), 10))
	}
	return "transform(concat(tid, '|', exporter), [" + strings.Join(ks, ", ") + "], [toUInt64(" + strings.Join(vs, "), toUInt64(") + ")], toUInt64(1))"
}

// scaledB / scaledP are a unified row's bytes and packets after sampling:
// rollup and raw rows already carry the REPORTED rate applied; a record whose
// exporter reported none is multiplied by the declared rate (1 if none).
func scaledB(decl map[DeclKey]uint32) string {
	return "(b * if(rr = 1, 1, " + DeclaredExpr(decl) + "))"
}
func scaledP(decl map[DeclKey]uint32) string {
	return "(p * if(rr = 1, 1, " + DeclaredExpr(decl) + "))"
}

// durMsExpr is a raw record's usable flow duration in milliseconds, 0 when
// none (see the file comment).
const durMsExpr = `multiIf(toUnixTimestamp64Milli(flow_start) <= 0 OR flow_end < flow_start, toInt64(0),
         toUnixTimestamp64Milli(flow_end) - toUnixTimestamp64Milli(flow_start) > ` + "3600000" + `, toInt64(0),
         toInt64(toUnixTimestamp64Milli(flow_end) - toUnixTimestamp64Milli(flow_start)))`

// SpreadRowsSQL turns raw records matching where into per-direction,
// per-minute rows (the unified shape plus flow_type, platform and
// recv_minute). platformCond classifies a record as Correlix's own monitoring
// traffic ("" = nothing is). where is a complete boolean expression.
func SpreadRowsSQL(where, platformCond string) string {
	pf := "toUInt8(0)"
	if strings.TrimSpace(platformCond) != "" {
		pf = "toUInt8(" + platformCond + ")"
	}
	alloc := func(col string) string {
		// cum(i) = covered milliseconds up to the end of minute i; the part of
		// minute i is floor(total·cum(i)/dur) − floor(total·cum(i−1)/dur), so the
		// parts are integers and always add up to the total.
		cum := func(end string) string {
			return "toUInt128(least(e_ms, " + end + ") - s_ms)"
		}
		return "if(dur_ms = 0, " + col + ", toUInt64(intDiv(toUInt128(" + col + ") * " + cum("(m0 + toInt64(i) + 1) * 60000") +
			", toUInt128(dur_ms)) - if(i = 0, toUInt128(0), intDiv(toUInt128(" + col + ") * " + cum("(m0 + toInt64(i)) * 60000") + ", toUInt128(dur_ms)))))"
	}
	return `
SELECT tid, exporter, odid, d.1 AS ifx, d.2 AS dir, ft AS flow_type, rr, pf AS platform, rm AS recv_minute,
       a.1 AS minute, a.2 AS b, a.3 AS p, a.4 AS rec
  FROM (
    SELECT tenant_id AS tid, sampler_address AS exporter, odid, flow_type AS ft,
           toUInt8(` + RateReported + `) AS rr, ` + pf + ` AS pf,
           toStartOfMinute(ts) AS rm, in_if, out_if,
           toUInt64(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS sb,
           toUInt64(packets * if(sampling_rate = 0, 1, sampling_rate)) AS sp,
           toInt64(toUnixTimestamp64Milli(ts)) AS e_ms,
           ` + durMsExpr + ` AS dur_ms,
           e_ms - dur_ms AS s_ms,
           intDiv(s_ms, 60000) AS m0,
           intDiv(e_ms, 60000) - m0 AS k
      FROM netops.flows
     WHERE ` + where + `
  )
 ARRAY JOIN [(in_if, 'in'), (out_if, 'out')] AS d
 ARRAY JOIN arrayMap(i -> (toDateTime((m0 + toInt64(i)) * 60, 'UTC'), ` + alloc("sb") + `, ` + alloc("sp") + `, toUInt64(i = k)),
                     range(toUInt64(k + 1))) AS a`
}

// RollupColumns is the INSERT column list of netops.flow_iface_1m.
const RollupColumns = "tenant_id, minute, recv_minute, sampler_address, odid, ifindex, direction, flow_type, rate_reported, platform, platform_sig, bytes, packets, records, version"

// RollupInsertSQL rolls the records RECEIVED in [from, to) (whole minutes) into
// netops.flow_iface_1m, one row per key, under version. Run at the platform
// scope: each row keeps the source record's own tenant_id.
func RollupInsertSQL(from, to time.Time, platformCond string, version int64) string {
	sig := strconv.FormatUint(PlatformSignature(platformCond), 10)
	where := "ts >= " + TSLit(floorMinute(from)) + " AND ts < " + TSLit(floorMinute(to))
	return `INSERT INTO netops.flow_iface_1m (` + RollupColumns + `)
SELECT tid, minute, recv_minute, exporter, odid, ifx, dir, flow_type, rr, platform, toUInt64(` + sig + `),
       sum(b), sum(p), sum(rec), toUInt64(` + strconv.FormatInt(version, 10) + `)
  FROM (` + SpreadRowsSQL(where, platformCond) + `
  )
 GROUP BY tid, minute, recv_minute, exporter, odid, ifx, dir, flow_type, rr, platform`
}

// sourceSQL is the unified-row subquery for the minutes [mFrom, mTo): rollup
// rows for received minutes the rollup holds, raw rows for everything else the
// window can need, never both for one record.
func sourceSQL(src Source, mFrom, mTo time.Time) string {
	scanLo := floorMinute(mFrom)
	scanHi := floorMinute(mTo).Add(spreadLookahead)
	minuteCond := "minute >= " + minuteLit(mFrom) + " AND minute < " + minuteLit(mTo)
	if !mFrom.Equal(floorMinute(mFrom)) {
		// A minute belongs to the window when its start is at or after `from`.
		minuteCond = "minute >= " + minuteLit(floorMinute(mFrom).Add(time.Minute)) + " AND minute < " + minuteLit(mTo)
	}
	if !mTo.Equal(floorMinute(mTo)) {
		minuteCond = strings.Replace(minuteCond, "minute < "+minuteLit(mTo), "minute < "+minuteLit(floorMinute(mTo).Add(time.Minute)), 1)
	}

	type span struct{ lo, hi time.Time }
	var raw []span
	var roll *span
	if src.UsesRollup() {
		lo, hi := maxT(scanLo, floorMinute(src.RollupLo)), minT(scanHi, floorMinute(src.RollupHi))
		if lo.Before(hi) {
			roll = &span{lo, hi}
			if scanLo.Before(lo) {
				raw = append(raw, span{scanLo, lo})
			}
			if hi.Before(scanHi) {
				raw = append(raw, span{hi, scanHi})
			}
		}
	}
	if roll == nil {
		raw = []span{{scanLo, scanHi}}
	}

	var parts []string
	if roll != nil {
		parts = append(parts, `
  SELECT tenant_id AS tid, sampler_address AS exporter, odid, ifindex AS ifx, direction AS dir, minute,
         rate_reported AS rr, bytes AS b, packets AS p, records AS rec
    FROM netops.flow_iface_1m FINAL
   WHERE platform_sig = `+strconv.FormatUint(src.PlatformSig, 10)+`
     AND recv_minute >= `+minuteLit(roll.lo)+` AND recv_minute < `+minuteLit(roll.hi)+`
     AND `+minuteCond+src.RollupScope)
	}
	if len(raw) > 0 { // the rollup may hold the whole scan; then no raw row is read
		var ranges []string
		for _, r := range raw {
			ranges = append(ranges, "(ts >= "+TSLit(r.lo)+" AND ts < "+TSLit(r.hi)+")")
		}
		where := "(" + strings.Join(ranges, " OR ") + ")" + src.RawScope
		parts = append(parts, `
  SELECT tid, exporter, odid, ifx, dir, minute, rr, b, p, rec
    FROM (`+SpreadRowsSQL(where, "")+`
    )
   WHERE `+minuteCond)
	}
	return "(" + strings.Join(parts, "\n  UNION ALL") + "\n)"
}

func maxT(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minT(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// curCond is true for a unified row in the current window (its minute starts
// at or after the window's start).
func curCond(w Window) string {
	f := w.From
	if !f.Equal(floorMinute(f)) {
		f = floorMinute(f).Add(time.Minute)
	}
	return "minute >= " + minuteLit(f)
}
