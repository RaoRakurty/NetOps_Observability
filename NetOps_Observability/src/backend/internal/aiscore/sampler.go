// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// sampler.go — the correlation half of the scorecard: the alert compression
// ratio and the evidence-backed precondition, sampled from the store on a slow
// cadence and cached, so the Prometheus scrape never issues a ClickHouse query.

// ── the injected seams (§5: interfaces for all external dependencies) ────────

// Query runs one read-only SELECT and returns the decoded rows. The integrator
// binds the CROSS-TENANT WORKER lane: these are platform aggregates by design
// (§3a — see the package doc), the narrowing lives in the SQL below, and this
// package holds no URL, credential or client of its own.
type Query func(ctx context.Context, sql string) ([]map[string]any, error)

// Deps is everything the sampler needs, resolved ONCE by the integrator. A nil
// Query is not a crash and not a zero: it is a sample that reports itself
// unreadable, which renders as a censored metric with a reason.
type Deps struct {
	// Query reads the correlation store. nil → every sampled metric censors.
	Query Query
	// Now is the clock. nil → time.Now().UTC().
	Now func() time.Time
	// Log is the structured logger. nil discards.
	Log func(msg string, kv ...any)
	// Window is the span the compression numbers cover. Zero → DefaultWindow.
	Window time.Duration
	// SampleEvery is the background cadence. Zero → DefaultSampleEvery.
	SampleEvery time.Duration
	// SampleTimeout bounds ONE pass. Zero → DefaultSampleTimeout.
	SampleTimeout time.Duration
}

func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now().UTC()
	}
	return d.Now().UTC()
}

func (d Deps) logf(msg string, kv ...any) {
	if d.Log != nil {
		d.Log(msg, kv...)
	}
}

func (d Deps) window() time.Duration {
	if d.Window <= 0 {
		return DefaultWindow
	}
	return d.Window
}

func (d Deps) sampleEvery() time.Duration {
	if d.SampleEvery <= 0 {
		return DefaultSampleEvery
	}
	return d.SampleEvery
}

func (d Deps) sampleTimeout() time.Duration {
	if d.SampleTimeout <= 0 {
		return DefaultSampleTimeout
	}
	return d.SampleTimeout
}

// ── the sample ───────────────────────────────────────────────────────────────

// Sample is one pass over the correlation store. Err non-empty means the pass
// FAILED — every count in it is meaningless and the renderer emits no value
// gauges at all. "The store could not be read" and "there were no incidents"
// are opposite statements and must never render identically.
type Sample struct {
	// WindowSeconds is the span this sample covers.
	WindowSeconds int
	// SignalsIngested is every signal written to the store in the window.
	SignalsIngested int64
	// SignalsFolded is the sum of per-object signal_count — signals that
	// actually joined a correlation object.
	SignalsFolded int64
	// Objects is the correlation-object (incident) count in the window.
	Objects int64
	// ByTier partitions Objects over the verdict-tier enum.
	ByTier map[string]int64
	// EvidenceBacked counts objects whose CURRENT state satisfies the engine's
	// own independence test: verdict tier above undetermined AND plane_count
	// (== len(verdict.modality_coverage)) of two or more.
	EvidenceBacked int64
	// SingleModality counts objects carrying fewer than two modality classes.
	SingleModality int64
	// Err is the failure reason, empty on success.
	Err string
}

// ── SQL ──────────────────────────────────────────────────────────────────────

// Tier names, in the ClickHouse Enum8 order. Fixed here so the rendered label
// set is stable across samples — a tier with no objects reports a zero rather
// than vanishing.
var verdictTiers = []string{"undetermined", "suspected", "confirmed"}

// objectsSQL reads the correlation-object half of the sample from the NARROW
// hot projection. Shape rules, all of them load-bearing and all of them
// borrowed rather than reinvented (see scripts/lab/twin/scorer.py's header for
// what happens when they are not):
//
//   - netops.corr_current, never a LIMIT 1 BY fold of the history table;
//   - bounded by window_start so ClickHouse prunes rather than folding
//     everything ever retained;
//   - NARROW columns only — signal_count / node_count / verdict_tier /
//     plane_count. The ~26 KB `hypotheses` blob is never touched;
//   - merged objects contribute nothing (scorer v2's own rule), and
//     debug-excluded rows and NAMED chaos fixtures are excluded because an
//     intentional storm source would otherwise inflate the headline ratio the
//     product is sold on.
func objectsSQL(windowSeconds int) string {
	return fmt.Sprintf(`SELECT
  count()                                                          AS objects,
  sum(signal_count)                                                AS signals_folded,
  countIf(verdict_tier = 'undetermined')                           AS tier_undetermined,
  countIf(verdict_tier = 'suspected')                              AS tier_suspected,
  countIf(verdict_tier = 'confirmed')                              AS tier_confirmed,
  countIf(plane_count >= 2 AND verdict_tier != 'undetermined')     AS evidence_backed,
  countIf(plane_count < 2)                                         AS single_modality
FROM netops.corr_current FINAL
WHERE window_start >= now() - INTERVAL %d SECOND
  AND state != 'merged'
  AND debug_excluded = 0
  AND chaos_fixture = ''`, windowSeconds)
}

// signalsSQL reads the ingest half — the denominator-free numerator of the
// end-to-end compression ratio. `ts` is the signal's own event time, the same
// bound corr_current's window_start is expressed in, so the two halves cover the
// same span rather than two nearby ones.
func signalsSQL(windowSeconds int) string {
	return fmt.Sprintf(`SELECT count() AS signals
FROM netops.corr_signals
WHERE ts >= now() - INTERVAL %d SECOND`, windowSeconds)
}

// ── the sampler ──────────────────────────────────────────────────────────────

// Sampler runs the store pass and writes the result into a Metrics cache.
type Sampler struct {
	deps Deps
	m    *Metrics
}

// NewSampler builds the sampler. A nil Metrics makes every method a no-op.
func NewSampler(m *Metrics, d Deps) *Sampler { return &Sampler{deps: d, m: m} }

// errNoQuery is the honest failure of a deployment that wired no store reader.
var errNoQuery = errors.New("no correlation-store reader is wired on this deployment")

// Sample runs one pass and replaces the cache. It never panics and never
// half-writes: a failed read produces a Sample carrying ONLY Err, so the
// renderer emits no value gauges rather than stale or zero ones.
func (s *Sampler) Sample(ctx context.Context) Sample {
	if s == nil || s.m == nil {
		return Sample{}
	}
	windowSeconds := int(s.deps.window().Seconds())
	out := Sample{WindowSeconds: windowSeconds, ByTier: map[string]int64{}}

	ctx, cancel := context.WithTimeout(ctx, s.deps.sampleTimeout())
	defer cancel()

	if s.deps.Query == nil {
		out.Err = errNoQuery.Error()
		s.finish(out, "correlation scorecard sample skipped", "err", out.Err)
		return out
	}

	rows, err := s.deps.Query(ctx, objectsSQL(windowSeconds))
	if err != nil {
		out.Err = err.Error()
		s.finish(out, "correlation scorecard sample failed", "phase", "objects", "err", err.Error())
		return out
	}
	if len(rows) != 1 {
		// An aggregate with no GROUP BY returns exactly one row. Anything else
		// means the query did not run the way this code believes it did, and
		// reading zeros out of it would publish a compression ratio nobody
		// computed.
		out.Err = fmt.Sprintf("objects aggregate returned %d rows, want 1", len(rows))
		s.finish(out, "correlation scorecard sample failed", "phase", "objects", "err", out.Err)
		return out
	}
	r := rows[0]
	out.Objects = asInt(r["objects"])
	out.SignalsFolded = asInt(r["signals_folded"])
	for _, t := range verdictTiers {
		out.ByTier[t] = asInt(r["tier_"+t])
	}
	out.EvidenceBacked = asInt(r["evidence_backed"])
	out.SingleModality = asInt(r["single_modality"])

	srows, serr := s.deps.Query(ctx, signalsSQL(windowSeconds))
	if serr != nil {
		out.Err = serr.Error()
		s.finish(out, "correlation scorecard sample failed", "phase", "signals", "err", serr.Error())
		return out
	}
	if len(srows) != 1 {
		out.Err = fmt.Sprintf("signals aggregate returned %d rows, want 1", len(srows))
		s.finish(out, "correlation scorecard sample failed", "phase", "signals", "err", out.Err)
		return out
	}
	out.SignalsIngested = asInt(srows[0]["signals"])

	s.finish(out, "correlation scorecard sampled",
		"objects", out.Objects, "signals_ingested", out.SignalsIngested,
		"signals_folded", out.SignalsFolded, "evidence_backed", out.EvidenceBacked)
	return out
}

// finish caches the sample and logs the pass. A failure is logged EVERY pass,
// not once: §10 forbids a silent failure, and a censored metric an operator
// never sees a log line for is only half-honest.
func (s *Sampler) finish(out Sample, msg string, kv ...any) {
	s.m.setSample(out, s.deps.now())
	s.deps.logf(msg, kv...)
}

// RunSampler is the background worker: sample once immediately so the first
// scrape after boot carries real numbers, then on the cadence. Nothing retries
// — the next tick IS the retry, and a failed pass is already a visible censor
// rather than a silence.
func (s *Sampler) RunSampler(ctx context.Context) {
	if s == nil || s.m == nil {
		return
	}
	s.Sample(ctx)
	t := time.NewTicker(s.deps.sampleEvery())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sample(ctx)
		}
	}
}

// asInt coerces one ClickHouse JSON aggregate value to int64. ClickHouse's
// JSONEachRow renders UInt64 as a STRING and smaller ints as numbers, so both
// shapes have to be handled; anything else is a zero, which is correct here
// because the only callers are COUNT/SUM aggregates that cannot legitimately be
// absent when the query succeeded.
func asInt(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0
		}
		return n
	case nil:
		return 0
	}
	return 0
}
