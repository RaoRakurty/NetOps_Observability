package timeintel

// derive_detection_test.go — the DETECTION-LATENCY HONESTY contract.
//
// The defect these pin: DeriveLifecycle used to fall back to WindowStart (the
// onset) when the ingest timestamp was unknown, so `detected` was stamped at the
// same instant as `first_signal` and ComputeTimeMetrics reported ttd as a
// COMPLETE 0 ms. The caller (server.minIngestTS) documents the opposite — its
// result is "left INCOMPLETE, never zero" — and the package honesty rule
// (types.go) is that a missing event yields an incomplete metric, never a bogus
// zero. A fabricated 0 ms is worse than an absent number: it renders exactly
// like a real, perfect measurement (§10 no silent failures).
//
// Cases:
//
//	(a) ingest present  → detected stamped at the ingest; ttd = the real latency
//	(b) ingest missing  → NO detected stamp; ttd incomplete, missing_event=detected,
//	                      and specifically NOT a complete 0
//	(c) render path     → the lifecycle rows the API serialises (and the Time
//	                      Impact card reads) carry no detection row at all, so no
//	                      consumer has a timestamp to print an elapsed from

import (
	"sort"
	"testing"
	"time"
)

func metricNamed(ms []TimeMetric, n MetricName) TimeMetric {
	for _, m := range ms {
		if m.Name == n {
			return m
		}
	}
	return TimeMetric{}
}

// TestDetectionLatencyIsUnknownNotZeroWhenIngestIsMissing is the table test for
// (a) and (b), plus the metric that shares `detected` as its START (ttm), which
// must degrade the same way rather than silently measure from the onset.
func TestDetectionLatencyIsUnknownNotZeroWhenIngestIsMissing(t *testing.T) {
	b := tBase()
	cases := []struct {
		name        string
		firstIngest time.Time
		wantStamp   bool
		wantAt      time.Time
		wantTTDMs   int64 // meaningful only when wantStamp
	}{
		{
			name:        "ingest present — the real latency",
			firstIngest: b.Add(2 * time.Second),
			wantStamp:   true, wantAt: b.Add(2 * time.Second), wantTTDMs: 2_000,
		},
		{
			name:        "ingest present, sub-second — still a real measurement",
			firstIngest: b.Add(250 * time.Millisecond),
			wantStamp:   true, wantAt: b.Add(250 * time.Millisecond), wantTTDMs: 250,
		},
		{
			name: "ingest MISSING — unknown, never zero",
			// the zero time is exactly what minIngestTS returns for "the archive
			// did not answer" and for "no archived signals"
			firstIngest: time.Time{},
			wantStamp:   false,
		},
		{
			name:        "ingest skewed before the onset — clamped, still a measurement",
			firstIngest: b.Add(-5 * time.Second),
			wantStamp:   true, wantAt: b, wantTTDMs: 0, // a REAL zero: ingest ≤ onset
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := DeriveLifecycle(CorrTimeFacts{
				WindowStart: b, FirstIngest: tc.firstIngest,
				CreatedAt: b.Add(30 * time.Second), VerdictTier: "confirmed",
				Owner: "isp", Confidence: 0.9,
			}, ITSMTimeFacts{})
			st, has := lc[EvDetected]

			if has != tc.wantStamp {
				t.Fatalf("detected stamp present = %v, want %v (lifecycle %+v)", has, tc.wantStamp, lc)
			}
			// The onset is always known here, so a regression to the old fallback
			// would show up as a detection stamped exactly at first_signal.
			if !tc.wantStamp && has {
				t.Fatalf("FABRICATED DETECTION: detected stamped at %v with an unknown ingest", st.At)
			}

			ms := ComputeTimeMetrics(lc, "test", b.Add(time.Hour))
			ttd, ttm := metricNamed(ms, MetricTTD), metricNamed(ms, MetricTTM)

			if !tc.wantStamp {
				// (b) — the honest shape: incomplete, naming what is missing.
				if ttd.Complete {
					t.Errorf("ttd must be INCOMPLETE when the ingest time is unknown, got %+v", ttd)
				}
				if ttd.MissingEvent != string(EvDetected) {
					t.Errorf("ttd.missing_event = %q, want %q", ttd.MissingEvent, EvDetected)
				}
				if ttd.EndedAt != nil {
					t.Errorf("ttd must carry no end instant when detection is unknown, got %v", *ttd.EndedAt)
				}
				// The precise regression: a COMPLETE zero. An incomplete metric may
				// carry DurationMs 0 (it is documented as meaningless unless
				// Complete); a complete one claiming 0 ms is the fabrication.
				if ttd.Complete && ttd.DurationMs == 0 {
					t.Errorf("REGRESSION: time-to-detect reported as a complete 0 ms")
				}
				// ttm starts at `detected`; with no detection it is incomplete too,
				// rather than quietly measuring mitigation from the onset.
				if ttm.Complete || ttm.MissingEvent != string(EvDetected) {
					t.Errorf("ttm must be incomplete naming detected, got %+v", ttm)
				}
				return
			}

			// (a) — a real measurement.
			if !st.At.Equal(tc.wantAt) {
				t.Errorf("detected at %v, want %v", st.At, tc.wantAt)
			}
			if st.Source != SrcObserved {
				t.Errorf("a measured detection is observed, got %q", st.Source)
			}
			if !ttd.Complete {
				t.Fatalf("ttd must be complete when the ingest time is known, got %+v", ttd)
			}
			if ttd.DurationMs != tc.wantTTDMs {
				t.Errorf("ttd = %d ms, want %d", ttd.DurationMs, tc.wantTTDMs)
			}
		})
	}
}

// TestUnknownDetectionRendersNoNumber is (c): the CONSUMER proof.
//
// The API serialises the Lifecycle as sorted {event_type, at, timestamp_source}
// rows, and the Time Impact card computes each phase's elapsed time from the row
// for that event (`at.get(ev)` → `Date.parse(ev.at) - impactMs`), rendering the
// phase's pending copy when there is no row. This walks that exact rule: with an
// unknown ingest there is no `detected` row, so the renderer has nothing to
// compute from and cannot print a number — where the old fallback handed it a
// row at the onset, which formatted as "0 ms".
func TestUnknownDetectionRendersNoNumber(t *testing.T) {
	b := tBase()

	// The API's row projection (timeIntelResponse.lifecycle), reproduced.
	type row struct {
		event  EventType
		at     time.Time
		source TimestampSource
	}
	rowsOf := func(lc Lifecycle) []row {
		out := make([]row, 0, len(lc))
		for ev, st := range lc {
			out = append(out, row{ev, st.At, st.Source})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].at.Equal(out[j].at) {
				return out[i].event < out[j].event
			}
			return out[i].at.Before(out[j].at)
		})
		return out
	}
	// The card's per-phase cell: an elapsed in ms when the phase has a row,
	// otherwise the pending copy (no number).
	renderDetection := func(rows []row) (string, bool) {
		var impact time.Time
		for _, r := range rows {
			if r.event == EvFirstSignal {
				impact = r.at
			}
		}
		for _, r := range rows {
			if r.event == EvDetected && !impact.IsZero() {
				return r.at.Sub(impact).String(), true
			}
		}
		return "Awaiting detection", false
	}

	// Unknown ingest → no row, no number.
	unknown := rowsOf(DeriveLifecycle(CorrTimeFacts{WindowStart: b, CreatedAt: b.Add(time.Minute)}, ITSMTimeFacts{}))
	for _, r := range unknown {
		if r.event == EvDetected {
			t.Fatalf("an unknown ingest must serialise NO detection row, got %+v", r)
		}
	}
	if txt, numeric := renderDetection(unknown); numeric {
		t.Errorf("the detection phase printed a number (%q) for an unmeasured detection", txt)
	} else if txt != "Awaiting detection" {
		t.Errorf("unmeasured detection copy = %q", txt)
	}

	// Known ingest → a row, and a real number.
	known := rowsOf(DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, FirstIngest: b.Add(3 * time.Second), CreatedAt: b.Add(time.Minute),
	}, ITSMTimeFacts{}))
	if txt, numeric := renderDetection(known); !numeric || txt != "3s" {
		t.Errorf("measured detection should render its real latency, got %q (numeric=%v)", txt, numeric)
	}
}

// TestSnapshotRollupsCarryNoFabricatedDetection covers the OTHER consumer: the
// reliability rollup path. The backfill worker never runs the per-object
// min(ingest_ts) query, so every snapshot it derives has an unknown ingest — the
// exact population where a complete 0 ms would have been aggregated into a fleet
// "detection" statistic. It must contribute no ttd duration at all.
func TestSnapshotRollupsCarryNoFabricatedDetection(t *testing.T) {
	b := tBase()
	row := DeriveMetricRow("t1", "corr-1", "test",
		CorrTimeFacts{ // no FirstIngest — exactly what foldTimeIntelPage supplies
			WindowStart: b, CreatedAt: b.Add(30 * time.Second),
			VerdictTier: "confirmed", Owner: "isp", Confidence: 0.9,
		},
		map[string]string{"device": "spine1"}, "DIA", "closed", false, b.Add(time.Hour))

	ttd := metricNamed(row.Metrics, MetricTTD)
	if ttd.Complete {
		t.Fatalf("a snapshot with no ingest read must carry an INCOMPLETE ttd, got %+v", ttd)
	}
	for _, s := range SummariesFromSnapshots([]MetricRow{row}, Filters{}, true) {
		if d, ok := s.Durations[MetricTTD]; ok {
			t.Errorf("rollups must carry no detection duration for an unmeasured detection, got %d ms", d)
		}
	}
}
