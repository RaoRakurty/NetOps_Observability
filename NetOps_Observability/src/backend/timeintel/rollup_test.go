package timeintel

import (
	"testing"
	"time"
)

func inc(id string, group map[string]string, occurred time.Time, durs map[MetricName]int64) IncidentSummary {
	return IncidentSummary{CorrelationID: id, Group: group, OccurredAt: occurred, Durations: durs, State: "closed"}
}

func day(n int) time.Time { return time.Date(2026, 6, n, 0, 0, 0, 0, time.UTC) }

// Test 12: rollups compute p50/p90/p95 + incident_count (not just averages).
func TestRollupPercentiles(t *testing.T) {
	var incs []IncidentSummary
	// 10 incidents with TTI durations 1..10 seconds
	for i := 1; i <= 10; i++ {
		incs = append(incs, inc("c"+string(rune('0'+i)), map[string]string{"device": "d1"}, day(i),
			map[MetricName]int64{MetricTTI: int64(i) * 1000}))
	}
	r := Rollup(incs)
	st := r.Metrics[MetricTTI]
	if st.Count != 10 {
		t.Fatalf("count = %d, want 10", st.Count)
	}
	// nearest-rank on 1..10s: p50=ceil(.5*10)=5th=5s, p90=9th=9s, p95=ceil(9.5)=10th=10s
	if st.P50ms != 5000 || st.P90ms != 9000 || st.P95ms != 10000 {
		t.Fatalf("percentiles p50=%d p90=%d p95=%d", st.P50ms, st.P90ms, st.P95ms)
	}
	if st.MeanMs != 5500 {
		t.Fatalf("mean = %d, want 5500", st.MeanMs)
	}
}

// Test 9: MTBF / chronic offenders EXCLUDE child/suppressed duplicate incidents.
func TestMTBFExcludesChildren(t *testing.T) {
	g := map[string]string{"seam_id": "sm-1"}
	incs := []IncidentSummary{
		inc("a", g, day(1), nil),
		inc("b", g, day(3), nil),
		{CorrelationID: "child", Group: g, OccurredAt: day(2), IsChild: true}, // suppressed dup — ignored
	}
	off := ChronicOffenders(incs, 10)
	if len(off) != 1 {
		t.Fatalf("want 1 offender group, got %d", len(off))
	}
	if off[0].IncidentCount != 2 {
		t.Fatalf("child must be excluded: count = %d, want 2", off[0].IncidentCount)
	}
	// MTBF = gap day1→day3 = 2 days
	if off[0].MTBFms != int64(2*24*time.Hour/time.Millisecond) {
		t.Fatalf("mtbf = %d ms, want 2 days", off[0].MTBFms)
	}
}

// Test 10: MTBF separates planned maintenance from unplanned incidents.
func TestMTBFSeparatesMaintenance(t *testing.T) {
	g := map[string]string{"device": "rtr1"}
	incs := []IncidentSummary{
		inc("a", g, day(1), nil),
		{CorrelationID: "maint", Group: g, OccurredAt: day(2), Maintenance: true}, // planned — excluded
		inc("b", g, day(5), nil),
	}
	_, mtbf := repeatAndMTBF(incs)
	// only day1 and day5 count → gap 4 days, maintenance at day2 must not split it
	if mtbf != int64(4*24*time.Hour/time.Millisecond) {
		t.Fatalf("mtbf = %d ms, want 4 days (maintenance excluded)", mtbf)
	}
}

// Test 11: MTTF applies ONLY to non-repairable assets (not logical services).
func TestMTTFNonRepairableOnly(t *testing.T) {
	incs := []IncidentSummary{
		{CorrelationID: "svc", Group: map[string]string{"app_path": "checkout"}, OccurredAt: day(1)},            // logical → excluded
		{CorrelationID: "optic", Group: map[string]string{"device": "optic-1"}, OccurredAt: day(2), NonRepairable: true},
	}
	_, count := MTTF(incs)
	if count != 1 {
		t.Fatalf("MTTF must count only the non-repairable asset: count = %d, want 1", count)
	}
}

// Repeat-incident rate: groups seen more than once contribute to the rate.
func TestRepeatIncidentRate(t *testing.T) {
	incs := []IncidentSummary{
		inc("a", map[string]string{"seam_id": "s1"}, day(1), nil),
		inc("b", map[string]string{"seam_id": "s1"}, day(2), nil), // s1 recurs (2)
		inc("c", map[string]string{"seam_id": "s2"}, day(3), nil), // s2 once
	}
	rate, _ := repeatAndMTBF(incs)
	// 2 of 3 incidents are on a recurring group → 0.666...
	if rate < 0.66 || rate > 0.67 {
		t.Fatalf("repeat rate = %f, want ~0.667", rate)
	}
}

// Top time-loss phase = the most common driver across the window.
func TestTopTimeLossPhase(t *testing.T) {
	mk := func(id string, d TimeLossDriver) IncidentSummary {
		return IncidentSummary{CorrelationID: id, TimeLossDriver: d, Group: map[string]string{"device": id}, OccurredAt: day(1)}
	}
	r := Rollup([]IncidentSummary{
		mk("a", DriverProviderRepair), mk("b", DriverProviderRepair), mk("c", DriverDetection),
	})
	if r.TopTimeLossPhase != DriverProviderRepair {
		t.Fatalf("top phase = %s, want provider_repair", r.TopTimeLossPhase)
	}
}

func TestChronicOffenderRanking(t *testing.T) {
	incs := []IncidentSummary{
		inc("a1", map[string]string{"device": "A"}, day(1), nil),
		inc("a2", map[string]string{"device": "A"}, day(2), nil),
		inc("a3", map[string]string{"device": "A"}, day(3), nil),
		inc("b1", map[string]string{"device": "B"}, day(1), nil),
		inc("b2", map[string]string{"device": "B"}, day(4), nil),
	}
	off := ChronicOffenders(incs, 10)
	if len(off) != 2 || off[0].GroupKey != "device:A" {
		t.Fatalf("device:A (3 incidents) must rank first: %+v", off)
	}
}
