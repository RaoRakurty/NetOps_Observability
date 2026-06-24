package timeintel

import (
	"encoding/json"
	"testing"
	"time"
)

var base = time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

func obs(sec int) EventStamp { return EventStamp{At: at(sec), Source: SrcObserved, Confidence: 1} }

// fullLifecycle: a clean incident with every phase observed, monotonically ordered.
func fullLifecycle() Lifecycle {
	return Lifecycle{
		EvImpactStarted:        obs(0),
		EvFirstSignal:          obs(5),
		EvDetected:             obs(10),
		EvCorrelationCompleted: obs(20),
		EvRootDomainIdentified: obs(25),
		EvOwnerIdentified:      obs(30),
		EvEvidenceReady:        obs(35),
		EvTicketCreated:        obs(40),
		EvAcknowledged:         obs(70),
		EvMitigated:            obs(100),
		EvRecovered:            obs(120),
		EvClosed:               obs(300),
	}
}

func metricByName(ms []TimeMetric, n MetricName) TimeMetric {
	for _, m := range ms {
		if m.Name == n {
			return m
		}
	}
	return TimeMetric{}
}

// Test 7/8/6/5: each metric uses its EXACT start/end pair (no cross-wiring).
func TestMetricFormulas(t *testing.T) {
	ms := ComputeTimeMetrics(fullLifecycle(), "v1", base)
	cases := []struct {
		name           MetricName
		wantMs         int64
		wantStart, end EventType
	}{
		{MetricTTD, 10_000, EvImpactStarted, EvDetected},                 // 10s
		{MetricTTC, 15_000, EvFirstSignal, EvCorrelationCompleted},       // 20−5
		{MetricTTI, 20_000, EvFirstSignal, EvRootDomainIdentified},       // 25−5  (the differentiator)
		{MetricTTE, 30_000, EvFirstSignal, EvEvidenceReady},              // 35−5
		{MetricTTA, 30_000, EvTicketCreated, EvAcknowledged},             // 70−40 (NOT impact→ack)
		{MetricTTM, 90_000, EvDetected, EvMitigated},                     // 100−10
		{MetricTTRRecovery, 120_000, EvImpactStarted, EvRecovered},       // 120−0
		{MetricTTRResolution, 300_000, EvImpactStarted, EvClosed},        // 300−0
	}
	for _, c := range cases {
		m := metricByName(ms, c.name)
		if !m.Complete {
			t.Fatalf("%s: incomplete, want complete", c.name)
		}
		if m.DurationMs != c.wantMs {
			t.Errorf("%s: duration %d ms, want %d", c.name, m.DurationMs, c.wantMs)
		}
		if m.StartEvent != c.wantStart || m.EndEvent != c.end {
			t.Errorf("%s: events (%s→%s), want (%s→%s)", c.name, m.StartEvent, m.EndEvent, c.wantStart, c.end)
		}
	}
}

// Test 5: recovery and resolution are DISTINCT (recovered ≠ closed).
func TestRecoveryVsResolutionDistinct(t *testing.T) {
	ms := ComputeTimeMetrics(fullLifecycle(), "v1", base)
	rec := metricByName(ms, MetricTTRRecovery)
	res := metricByName(ms, MetricTTRResolution)
	if rec.DurationMs == res.DurationMs {
		t.Fatalf("recovery (%d) and resolution (%d) must differ", rec.DurationMs, res.DurationMs)
	}
	if rec.EndEvent != EvRecovered || res.EndEvent != EvClosed {
		t.Fatalf("recovery must end at recovered, resolution at closed; got %s / %s", rec.EndEvent, res.EndEvent)
	}
}

// Test 3: a missing start/end yields an INCOMPLETE metric naming the gap — never a 0.
func TestMissingTimestampsAreIncompleteNotZero(t *testing.T) {
	lc := Lifecycle{EvFirstSignal: obs(5), EvCorrelationCompleted: obs(20)} // only TTC computable
	ms := ComputeTimeMetrics(lc, "v1", base)

	ttc := metricByName(ms, MetricTTC)
	if !ttc.Complete || ttc.DurationMs != 15_000 {
		t.Fatalf("TTC should compute: %+v", ttc)
	}
	tti := metricByName(ms, MetricTTI)
	if tti.Complete {
		t.Fatalf("TTI must be incomplete (no root_domain_identified)")
	}
	if tti.DurationMs != 0 || tti.MissingEvent != string(EvRootDomainIdentified) {
		t.Fatalf("incomplete TTI must name missing event and not fake a duration: %+v", tti)
	}
	tta := metricByName(ms, MetricTTA)
	if tta.Complete || tta.MissingEvent != string(EvTicketCreated) {
		t.Fatalf("TTA must be incomplete with missing ticket_created: %+v", tta)
	}
}

// Test 4: an inferred impact-start flags is_inferred and propagates min confidence.
func TestInferredImpactFlaggedAndConfidencePropagated(t *testing.T) {
	lc := Lifecycle{
		EvFirstSignal: {At: at(5), Source: SrcObserved, Confidence: 0.8}, // impact inferred from this
		EvDetected:    {At: at(10), Source: SrcObserved, Confidence: 1.0},
		EvRecovered:   {At: at(120), Source: SrcObserved, Confidence: 1.0},
	}
	ms := ComputeTimeMetrics(lc, "v1", base)

	ttd := metricByName(ms, MetricTTD)
	if !ttd.Complete || !ttd.IsInferred {
		t.Fatalf("TTD on inferred impact must be complete+inferred: %+v", ttd)
	}
	if ttd.StartEvent != EvImpactStarted {
		t.Fatalf("TTD start_event must stay impact_started (what it means): %s", ttd.StartEvent)
	}
	if ttd.DurationMs != 5_000 { // detected(10) − inferred impact(=first_signal 5)
		t.Fatalf("TTD duration %d, want 5000", ttd.DurationMs)
	}
	if ttd.Confidence != 0.8 {
		t.Fatalf("confidence must propagate min(0.8,1.0)=0.8, got %v", ttd.Confidence)
	}
	rec := metricByName(ms, MetricTTRRecovery)
	if !rec.IsInferred {
		t.Fatalf("recovery from inferred impact must be flagged inferred")
	}
}

// Determinism (supports test 1's idempotency at the calc layer): same input → same output.
func TestComputeIsDeterministic(t *testing.T) {
	lc := fullLifecycle()
	// Compare by serialized value (TimeMetric holds *time.Time pointers, so == would
	// compare addresses, not values).
	aJSON, _ := json.Marshal(ComputeTimeMetrics(lc, "v1", base))
	bJSON, _ := json.Marshal(ComputeTimeMetrics(lc, "v1", base))
	if string(aJSON) != string(bJSON) {
		t.Fatalf("non-deterministic:\n%s\n%s", aJSON, bJSON)
	}
}

// Negative durations (clock skew) clamp to 0 but stay complete — no nonsense negatives.
func TestNegativeDurationClampsToZero(t *testing.T) {
	lc := Lifecycle{EvFirstSignal: obs(20), EvCorrelationCompleted: obs(5)} // end before start
	ttc := metricByName(ComputeTimeMetrics(lc, "v1", base), MetricTTC)
	if !ttc.Complete || ttc.DurationMs != 0 {
		t.Fatalf("skewed TTC should clamp to 0 and stay complete: %+v", ttc)
	}
}

// Test 15: evidence still missing → time-loss driver = evidence_missing.
func TestDriverEvidenceMissing(t *testing.T) {
	d, expl := DeriveTimeLossDriver(fullLifecycle(), DriverContext{EvidenceMissing: true, Owner: "customer"})
	if d != DriverEvidenceMissing {
		t.Fatalf("driver = %s, want evidence_missing", d)
	}
	if expl == "" {
		t.Fatalf("explanation must be present")
	}
}

// Test 16: provider-owned seam → provider_repair ONLY after owner_identified and
// before recovered.
func TestDriverProviderRepairWindow(t *testing.T) {
	// owner identified, NOT yet recovered → provider_repair
	lc := Lifecycle{
		EvFirstSignal: obs(5), EvDetected: obs(10),
		EvRootDomainIdentified: obs(25), EvOwnerIdentified: obs(30),
	}
	d, _ := DeriveTimeLossDriver(lc, DriverContext{Owner: "isp"})
	if d != DriverProviderRepair {
		t.Fatalf("pre-recovery provider incident: driver %s, want provider_repair", d)
	}
	// once recovered, provider_repair no longer applies (falls to segment analysis)
	lc[EvRecovered] = obs(120)
	d2, _ := DeriveTimeLossDriver(lc, DriverContext{Owner: "isp"})
	if d2 == DriverProviderRepair {
		t.Fatalf("after recovery, provider_repair must NOT apply, got %s", d2)
	}
	// before owner identified, provider_repair must not apply either
	lc2 := Lifecycle{EvFirstSignal: obs(5), EvDetected: obs(10), EvRootDomainIdentified: obs(25)}
	d3, _ := DeriveTimeLossDriver(lc2, DriverContext{Owner: "isp"})
	if d3 == DriverProviderRepair {
		t.Fatalf("before owner_identified, provider_repair must NOT apply, got %s", d3)
	}
}

// Driver picks the largest controllable segment when no override applies.
func TestDriverLargestSegment(t *testing.T) {
	// acknowledgement is the long pole: ticket(40)→ack(70) = 30s, beats detection 10s,
	// correlation 20s, ownership 5s.
	d, _ := DeriveTimeLossDriver(fullLifecycle(), DriverContext{Owner: "customer"})
	if d != DriverAcknowledgement {
		t.Fatalf("driver = %s, want acknowledgement (longest segment)", d)
	}
}

func TestDriverUnknownWhenInsufficient(t *testing.T) {
	d, _ := DeriveTimeLossDriver(Lifecycle{EvFirstSignal: obs(5)}, DriverContext{Owner: "customer"})
	if d != DriverUnknown {
		t.Fatalf("driver = %s, want unknown", d)
	}
}
