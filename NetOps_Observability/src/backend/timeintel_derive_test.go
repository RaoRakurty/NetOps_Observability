package main

import (
	"testing"
	"time"

	"netops/backend/timeintel"
)

func tBase() time.Time { return time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC) }

func TestDeriveLifecycle_GroundedWithOwner(t *testing.T) {
	b := tBase()
	c := corrTimeFacts{
		WindowStart: b, FirstIngest: b.Add(2 * time.Second),
		CreatedAt: b.Add(30 * time.Second), VerdictTier: "confirmed",
		Owner: "isp", EvidenceMissing: false, Confidence: 0.9,
	}
	lc := deriveLifecycle(c, itsmTimeFacts{})

	if lc[timeintel.EvFirstSignal].At != b {
		t.Fatalf("first_signal should be window_start")
	}
	if lc[timeintel.EvDetected].At != b.Add(2*time.Second) {
		t.Fatalf("detected should be first ingest (detection latency)")
	}
	if lc[timeintel.EvCorrelationCompleted].At != b.Add(30*time.Second) {
		t.Fatalf("correlation_completed should be created_at")
	}
	if _, ok := lc[timeintel.EvRootDomainIdentified]; !ok {
		t.Fatalf("grounded verdict must produce root_domain_identified")
	}
	oi, ok := lc[timeintel.EvOwnerIdentified]
	if !ok || oi.Source != timeintel.SrcInferred {
		t.Fatalf("owner_identified must exist and be inferred timing: %+v", oi)
	}
	if _, ok := lc[timeintel.EvEvidenceReady]; !ok {
		t.Fatalf("evidence satisfied must produce evidence_ready")
	}
	// confidence floored/propagated from top_confidence on grounded stamps
	if lc[timeintel.EvRootDomainIdentified].Confidence != 0.9 {
		t.Fatalf("root_domain confidence should carry top_confidence 0.9")
	}
}

func TestDeriveLifecycle_UndeterminedNoIsolation(t *testing.T) {
	b := tBase()
	c := corrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(20 * time.Second),
		VerdictTier: "undetermined", Owner: "", EvidenceMissing: true, Confidence: 0.2,
	}
	lc := deriveLifecycle(c, itsmTimeFacts{})

	if _, ok := lc[timeintel.EvRootDomainIdentified]; ok {
		t.Fatalf("undetermined must NOT produce root_domain_identified (TTI incomplete)")
	}
	if _, ok := lc[timeintel.EvOwnerIdentified]; ok {
		t.Fatalf("no owner → no owner_identified")
	}
	if _, ok := lc[timeintel.EvEvidenceReady]; ok {
		t.Fatalf("evidence_missing → no evidence_ready (drives evidence_missing driver)")
	}
	// correlation still completed, so TTC computes; TTI/TTE stay incomplete (honest).
	ms := timeintel.ComputeTimeMetrics(lc, "v1", b)
	var tti timeintel.TimeMetric
	for _, m := range ms {
		if m.Name == timeintel.MetricTTI {
			tti = m
		}
	}
	if tti.Complete {
		t.Fatalf("TTI must be incomplete for an undetermined object")
	}
}

func TestDeriveLifecycle_ITSMOwnedSource(t *testing.T) {
	b := tBase()
	itsm := itsmTimeFacts{
		TicketCreated: b.Add(40 * time.Second),
		Acknowledged:  b.Add(70 * time.Second),
		Recovered:     b.Add(120 * time.Second),
		Closed:        b.Add(300 * time.Second),
	}
	lc := deriveLifecycle(corrTimeFacts{WindowStart: b, CreatedAt: b.Add(20 * time.Second)}, itsm)

	for _, ev := range []timeintel.EventType{timeintel.EvTicketCreated, timeintel.EvAcknowledged, timeintel.EvRecovered, timeintel.EvClosed} {
		if lc[ev].Source != timeintel.SrcITSM {
			t.Fatalf("%s must be source=itsm, got %s", ev, lc[ev].Source)
		}
	}
	// TTA = acknowledged − ticket_created = 30s (not impact→ack)
	ms := timeintel.ComputeTimeMetrics(lc, "v1", b)
	for _, m := range ms {
		if m.Name == timeintel.MetricTTA && (!m.Complete || m.DurationMs != 30_000) {
			t.Fatalf("TTA should be 30s ticket→ack: %+v", m)
		}
	}
}

func TestDeriveLifecycle_DetectionNeverBeforeOnset(t *testing.T) {
	b := tBase()
	// ingest reported BEFORE onset (skew) → detection clamps to onset, not negative.
	lc := deriveLifecycle(corrTimeFacts{WindowStart: b, FirstIngest: b.Add(-5 * time.Second)}, itsmTimeFacts{})
	if lc[timeintel.EvDetected].At != b {
		t.Fatalf("detection must not precede first_signal; got %v", lc[timeintel.EvDetected].At)
	}
}
