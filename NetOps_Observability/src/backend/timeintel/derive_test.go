package timeintel

import (
	"testing"
	"time"
)

func tBase() time.Time { return time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC) }

func TestDeriveLifecycle_GroundedWithOwner(t *testing.T) {
	b := tBase()
	c := CorrTimeFacts{
		WindowStart: b, FirstIngest: b.Add(2 * time.Second),
		CreatedAt: b.Add(30 * time.Second), VerdictTier: "confirmed",
		Owner: "isp", EvidenceMissing: false, Confidence: 0.9,
	}
	lc := DeriveLifecycle(c, ITSMTimeFacts{})

	if lc[EvFirstSignal].At != b {
		t.Fatalf("first_signal should be window_start")
	}
	if lc[EvDetected].At != b.Add(2*time.Second) {
		t.Fatalf("detected should be first ingest (detection latency)")
	}
	if lc[EvCorrelationCompleted].At != b.Add(30*time.Second) {
		t.Fatalf("correlation_completed should be created_at")
	}
	if _, ok := lc[EvRootDomainIdentified]; !ok {
		t.Fatalf("grounded verdict must produce root_domain_identified")
	}
	oi, ok := lc[EvOwnerIdentified]
	if !ok || oi.Source != SrcInferred {
		t.Fatalf("owner_identified must exist and be inferred timing: %+v", oi)
	}
	if _, ok := lc[EvEvidenceReady]; !ok {
		t.Fatalf("evidence satisfied must produce evidence_ready")
	}
	// confidence floored/propagated from top_confidence on grounded stamps
	if lc[EvRootDomainIdentified].Confidence != 0.9 {
		t.Fatalf("root_domain confidence should carry top_confidence 0.9")
	}
}

func TestDeriveLifecycle_UndeterminedNoIsolation(t *testing.T) {
	b := tBase()
	c := CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(20 * time.Second),
		VerdictTier: "undetermined", Owner: "", EvidenceMissing: true, Confidence: 0.2,
	}
	lc := DeriveLifecycle(c, ITSMTimeFacts{})

	if _, ok := lc[EvRootDomainIdentified]; ok {
		t.Fatalf("undetermined must NOT produce root_domain_identified (TTI incomplete)")
	}
	if _, ok := lc[EvOwnerIdentified]; ok {
		t.Fatalf("no owner → no owner_identified")
	}
	if _, ok := lc[EvEvidenceReady]; ok {
		t.Fatalf("evidence_missing → no evidence_ready (drives evidence_missing driver)")
	}
	// correlation still completed, so TTC computes; TTI/TTE stay incomplete (honest).
	ms := ComputeTimeMetrics(lc, "v1", b)
	var tti TimeMetric
	for _, m := range ms {
		if m.Name == MetricTTI {
			tti = m
		}
	}
	if tti.Complete {
		t.Fatalf("TTI must be incomplete for an undetermined object")
	}
}

func TestDeriveLifecycle_ITSMOwnedSource(t *testing.T) {
	b := tBase()
	itsm := ITSMTimeFacts{
		TicketCreated: b.Add(40 * time.Second),
		Acknowledged:  b.Add(70 * time.Second),
		Recovered:     b.Add(120 * time.Second),
		Closed:        b.Add(300 * time.Second),
	}
	lc := DeriveLifecycle(CorrTimeFacts{WindowStart: b, CreatedAt: b.Add(20 * time.Second)}, itsm)

	for _, ev := range []EventType{EvTicketCreated, EvAcknowledged, EvRecovered, EvClosed} {
		if lc[ev].Source != SrcITSM {
			t.Fatalf("%s must be source=itsm, got %s", ev, lc[ev].Source)
		}
	}
	// TTA = acknowledged − ticket_created = 30s (not impact→ack)
	ms := ComputeTimeMetrics(lc, "v1", b)
	for _, m := range ms {
		if m.Name == MetricTTA && (!m.Complete || m.DurationMs != 30_000) {
			t.Fatalf("TTA should be 30s ticket→ack: %+v", m)
		}
	}
}

func TestDeriveLifecycle_DetectionNeverBeforeOnset(t *testing.T) {
	b := tBase()
	// ingest reported BEFORE onset (skew) → detection clamps to onset, not negative.
	lc := DeriveLifecycle(CorrTimeFacts{WindowStart: b, FirstIngest: b.Add(-5 * time.Second)}, ITSMTimeFacts{})
	if lc[EvDetected].At != b {
		t.Fatalf("detection must not precede first_signal; got %v", lc[EvDetected].At)
	}
}

// ── engine-inferred recovery (v2 mapping) ────────────────────────────────────
//
// No ITSM workflow is linked in most deployments, so ttr_recovery used to be
// permanently INCOMPLETE and the driver permanently "workflow_not_connected" —
// even though the engine already records the incident's own close. These pin the
// exact mapping, including the three states that must yield NOTHING.

func TestDeriveLifecycle_ClosedObjectInfersRecovery(t *testing.T) {
	b := tBase()
	end := b.Add(9 * time.Minute)
	lc := DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(30 * time.Second),
		VerdictTier: "confirmed", Owner: "isp", Confidence: 0.9,
		State: "closed", WindowEnd: end,
	}, ITSMTimeFacts{})

	rec, ok := lc[EvRecovered]
	if !ok {
		t.Fatal("a CLOSED object with a window_end must yield an inferred recovery stamp")
	}
	if !rec.At.Equal(end) {
		t.Fatalf("recovery must land on window_end (last observed symptom); got %v want %v", rec.At, end)
	}
	if rec.Source != SrcInferred {
		t.Fatalf("engine recovery must be source=inferred, never observed/itsm; got %s", rec.Source)
	}
	if rec.Confidence != inferredRecoveryMaxConfidence {
		t.Fatalf("a 0.9-confidence verdict must still cap the recovery stamp at %v; got %v",
			inferredRecoveryMaxConfidence, rec.Confidence)
	}
	// The whole point: ttr_recovery is now COMPLETE and flagged inferred.
	var ttr TimeMetric
	for _, m := range ComputeTimeMetrics(lc, "v1", b) {
		if m.Name == MetricTTRRecovery {
			ttr = m
		}
	}
	if !ttr.Complete || ttr.DurationMs != int64(9*time.Minute/time.Millisecond) {
		t.Fatalf("ttr_recovery must be complete at 9m: %+v", ttr)
	}
	if !ttr.IsInferred {
		t.Fatal("ttr_recovery built on an engine proxy MUST be flagged is_inferred")
	}
	if ttr.Confidence > inferredRecoveryMaxConfidence {
		t.Fatalf("ttr_recovery confidence must propagate the capped stamp; got %v", ttr.Confidence)
	}
}

func TestDeriveLifecycle_ITSMRecoveryBeatsEngineInference(t *testing.T) {
	b := tBase()
	itsmAt := b.Add(20 * time.Minute)
	lc := DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(30 * time.Second), Confidence: 0.9,
		State: "closed", WindowEnd: b.Add(9 * time.Minute),
	}, ITSMTimeFacts{Recovered: itsmAt})

	rec := lc[EvRecovered]
	if rec.Source != SrcITSM || !rec.At.Equal(itsmAt) {
		t.Fatalf("a linked ITSM recovery must WIN over the engine proxy; got %+v", rec)
	}
	if rec.Confidence != 1 {
		t.Fatalf("an ITSM recovery keeps confidence 1, got %v", rec.Confidence)
	}
}

func TestDeriveLifecycle_MergedAndOpenNeverRecover(t *testing.T) {
	b := tBase()
	for _, state := range []string{"merged", "open", "", "unknown"} {
		lc := DeriveLifecycle(CorrTimeFacts{
			WindowStart: b, CreatedAt: b.Add(30 * time.Second), Confidence: 0.9,
			State: state, WindowEnd: b.Add(9 * time.Minute),
		}, ITSMTimeFacts{})
		if _, ok := lc[EvRecovered]; ok {
			t.Fatalf("state %q must NOT yield recovery (merged folds into its parent; open is still live)", state)
		}
	}
}

func TestDeriveLifecycle_ClosedWithoutWindowEndStaysIncomplete(t *testing.T) {
	b := tBase()
	lc := DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(30 * time.Second), Confidence: 0.9,
		State: "CLOSED", // case-insensitive, but no timestamp to stand on
	}, ITSMTimeFacts{})
	if _, ok := lc[EvRecovered]; ok {
		t.Fatal("a closed object with a zero window_end must yield NO recovery — never a bogus zero time")
	}
}

func TestDeriveLifecycle_InferredRecoveryNeverPrecedesOnset(t *testing.T) {
	b := tBase()
	// Corrupt/skewed row: window_end before window_start. Clamp to the onset, the
	// same guard `detected` carries — never a "recovered before it started" timeline.
	lc := DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(30 * time.Second), Confidence: 0.9,
		State: "closed", WindowEnd: b.Add(-5 * time.Second),
	}, ITSMTimeFacts{})
	if got := lc[EvRecovered].At; !got.Equal(b) {
		t.Fatalf("recovery must clamp to the onset under skew; got %v want %v", got, b)
	}
}

func TestDeriveLifecycle_InferredRecoveryConfidenceFloors(t *testing.T) {
	b := tBase()
	// An object reporting no confidence floors at 0.5, which is BELOW the cap —
	// min() must keep the floor, not raise it to the cap.
	lc := DeriveLifecycle(CorrTimeFacts{
		WindowStart: b, CreatedAt: b.Add(30 * time.Second),
		State: "closed", WindowEnd: b.Add(time.Minute),
	}, ITSMTimeFacts{})
	if got := lc[EvRecovered].Confidence; got != 0.5 {
		t.Fatalf("a confidence-less object must keep the 0.5 floor, not the 0.7 cap; got %v", got)
	}
}
