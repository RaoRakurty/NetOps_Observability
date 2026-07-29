package timeintel

import (
	"strings"
	"time"
)

// timeintel_derive.go — derive an incident's lifecycle (RCA Time Intelligence) from
// what Correlix ALREADY records, WITHOUT modifying the Python engine. The correlation
// object carries the engine-side timestamps; ITSM carries the human/ticket ones. Each
// derived stamp is honestly source-attributed (observed vs inferred vs itsm) so the
// UI never reads an approximation as ground truth.
//
// Mapping (v1, documented so it can be refined): first_signal = window_start (min
// signal onset); detected = earliest ingest (Correlix's detection latency); correlation
// _completed = object persist time; root_domain_identified = persist time once the
// verdict is grounded (suspected/confirmed); owner_identified = same instant (owner is
// intrinsic to the grounded hypothesis → timing INFERRED); evidence_ready = persist
// time once evidence_missing is empty. impact_started is left ABSENT — the true onset
// is unobservable, so the calculator infers it from first_signal and flags it.

// CorrTimeFacts are the engine-side facts pulled from a correlation object.
type CorrTimeFacts struct {
	WindowStart     time.Time // min signal ts (onset) — first_signal
	FirstIngest     time.Time // min signal ingest_ts — detection (zero if unknown)
	CreatedAt       time.Time // object persisted — correlation completed
	VerdictTier     string    // undetermined | suspected | confirmed
	Owner           string    // seam owner from the top hypothesis (may be "")
	EvidenceMissing bool      // evidence_missing non-empty → evidence not yet ready
	Confidence      float64   // top_confidence 0..1
}

// ITSMTimeFacts are the human/ticket-side facts (ServiceNow/Jira/PagerDuty/Slack).
// Any zero time means the event has not occurred / is not linked yet.
type ITSMTimeFacts struct {
	TicketCreated     time.Time
	Acknowledged      time.Time
	MitigationStarted time.Time
	Mitigated         time.Time
	Recovered         time.Time
	Resolved          time.Time
	Closed            time.Time
}

func verdictGrounded(tier string) bool {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "suspected", "confirmed":
		return true
	}
	return false
}

func ownerKnown(owner string) bool {
	o := strings.ToLower(strings.TrimSpace(owner))
	return o != "" && o != "unknown"
}

// DeriveLifecycle builds the lifecycle map from engine + ITSM facts. Pure and
// testable. Confidence floors at 0.5 when the object reports none, so a grounded
// verdict never claims certainty it didn't have.
func DeriveLifecycle(c CorrTimeFacts, t ITSMTimeFacts) Lifecycle {
	lc := Lifecycle{}
	conf := c.Confidence
	if conf <= 0 || conf > 1 {
		conf = 0.5
	}
	put := func(ev EventType, at time.Time, src TimestampSource, cf float64) {
		if at.IsZero() {
			return
		}
		lc[ev] = EventStamp{At: at.UTC(), Source: src, Confidence: cf}
	}

	if !c.WindowStart.IsZero() {
		put(EvFirstSignal, c.WindowStart, SrcObserved, 1)
		// Detection = when Correlix first ingested the onset. Never before the onset
		// itself (clock skew guard); fall back to the onset when ingest is unknown.
		det := c.FirstIngest
		if det.IsZero() || det.Before(c.WindowStart) {
			det = c.WindowStart
		}
		put(EvDetected, det, SrcObserved, 1)
	}
	if !c.CreatedAt.IsZero() {
		put(EvCorrelationCompleted, c.CreatedAt, SrcObserved, 1)
		if verdictGrounded(c.VerdictTier) {
			put(EvRootDomainIdentified, c.CreatedAt, SrcObserved, conf)
			if ownerKnown(c.Owner) {
				// Owner is intrinsic to the grounded hypothesis (no separate timestamp),
				// so its timing is INFERRED at the grounding instant.
				put(EvOwnerIdentified, c.CreatedAt, SrcInferred, conf)
			}
		}
		if !c.EvidenceMissing {
			put(EvEvidenceReady, c.CreatedAt, SrcObserved, conf)
		}
	}

	// Human / ticket lifecycle — all source=itsm.
	put(EvTicketCreated, t.TicketCreated, SrcITSM, 1)
	put(EvAcknowledged, t.Acknowledged, SrcITSM, 1)
	put(EvMitigationStarted, t.MitigationStarted, SrcITSM, 1)
	put(EvMitigated, t.Mitigated, SrcITSM, 1)
	put(EvRecovered, t.Recovered, SrcITSM, 1)
	put(EvResolved, t.Resolved, SrcITSM, 1)
	put(EvClosed, t.Closed, SrcITSM, 1)
	return lc
}
