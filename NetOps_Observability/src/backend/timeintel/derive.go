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
//
// Mapping (v2 addition — engine-inferred RECOVERY). recovered = the ITSM recovery
// timestamp whenever a workflow is linked (source=itsm, confidence 1, unchanged).
// When it is NOT — the common case, since most deployments link no ITSM workflow —
// a CLOSED correlation object stands in for it:
//
//	state=closed + window_end ≠ 0 → recovered = window_end, source=INFERRED,
//	                                confidence = min(top_confidence, 0.7)
//	state=merged                  → NO recovery, ever. The object was folded into
//	                                another one, which carries the real lifecycle;
//	                                a merged child recovers only in its parent.
//	state=open                    → nothing (the incident is still live).
//
// Why this is INFERRED and not observed, stated exactly: window_end is the last
// WRITTEN EVIDENCE time of the object's window (the engine's own words — see
// corr_current's window_end note in the correlation engine), and the engine closes
// a window after CORR_QUIESCE_S of silence. So "closed at window_end" means "the
// engine saw no further symptoms and closed the window" — a PROXY for service
// recovery, not a measurement of it. True recovery lies at or after window_end,
// so this is also the EARLIEST defensible estimate; the 0.7 confidence cap and the
// inferred source are what stop the UI reading a proxy as ground truth. A stamp
// that would precede first_signal (a corrupt/skewed row) is clamped to the onset,
// the same guard `detected` carries.

// inferredRecoveryMaxConfidence caps an ENGINE-inferred recovery stamp. A window
// close is evidence of silence, never of a verified service restore, so however
// confident the verdict was, the recovery timing it implies is not.
const inferredRecoveryMaxConfidence = 0.7

// CorrTimeFacts are the engine-side facts pulled from a correlation object.
type CorrTimeFacts struct {
	WindowStart     time.Time // min signal ts (onset) — first_signal
	FirstIngest     time.Time // min signal ingest_ts — detection (zero if unknown)
	CreatedAt       time.Time // object persisted — correlation completed
	VerdictTier     string    // undetermined | suspected | confirmed
	Owner           string    // seam owner from the top hypothesis (may be "")
	EvidenceMissing bool      // evidence_missing non-empty → evidence not yet ready
	Confidence      float64   // top_confidence 0..1
	// State is the engine lifecycle state of the object: open | closed | merged.
	// Only "closed" can imply recovery (see the v2 mapping above).
	State string
	// WindowEnd is the object's last WRITTEN evidence time — the last observed
	// symptom, NOT the instant the engine closed the window. Zero if unknown.
	WindowEnd time.Time
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

	// ENGINE-INFERRED RECOVERY (v2 mapping in the header). ITSM wins outright: this
	// runs only when no workflow recovery is linked, so a linked ticket can never be
	// overwritten by a proxy. Everything else about the lifecycle is unchanged.
	if t.Recovered.IsZero() && engineClosed(c.State) && !c.WindowEnd.IsZero() {
		rec := c.WindowEnd
		if !c.WindowStart.IsZero() && rec.Before(c.WindowStart) {
			// Clock skew / corrupt row: recovery can never precede the onset. Clamp
			// rather than drop, exactly as `detected` does above.
			rec = c.WindowStart
		}
		put(EvRecovered, rec, SrcInferred, min(conf, inferredRecoveryMaxConfidence))
	}
	return lc
}

// engineClosed reports whether the correlation object's state is the ONE state that
// implies the incident stopped producing symptoms. "merged" is deliberately excluded:
// a merged object was folded into another, whose lifecycle carries the real recovery.
func engineClosed(state string) bool {
	return strings.EqualFold(strings.TrimSpace(state), "closed")
}
