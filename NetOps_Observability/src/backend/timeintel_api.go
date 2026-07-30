package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/ticketing"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/timeintel"
)

// timeintel_api.go — GET /api/correlations/{id}/time-metrics : RCA Time Intelligence
// for one incident. Decomposes the correlation object's lifecycle into phase metrics
// (TTD/TTC/TTI/TTE/TTA/TTM/recovery/resolution) + a "where did the time go" driver,
// derived from engine + ITSM facts (see timeintel_derive.go). Read-only and
// tenant-scoped via chRows (chTenantScope) — a correlation the caller can't see
// returns 404, so there is no cross-tenant metric leak.

const timeIntelCalcVersion = "ti-1"

// parseCHTime parses a ClickHouse DateTime64 string ("2026-06-24 12:00:00.000",
// UTC). Returns the zero time on anything unparseable/empty (→ absent event).
func parseCHTime(v any) time.Time {
	s := strings.TrimSpace(asString(v))
	if s == "" || strings.HasPrefix(s, "0000-00-00") || strings.HasPrefix(s, "1970-01-01") {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// (asString + asFloat are shared helpers from health_score.go.)

// ownerFromHypotheses pulls the top hypothesis's seam owner out of the hypotheses
// JSON blob (ranking.hypotheses[0].verdict.owner). Best-effort: "" when absent.
func ownerFromHypotheses(blob string) string {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return ""
	}
	var h struct {
		Ranking struct {
			Hypotheses []struct {
				Verdict struct {
					Owner string `json:"owner"`
				} `json:"verdict"`
			} `json:"hypotheses"`
		} `json:"ranking"`
	}
	if err := json.Unmarshal([]byte(blob), &h); err != nil {
		return ""
	}
	if len(h.Ranking.Hypotheses) == 0 {
		return ""
	}
	return h.Ranking.Hypotheses[0].Verdict.Owner
}

// seamTypeFromHypotheses pulls the grounded seam TYPE (DIA / SDWAN / VPN / DX /
// CLOUD_BACKBONE / …) from the hypotheses blob (grounding_context.seams[0].seam_type).
// "" when the object isn't grounded on a seam (most LAN/DC incidents).
func seamTypeFromHypotheses(blob string) string {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return ""
	}
	var h struct {
		GroundingContext struct {
			Seams []struct {
				SeamType string `json:"seam_type"`
			} `json:"seams"`
		} `json:"grounding_context"`
	}
	if err := json.Unmarshal([]byte(blob), &h); err != nil {
		// Our OWN stored blob failed to parse — that is corruption, not "this
		// incident is not grounded on a seam". Both still answer "" (never guess
		// a seam type), but the corrupt case is now observable (§10).
		logWarn("timeintel", "hypotheses blob unparseable — seam type reported as UNGROUNDED", errf(err))
		return ""
	}
	if len(h.GroundingContext.Seams) == 0 {
		return "" // parsed: this object genuinely is not grounded on a seam
	}
	return strings.TrimSpace(h.GroundingContext.Seams[0].SeamType)
}

// evidenceMissingFromBlob reports whether the evidence_missing JSON array is
// non-empty (evidence not yet sufficient).
func evidenceMissingFromBlob(blob string) bool {
	blob = strings.TrimSpace(blob)
	if blob == "" || blob == "[]" {
		return false
	}
	var arr []string
	if err := json.Unmarshal([]byte(blob), &arr); err != nil {
		// Unparseable but non-empty → treat as present (conservative/honest).
		return true
	}
	return len(arr) > 0
}

type timeIntelLifecycleRow struct {
	EventType  timeintel.EventType       `json:"event_type"`
	At         time.Time                 `json:"at"`
	Source     timeintel.TimestampSource `json:"timestamp_source"`
	Confidence float64                   `json:"confidence"`
}

type timeIntelResponse struct {
	CorrelationID   string                  `json:"correlation_id"`
	VerdictTier     string                  `json:"verdict_tier"`
	Owner           string                  `json:"owner,omitempty"`
	OwnerDomain     timeintel.OwnerDomain   `json:"owner_domain"`
	OwnerLabel      string                  `json:"owner_label"`         // operator-facing (never lowercase raw)
	SeamType        string                  `json:"seam_type,omitempty"` // DIA/SDWAN/VPN/DX/CLOUD_BACKBONE (grounded seam)
	RootDomain      string                  `json:"root_domain,omitempty"`
	ConfidenceLbl   string                  `json:"confidence_label"` // Evidence-backed | Candidate | Insufficient evidence
	EvidenceMissing bool                    `json:"evidence_missing"`
	Lifecycle       []timeIntelLifecycleRow `json:"lifecycle"`
	Metrics         []timeintel.TimeMetric  `json:"metrics"`
	// Current bottleneck = the EARLIEST incomplete lifecycle phase (phase-consistent).
	CurrentBottleneck  timeintel.TimeLossDriver `json:"current_bottleneck"`
	BottleneckMessage  string                   `json:"bottleneck_message"`
	WorkflowConnected  bool                     `json:"workflow_connected"`
	CalculationVersion string                   `json:"calculation_version"`
}

// confidenceLabel maps a verdict tier to operator-facing evidence-strength copy.
func confidenceLabel(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "confirmed":
		return "Evidence-backed"
	case "suspected":
		return "Candidate"
	case "undetermined":
		return "Insufficient evidence"
	default:
		return ""
	}
}

// serveCorrelationTimeMetrics handles GET /api/correlations/{id}/time-metrics.
func (s *server) serveCorrelationTimeMetrics(w http.ResponseWriter, r *http.Request, id string) {
	objSQL := `
SELECT ` + chschema.ISO("window_start") + ` AS window_start,
       ` + chschema.ISO("created_at") + `   AS created_at,
       verdict_tier, top_confidence,
       hypotheses, evidence_missing, affected
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := s.chRows(r, objSQL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(rows) == 0 {
		// Not found OR not visible to this tenant — same 404 either way (no id leak).
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	o := rows[0]
	owner := ownerFromHypotheses(asString(o["hypotheses"]))
	group := timeintel.GroupKeysFromAffected(asString(o["affected"]))
	facts := timeintel.CorrTimeFacts{
		WindowStart:     parseCHTime(o["window_start"]),
		FirstIngest:     s.minIngestTS(r, id), // detection latency (best-effort)
		CreatedAt:       parseCHTime(o["created_at"]),
		VerdictTier:     asString(o["verdict_tier"]),
		Owner:           owner,
		EvidenceMissing: evidenceMissingFromBlob(asString(o["evidence_missing"])),
		Confidence:      asFloat(o["top_confidence"]),
	}
	ownerDomain, _ := timeintel.ClassifyOwnerDomain(owner, group)

	// ITSM facts: per-correlation ticket lifecycle, derived from the #78 ticket
	// audit ledger (tenant-scoped). "ticket filed" + "resolved" populate from the
	// outbound worker today; the human phases (acknowledged/mitigated/…) populate
	// the moment an inbound ServiceNow sync appends those audit rows. workflow
	// Connected is true once a ticket exists, so the bottleneck logic stops reading
	// "workflow not connected" instead of inventing a phase that can't move.
	itsm, workflowConnected := s.itsmFactsFor(r, id)

	lc := timeintel.DeriveLifecycle(facts, itsm)
	// Overlay the caller's stored MANUAL events (operator-supplied recovery/closure/
	// ack timestamps) — tenant-scoped, user-entered wins. Unblocks the human phases.
	if claims, ok := userFrom(r.Context()); ok {
		s.manualLifecycle(r, claims, id, lc)
	}
	now := time.Now().UTC()
	metrics := timeintel.ComputeTimeMetrics(lc, timeIntelCalcVersion, now)
	bottleneck, message := timeintel.DeriveCurrentBottleneck(lc, timeintel.DriverContext{
		EvidenceMissing:   facts.EvidenceMissing,
		Owner:             facts.Owner,
		WorkflowConnected: workflowConnected,
	})

	// Lifecycle → sorted rows (chronological) for the UI timeline.
	lcRows := make([]timeIntelLifecycleRow, 0, len(lc))
	for ev, st := range lc {
		lcRows = append(lcRows, timeIntelLifecycleRow{EventType: ev, At: st.At, Source: st.Source, Confidence: st.Confidence})
	}
	sort.Slice(lcRows, func(i, j int) bool {
		if lcRows[i].At.Equal(lcRows[j].At) {
			return lcRows[i].EventType < lcRows[j].EventType
		}
		return lcRows[i].At.Before(lcRows[j].At)
	})

	writeJSON(w, http.StatusOK, timeIntelResponse{
		CorrelationID:      id,
		VerdictTier:        facts.VerdictTier,
		Owner:              facts.Owner,
		OwnerDomain:        ownerDomain,
		OwnerLabel:         timeintel.OwnerLabel(facts.Owner),
		SeamType:           seamTypeFromHypotheses(asString(o["hypotheses"])),
		RootDomain:         group["root_entity"],
		ConfidenceLbl:      confidenceLabel(facts.VerdictTier),
		EvidenceMissing:    facts.EvidenceMissing,
		Lifecycle:          lcRows,
		Metrics:            metrics,
		CurrentBottleneck:  bottleneck,
		BottleneckMessage:  message,
		WorkflowConnected:  workflowConnected,
		CalculationVersion: timeIntelCalcVersion,
	})
}

// minIngestTS returns the earliest signal ingest time for the object (detection
// latency input). Best-effort: zero time on any error / no archive rows.
func (s *server) minIngestTS(r *http.Request, id string) time.Time {
	sql := `SELECT ` + chschema.ISO("min(ingest_ts)") + ` AS fi
              FROM netops.corr_signals_archive
             WHERE toString(archived_for) = '` + id + `'
             FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		// The archive did not answer. Detection latency stays UNSET (the zero
		// time the calculator reads as "incomplete"), which is also what "no
		// archived signals" produces — but only one of the two is a fault, and
		// it is no longer silent (§10).
		logWarn("timeintel", "earliest-ingest read failed — detection latency left INCOMPLETE, never zero",
			map[string]any{"correlation_id": id, "err": err.Error()})
		return time.Time{}
	}
	if len(rows) == 0 {
		return time.Time{} // answered: no archived signals for this object
	}
	return parseCHTime(rows[0]["fi"])
}

// timeintel.ITSMTimeFacts resolves the per-correlation ticket lifecycle from the #78 ticket
// audit ledger + link, scoped to the caller's tenant (a cross-tenant id simply
// resolves to no link → empty facts, never a leak). Returns the human-phase
// timestamps plus whether the ITSM workflow is connected (a ticket exists).
// Best-effort: any store error degrades to empty/unconnected rather than failing
// the whole time-metrics read. Phases with no timestamp stay INCOMPLETE in the
// calculator — honest, never guessed.
func (s *server) itsmFactsFor(r *http.Request, id string) (timeintel.ITSMTimeFacts, bool) {
	if s.ticketing == nil {
		return timeintel.ITSMTimeFacts{}, false
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		return timeintel.ITSMTimeFacts{}, false
	}
	tenant, cross := principalTenant(claims)
	link, found, err := s.ticketing.GetLink(r.Context(), tenant, cross, id, "servicenow")
	if err != nil {
		return timeintel.ITSMTimeFacts{}, false
	}
	// Per-object ledger (one row per action) — the max page covers it whole.
	audit, _, err := s.ticketing.ListAudit(r.Context(), tenant, cross, id, ticketing.MaxPage, 0)
	if err != nil {
		audit = nil
	}
	return ticketAuditToITSMFacts(audit, link, found)
}
