package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

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
	OwnerLabel      string                  `json:"owner_label"` // operator-facing (never lowercase raw)
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
SELECT toString(window_start) AS window_start,
       toString(created_at)   AS created_at,
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
	group := groupKeysFromAffected(asString(o["affected"]))
	facts := corrTimeFacts{
		WindowStart:     parseCHTime(o["window_start"]),
		FirstIngest:     s.minIngestTS(r, id), // detection latency (best-effort)
		CreatedAt:       parseCHTime(o["created_at"]),
		VerdictTier:     asString(o["verdict_tier"]),
		Owner:           owner,
		EvidenceMissing: evidenceMissingFromBlob(asString(o["evidence_missing"])),
		Confidence:      asFloat(o["top_confidence"]),
	}
	ownerDomain, _ := timeintel.ClassifyOwnerDomain(owner, group)

	// ITSM facts: per-correlation ticket lifecycle. The hub-and-spoke ticket linkage
	// (#78) is not wired yet → workflowConnected=false, so the bottleneck says
	// "workflow not connected" instead of inventing a ticket phase that can't move.
	itsm := s.itsmTimeFacts(r, id)
	workflowConnected := false

	lc := deriveLifecycle(facts, itsm)
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
	sql := `SELECT toString(min(ingest_ts)) AS fi
              FROM netops.corr_signals_archive
             WHERE toString(archived_for) = '` + id + `'
             FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil || len(rows) == 0 {
		return time.Time{}
	}
	return parseCHTime(rows[0]["fi"])
}

// itsmTimeFacts resolves the per-correlation ticket lifecycle from the integration
// event ledger. Empty until per-correlation ticket linkage (#78) is wired; the
// calculator then leaves the human-phase metrics INCOMPLETE rather than guessing.
func (s *server) itsmTimeFacts(_ *http.Request, _ string) itsmTimeFacts {
	return itsmTimeFacts{}
}
