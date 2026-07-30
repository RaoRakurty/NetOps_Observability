package backend

// rca_reports_list.go — GET /api/correlations/rca-reports (#113 point 3, the
// management library). The owner's model: the Correlations/candidates page
// shows EVERYTHING (engineer surface, don't-hide); this endpoint lists ONLY the
// PROMOTED real outages whose documents management browses.
//
// Auto-promotion cannot be decided from SQL alone (impact/validation/duration
// derive inside the built report), so the list is a bounded two-phase:
//
//	(a) SQL prefilter under the CALLER's ClickHouse tenant scope (row
//	    policies): confirmed, non-merged objects long enough to possibly
//	    auto-promote, newest first, hard-capped at rcaLibraryEvalCap;
//	(b) per candidate, the SHARED report pipeline (buildRcaReportForID —
//	    the same path serveRcaReport uses, never a duplicate) builds the
//	    report and rca.EvaluatePromotion keeps promoted cases only.
//
// The caller-tenant's MANUAL promotions are unioned in (they are promoted by
// definition, even outside the prefilter window/criteria) and deduped. The
// per-candidate build is the expensive path — acceptable ONLY because of the
// hard cap; no silent truncation: the response discloses evaluated count,
// truncated flag and window.

import (
	"errors"
	"net/http"
	"netops/backend/internal/rca"
	"sort"
)

// rcaLibraryEvalCap bounds how many prefiltered candidates one request may
// build/evaluate — each evaluation is a full report build (§9 bounded work).
const rcaLibraryEvalCap = 100

// rcaLibraryReport is one library row, projected from the BUILT rca.Report so
// the list can never disagree with the document it links to.
type rcaLibraryReport struct {
	CorrelationID string              `json:"correlation_id"`
	DisplayID     string              `json:"display_id"`
	ReportType    string              `json:"report_type"`
	Title         string              `json:"title"`
	AtAGlance     rca.AtAGlance       `json:"at_a_glance"`
	States        rcaLibraryStates    `json:"states"`
	Times         rcaLibraryTimes     `json:"times"`
	Promotion     rca.PromotionStatus `json:"promotion"`
	Validation    bool                `json:"validation"`
}

type rcaLibraryStates struct {
	Incident string `json:"incident"`
	Analysis string `json:"analysis"`
	Impact   string `json:"impact"`
}

type rcaLibraryTimes struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	DurationMS int64  `json:"duration_ms"`
}

func rcaLibraryRow(rep rca.Report) rcaLibraryReport {
	return rcaLibraryReport{
		CorrelationID: rep.CorrelationID,
		DisplayID:     rep.DisplayID,
		ReportType:    rep.ReportType,
		Title:         rep.Title,
		AtAGlance:     rep.AtAGlance,
		States: rcaLibraryStates{
			Incident: rep.States.Incident,
			Analysis: rep.States.Analysis,
			Impact:   rep.States.Impact,
		},
		Times: rcaLibraryTimes{
			Start:      rep.Times.FirstObserved,
			End:        rep.Times.LastAnomalous,
			DurationMS: rep.Times.DurationMS,
		},
		Promotion:  rep.Promotion,
		Validation: rep.Validation,
	}
}

// rcaLibraryPrefilterSQL — phase (a): the tenant-scoped candidate prefilter.
// Only rows that could possibly auto-promote (confirmed, non-merged, at least
// the auto-promotion duration) inside the window, newest first, hard-capped.
// Pure so its bounded shape is unit-testable. Duration reuses the SAME
// constant the promotion criteria enforce — the two can never drift.
func rcaLibraryPrefilterSQL(days int) string {
	return `
SELECT toString(correlation_id) AS correlation_id
  FROM netops.corr_current FINAL
 WHERE verdict_tier = 'confirmed'
   AND state != 'merged'
   AND dateDiff('second', window_start, window_end) >= ` + intToString(int(rca.PromotionMinDuration.Seconds())) + `
   AND window_end >= now() - INTERVAL ` + intToString(days*86400) + ` SECOND
 ORDER BY window_end DESC
 LIMIT ` + intToString(rcaLibraryEvalCap) + `
 FORMAT JSON`
}

// handleRcaReportsLibrary serves GET /api/correlations/rca-reports.
func (s *server) handleRcaReportsLibrary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	days, errDays := intQuery(r, "days", 30, 1, 365)
	if errDays != nil {
		writeError(w, http.StatusBadRequest, errDays)
		return
	}

	// (a) prefilter — every read under the caller's tenant scope (row policies).
	preRows, err := s.chRows(r, rcaLibraryPrefilterSQL(days))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	ids := make([]string, 0, len(preRows)+4)
	seen := map[string]bool{}
	for _, row := range preRows {
		id := asString(row["correlation_id"])
		if isUUIDToken(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	truncated := len(preRows) >= rcaLibraryEvalCap

	// Union the caller-tenant's manual promotions (§3a rule 4: the store lists
	// one tenant's records only — a cross-scope caller unions nothing here and
	// still sees auto-promotable cases via the __all__ prefilter above).
	tenant, cross := principalTenant(claims)
	if !cross {
		for _, id := range s.rcaPromotions.List(tenant) {
			if isUUIDToken(id) && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}

	// (b) build + evaluate through the SHARED pipeline; keep promoted only. A
	// 404 (object aged out / invisible under this caller's scope) skips the id —
	// the row policy already decided the caller may not see it. Other failures
	// abort loudly (§10 no silent failures).
	evaluated := 0
	reports := make([]rcaLibraryReport, 0, len(ids))
	for _, id := range ids {
		rep, status, err := s.buildRcaReportForID(r, claims, id, 0)
		evaluated++
		if err != nil {
			if status == http.StatusNotFound {
				continue
			}
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if !rep.Promotion.Promoted {
			continue
		}
		reports = append(reports, rcaLibraryRow(rep))
	}
	// Newest outage first; ties (or missing times) fall back to id for
	// determinism. Manual unions may arrive out of window order.
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].Times.End != reports[j].Times.End {
			return reports[i].Times.End > reports[j].Times.End
		}
		return reports[i].CorrelationID > reports[j].CorrelationID
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"reports":     reports,
		"evaluated":   evaluated,
		"truncated":   truncated,
		"window_days": days,
	})
}
