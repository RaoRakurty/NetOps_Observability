package backend

// rca_promotion.go — #113 point 3: RCA creation policy. An RCA document is a
// management/C-suite artifact for REAL outages (a primary network failure that
// hits user/application access) — NOT every middle-mile latency blip. Candidates
// (#111) and RCA documents are different tiers:
//
//   · every correlation object stays a CANDIDATE — workspace + report JSON are
//     always readable (same permission/tenant gates as before);
//   · the DOCUMENT renders (?format=html|pdf) only for a PROMOTED case:
//       auto-promoted   — production incident AND confirmed verdict AND
//                         confirmed user/application impact AND duration ≥ 2m;
//       manually promoted — an explicit, audited operator decision
//                           (POST /api/correlations/{id}/rca-promotion).
//
// Tenant isolation (§3a): the manual-promotion store is keyed by the OBJECT's
// owning tenant in the store itself (no unscoped listing); the handler resolves
// the object under the caller's ClickHouse tenant scope first, so a cross-tenant
// id answers 404 and can never be promoted, revoked or probed.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"netops/backend/internal/rca"
	"os"
	"strings"
	"time"
)

// ---- interfaces / model -----------------------------------------------------

// The promotion model types (rca.PromotionStatus / PromotionCriterion /
// PromotionRecord) live in internal/rca — they are part of the report's shape.

// ---- store (internal/rca/promotion_store.go, P2 RA.6) -----------------------

type rcaPromotionStore = rca.PromotionStore

func newRcaPromotionStore(path string) *rcaPromotionStore { return rca.NewPromotionStore(path) }

func rcaPromotionsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_PROMOTIONS_PATH")); p != "" {
		return p
	}
	return "/data/rca_promotions.json"
}

// ---- evaluation -------------------------------------------------------------

// The evaluation (rca.EvaluatePromotion + rca.PromotionMinDuration) lives in
// internal/rca — it reads only the finished report and the manual record.
// ---- HTTP -------------------------------------------------------------------

// handleRcaPromotion serves /api/correlations/{id}/rca-promotion:
//
//	GET    — the caller-tenant's manual promotion record (read permission)
//	POST   — promote (write permission, audited; body {"note": "..."} bounded)
//	DELETE — revoke a manual promotion (write permission, audited)
//
// The object is resolved under the caller's ClickHouse tenant scope FIRST —
// a cross-tenant correlation id answers 404 before any store access (§3a).
func (s *server) handleRcaPromotion(w http.ResponseWriter, r *http.Request, id string) {
	level := LevelWrite
	if r.Method == http.MethodGet {
		level = LevelRead
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return
	}
	// Resolve the object's owning tenant under the caller's row-policy scope:
	// invisible (other tenant / absent) → 404, id existence never revealed.
	rows, err := s.chRowsScope(r.Context(), chTenantScope(r), `
SELECT tenant_id FROM netops.corr_objects
 WHERE correlation_id = '`+id+`'
 LIMIT 1
 FORMAT JSON`)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	objTenant := canonicalCorrTenant(asString(rows[0]["tenant_id"]))

	switch r.Method {
	case http.MethodGet:
		rec, has := s.rcaPromotions.Get(objTenant, id)
		out := map[string]any{"manually_promoted": has}
		if has {
			out["manual"] = rec
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		if s.rcaPromotions == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("promotion store unavailable"))
			return
		}
		var body struct {
			Note string `json:"note"`
		}
		if r.Body != nil {
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
			// an empty body is allowed (no note); malformed JSON is not.
			if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
				writeError(w, http.StatusBadRequest, errors.New("malformed body"))
				return
			}
		}
		if len(body.Note) > 500 {
			writeError(w, http.StatusBadRequest, errors.New("note must be at most 500 characters"))
			return
		}
		rec := rca.PromotionRecord{PromotedBy: claims.Sub, PromotedAt: rca.FmtUTC(time.Now().UTC()), Note: strings.TrimSpace(body.Note)}
		if err := s.rcaPromotions.Set(objTenant, id, rec); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("promotion was not saved"))
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_promote", id, map[string]any{"note": rec.Note})
		writeJSON(w, http.StatusOK, map[string]any{"manually_promoted": true, "manual": rec})
	case http.MethodDelete:
		if s.rcaPromotions == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("promotion store unavailable"))
			return
		}
		if err := s.rcaPromotions.Remove(objTenant, id); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("promotion was not cleared"))
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_unpromote", id, map[string]any{})
		writeJSON(w, http.StatusOK, map[string]any{"manually_promoted": false})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, POST or DELETE"))
	}
}
