package main

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
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// rcaPromotionMinDuration — the shortest incident an AUTO-promotion accepts. A
// blip shorter than this never self-promotes; a human may still promote it.
// 2m (owner decision 2026-07-18, was 5m): in a single-WAN-link deployment a
// total loss of app access is an outage well before 5 minutes; 2m still keeps
// sub-minute reconvergence blips out of the management tier.
const rcaPromotionMinDuration = 2 * time.Minute

// ---- interfaces / model -----------------------------------------------------

// rcaPromotionRecord is one manual promotion: who, when, why. Non-secret.
type rcaPromotionRecord struct {
	PromotedBy string `json:"promoted_by"`
	PromotedAt string `json:"promoted_at"` // UTC, canonical fmtUTC
	Note       string `json:"note,omitempty"`
}

// rcaPromotionCriterion is one auto-promotion gate with its honest state.
type rcaPromotionCriterion struct {
	Name   string `json:"name"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}

// rcaPromotionStatus is the report's promotion block — the UI's single source
// for "is this an RCA document or a candidate, and why".
type rcaPromotionStatus struct {
	Promoted bool                    `json:"promoted"`
	Basis    string                  `json:"basis"` // auto | manual | not_promoted
	Reason   string                  `json:"reason"`
	Criteria []rcaPromotionCriterion `json:"criteria"`
	Manual   *rcaPromotionRecord     `json:"manual,omitempty"`
}

// ---- store ------------------------------------------------------------------

// rcaPromotionStore is a file-backed map keyed tenant → correlation id →
// record. §3a rule 4: the key includes the tenant in the store itself and no
// cross-tenant listing exists.
type rcaPromotionStore struct {
	mu   sync.RWMutex
	m    map[string]map[string]rcaPromotionRecord
	path string
}

func rcaPromotionsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_PROMOTIONS_PATH")); p != "" {
		return p
	}
	return "rca_promotions.json"
}

func newRcaPromotionStore(path string) *rcaPromotionStore {
	s := &rcaPromotionStore{m: map[string]map[string]rcaPromotionRecord{}, path: path}
	if b, err := kvLoad(path); err == nil && len(b) > 0 {
		var m map[string]map[string]rcaPromotionRecord
		if json.Unmarshal(b, &m) == nil {
			s.m = m
		}
	}
	return s
}

func (s *rcaPromotionStore) saveLocked() {
	if s.path == "" {
		return
	}
	if b, err := json.MarshalIndent(s.m, "", "  "); err == nil {
		if err := kvSave(s.path, b); err != nil {
			logWarn("rca", "persist rca promotions failed", map[string]any{"err": err.Error()})
		}
	}
}

// get returns the tenant's manual promotion for one correlation. Nil-safe.
func (s *rcaPromotionStore) get(tenant, id string) (rcaPromotionRecord, bool) {
	if s == nil {
		return rcaPromotionRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[tenant][id]
	return rec, ok
}

func (s *rcaPromotionStore) set(tenant, id string, rec rcaPromotionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[tenant] == nil {
		s.m[tenant] = map[string]rcaPromotionRecord{}
	}
	s.m[tenant][id] = rec
	s.saveLocked()
}

func (s *rcaPromotionStore) remove(tenant, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m[tenant], id)
	if len(s.m[tenant]) == 0 {
		delete(s.m, tenant)
	}
	s.saveLocked()
}

// ---- evaluation -------------------------------------------------------------

// evaluateRcaPromotion decides the case's tier from the FINISHED report (the
// states/times there are already derived honestly) plus any manual record. A
// manual promotion is an explicit human decision and always wins; auto requires
// every criterion. The reason strings are user-facing — they say exactly what
// is unmet and how to promote, never a bare refusal.
func evaluateRcaPromotion(rep *rcaReport, manual *rcaPromotionRecord) rcaPromotionStatus {
	crit := []rcaPromotionCriterion{
		{
			Name: "production incident", Met: !rep.Validation,
			Detail: map[bool]string{true: "not a validation scenario", false: "validation scenario — never a customer RCA"}[!rep.Validation],
		},
		{
			Name: "confirmed verdict", Met: rep.States.Analysis == "confirmed",
			Detail: "analysis is " + orDefault(rep.States.Analysis, "unknown"),
		},
		{
			Name: "user/application impact", Met: rep.States.Impact == "confirmed",
			Detail: fmt.Sprintf("impact is %s (real-user: %s, synthetic: %s)",
				orDefault(rep.States.Impact, "unknown"),
				orDefault(rep.States.ImpactRealUser, "unknown"),
				orDefault(rep.States.ImpactSynthetic, "unknown")),
		},
		{
			Name: "duration", Met: time.Duration(rep.Times.DurationMS)*time.Millisecond >= rcaPromotionMinDuration,
			Detail: fmt.Sprintf("%s observed; auto-promotion requires ≥ %s",
				fmtDur(time.Duration(rep.Times.DurationMS)*time.Millisecond), fmtDur(rcaPromotionMinDuration)),
		},
	}
	st := rcaPromotionStatus{Criteria: crit, Manual: manual}
	if manual != nil {
		st.Promoted = true
		st.Basis = "manual"
		st.Reason = fmt.Sprintf("manually promoted by %s at %s", manual.PromotedBy, manual.PromotedAt)
		return st
	}
	var unmet []string
	for _, c := range crit {
		if !c.Met {
			unmet = append(unmet, c.Name)
		}
	}
	if len(unmet) == 0 {
		st.Promoted = true
		st.Basis = "auto"
		st.Reason = "meets the real-outage criteria: confirmed verdict, confirmed user/application impact, duration ≥ " + fmtDur(rcaPromotionMinDuration)
		return st
	}
	st.Basis = "not_promoted"
	st.Reason = "RCA documents are reserved for promoted real outages; this candidate does not meet: " +
		strings.Join(unmet, ", ") + ". An operator with write permission can promote it explicitly (audited)."
	return st
}

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
		rec, has := s.rcaPromotions.get(objTenant, id)
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
		rec := rcaPromotionRecord{PromotedBy: claims.Sub, PromotedAt: fmtUTC(time.Now().UTC()), Note: strings.TrimSpace(body.Note)}
		s.rcaPromotions.set(objTenant, id, rec)
		s.auditManualEdit(r, claims, objTenant, "rca_promote", id, map[string]any{"note": rec.Note})
		writeJSON(w, http.StatusOK, map[string]any{"manually_promoted": true, "manual": rec})
	case http.MethodDelete:
		if s.rcaPromotions == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("promotion store unavailable"))
			return
		}
		s.rcaPromotions.remove(objTenant, id)
		s.auditManualEdit(r, claims, objTenant, "rca_unpromote", id, map[string]any{})
		writeJSON(w, http.StatusOK, map[string]any{"manually_promoted": false})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, POST or DELETE"))
	}
}
