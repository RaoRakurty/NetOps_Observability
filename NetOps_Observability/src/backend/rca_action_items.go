package main

// rca_action_items.go — Phase 1 structured action items (postmortem spec §3 +
// §7, docs/design/rca-postmortem-enhancements-spec.md).
//
// An action item is the PERSISTED corrective/diagnostic work record — distinct
// from rca_actions.go's ephemeral derived next-steps. Schema: action ·
// category (prevent/mitigate/detect/diagnose/respond/resilience) · ONE
// accountable owner · collaborators · priority · due date · remediation status
// (spec §7 states) · success criteria · verification evidence · external
// ticket id · source (machine-suggested vs human-created) · related cause /
// gap links · completion + verification timestamps.
//
// Rules enforced here:
//   - seam ownership SUGGESTS an owning team, never auto-assigns: a
//     machine-suggested item has an empty accountable owner until a HUMAN
//     acceptance (status proposed → accepted) names exactly one;
//   - "overdue" is DERIVED at read time from the due date, never stored;
//   - remediation status is separate from postmortem completion and follows an
//     explicit transition table — no free-form jumps;
//   - tenant isolation (§3a): the store is keyed by the OBJECT's owning tenant
//     (resolved under the caller's ClickHouse row-policy scope first, so a
//     cross-tenant id answers 404); every write is audited.

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/rca"
	"os"
	"strings"
	"time"
)

// ---- vocabulary ---------------------------------------------------------------

// The action-item domain moved to internal/rca/action_items.go (Phase-2 W3.3).
type (
	rcaActionItem      = rca.ActionItem
	rcaActionLink      = rca.ActionLink
	rcaActionItemStore = rca.ActionItemStore
)

func newRcaActionItemStore(path string) *rcaActionItemStore { return rca.NewActionItemStore(path) }

func rcaActionItemsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_ACTION_ITEMS_PATH")); p != "" {
		return p
	}
	return "/data/rca_action_items.json"
}

func (s *server) handleRcaActionItems(w http.ResponseWriter, r *http.Request, id, rest string) {
	level := LevelWrite
	if r.Method == http.MethodGet {
		level = LevelRead
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return
	}
	if s.rcaActionItems == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("action-item store unavailable"))
		return
	}
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
	now := time.Now().UTC()

	switch {
	case r.Method == http.MethodGet && rest == "":
		items := s.rcaActionItems.List(objTenant, id)
		for i := range items {
			rca.StampActionDerived(&items[i], now)
		}
		writeJSON(w, http.StatusOK, map[string]any{"actions": items})

	case r.Method == http.MethodPost && rest == "":
		var it rcaActionItem
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&it); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
			return
		}
		// Server-owned fields: identity, source, lifecycle stamps.
		it.ID = randID()
		it.CorrelationID = id
		it.Source = "human_created"
		it.SuggestedOwner = ""
		it.Status = "proposed"
		it.CreatedAt, it.CreatedBy = rca.FmtUTC(now), claims.Sub
		it.UpdatedAt, it.UpdatedBy = "", ""
		it.AcceptedAt, it.AcceptedBy, it.CompletedAt, it.VerifiedAt = "", "", "", ""
		if err := rca.ValidateActionItemFields(&it); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.rcaActionItems.Put(objTenant, id, it); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_create", id, map[string]any{"action_id": it.ID, "category": it.Category})
		rca.StampActionDerived(&it, now)
		writeJSON(w, http.StatusOK, it)

	case r.Method == http.MethodPost && rest == "suggest":
		// Build the report through the SHARED pipeline (tenant-scoped) and
		// derive suggestions from seam ownership. Idempotent: an existing item
		// with the same action text is never duplicated.
		rep, status, err := s.buildRcaReportForID(r, claims, id, 0)
		if err != nil {
			writeError(w, status, err)
			return
		}
		var owners map[string]seamOwnerEntry
		if s.governance != nil {
			owners, _ = s.governance.SeamOwners(objTenant)
		}
		existing := map[string]bool{}
		for _, it := range s.rcaActionItems.List(objTenant, id) {
			existing[it.Action] = true
		}
		created := []rcaActionItem{}
		for _, it := range rca.SuggestActionItems(rep, owners) {
			if existing[it.Action] {
				continue
			}
			it.ID = randID()
			it.CorrelationID = id
			it.CreatedAt, it.CreatedBy = rca.FmtUTC(now), "correlix (machine-suggested)"
			if err := rca.ValidateActionItemFields(&it); err != nil {
				continue // a malformed suggestion is dropped, never half-written
			}
			if err := s.rcaActionItems.Put(objTenant, id, it); err != nil {
				break // register full — stop suggesting, report what was created
			}
			created = append(created, it)
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_suggest", id, map[string]any{"created": len(created)})
		writeJSON(w, http.StatusOK, map[string]any{"created": created, "note": "machine-suggested items carry a suggested owner only; human acceptance (status → accepted) names the one accountable owner"})

	case r.Method == http.MethodPut && rest != "":
		cur, has := s.rcaActionItems.Get(objTenant, id, rest)
		if !has {
			writeError(w, http.StatusNotFound, errors.New("action item not found"))
			return
		}
		var body rcaActionItem
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
			return
		}
		// Mutable fields only; identity/source/lifecycle stamps stay server-owned.
		next := cur
		next.Action = body.Action
		next.Category = body.Category
		next.AccountableOwner = body.AccountableOwner
		next.Collaborators = body.Collaborators
		next.Priority = body.Priority
		next.DueDate = body.DueDate
		next.SuccessCriteria = body.SuccessCriteria
		next.VerificationEvidence = body.VerificationEvidence
		next.ExternalTicketID = body.ExternalTicketID
		next.Related = body.Related
		if err := rca.ValidateActionItemFields(&next); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if body.Status != "" {
			if err := rca.ApplyActionStatusChange(&next, body.Status, claims.Sub, rca.FmtUTC(now)); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		next.UpdatedAt, next.UpdatedBy = rca.FmtUTC(now), claims.Sub
		if err := s.rcaActionItems.Put(objTenant, id, next); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_update", id, map[string]any{"action_id": next.ID, "status": next.Status})
		rca.StampActionDerived(&next, now)
		writeJSON(w, http.StatusOK, next)

	case r.Method == http.MethodDelete && rest != "":
		removed, err := s.rcaActionItems.Remove(objTenant, id, rest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("action item was not deleted"))
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, errors.New("action item not found"))
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_delete", id, map[string]any{"action_id": rest})
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})

	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET/POST /actions, POST /actions/suggest, PUT/DELETE /actions/{id}"))
	}
}
