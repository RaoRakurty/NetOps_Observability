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
	"fmt"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/rca"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/tenant"
)

// ---- vocabulary ---------------------------------------------------------------

var rcaActionCategories = map[string]bool{
	"prevent": true, "mitigate": true, "detect": true,
	"diagnose": true, "respond": true, "resilience": true,
}

// Remediation states (spec §7). "overdue" is intentionally NOT here: it is a
// derived read-time flag, never a stored state.
var rcaRemediationStates = map[string]bool{
	"proposed": true, "accepted": true, "in_progress": true, "blocked": true,
	"completed": true, "verified": true, "rejected": true, "superseded": true,
}

// rcaActionTransitions is the explicit lifecycle: from → allowed targets.
var rcaActionTransitions = map[string][]string{
	"proposed":    {"accepted", "rejected", "superseded"},
	"accepted":    {"in_progress", "blocked", "rejected", "superseded"},
	"in_progress": {"blocked", "completed", "superseded"},
	"blocked":     {"in_progress", "superseded"},
	"completed":   {"verified", "in_progress"}, // reopen when verification fails
	"verified":    {},
	"rejected":    {},
	"superseded":  {},
}

var rcaActionLinkKinds = map[string]bool{
	"root_cause": true, "contributing_factor": true, "detection_gap": true, "recovery_gap": true,
}

var rcaActionPriorities = map[string]bool{"P1": true, "P2": true, "P3": true}

// rcaActionItemsMaxPerCase bounds the register (§9 bounded everything).
const rcaActionItemsMaxPerCase = 200

// ---- model --------------------------------------------------------------------

// rcaActionLink relates an action item to the cause/gap it addresses.
type rcaActionLink struct {
	Kind string `json:"kind"` // root_cause | contributing_factor | detection_gap | recovery_gap
	Ref  string `json:"ref"`  // free-text reference (statement / lane / milestone key), bounded
}

// rcaActionItem is one persisted action-register row.
type rcaActionItem struct {
	ID            string `json:"id"`
	CorrelationID string `json:"correlation_id"`

	Action   string `json:"action"`
	Category string `json:"category"`

	// AccountableOwner: exactly ONE accountable owner. Empty while the item is
	// a machine suggestion — human acceptance fills it.
	AccountableOwner string `json:"accountable_owner,omitempty"`
	// SuggestedOwner: what seam ownership SUGGESTS (never auto-assigned).
	SuggestedOwner string   `json:"suggested_owner,omitempty"`
	Collaborators  []string `json:"collaborators,omitempty"`

	Priority string `json:"priority,omitempty"` // P1 | P2 | P3
	DueDate  string `json:"due_date,omitempty"` // YYYY-MM-DD
	Status   string `json:"status"`             // spec §7 remediation states
	// Overdue: DERIVED at read time (due date passed while not terminal/done).
	Overdue bool `json:"overdue"`

	SuccessCriteria      string `json:"success_criteria,omitempty"`
	VerificationEvidence string `json:"verification_evidence,omitempty"`
	ExternalTicketID     string `json:"external_ticket_id,omitempty"`

	// Source: machine_suggested | human_created.
	Source  string          `json:"source"`
	Related []rcaActionLink `json:"related,omitempty"`

	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	UpdatedBy   string `json:"updated_by,omitempty"`
	AcceptedAt  string `json:"accepted_at,omitempty"`
	AcceptedBy  string `json:"accepted_by,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	VerifiedAt  string `json:"verified_at,omitempty"`
}

// ---- store (tenant-keyed, §3a rule 4) -----------------------------------------

type rcaActionItemStore struct {
	mu   sync.RWMutex
	m    map[string]map[string]map[string]rcaActionItem // tenant → correlation → id → item
	path string
}

func rcaActionItemsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_ACTION_ITEMS_PATH")); p != "" {
		return p
	}
	return "/data/rca_action_items.json"
}

func newRcaActionItemStore(path string) *rcaActionItemStore {
	s := &rcaActionItemStore{m: map[string]map[string]map[string]rcaActionItem{}, path: path}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var m map[string]map[string]map[string]rcaActionItem
		if json.Unmarshal(b, &m) == nil {
			s.m = m
		}
	}
	return s
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *rcaActionItemStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rca action items: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		logError("rca", "persist rca action items failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist rca action items: %w", err)
	}
	return nil
}

// list returns ONE tenant's items for one correlation, oldest first. No
// cross-tenant or unscoped enumeration exists on this store. Nil-safe.
func (s *rcaActionItemStore) list(tenant, corrID string) []rcaActionItem {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]rcaActionItem, 0, len(s.m[tenant][corrID]))
	for _, it := range s.m[tenant][corrID] {
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt != items[j].CreatedAt {
			return items[i].CreatedAt < items[j].CreatedAt
		}
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *rcaActionItemStore) get(tenant, corrID, id string) (rcaActionItem, bool) {
	if s == nil {
		return rcaActionItem{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.m[tenant][corrID][id]
	return it, ok
}

func (s *rcaActionItemStore) put(tenant, corrID string, it rcaActionItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[tenant] == nil {
		s.m[tenant] = map[string]map[string]rcaActionItem{}
	}
	if s.m[tenant][corrID] == nil {
		s.m[tenant][corrID] = map[string]rcaActionItem{}
	}
	if _, exists := s.m[tenant][corrID][it.ID]; !exists && len(s.m[tenant][corrID]) >= rcaActionItemsMaxPerCase {
		return fmt.Errorf("action register full for this case (max %d items)", rcaActionItemsMaxPerCase)
	}
	prev, had := s.m[tenant][corrID][it.ID]
	s.m[tenant][corrID][it.ID] = it
	if err := s.saveLocked(); err != nil {
		if had {
			s.m[tenant][corrID][it.ID] = prev
		} else {
			delete(s.m[tenant][corrID], it.ID)
		}
		return err
	}
	return nil
}

func (s *rcaActionItemStore) remove(tenant, corrID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.m[tenant][corrID][id]
	if !ok {
		return false, nil
	}
	byCorr, hadCorr := s.m[tenant]
	items := s.m[tenant][corrID]
	delete(s.m[tenant][corrID], id)
	if len(s.m[tenant][corrID]) == 0 {
		delete(s.m[tenant], corrID)
		if len(s.m[tenant]) == 0 {
			delete(s.m, tenant)
		}
	}
	if err := s.saveLocked(); err != nil {
		// Rebuild the exact pre-delete shape: the empty-bucket pruning above may
		// have removed two levels of map, so restoring the item alone is not
		// enough.
		if !hadCorr {
			byCorr = map[string]map[string]rcaActionItem{}
		}
		s.m[tenant] = byCorr
		if items == nil {
			items = map[string]rcaActionItem{}
		}
		items[id] = prev
		s.m[tenant][corrID] = items
		return false, err
	}
	return true, nil
}

// ---- validation ---------------------------------------------------------------

func validateActionItemFields(it *rcaActionItem) error {
	it.Action = strings.TrimSpace(it.Action)
	if it.Action == "" || len(it.Action) > 500 {
		return errors.New("action is required (at most 500 characters)")
	}
	if !rcaActionCategories[it.Category] {
		return errors.New("category must be one of prevent, mitigate, detect, diagnose, respond, resilience")
	}
	// ONE accountable owner: a single named party, never a list.
	it.AccountableOwner = strings.TrimSpace(it.AccountableOwner)
	if len(it.AccountableOwner) > 120 || strings.ContainsAny(it.AccountableOwner, ",;/") {
		return errors.New("accountable_owner must name exactly ONE party (at most 120 characters, no lists)")
	}
	if len(it.Collaborators) > 10 {
		return errors.New("at most 10 collaborators")
	}
	for i, c := range it.Collaborators {
		it.Collaborators[i] = strings.TrimSpace(c)
		if it.Collaborators[i] == "" || len(it.Collaborators[i]) > 120 {
			return errors.New("collaborators must be non-empty names of at most 120 characters")
		}
	}
	if it.Priority != "" && !rcaActionPriorities[it.Priority] {
		return errors.New("priority must be P1, P2 or P3")
	}
	if it.DueDate != "" {
		if _, err := time.Parse("2006-01-02", it.DueDate); err != nil {
			return errors.New("due_date must be YYYY-MM-DD")
		}
	}
	for _, f := range []struct {
		name string
		val  string
		max  int
	}{
		{"success_criteria", it.SuccessCriteria, 500},
		{"verification_evidence", it.VerificationEvidence, 500},
		{"external_ticket_id", it.ExternalTicketID, 120},
		{"suggested_owner", it.SuggestedOwner, 160},
	} {
		if len(f.val) > f.max {
			return fmt.Errorf("%s must be at most %d characters", f.name, f.max)
		}
	}
	if len(it.Related) > 10 {
		return errors.New("at most 10 related links")
	}
	for i, l := range it.Related {
		if !rcaActionLinkKinds[l.Kind] {
			return errors.New("related.kind must be root_cause, contributing_factor, detection_gap or recovery_gap")
		}
		it.Related[i].Ref = strings.TrimSpace(l.Ref)
		if it.Related[i].Ref == "" || len(it.Related[i].Ref) > 300 {
			return errors.New("related.ref is required (at most 300 characters)")
		}
	}
	return nil
}

// applyActionStatusChange enforces the transition table and the acceptance /
// verification rules, stamping timestamps server-side.
func applyActionStatusChange(it *rcaActionItem, newStatus, actor, nowUTC string) error {
	if newStatus == it.Status {
		return nil
	}
	if !rcaRemediationStates[newStatus] {
		return errors.New("status must be one of proposed, accepted, in_progress, blocked, completed, verified, rejected, superseded (overdue is derived, never set)")
	}
	allowed := false
	for _, to := range rcaActionTransitions[it.Status] {
		if to == newStatus {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("status transition %s → %s is not allowed", it.Status, newStatus)
	}
	switch newStatus {
	case "accepted":
		// Human acceptance converts suggested → committed and REQUIRES the one
		// accountable owner. A machine suggestion can never self-accept.
		if it.AccountableOwner == "" {
			return errors.New("acceptance requires exactly one accountable_owner — a suggested owner is a suggestion, never an assignment")
		}
		it.AcceptedAt, it.AcceptedBy = nowUTC, actor
	case "completed":
		it.CompletedAt = nowUTC
	case "verified":
		if strings.TrimSpace(it.VerificationEvidence) == "" {
			return errors.New("verification requires verification_evidence")
		}
		it.VerifiedAt = nowUTC
	}
	it.Status = newStatus
	return nil
}

// stampActionDerived computes the read-time derived flags (overdue).
func stampActionDerived(it *rcaActionItem, now time.Time) {
	it.Overdue = false
	if it.DueDate == "" {
		return
	}
	due, err := time.Parse("2006-01-02", it.DueDate)
	if err != nil {
		return
	}
	switch it.Status {
	case "accepted", "in_progress", "blocked":
		it.Overdue = now.After(due.Add(24 * time.Hour))
	}
}

// ---- machine suggestions (from seam ownership — SUGGEST, never assign) --------

// ownerClassForLabel reverse-maps a rendered owner-team label to its catalog
// owner class (first match in the closed vocabulary), "" when unknown.
func ownerClassForLabel(label string) string {
	for _, class := range tenant.SeamOwnerClasses {
		if rca.OwnerTeam[class] == label {
			return class
		}
	}
	return ""
}

// suggestRcaActionItems derives machine-SUGGESTED items from the built report:
// seam ownership names the suggested owner; the accountable owner stays empty
// until a human accepts. Suggestions only state what the report already
// establishes (localization, coverage gaps, recovery gaps) — never new claims.
func suggestRcaActionItems(rep rca.Report, seamOwners map[string]seamOwnerEntry) []rcaActionItem {
	suggestOwner := func(teamLabel string) string {
		if teamLabel == "" {
			return ""
		}
		if class := ownerClassForLabel(teamLabel); class != "" {
			if e, ok := seamOwners[class]; ok && strings.TrimSpace(e.Name) != "" {
				return e.Name
			}
		}
		return teamLabel
	}
	var out []rcaActionItem
	add := func(action, category, owner string, related []rcaActionLink) {
		out = append(out, rcaActionItem{
			Action: action, Category: category,
			SuggestedOwner: suggestOwner(owner),
			Source:         "machine_suggested", Status: "proposed",
			Related: related,
		})
	}

	if rep.FaultLocalization.Localized && !rep.RootCause.Identified {
		owner := rep.Ownership.TechnicalOwner
		if owner == "" {
			owner = rep.Ownership.TriageOwner
		}
		add(fmt.Sprintf("Establish the failure mechanism on %s — the fault is localized there but the causal mechanism is not identified", rep.FaultLocalization.Object),
			"diagnose", owner,
			[]rcaActionLink{{Kind: "root_cause", Ref: rep.RootCause.Statement}})
	}
	for _, lane := range rep.Coverage {
		if lane.Availability == "no_data" || lane.Coverage == "partial" {
			add(fmt.Sprintf("Close the %s coverage gap observed during this incident (%s)", strings.ToLower(lane.Label), orDefault(lane.MissingInterval, "no data for the lane")),
				"detect", "Platform operations",
				[]rcaActionLink{{Kind: "detection_gap", Ref: lane.Label}})
		}
		if len(out) >= 4 {
			break
		}
	}
	if rep.States.Recovery == "component_only" || rep.States.Recovery == "failed_validation" {
		add("Define and validate an end-to-end service recovery check — component recovery did not prove service recovery in this incident",
			"resilience", rep.Ownership.TriageOwner,
			[]rcaActionLink{{Kind: "recovery_gap", Ref: rep.States.RecoveryBasis}})
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// ---- HTTP ---------------------------------------------------------------------

// handleRcaActionItems serves /api/correlations/{id}/actions[/{actionID}|/suggest]:
//
//	GET    …/actions             — list (read)
//	POST   …/actions             — create a human item (write, audited)
//	POST   …/actions/suggest     — derive machine suggestions (write, audited)
//	PUT    …/actions/{actionID}  — update / status transition (write, audited)
//	DELETE …/actions/{actionID}  — remove (write, audited)
//
// The object is resolved under the caller's ClickHouse tenant scope FIRST — a
// cross-tenant correlation id answers 404 before any store access (§3a).
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
		items := s.rcaActionItems.list(objTenant, id)
		for i := range items {
			stampActionDerived(&items[i], now)
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
		if err := validateActionItemFields(&it); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.rcaActionItems.put(objTenant, id, it); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_create", id, map[string]any{"action_id": it.ID, "category": it.Category})
		stampActionDerived(&it, now)
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
		for _, it := range s.rcaActionItems.list(objTenant, id) {
			existing[it.Action] = true
		}
		created := []rcaActionItem{}
		for _, it := range suggestRcaActionItems(rep, owners) {
			if existing[it.Action] {
				continue
			}
			it.ID = randID()
			it.CorrelationID = id
			it.CreatedAt, it.CreatedBy = rca.FmtUTC(now), "correlix (machine-suggested)"
			if err := validateActionItemFields(&it); err != nil {
				continue // a malformed suggestion is dropped, never half-written
			}
			if err := s.rcaActionItems.put(objTenant, id, it); err != nil {
				break // register full — stop suggesting, report what was created
			}
			created = append(created, it)
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_suggest", id, map[string]any{"created": len(created)})
		writeJSON(w, http.StatusOK, map[string]any{"created": created, "note": "machine-suggested items carry a suggested owner only; human acceptance (status → accepted) names the one accountable owner"})

	case r.Method == http.MethodPut && rest != "":
		cur, has := s.rcaActionItems.get(objTenant, id, rest)
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
		if err := validateActionItemFields(&next); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if body.Status != "" {
			if err := applyActionStatusChange(&next, body.Status, claims.Sub, rca.FmtUTC(now)); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		next.UpdatedAt, next.UpdatedBy = rca.FmtUTC(now), claims.Sub
		if err := s.rcaActionItems.put(objTenant, id, next); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		s.auditManualEdit(r, claims, objTenant, "rca_action_update", id, map[string]any{"action_id": next.ID, "status": next.Status})
		stampActionDerived(&next, now)
		writeJSON(w, http.StatusOK, next)

	case r.Method == http.MethodDelete && rest != "":
		removed, err := s.rcaActionItems.remove(objTenant, id, rest)
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
