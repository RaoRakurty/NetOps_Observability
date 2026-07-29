package rca

// action_items.go — the persisted RCA action-item register (Phase-2 W3.3,
// extracted from package main): the closed vocabularies, the remediation
// state machine with validated transitions, the tenant-keyed JSON store with
// rollback-on-persist-failure, field validation, overdue derivation, and the
// machine-suggestion synthesis over a Report + the tenant seam-owner registry.
// The multiplexed handler (RBAC, CH tenant resolve, audit) and the env path
// stay in main.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/tenant"
)

var ActionCategories = map[string]bool{
	"prevent": true, "mitigate": true, "detect": true,
	"diagnose": true, "respond": true, "resilience": true,
}

// Remediation states (spec §7). "overdue" is intentionally NOT here: it is a
// derived read-time flag, never a stored state.
var RemediationStates = map[string]bool{
	"proposed": true, "accepted": true, "in_progress": true, "blocked": true,
	"completed": true, "verified": true, "rejected": true, "superseded": true,
}

// ActionTransitions is the explicit lifecycle: from → allowed targets.
var ActionTransitions = map[string][]string{
	"proposed":    {"accepted", "rejected", "superseded"},
	"accepted":    {"in_progress", "blocked", "rejected", "superseded"},
	"in_progress": {"blocked", "completed", "superseded"},
	"blocked":     {"in_progress", "superseded"},
	"completed":   {"verified", "in_progress"}, // reopen when verification fails
	"verified":    {},
	"rejected":    {},
	"superseded":  {},
}

var ActionLinkKinds = map[string]bool{
	"root_cause": true, "contributing_factor": true, "detection_gap": true, "recovery_gap": true,
}

var ActionPriorities = map[string]bool{"P1": true, "P2": true, "P3": true}

// actionItemsMaxPerCase bounds the register (§9 bounded everything).
const actionItemsMaxPerCase = 200

// ---- model --------------------------------------------------------------------

// ActionLink relates an action item to the cause/gap it addresses.
type ActionLink struct {
	Kind string `json:"kind"` // root_cause | contributing_factor | detection_gap | recovery_gap
	Ref  string `json:"ref"`  // free-text reference (statement / lane / milestone key), bounded
}

// ActionItem is one persisted action-register row.
type ActionItem struct {
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
	Source  string       `json:"source"`
	Related []ActionLink `json:"related,omitempty"`

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

type ActionItemStore struct {
	mu   sync.RWMutex
	m    map[string]map[string]map[string]ActionItem // tenant → correlation → id → item
	path string
}

func NewActionItemStore(path string) *ActionItemStore {
	s := &ActionItemStore{m: map[string]map[string]map[string]ActionItem{}, path: path}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var m map[string]map[string]map[string]ActionItem
		if json.Unmarshal(b, &m) == nil {
			s.m = m
		}
	}
	return s
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *ActionItemStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rca action items: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("rca", "persist rca action items failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist rca action items: %w", err)
	}
	return nil
}

// list returns ONE tenant's items for one correlation, oldest first. No
// cross-tenant or unscoped enumeration exists on this store. Nil-safe.
func (s *ActionItemStore) List(tenant, corrID string) []ActionItem {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]ActionItem, 0, len(s.m[tenant][corrID]))
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

func (s *ActionItemStore) Get(tenant, corrID, id string) (ActionItem, bool) {
	if s == nil {
		return ActionItem{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.m[tenant][corrID][id]
	return it, ok
}

func (s *ActionItemStore) Put(tenant, corrID string, it ActionItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[tenant] == nil {
		s.m[tenant] = map[string]map[string]ActionItem{}
	}
	if s.m[tenant][corrID] == nil {
		s.m[tenant][corrID] = map[string]ActionItem{}
	}
	if _, exists := s.m[tenant][corrID][it.ID]; !exists && len(s.m[tenant][corrID]) >= actionItemsMaxPerCase {
		return fmt.Errorf("action register full for this case (max %d items)", actionItemsMaxPerCase)
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

func (s *ActionItemStore) Remove(tenant, corrID, id string) (bool, error) {
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
			byCorr = map[string]map[string]ActionItem{}
		}
		s.m[tenant] = byCorr
		if items == nil {
			items = map[string]ActionItem{}
		}
		items[id] = prev
		s.m[tenant][corrID] = items
		return false, err
	}
	return true, nil
}

// ---- validation ---------------------------------------------------------------

func ValidateActionItemFields(it *ActionItem) error {
	it.Action = strings.TrimSpace(it.Action)
	if it.Action == "" || len(it.Action) > 500 {
		return errors.New("action is required (at most 500 characters)")
	}
	if !ActionCategories[it.Category] {
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
	if it.Priority != "" && !ActionPriorities[it.Priority] {
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
		if !ActionLinkKinds[l.Kind] {
			return errors.New("related.kind must be root_cause, contributing_factor, detection_gap or recovery_gap")
		}
		it.Related[i].Ref = strings.TrimSpace(l.Ref)
		if it.Related[i].Ref == "" || len(it.Related[i].Ref) > 300 {
			return errors.New("related.ref is required (at most 300 characters)")
		}
	}
	return nil
}

// ApplyActionStatusChange enforces the transition table and the acceptance /
// verification rules, stamping timestamps server-side.
func ApplyActionStatusChange(it *ActionItem, newStatus, actor, nowUTC string) error {
	if newStatus == it.Status {
		return nil
	}
	if !RemediationStates[newStatus] {
		return errors.New("status must be one of proposed, accepted, in_progress, blocked, completed, verified, rejected, superseded (overdue is derived, never set)")
	}
	allowed := false
	for _, to := range ActionTransitions[it.Status] {
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

// StampActionDerived computes the read-time derived flags (overdue).
func StampActionDerived(it *ActionItem, now time.Time) {
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

// OwnerClassForLabel reverse-maps a rendered owner-team label to its catalog
// owner class (first match in the closed vocabulary), "" when unknown.
func OwnerClassForLabel(label string) string {
	for _, class := range tenant.SeamOwnerClasses {
		if OwnerTeam[class] == label {
			return class
		}
	}
	return ""
}

// SuggestActionItems derives machine-SUGGESTED items from the built report:
// seam ownership names the suggested owner; the accountable owner stays empty
// until a human accepts. Suggestions only state what the report already
// establishes (localization, coverage gaps, recovery gaps) — never new claims.
func SuggestActionItems(rep Report, seamOwners map[string]tenant.SeamOwnerEntry) []ActionItem {
	suggestOwner := func(teamLabel string) string {
		if teamLabel == "" {
			return ""
		}
		if class := OwnerClassForLabel(teamLabel); class != "" {
			if e, ok := seamOwners[class]; ok && strings.TrimSpace(e.Name) != "" {
				return e.Name
			}
		}
		return teamLabel
	}
	var out []ActionItem
	add := func(action, category, owner string, related []ActionLink) {
		out = append(out, ActionItem{
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
			[]ActionLink{{Kind: "root_cause", Ref: rep.RootCause.Statement}})
	}
	for _, lane := range rep.Coverage {
		if lane.Availability == "no_data" || lane.Coverage == "partial" {
			add(fmt.Sprintf("Close the %s coverage gap observed during this incident (%s)", strings.ToLower(lane.Label), orDefault(lane.MissingInterval, "no data for the lane")),
				"detect", "Platform operations",
				[]ActionLink{{Kind: "detection_gap", Ref: lane.Label}})
		}
		if len(out) >= 4 {
			break
		}
	}
	if rep.States.Recovery == "component_only" || rep.States.Recovery == "failed_validation" {
		add("Define and validate an end-to-end service recovery check — component recovery did not prove service recovery in this incident",
			"resilience", rep.Ownership.TriageOwner,
			[]ActionLink{{Kind: "recovery_gap", Ref: rep.States.RecoveryBasis}})
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
