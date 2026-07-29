package main

// rca_action_items_test.go — postmortem Phase 1 action items (spec §3/§7):
// schema validation, the remediation-state machine, suggested-vs-committed
// with human acceptance, derived overdue, machine suggestions from seam
// ownership, and the §3a tenant-isolation contract of the subresource.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/rca"
	"strings"
	"testing"
	"time"
)

// ---- schema / state machine ---------------------------------------------------

func validItem() rcaActionItem {
	return rcaActionItem{
		Action:   "Add an independent second vantage for the affected service checks",
		Category: "detect", Source: "human_created", Status: "proposed",
	}
}

func TestActionItemValidation(t *testing.T) {
	it := validItem()
	if err := rca.ValidateActionItemFields(&it); err != nil {
		t.Fatalf("valid item rejected: %v", err)
	}
	bad := []func(*rcaActionItem){
		func(i *rcaActionItem) { i.Action = "" },
		func(i *rcaActionItem) { i.Action = strings.Repeat("x", 501) },
		func(i *rcaActionItem) { i.Category = "improve" },
		func(i *rcaActionItem) { i.AccountableOwner = "alice, bob" }, // ONE owner
		func(i *rcaActionItem) { i.Priority = "urgent" },
		func(i *rcaActionItem) { i.DueDate = "next week" },
		func(i *rcaActionItem) { i.Related = []rcaActionLink{{Kind: "vibes", Ref: "x"}} },
		func(i *rcaActionItem) { i.Related = []rcaActionLink{{Kind: "root_cause", Ref: ""}} },
	}
	for n, mutate := range bad {
		i := validItem()
		mutate(&i)
		if err := rca.ValidateActionItemFields(&i); err == nil {
			t.Fatalf("bad item %d accepted: %+v", n, i)
		}
	}
}

func TestActionStatusMachine(t *testing.T) {
	now := "2026-07-19 12:00:00 UTC"
	it := validItem()

	// A suggestion cannot be accepted without the ONE accountable owner.
	if err := rca.ApplyActionStatusChange(&it, "accepted", "ops@acme", now); err == nil {
		t.Fatal("acceptance without accountable owner must be refused")
	}
	it.AccountableOwner = "NetOps on-call"
	if err := rca.ApplyActionStatusChange(&it, "accepted", "ops@acme", now); err != nil {
		t.Fatalf("acceptance refused: %v", err)
	}
	if it.AcceptedAt != now || it.AcceptedBy != "ops@acme" {
		t.Fatalf("acceptance stamps missing: %+v", it)
	}

	// No free-form jumps: accepted → verified is not a legal transition.
	if err := rca.ApplyActionStatusChange(&it, "verified", "ops@acme", now); err == nil {
		t.Fatal("accepted → verified must be refused")
	}
	if err := rca.ApplyActionStatusChange(&it, "in_progress", "ops@acme", now); err != nil {
		t.Fatalf("in_progress: %v", err)
	}
	if err := rca.ApplyActionStatusChange(&it, "completed", "ops@acme", now); err != nil {
		t.Fatalf("completed: %v", err)
	}
	if it.CompletedAt != now {
		t.Fatalf("completion timestamp missing: %+v", it)
	}
	// Verification requires evidence.
	if err := rca.ApplyActionStatusChange(&it, "verified", "ops@acme", now); err == nil {
		t.Fatal("verification without evidence must be refused")
	}
	it.VerificationEvidence = "second vantage live; alert fired in the drill"
	if err := rca.ApplyActionStatusChange(&it, "verified", "ops@acme", now); err != nil {
		t.Fatalf("verified: %v", err)
	}
	if it.VerifiedAt != now {
		t.Fatalf("verification timestamp missing: %+v", it)
	}
	// Terminal.
	if err := rca.ApplyActionStatusChange(&it, "in_progress", "ops@acme", now); err == nil {
		t.Fatal("verified is terminal")
	}
	// "overdue" is derived, never a settable state.
	fresh := validItem()
	if err := rca.ApplyActionStatusChange(&fresh, "overdue", "ops@acme", now); err == nil {
		t.Fatal("overdue must be refused as a stored state")
	}
}

func TestActionOverdueIsDerived(t *testing.T) {
	it := validItem()
	it.AccountableOwner = "NetOps"
	it.Status, it.DueDate = "in_progress", "2026-07-01"
	rca.StampActionDerived(&it, time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC))
	if !it.Overdue {
		t.Fatal("past-due in-progress item must derive overdue")
	}
	it.Status = "completed"
	rca.StampActionDerived(&it, time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC))
	if it.Overdue {
		t.Fatal("a completed item is never overdue")
	}
}

// ---- machine suggestions ------------------------------------------------------

func TestSuggestionsCarrySuggestedOwnerNeverAssign(t *testing.T) {
	rep := rca.Report{
		FaultLocalization: rca.FaultLocalization{Localized: true, Object: "sm-ipsec-1"},
		RootCause:         rca.RootCause{Identified: false, Statement: "Root cause has not been identified."},
		Ownership:         rca.Ownership{TriageOwner: "NOC", TechnicalOwner: "ISP / carrier"},
		States:            rca.ReportStates{Recovery: "component_only", RecoveryBasis: "component up; service checks still failing"},
	}
	items := rca.SuggestActionItems(rep, map[string]seamOwnerEntry{
		"isp": {Name: "Lumen (DIA circuit #12345)"},
	})
	if len(items) == 0 {
		t.Fatal("no suggestions derived")
	}
	foundSeamOwner := false
	for _, it := range items {
		if it.Source != "machine_suggested" || it.Status != "proposed" {
			t.Fatalf("suggestion must be machine_suggested/proposed: %+v", it)
		}
		if it.AccountableOwner != "" {
			t.Fatalf("AUTO-ASSIGNMENT: suggestion carries an accountable owner: %+v", it)
		}
		if it.SuggestedOwner == "Lumen (DIA circuit #12345)" {
			foundSeamOwner = true
		}
		if !rca.ActionCategories[it.Category] {
			t.Fatalf("suggestion outside the category enum: %+v", it)
		}
	}
	if !foundSeamOwner {
		t.Fatalf("seam-ownership registry name must flow into the SUGGESTED owner: %+v", items)
	}
	// Recovery gap must be linked.
	linked := false
	for _, it := range items {
		for _, l := range it.Related {
			if l.Kind == "recovery_gap" {
				linked = true
			}
		}
	}
	if !linked {
		t.Fatal("component-only recovery must yield a recovery_gap-linked suggestion")
	}
}

// ---- store isolation (§3a rule 4) ---------------------------------------------

func TestActionStoreIsTenantKeyed(t *testing.T) {
	st := newRcaActionItemStore("") // in-memory
	it := validItem()
	it.ID, it.CorrelationID = "a-1", "c-1"
	if err := st.Put("acme", "c-1", it); err != nil {
		t.Fatalf("put: %v", err)
	}
	if got := st.List("globex", "c-1"); len(got) != 0 {
		t.Fatalf("TENANT LEAK: globex read acme's action items: %+v", got)
	}
	if got := st.List("acme", "c-1"); len(got) != 1 {
		t.Fatalf("own items lost: %+v", got)
	}
	if _, ok := st.Get("globex", "c-1", "a-1"); ok {
		t.Fatal("TENANT LEAK: cross-tenant get")
	}
	if removed, _ := st.Remove("globex", "c-1", "a-1"); removed {
		t.Fatal("TENANT LEAK: cross-tenant remove")
	}
	if removed, err := st.Remove("acme", "c-1", "a-1"); err != nil || !removed {
		t.Fatal("own remove failed")
	}
}

// ---- HTTP isolation (§3a rule 5 — the required cross-org test) ----------------

func actionServer(t *testing.T) *server {
	t.Helper()
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaActionItems = newRcaActionItemStore("")
	return s
}

func TestActionItemsCRUDOwnTenant(t *testing.T) {
	promoFakeCH(t, "acme")
	s := actionServer(t)

	body, _ := json.Marshal(map[string]any{
		"action": "Add an independent second vantage", "category": "detect",
		"related": []map[string]string{{"kind": "detection_gap", "ref": "Active checks"}},
	})
	w := httptest.NewRecorder()
	s.handleRcaActionItems(w, req(http.MethodPost, "/api/correlations/"+promoCorrID+"/actions", string(body), acme()), promoCorrID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d (%s)", w.Code, w.Body.String())
	}
	var created rcaActionItem
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Source != "human_created" || created.Status != "proposed" || created.CreatedBy != "a@acme" {
		t.Fatalf("server-owned fields wrong: %+v", created)
	}

	// The record is keyed by the OBJECT's owning tenant.
	if got := s.rcaActionItems.List("acme", promoCorrID); len(got) != 1 {
		t.Fatalf("not stored under owner tenant: %+v", got)
	}

	// List returns it.
	w = httptest.NewRecorder()
	s.handleRcaActionItems(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/actions", "", acme()), promoCorrID, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), created.ID) {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}

	// Update: accept with ONE accountable owner.
	upd, _ := json.Marshal(map[string]any{
		"action": created.Action, "category": created.Category,
		"accountable_owner": "NetOps on-call", "status": "accepted",
	})
	w = httptest.NewRecorder()
	s.handleRcaActionItems(w, req(http.MethodPut, "/api/correlations/"+promoCorrID+"/actions/"+created.ID, string(upd), acme()), promoCorrID, created.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("update = %d (%s)", w.Code, w.Body.String())
	}
	var accepted rcaActionItem
	_ = json.NewDecoder(w.Body).Decode(&accepted)
	if accepted.Status != "accepted" || accepted.AcceptedBy != "a@acme" || accepted.AccountableOwner != "NetOps on-call" {
		t.Fatalf("acceptance not recorded: %+v", accepted)
	}

	// Delete.
	w = httptest.NewRecorder()
	s.handleRcaActionItems(w, req(http.MethodDelete, "/api/correlations/"+promoCorrID+"/actions/"+created.ID, "", acme()), promoCorrID, created.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d (%s)", w.Code, w.Body.String())
	}
}

func TestActionItemsCrossTenantIs404(t *testing.T) {
	promoFakeCH(t, "acme")
	s := actionServer(t)
	seed := validItem()
	seed.ID = "a-1"
	if err := s.rcaActionItems.Put("acme", promoCorrID, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Every method from a foreign tenant answers 404 — the id's existence is
	// never revealed, nothing is written or deleted.
	for _, c := range []struct{ method, rest, body string }{
		{http.MethodGet, "", ""},
		{http.MethodPost, "", `{"action":"x","category":"detect"}`},
		{http.MethodPut, "a-1", `{"action":"x","category":"detect"}`},
		{http.MethodDelete, "a-1", ""},
	} {
		w := httptest.NewRecorder()
		s.handleRcaActionItems(w, req(c.method, "/api/correlations/"+promoCorrID+"/actions/"+c.rest, c.body, globex()), promoCorrID, c.rest)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s %q = %d, want 404", c.method, c.rest, w.Code)
		}
	}
	if got := s.rcaActionItems.List("acme", promoCorrID); len(got) != 1 {
		t.Fatalf("cross-tenant call mutated the owner's register: %+v", got)
	}
	if got := s.rcaActionItems.List("globex", promoCorrID); len(got) != 0 {
		t.Fatalf("cross-tenant call created foreign records: %+v", got)
	}
}

func TestActionItemsCrossScopeAdminKeysByObjectTenant(t *testing.T) {
	promoFakeCH(t, "acme")
	s := actionServer(t)
	body, _ := json.Marshal(map[string]any{"action": "Review demarcation evidence", "category": "diagnose"})
	w := httptest.NewRecorder()
	s.handleRcaActionItems(w, req(http.MethodPost, "/api/correlations/"+promoCorrID+"/actions", string(body), superA()), promoCorrID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("platform-admin create = %d (%s)", w.Code, w.Body.String())
	}
	if got := s.rcaActionItems.List("acme", promoCorrID); len(got) != 1 {
		t.Fatal("item must key by the OBJECT's owning tenant, never the admin's")
	}
}
