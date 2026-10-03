// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_decision_ledger.go — the Iris AI decision ledger (tracker 337 N-A6,
// internal/aidecision, migration 0055).
//
// Every accepted POST /api/ai/ask is one DECISION: a Recorder rides the
// request context, and each seam the decision passes through adds its steps —
//
//	QUESTION_RECEIVED       the handler (SHA-256 of the question, the incident
//	                        id the UI named)
//	INVESTIGATION_STARTED   the first troubleshooting method of a chain
//	PLAN_CREATED            a next method chosen (rule / model), or a typed
//	                        query compiled by the data arm (result = its hash)
//	TOOL_SELECTED           a tool the plan named that is not wired here
//	POLICY_EVALUATED        every Policy Engine verdict on a tool (allow / deny)
//	TOOL_EXECUTED           every tool run, with SHA-256 of its arguments and
//	                        of its result
//	EVIDENCE_ADDED          the citations the answer rests on (hash of the ids)
//	RECOMMENDATION_CREATED  the next actions it recommends (hash)
//	ANSWER_RETURNED         the answer: mode, intent, the model that answered
//	                        (provider, model name, tier), hash of the answer,
//	                        the persisted answer id / query-log id
//
// — and the handler appends them in ONE transaction at the end. Hashes only:
// no question text, no tool values, no results, no prose (§8, §15 LLM06).
//
// A ledger write is best-effort for the operator — a failed append never
// costs them the answer — but never silent: it is counted
// (netops_ai_decision_ledger_decisions_total{result="failed"}), logged, and the
// answer then carries NO decision_id, so the UI never points at a record that
// does not exist.
//
// The ask also enters the platform AUDIT TRAIL with its decision id (aiAskAudit),
// beside the request envelope withAudit already writes: the trail says who asked
// and how it ended; the ledger says how the answer was reached.
//
// GET /api/ai/decisions[?decision_id=][&before=RFC3339][&limit=N] — workspace
// admins read their own tenant's ledger; the platform owner reads every
// tenant's. Tenant and scope come from the token only (§3a).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/nlquery/modelc"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/platformdb"
)

// newAIDecisionStore picks the ledger store: Postgres (append-only, RLS) when
// the platform database is active, otherwise the bounded in-memory store.
func newAIDecisionStore() aidecision.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return aidecision.NewPGStore(ps.DB())
	}
	return aidecision.NewMemStore()
}

// aiDecisionAppendTimeout bounds the one ledger write per decision.
const aiDecisionAppendTimeout = 3 * time.Second

// aiToolVersion is the version of every compiled-in tool: the build itself.
// "unknown" stays visible (build_provenance.go: never invent a revision).
func aiToolVersion() string {
	sha := buildSHA
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return aidecision.Token(version + "+" + sha)
}

// aiDecisionStart opens the ledger record for one accepted question and
// returns the request carrying it. Without a ledger store it returns r
// unchanged and a nil Recorder (every Recorder method is nil-safe).
func (s *server) aiDecisionStart(r *http.Request, claims jwtClaims, req aiAskRequest) (*http.Request, *aidecision.Recorder) {
	if s.aiDecisions == nil {
		return r, nil
	}
	rec, err := aidecision.NewRecorder(claims.Sub, aidecision.SurfaceAsk)
	if err != nil {
		logError("ai.ledger", "decision id unavailable — this ask is not ledgered", errf(err))
		s.aiDecisionMetrics.Failed()
		return r, nil
	}
	incident := req.Context["correlation_id"]
	if incident == "" {
		incident = req.Context["problem_id"]
	}
	rec.Add(aidecision.Entry{
		EventType:   aidecision.QuestionReceived,
		IncidentRef: incident,
		ArgsSHA256:  aidecision.SHA256Hex([]byte(req.Question)),
	})
	return r.WithContext(aidecision.WithRecorder(r.Context(), rec)), rec
}

// aiLedgerToolEntry turns one audited tool step into ledger entries. The
// orchestrator's ToolAudit hook calls it; rec is the request's Recorder.
func aiLedgerToolEntry(rec *aidecision.Recorder, e ai.ToolAuditEntry) {
	if rec == nil {
		return
	}
	if e.Skill != "" {
		rec.StartInvestigation(e.Skill, e.Selected)
	}
	switch {
	case e.Tool == "next_skill":
		// A SELECTION, not a tool run: the investigation plan moved on (or a
		// model's choice was refused — Reason says which).
		rec.Add(aidecision.Entry{EventType: aidecision.PlanCreated, Skill: e.Skill, Outcome: e.Reason})
		return
	case e.Reason == "not_registered":
		rec.Add(aidecision.Entry{EventType: aidecision.ToolSelected, Skill: e.Skill, Tool: e.Tool,
			ToolVersion: aiToolVersion(), ArgsSHA256: e.ArgsSHA256, Outcome: "not_registered"})
		return
	case e.Reason == "policy_denied":
		rec.Add(aidecision.Entry{EventType: aidecision.PolicyEvaluated, Skill: e.Skill, Tool: e.Tool,
			ToolVersion: aiToolVersion(), ArgsSHA256: e.ArgsSHA256, Outcome: "deny"})
		return
	}
	rec.Add(aidecision.Entry{EventType: aidecision.PolicyEvaluated, Skill: e.Skill, Tool: e.Tool,
		ToolVersion: aiToolVersion(), ArgsSHA256: e.ArgsSHA256, Outcome: "allow"})
	rec.Add(aidecision.Entry{EventType: aidecision.ToolExecuted, Skill: e.Skill, Tool: e.Tool,
		ToolVersion: aiToolVersion(), ArgsSHA256: e.ArgsSHA256, ResultSHA256: e.ResultSHA256,
		ItemCount: e.Items, Outcome: e.Reason})
}

// nlqLedgerTool names the data arm's query execution in the ledger.
const nlqLedgerTool = "nl_query"

// nlqPlanEntry is the data arm's PLAN_CREATED: the question (hashed) became a
// typed query (its hash is the result) — or did not (the outcome says why).
// When the model fallback wrote the query, the model that did is named.
func nlqPlanEntry(ledger *aidecision.Recorder, question string, c nlqCompiled, rec irisquerylog.Record) aidecision.Entry {
	e := aidecision.Entry{EventType: aidecision.PlanCreated, Intent: c.res.Intent, Tool: nlqLedgerTool,
		ArgsSHA256: aidecision.SHA256Hex([]byte(question)), Outcome: rec.Outcome}
	if rec.ASTHash != "" && aidecision.ValidSHA256(rec.ASTHash) {
		e.ResultSHA256 = rec.ASTHash
	}
	if rec.CatalogVersion != "" {
		e.ToolVersion = "catalog:" + rec.CatalogVersion
	}
	if c.source == modelc.SourceModel {
		m, _ := ledger.Model()
		e.ModelProvider, e.ModelName, e.ModelTier = m.Provider, m.Name, m.Tier
	}
	return e
}

// nlqLedgerRun is the data arm's TOOL_EXECUTED: the validated query (its hash
// is the arguments) ran, and this is the hash of the result set it returned.
func nlqLedgerRun(ledger *aidecision.Recorder, c nlqCompiled, rs *plan.ResultSet, runErr error) {
	if ledger == nil || c.checked == nil {
		return
	}
	e := aidecision.Entry{EventType: aidecision.ToolExecuted, Intent: c.res.Intent, Tool: nlqLedgerTool,
		ArgsSHA256: c.checked.Hash(), Outcome: "ok"}
	if !aidecision.ValidSHA256(e.ArgsSHA256) {
		e.ArgsSHA256 = ""
	}
	switch {
	case errors.Is(runErr, plan.ErrNotFound):
		e.Outcome = "not_found"
	case runErr != nil:
		e.Outcome = "tool_error"
	case rs != nil:
		e.ItemCount = len(rs.Rows) + len(rs.Series)
		if rs.CatalogVersion != "" {
			e.ToolVersion = "catalog:" + rs.CatalogVersion
		}
		if b, err := json.Marshal(rs); err == nil {
			e.ResultSHA256 = aidecision.SHA256Hex(b)
		}
	}
	ledger.Add(e)
}

// aiDecisionFinish closes the decision: the evidence, recommendation and
// answer entries, then ONE append; on success the answer is stamped with its
// decision id. ans is nil when the orchestrator failed (askErr). It also
// writes the ask into the platform audit trail. Returns the stored decision id
// ("" when nothing was stored).
func (s *server) aiDecisionFinish(r *http.Request, claims jwtClaims, rec *aidecision.Recorder, ans *ai.Answer, askErr error) string {
	stored := ""
	if rec != nil {
		model, _ := rec.Model()
		final := aidecision.Entry{EventType: aidecision.AnswerReturned,
			ModelProvider: model.Provider, ModelName: model.Name, ModelTier: model.Tier}
		if ans != nil {
			aiLedgerAnswerEntries(rec, ans)
			final.Intent, final.Mode = ans.Intent, string(ans.Mode)
			if final.ModelTier == "" {
				// No provider answered: the tier the router chose for this mode
				// (a deterministic mode says so).
				final.ModelTier = string(ai.RouteFor(ans.Mode).Tier)
			}
			if final.ModelProvider == "" {
				final.ModelProvider = ans.Provider
			}
			if ans.Skill != nil {
				final.Skill = ans.Skill.Name
			}
			final.ItemCount = len(ans.Citations)
			final.AnswerID = ans.AnswerID
			final.QueryLogID = answerQueryLogID(ans.Data)
			final.Outcome = "answered"
			if ans.Mode == ai.ModeUnavailable {
				final.Outcome = "unavailable"
			}
			// The hash is of the answer as returned, before the decision id is
			// stamped on it (the id names the record; it cannot be inside it).
			body, err := json.Marshal(ans)
			if err != nil {
				logError("ai.ledger", "answer not hashable", errf(err))
			} else {
				final.ResultSHA256 = aidecision.SHA256Hex(body)
			}
		} else {
			final.Outcome = "error"
		}
		rec.Add(final)
		if s.aiDecisionAppend(r, claims, rec) {
			stored = rec.DecisionID()
			if ans != nil {
				ans.DecisionID = stored
			}
		}
	}
	s.aiAskAudit(r, claims, stored, ans, askErr)
	return stored
}

// aiLedgerAnswerEntries records what the answer rests on and recommends.
func aiLedgerAnswerEntries(rec *aidecision.Recorder, ans *ai.Answer) {
	if ans.Skill != nil {
		// No-op when a gather step already opened the investigation.
		rec.StartInvestigation(ans.Skill.Name, "entry")
	}
	if len(ans.Citations) > 0 {
		ids := make([]string, 0, len(ans.Citations))
		for _, c := range ans.Citations {
			ids = append(ids, c.ID)
		}
		sort.Strings(ids)
		rec.Add(aidecision.Entry{EventType: aidecision.EvidenceAdded,
			ResultSHA256: aidecision.SHA256Hex([]byte(strings.Join(ids, "\n"))), ItemCount: len(ids)})
	}
	if len(ans.NextActions) > 0 {
		if b, err := json.Marshal(ans.NextActions); err == nil {
			rec.Add(aidecision.Entry{EventType: aidecision.RecommendationCreated,
				ResultSHA256: aidecision.SHA256Hex(b), ItemCount: len(ans.NextActions)})
		}
	}
}

// answerQueryLogID is the query-log record id a data answer carries (N-C8).
func answerQueryLogID(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var obj struct {
		ID string `json:"query_log_id"`
	}
	if json.Unmarshal(data, &obj) != nil {
		return ""
	}
	return aidecision.Token(obj.ID)
}

// aiDecisionAppend stores the decision. Detached from the request's
// cancellation (an operator who closes the drawer still leaves the record) and
// bounded by aiDecisionAppendTimeout. Reports whether it was stored.
func (s *server) aiDecisionAppend(r *http.Request, claims jwtClaims, rec *aidecision.Recorder) bool {
	tenant, _ := principalTenant(claims)
	s.aiDecisionMetrics.Dropped(rec.Dropped())
	entries := rec.Entries()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), aiDecisionAppendTimeout)
	defer cancel()
	if err := s.aiDecisions.Append(ctx, tenant, entries); err != nil {
		s.aiDecisionMetrics.Failed()
		logError("ai.ledger", "decision append failed", map[string]any{"tenant": tenant, "entries": len(entries), "error": err.Error()})
		return false
	}
	s.aiDecisionMetrics.Appended(len(entries))
	return true
}

// aiAskAudit enters one /api/ai/ask into the platform audit trail: who asked,
// the decision id, how it ended (intent, mode, provider, tier) — never the
// question or any retrieved data.
func (s *server) aiAskAudit(r *http.Request, claims jwtClaims, decisionID string, ans *ai.Answer, askErr error) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	detail := map[string]any{"action": "ai.ask", "decision_id": decisionID}
	status, decision := http.StatusOK, "allow"
	if askErr != nil || ans == nil {
		status, decision = http.StatusBadGateway, "error"
	} else {
		detail["intent"] = aidecision.Token(ans.Intent)
		detail["mode"] = string(ans.Mode)
		detail["provider"] = aidecision.Token(ans.Provider)
		detail["tier"] = string(ai.RouteFor(ans.Mode).Tier)
		if ans.AnswerID != "" {
			detail["answer_id"] = aidecision.Token(ans.AnswerID)
		}
	}
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross, SessionID: claims.Sid,
		Method: r.Method, Path: r.URL.Path, Status: status, Decision: decision,
		Remote: auditClientIP(r), Detail: detail,
	})
}

// handleAIDecisions serves GET /api/ai/decisions.
func (s *server) handleAIDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	// A workspace admin (own tenant) or the platform owner (every tenant). The
	// ledger is an audit record: it is readable whether or not Iris is on now.
	claims, ok := s.requirePerm(w, r, "administration", LevelAdmin)
	if !ok {
		return
	}
	if s.aiDecisions == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("the AI decision ledger is not available on this deployment"))
		return
	}
	q := r.URL.Query()
	var f aidecision.ListFilter
	if v := strings.TrimSpace(q.Get("decision_id")); v != "" {
		if !aidecision.ValidID(v) {
			writeError(w, http.StatusBadRequest, errors.New("decision_id is a decision id"))
			return
		}
		f.DecisionID = v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > aidecision.MaxListLimit {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit is 1 to %d", aidecision.MaxListLimit))
			return
		}
		f.Limit = n
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("before is an RFC 3339 time"))
			return
		}
		f.Before = t
	}
	tenant, cross := principalTenant(claims)
	entries, err := s.aiDecisions.List(r.Context(), tenant, cross, f)
	if err != nil {
		logError("ai.ledger", "list failed", errf(err))
		writeError(w, http.StatusInternalServerError, errors.New("the AI decision ledger could not be read"))
		return
	}
	scope := "platform"
	if !cross {
		scope = "tenant"
		for i := range entries {
			entries[i].TenantID = "" // the caller's own tenant; never echoed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": entries, "scope": scope,
		"event_types": aidecision.EventTypes})
}
