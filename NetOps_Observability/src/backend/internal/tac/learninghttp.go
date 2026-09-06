// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// learninghttp.go — the learning-backlog HTTP surface.
//
//	GET    /api/tac/learning                  — this tenant's backlog + candidates
//	POST   /api/tac/learning/candidates       — write a TAC answer down as a candidate
//	GET    /api/tac/learning/candidates/{id}  — one candidate
//	PUT    /api/tac/learning/candidates/{id}  — revise it
//	DELETE /api/tac/learning/candidates/{id}  — drop it
//	GET    /api/tac/learning/export?dialect=  — the research YAML for a dialect
//
// §3a: every route here is per-tenant DATA. A cross-tenant principal (the
// platform owner in the Global view) must scope into a concrete tenant before
// reading or writing — refused, never a wildcard. Another tenant's candidate id
// returns 404, identical to an id that does not exist, so this subtree is not an
// existence oracle. The tenant is taken from the resolved principal and does not
// exist as a wire field at all.
//
// §3 fail-closed at the boundary: unknown query parameters are refused, every
// body is bounded before it is decoded, unknown fields are rejected.
//
// THE EXPORT IS A FILE, NOT AN INGESTION. It renders text/yaml a human reads,
// reviews and feeds to `scripts/tac-merge-research.py`. Nothing on this surface
// writes the shipped catalogue, and there is deliberately no route that could.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The learning surface reuses TemplateGate rather than declaring a gate of its
// own. The backlog and the command templates are the SAME kind of thing — a
// tenant's own operator data behind read/write on `infrastructure` plus the
// tenant filter — and one enum for one question is what keeps the integrator
// from mapping them onto two different answers.

// LearningAPIDeps are the HTTP layer's injected collaborators. Every one is
// required; the constructor fails closed rather than defaulting a gap.
type LearningAPIDeps struct {
	// Authz authorizes the caller. It has already written the error response
	// when ok is false.
	Authz func(w http.ResponseWriter, r *http.Request, gate TemplateGate) (TemplatePrincipal, bool)
	// Store is the per-tenant learning store.
	Store LearningStore
	// Validator is the command validator — the SAME one the collect path uses.
	Validator *TemplateValidator
	// Catalog supplies the taxonomy and the dialect vocabulary.
	Catalog *Catalog
	// Audit records a write. A candidate is a proposal about what Correlix will
	// one day recognise; who wrote it is not optional (§10).
	Audit func(r *http.Request, p TemplatePrincipal, action string, fields map[string]any)
	// WriteJSON / WriteError are the platform's response writers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock.
	Now func() time.Time
}

func (d LearningAPIDeps) validate() error {
	missing := make([]string, 0, 8)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Store", d.Store != nil)
	check("Validator", d.Validator != nil)
	check("Catalog", d.Catalog != nil)
	check("Audit", d.Audit != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("Now", d.Now != nil)
	if len(missing) > 0 {
		return fmt.Errorf("tac: LearningAPIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// LearningAPI is the module's HTTP surface.
type LearningAPI struct{ deps LearningAPIDeps }

// NewLearningAPI builds the surface, failing CLOSED on incomplete deps.
func NewLearningAPI(d LearningAPIDeps) (*LearningAPI, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &LearningAPI{deps: d}, nil
}

// The registered route strings, exported so the integrator registers exactly
// what this file serves.
const (
	LearningPath           = "/api/tac/learning"
	LearningSubtreePath    = "/api/tac/learning/"
	LearningCandidatesPath = "/api/tac/learning/candidates"
	LearningExportPath     = "/api/tac/learning/export"
)

// learningMaxBody bounds a candidate body before it is decoded (§9). A
// candidate is a page of text, never a capture.
const learningMaxBody = 64 << 10

// learningNote states the standing rule wherever candidates are listed, so the
// boundary is visible in the product and not only in a design doc.
const learningNote = "A candidate is a proposal, not knowledge. Nothing here is matched against anything or " +
	"shown as coverage; the only way one becomes a rule is a reviewed merge of an exported file."

// scoped resolves the caller to ONE concrete tenant, refusing cross-tenant
// access to per-tenant data (§3a). It writes the error response itself.
func (a *LearningAPI) scoped(w http.ResponseWriter, r *http.Request, gate TemplateGate) (string, TemplatePrincipal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return "", TemplatePrincipal{}, false
	}
	t, err := concreteTenantID(p.Tenant)
	if err != nil || p.Cross {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New(
			"select a tenant to review its TAC learning backlog (it is per-tenant data; cross-tenant access is refused)"))
		return "", TemplatePrincipal{}, false
	}
	return t, p, true
}

func (a *LearningAPI) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, learningMaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a typo'd field must fail, not be silently dropped
	if err := dec.Decode(v); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid signature-candidate payload"))
		return false
	}
	return true
}

// candidateWire is the POST/PUT body. There is deliberately NO tenant, id,
// status-of-record, owner or timestamp field: ownership and provenance are
// stamped by the store (§3a rule 2), and `proposed_class` is DERIVED from the
// taxonomy rather than claimed.
type candidateWire struct {
	IssueID       string   `json:"issue_id"`
	Dialect       string   `json:"dialect"`
	ClassID       string   `json:"class_id"`
	Title         string   `json:"title"`
	Symptoms      []string `json:"symptoms"`
	LogSignatures []string `json:"log_signatures"`
	LikelyCauses  []string `json:"likely_causes"`
	Commands      []struct {
		Intent  string `json:"intent"`
		Command string `json:"command"`
	} `json:"commands"`
	TACFirstLook string `json:"tac_first_look"`
	Sources      []struct {
		Title     string `json:"title"`
		URL       string `json:"url"`
		Retrieved string `json:"retrieved"`
	} `json:"sources"`
	Answer       string `json:"answer"`
	FromIncident string `json:"from_incident"`
	FromRecord   string `json:"from_record"`
	Status       string `json:"status"`
}

func (in candidateWire) toCandidate() Candidate {
	cmds := make([]CandidateCommand, 0, len(in.Commands))
	for _, c := range in.Commands {
		cmds = append(cmds, CandidateCommand{Intent: c.Intent, Command: c.Command})
	}
	srcs := make([]CandidateSource, 0, len(in.Sources))
	for _, s := range in.Sources {
		srcs = append(srcs, CandidateSource{Title: s.Title, URL: s.URL, Retrieved: s.Retrieved})
	}
	return Candidate{
		IssueID: in.IssueID, Dialect: in.Dialect, ClassID: in.ClassID, Title: in.Title,
		Symptoms: in.Symptoms, LogSignatures: in.LogSignatures, LikelyCauses: in.LikelyCauses,
		Commands: cmds, TACFirstLook: in.TACFirstLook, Sources: srcs,
		Answer: in.Answer, FromIncident: in.FromIncident, FromRecord: in.FromRecord,
		Status: CandidateStatus(strings.TrimSpace(in.Status)),
	}
}

// ── GET /api/tac/learning ───────────────────────────────────────────────────

// HandleLearning serves the backlog view.
func (a *LearningAPI) HandleLearning(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if err := rejectUnknownTemplateQuery(r, "dialect"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	dialect := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("dialect")))
	records, err := a.deps.Store.Records(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	cands, err := a.deps.Store.Candidates(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if dialect != "" {
		records = filterRecordDialect(records, dialect)
		cands = filterCandidateDialect(cands, dialect)
	}
	gaps := map[GapKind]int{}
	for _, k := range GapKinds() {
		gaps[k] = 0
	}
	total := 0
	for _, rec := range records {
		for _, g := range rec.Gaps {
			gaps[g.Kind]++
			total++
		}
	}
	// The counts are keyed by kind so the UI never has to know the order, and
	// `tracked` is what lets the page stop saying "not yet tracked" — it is the
	// difference between "no gaps" and "nothing has been collected".
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"tracked":     true,
		"records":     records,
		"candidates":  cands,
		"gap_counts":  gapCountsWire(gaps),
		"gap_total":   total,
		"gap_kinds":   GapKinds(),
		"dialects":    a.deps.Catalog.Dialects(),
		"limit":       MaxCandidatesPerTenant,
		"note":        learningNote,
		"engine":      Version,
		"record_cap":  MaxRecordsPerTenant,
		"candidate_n": len(cands),
	})
}

func gapCountsWire(in map[GapKind]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}

func filterRecordDialect(in []LearningRecord, dialect string) []LearningRecord {
	out := make([]LearningRecord, 0, len(in))
	for _, r := range in {
		if r.Dialect == dialect {
			out = append(out, r)
		}
	}
	return out
}

func filterCandidateDialect(in []Candidate, dialect string) []Candidate {
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		if c.Dialect == dialect {
			out = append(out, c)
		}
	}
	return out
}

// ── /api/tac/learning/… ─────────────────────────────────────────────────────

// HandleLearningSubtree routes the candidates collection, one candidate, and
// the export. It is one handler because Go's mux dispatches on a prefix and a
// second registration would not narrow it.
func (a *LearningAPI) HandleLearningSubtree(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, LearningSubtreePath)
	switch {
	case rest == "export":
		a.export(w, r)
	case rest == "candidates":
		a.candidates(w, r)
	case strings.HasPrefix(rest, "candidates/"):
		a.candidateItem(w, r, strings.TrimPrefix(rest, "candidates/"))
	default:
		http.NotFound(w, r)
	}
}

func (a *LearningAPI) candidates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.HandleLearning(w, r) // the same listing; candidates travel with it
	case http.MethodPost:
		a.createCandidate(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (a *LearningAPI) createCandidate(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	var in candidateWire
	if !a.decode(w, r, &in) {
		return
	}
	cand, lines, err := ValidateCandidate(in.toCandidate(), a.deps.Catalog, a.deps.Validator)
	if err != nil {
		a.refuse(w, err, lines)
		return
	}
	cand.TenantID = tenant
	cand.CreatedBy = p.Subject
	saved, err := a.deps.Store.CreateCandidate(r.Context(), cand)
	if err != nil {
		a.storeError(w, err)
		return
	}
	a.deps.Audit(r, p, "tac.learning.candidate.create", map[string]any{
		"candidate_id": saved.ID, "dialect": saved.Dialect, "class_id": saved.ClassID,
		"proposed_class": saved.Proposed, "commands": len(saved.Commands),
	})
	a.deps.WriteJSON(w, http.StatusCreated, map[string]any{"candidate": saved, "lines": lines, "note": learningNote})
}

func (a *LearningAPI) candidateItem(w http.ResponseWriter, r *http.Request, id string) {
	if !candIDRE.MatchString(id) {
		// A malformed id is indistinguishable from an absent one, on purpose.
		a.deps.WriteError(w, http.StatusNotFound, ErrCandidateNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.getCandidate(w, r, id)
	case http.MethodPut:
		a.updateCandidate(w, r, id)
	case http.MethodDelete:
		a.deleteCandidate(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

func (a *LearningAPI) getCandidate(w http.ResponseWriter, r *http.Request, id string) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	c, err := a.deps.Store.Candidate(r.Context(), tenant, id)
	if err != nil {
		a.storeError(w, err)
		return
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"candidate": c, "note": learningNote})
}

func (a *LearningAPI) updateCandidate(w http.ResponseWriter, r *http.Request, id string) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	// Read first, so a foreign id 404s BEFORE the body is validated: a
	// validation message about another tenant's row is an existence oracle.
	if _, err := a.deps.Store.Candidate(r.Context(), tenant, id); err != nil {
		a.storeError(w, err)
		return
	}
	var in candidateWire
	if !a.decode(w, r, &in) {
		return
	}
	cand, lines, err := ValidateCandidate(in.toCandidate(), a.deps.Catalog, a.deps.Validator)
	if err != nil {
		a.refuse(w, err, lines)
		return
	}
	cand.TenantID = tenant
	saved, err := a.deps.Store.UpdateCandidate(r.Context(), tenant, id, cand)
	if err != nil {
		a.storeError(w, err)
		return
	}
	a.deps.Audit(r, p, "tac.learning.candidate.update", map[string]any{
		"candidate_id": saved.ID, "dialect": saved.Dialect, "status": string(saved.Status),
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"candidate": saved, "lines": lines, "note": learningNote})
}

func (a *LearningAPI) deleteCandidate(w http.ResponseWriter, r *http.Request, id string) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	if err := a.deps.Store.DeleteCandidate(r.Context(), tenant, id); err != nil {
		a.storeError(w, err)
		return
	}
	a.deps.Audit(r, p, "tac.learning.candidate.delete", map[string]any{"candidate_id": id})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ── GET /api/tac/learning/export?dialect= ───────────────────────────────────

func (a *LearningAPI) export(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	if err := rejectUnknownTemplateQuery(r, "dialect"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	dialect := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("dialect")))
	if dialect == "" {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("name the dialect to export (?dialect=)"))
		return
	}
	cands, err := a.deps.Store.Candidates(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	body, err := ExportResearch(dialect, cands, a.deps.Now())
	if err != nil {
		a.deps.WriteError(w, http.StatusNotFound, err)
		return
	}
	a.deps.Audit(r, p, "tac.learning.export", map[string]any{"dialect": dialect, "bytes": len(body)})
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// An attachment, not a rendered page: this file is edited and merged, and a
	// browser rendering it inline invites reading it as a finished artifact.
	// The filename is safe by construction — ExportResearch refused anything but
	// a kebab slug above, so `dialect` holds no quote, path or control byte.
	w.Header().Set("Content-Disposition", `attachment; filename="`+dialect+`-candidates.yaml"`)
	// #nosec G705 -- this response is not a document a browser renders. Its body
	// is the research YAML built by ExportResearch, which quotes EVERY scalar and
	// strips control characters and newlines at validation time; it is served as
	// text/yaml with nosniff (so no content-type guess can turn it into HTML) and
	// as an attachment (so it is saved, never displayed). The taint gosec follows
	// is the operator's own candidate text, which reaches no HTML context here.
	if _, werr := w.Write([]byte(body)); werr != nil {
		// The response is already committed; there is nothing to say to the
		// client, but the failure must not vanish (§10).
		a.deps.Audit(r, p, "tac.learning.export.failed", map[string]any{"dialect": dialect, "error": werr.Error()})
	}
}

// ── shared error shaping ────────────────────────────────────────────────────

// refuse states WHY a candidate was refused, and which line did it. "Invalid"
// teaches an operator nothing; the whole point of validating before storing is
// that they learn what Correlix will not carry.
func (a *LearningAPI) refuse(w http.ResponseWriter, err error, lines []LineVerdict) {
	bad := make([]LineVerdict, 0, len(lines))
	for _, lv := range lines {
		if !lv.OK {
			bad = append(bad, lv)
		}
	}
	if len(bad) == 0 {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.WriteJSON(w, http.StatusBadRequest, map[string]any{
		"error": err.Error(), "lines": bad,
	})
}

func (a *LearningAPI) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrCandidateNotFound):
		a.deps.WriteError(w, http.StatusNotFound, ErrCandidateNotFound)
	case errors.Is(err, ErrCandidateLimit):
		a.deps.WriteError(w, http.StatusConflict, err)
	case errors.Is(err, ErrNoTenant):
		a.deps.WriteError(w, http.StatusBadRequest, err)
	default:
		a.deps.WriteError(w, http.StatusInternalServerError, err)
	}
}
