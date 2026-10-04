// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package aidecision is the Iris AI decision ledger (tracker 337 N-A6; the
// event vocabulary is Part 1 §35): an append-only, tenant-scoped record of
// every step an AI decision took — the question received, the investigation
// and plan, each Policy Engine evaluation, each tool execution, the evidence
// cited, the recommendation made and the answer returned.
//
// Every Entry carries the model (provider, model name, router tier) and tool
// (name, version) that acted and the SHA-256 of the tool's arguments and its
// result. HASHES ONLY: arguments, results, question text, model prose and
// secrets are never stored. A hash proves what an investigation saw — re-run
// the tool with the same arguments, hash the result, compare — without the
// ledger becoming a second copy of tenant data (CLAUDE.md §8, §15 LLM06).
//
// Every free-form field is reduced to a bounded TOKEN (letters, digits and
// . _ : @ / + -), so nothing an operator typed and nothing a model wrote can
// ride into the ledger as text: what does not fit the token alphabet is
// dropped, never stored "cleaned".
//
// Append-only is enforced by the database (migration 0056: no UPDATE/DELETE/
// TRUNCATE grant, and a trigger refusing all three). The Store interface has
// no update or delete method either.
package aidecision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Event types: Part 1 §35's sixteen, plus ANSWER_RETURNED — the answer the
// operator was shown, which §35 does not name but which is the decision every
// other entry leads to. The read-only Iris of today emits QUESTION_RECEIVED,
// INVESTIGATION_STARTED, PLAN_CREATED, TOOL_SELECTED, TOOL_EXECUTED,
// POLICY_EVALUATED, EVIDENCE_ADDED, HYPOTHESIS_CREATED / HYPOTHESIS_REJECTED
// (N-B3 investigation hypotheses), RECOMMENDATION_CREATED and ANSWER_RETURNED.
// ROOT_CAUSE_SELECTED is never emitted by Iris — the correlation engine owns
// the cause — and the action/approval/execution types are accepted so a future
// gated action path needs no migration.
const (
	QuestionReceived      = "QUESTION_RECEIVED"
	InvestigationStarted  = "INVESTIGATION_STARTED"
	PlanCreated           = "PLAN_CREATED"
	ToolSelected          = "TOOL_SELECTED"
	ToolExecuted          = "TOOL_EXECUTED"
	EvidenceAdded         = "EVIDENCE_ADDED"
	HypothesisCreated     = "HYPOTHESIS_CREATED"
	HypothesisRejected    = "HYPOTHESIS_REJECTED"
	RootCauseSelected     = "ROOT_CAUSE_SELECTED"
	RecommendationCreated = "RECOMMENDATION_CREATED"
	ActionRequested       = "ACTION_REQUESTED"
	PolicyEvaluated       = "POLICY_EVALUATED"
	ApprovalReceived      = "APPROVAL_RECEIVED"
	ExecutionStarted      = "EXECUTION_STARTED"
	VerificationCompleted = "VERIFICATION_COMPLETED"
	RollbackExecuted      = "ROLLBACK_EXECUTED"
	AnswerReturned        = "ANSWER_RETURNED"
)

// EventTypes lists the closed vocabulary in the order §35 gives it. The
// migration's CHECK constraint must name exactly these (pinned by a test).
var EventTypes = []string{
	QuestionReceived, InvestigationStarted, PlanCreated, ToolSelected, ToolExecuted,
	EvidenceAdded, HypothesisCreated, HypothesisRejected, RootCauseSelected,
	RecommendationCreated, ActionRequested, PolicyEvaluated, ApprovalReceived,
	ExecutionStarted, VerificationCompleted, RollbackExecuted, AnswerReturned,
}

// ValidEventType reports whether t is in the vocabulary.
func ValidEventType(t string) bool {
	for _, v := range EventTypes {
		if v == t {
			return true
		}
	}
	return false
}

// Surfaces (closed): which API the decision was made on.
const (
	SurfaceAsk = "ask" // POST /api/ai/ask (and the data arm / grounded engine it fans into)
)

var surfaces = map[string]bool{SurfaceAsk: true}

// Bounds.
const (
	// MaxEntriesPerDecision caps one decision. The chain itself is bounded
	// (MaxChainToolCalls); this is the ledger's own line, and what does not
	// fit is COUNTED (Recorder.Dropped, a metric), never silently lost.
	MaxEntriesPerDecision = 96
	MaxTokenLen           = 128
	MaxPrincipalLen       = 256
	DefaultListLimit      = 50
	MaxListLimit          = 200
	// MaxMemPerTenant bounds the in-memory store (file-mode deployments).
	MaxMemPerTenant = 10000
)

// Errors.
var (
	ErrInvalid = errors.New("aidecision: invalid entry")
)

// Entry is one step of one decision. TenantID is the scope the entry was
// written in; it is serialized only on a platform-wide (cross-tenant) read.
type Entry struct {
	TenantID      string    `json:"tenant,omitempty"`
	ID            string    `json:"id"`
	DecisionID    string    `json:"decision_id"`
	Seq           int       `json:"seq"`
	EventType     string    `json:"event_type"`
	Principal     string    `json:"principal"`
	Surface       string    `json:"surface"`
	At            time.Time `json:"at"`
	IncidentRef   string    `json:"incident_ref,omitempty"`
	Intent        string    `json:"intent,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	Skill         string    `json:"skill,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	ToolVersion   string    `json:"tool_version,omitempty"`
	ModelProvider string    `json:"model_provider,omitempty"`
	ModelName     string    `json:"model_name,omitempty"`
	ModelTier     string    `json:"model_tier,omitempty"`
	ArgsSHA256    string    `json:"args_sha256,omitempty"`
	ResultSHA256  string    `json:"result_sha256,omitempty"`
	ItemCount     int       `json:"item_count,omitempty"`
	Outcome       string    `json:"outcome,omitempty"`
	AnswerID      string    `json:"answer_id,omitempty"`
	QueryLogID    string    `json:"query_log_id,omitempty"`
}

// ListFilter selects entries. DecisionID "" means every decision; Before is
// an exclusive keyset cursor on the entry time (zero = newest).
type ListFilter struct {
	DecisionID string
	Before     time.Time
	Limit      int
}

// Store is the ledger. tenant always comes from the authenticated principal;
// cross (the platform owner's all-tenants view) is honoured on reads only —
// an Append always writes in exactly one tenant's scope.
type Store interface {
	// Append writes one decision's entries atomically (all or none).
	Append(ctx context.Context, tenant string, entries []Entry) error
	// List returns entries newest first (a decision's own steps in seq order
	// when DecisionID is set).
	List(ctx context.Context, tenant string, cross bool, f ListFilter) ([]Entry, error)
}

// ---- ids, hashes, tokens -----------------------------------------------------

// NewID returns a random UUID v4.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("aidecision: id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

var (
	reUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reToken  = regexp.MustCompile(`^[A-Za-z0-9._:@/+-]+$`)
	// An incident reference is a correlation UUID or a NOC problem handle.
	reIncident = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|P-[0-9A-Fa-f]{4,32})$`)
)

// ValidID reports whether id is a lowercase UUID.
func ValidID(id string) bool { return reUUID.MatchString(id) }

// ValidSHA256 reports whether h is 64 lowercase hex characters.
func ValidSHA256(h string) bool { return reSHA256.MatchString(h) }

// SHA256Hex is the ledger's one hash: lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Token returns s when it is a bounded token, else "". Free text (anything with
// a space, quote, newline …) is DROPPED rather than stored cleaned: a field
// that cannot hold prose cannot leak it.
func Token(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxTokenLen || !reToken.MatchString(s) {
		return ""
	}
	return s
}

// IncidentRef returns ref when it is a correlation id or a problem handle,
// else "" — the client supplies it, so it is never stored on trust.
func IncidentRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if !reIncident.MatchString(ref) {
		return ""
	}
	return strings.ToLower(ref)
}

// Normalize checks and bounds one entry for tenant. It never trusts the caller
// to have bounded anything; a structurally wrong entry is ErrInvalid.
func Normalize(tenant string, e Entry, now time.Time) (Entry, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return Entry{}, fmt.Errorf("%w: no tenant scope", ErrInvalid)
	}
	e.Principal = strings.TrimSpace(e.Principal)
	if e.Principal == "" || len(e.Principal) > MaxPrincipalLen || strings.ContainsAny(e.Principal, "\r\n\t") {
		return Entry{}, fmt.Errorf("%w: principal", ErrInvalid)
	}
	if !ValidEventType(e.EventType) {
		return Entry{}, fmt.Errorf("%w: unknown event type %q", ErrInvalid, e.EventType)
	}
	if !surfaces[e.Surface] {
		return Entry{}, fmt.Errorf("%w: unknown surface %q", ErrInvalid, e.Surface)
	}
	if !ValidID(e.DecisionID) {
		return Entry{}, fmt.Errorf("%w: decision id", ErrInvalid)
	}
	if e.ID == "" {
		id, err := NewID()
		if err != nil {
			return Entry{}, err
		}
		e.ID = id
	}
	if !ValidID(e.ID) {
		return Entry{}, fmt.Errorf("%w: entry id", ErrInvalid)
	}
	if e.Seq < 0 || e.Seq >= MaxEntriesPerDecision {
		return Entry{}, fmt.Errorf("%w: seq %d", ErrInvalid, e.Seq)
	}
	if e.ArgsSHA256 != "" && !ValidSHA256(e.ArgsSHA256) {
		return Entry{}, fmt.Errorf("%w: args hash", ErrInvalid)
	}
	if e.ResultSHA256 != "" && !ValidSHA256(e.ResultSHA256) {
		return Entry{}, fmt.Errorf("%w: result hash", ErrInvalid)
	}
	e.TenantID = tenant
	e.IncidentRef = IncidentRef(e.IncidentRef)
	e.Intent, e.Mode, e.Skill = Token(e.Intent), Token(e.Mode), Token(e.Skill)
	e.Tool, e.ToolVersion = Token(e.Tool), Token(e.ToolVersion)
	e.ModelProvider, e.ModelName, e.ModelTier = Token(e.ModelProvider), Token(e.ModelName), Token(e.ModelTier)
	e.Outcome, e.AnswerID, e.QueryLogID = Token(e.Outcome), Token(e.AnswerID), Token(e.QueryLogID)
	e.ItemCount = max(e.ItemCount, 0)
	if e.At.IsZero() {
		e.At = now
	}
	e.At = e.At.UTC()
	return e, nil
}

// NormalizeBatch normalizes one decision's entries: all for the same decision,
// seq unique, at most MaxEntriesPerDecision. One bad entry refuses the batch.
func NormalizeBatch(tenant string, in []Entry, now time.Time) ([]Entry, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxEntriesPerDecision {
		return nil, fmt.Errorf("%w: %d entries (max %d)", ErrInvalid, len(in), MaxEntriesPerDecision)
	}
	out := make([]Entry, 0, len(in))
	seen := map[int]bool{}
	for _, e := range in {
		n, err := Normalize(tenant, e, now)
		if err != nil {
			return nil, err
		}
		if n.DecisionID != in[0].DecisionID || seen[n.Seq] {
			return nil, fmt.Errorf("%w: a batch is one decision with unique seq", ErrInvalid)
		}
		seen[n.Seq] = true
		out = append(out, n)
	}
	return out, nil
}

func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultListLimit
	case n > MaxListLimit:
		return MaxListLimit
	}
	return n
}

// ---- the per-request recorder ------------------------------------------------

// Recorder collects one decision's entries while the request runs, in the
// order they happen, and hands them to the Store in one Append at the end. It
// is carried on the request context (WithRecorder) so the seams the decision
// passes through — the tool audit hook, the provider adapter, the data arm —
// can add to it without each growing a parameter. All methods are nil-safe:
// code outside a ledgered request sees a nil Recorder and does nothing.
type Recorder struct {
	mu         sync.Mutex
	decisionID string
	principal  string
	surface    string
	now        func() time.Time
	entries    []Entry
	dropped    int
	started    bool // INVESTIGATION_STARTED already recorded
	model      ModelUse
	modelCalls int
}

// ModelUse names the model that answered a provider call.
type ModelUse struct {
	Provider string
	Name     string
	Tier     string
}

// NewRecorder starts a decision for principal on surface.
func NewRecorder(principal, surface string) (*Recorder, error) {
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	return &Recorder{decisionID: id, principal: principal, surface: surface,
		now: func() time.Time { return time.Now().UTC() }}, nil
}

// DecisionID is the id every entry of this decision carries ("" on nil).
func (r *Recorder) DecisionID() string {
	if r == nil {
		return ""
	}
	return r.decisionID
}

// Add appends one entry, stamping the decision, principal, surface, sequence
// and time. Past MaxEntriesPerDecision the entry is counted as dropped.
func (r *Recorder) Add(e Entry) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked(e)
}

func (r *Recorder) addLocked(e Entry) {
	if len(r.entries) >= MaxEntriesPerDecision {
		r.dropped++
		return
	}
	e.DecisionID, e.Principal, e.Surface = r.decisionID, r.principal, r.surface
	e.Seq = len(r.entries)
	if e.At.IsZero() {
		e.At = r.now()
	}
	r.entries = append(r.entries, e)
}

// StartInvestigation records INVESTIGATION_STARTED once per decision (the
// first method of a chain); later calls are no-ops.
func (r *Recorder) StartInvestigation(skill, selected string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	r.addLocked(Entry{EventType: InvestigationStarted, Skill: skill, Outcome: selected})
}

// NoteModel records that a provider call was answered by m. The last model to
// answer is what ANSWER_RETURNED names; the count says how many calls it took.
func (r *Recorder) NoteModel(m ModelUse) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.model = m
	r.modelCalls++
}

// Model returns the last model that answered and how many provider calls the
// decision made.
func (r *Recorder) Model() (ModelUse, int) {
	if r == nil {
		return ModelUse{}, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.model, r.modelCalls
}

// Entries returns a copy of what was recorded.
func (r *Recorder) Entries() []Entry {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Entry(nil), r.entries...)
}

// Dropped is how many entries did not fit MaxEntriesPerDecision.
func (r *Recorder) Dropped() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

type ctxKey struct{}

// WithRecorder returns ctx carrying r.
func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// FromContext returns the Recorder on ctx, or nil.
func FromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(ctxKey{}).(*Recorder) // a missing or foreign value is "no ledger here"
	return r
}
