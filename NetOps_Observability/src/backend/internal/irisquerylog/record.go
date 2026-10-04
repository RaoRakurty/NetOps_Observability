// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisquerylog records what Iris made of each question, and what the
// operator said it should have made of it (tracker 337 N-C8, Part 2 §22).
//
// One Record per compiled question: who asked (tenant + principal, both from
// the token), the question text (clipped), the intent, the outcome, the query's
// hash and catalog version, the validator's error codes, the entities it
// resolved and HOW, row/series counts and the time it took, and which surface
// answered it — the router's data arm, the query API or a conversation.
//
// What is NEVER stored: result rows, series points, model prose. The record is
// telemetry about the question, not a copy of the answer. It DOES keep the
// validated query itself (tracker 337 N-C5: GET /api/ai/query/{id} and its
// plain-language /explain) and who wrote it — the grammar, the model fallback
// or the client (the execute API) — so a model-written query stays disclosed
// for as long as the record lives.
//
// A Correction is the operator's "that's not what I meant": a closed kind, an
// optional corrected query (decoded strictly and validated against the
// caller's CURRENT scope before it is accepted — never trusted) and a short
// note. Corrections exist for OFFLINE evaluation only. Nothing reads them back
// into the compiler, the resolver or any model: there is no automatic
// retraining, by design (plan §22; owner decision: no training).
//
// Everything is bounded: question and note length, entities and codes per
// record, corrections per record, records per tenant, and age.
package irisquerylog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/validate"
)

// Bounds.
const (
	MaxQuestionLen   = 1000
	MaxNoteLen       = 500
	MaxEntities      = 20
	MaxCodes         = 20
	MaxCorrections   = 5
	MaxPerTenant     = 5000
	MaxIDLen         = 256
	MaxListLimit     = 100
	DefaultListLimit = 20
	Retention        = 30 * 24 * time.Hour
)

// Outcomes (closed). "compiled" is a question the query API compiled to a
// valid query without running it (POST /api/ai/query/compile).
const (
	OutcomeAnswered = "answered"
	OutcomeCompiled = "compiled"
	OutcomeClarify  = "clarify"
	OutcomeDeclined = "declined"
	OutcomeUnparsed = "unparsed"
	OutcomeInvalid  = "invalid"
	OutcomeError    = "error"
)

var outcomes = map[string]bool{OutcomeAnswered: true, OutcomeCompiled: true, OutcomeClarify: true,
	OutcomeDeclined: true, OutcomeUnparsed: true, OutcomeInvalid: true, OutcomeError: true}

// Sources (closed): which surface answered.
const (
	SourceRouter       = "router"        // the /api/ai/ask data arm
	SourceQueryCompile = "query_compile" // POST /api/ai/query/compile
	SourceQueryExecute = "query_execute" // POST /api/ai/query/execute
	SourceConversation = "conversation"  // POST /api/ai/conversations/{id}/messages
)

var sources = map[string]bool{SourceRouter: true, SourceQueryCompile: true, SourceQueryExecute: true, SourceConversation: true}

// CompiledBy values (closed): who wrote the stored query. A record without a
// query has none.
const (
	CompiledByGrammar  = "grammar"  // the deterministic question grammar
	CompiledByModel    = "model"    // the guarded model fallback (modelc.SourceModel)
	CompiledBySupplied = "supplied" // a client-supplied query (the execute API)
)

var compiledBy = map[string]bool{CompiledByGrammar: true, CompiledByModel: true, CompiledBySupplied: true}

// Correction kinds (closed).
const (
	KindWrongEntity = "wrong_entity"
	KindWrongMetric = "wrong_metric"
	KindWrongWindow = "wrong_window"
	KindWrongFilter = "wrong_filter"
	KindOther       = "other"
)

// Kinds lists the correction kinds, in display order.
var Kinds = []string{KindWrongEntity, KindWrongMetric, KindWrongWindow, KindWrongFilter, KindOther}

// ValidKind reports whether k is a correction kind.
func ValidKind(k string) bool {
	for _, v := range Kinds {
		if v == k {
			return true
		}
	}
	return false
}

// MethodSupplied marks an entity that arrived in a client-supplied query
// (the execute API) rather than being resolved from words.
const MethodSupplied = "supplied"

// Errors.
var (
	ErrNotFound = errors.New("irisquerylog: query record not found")
	ErrFull     = fmt.Errorf("irisquerylog: a question holds at most %d corrections", MaxCorrections)
	ErrInvalid  = errors.New("irisquerylog: invalid")
)

// Entity is one entity the question resolved, and how.
type Entity struct {
	Type       string  `json:"type"`
	ID         string  `json:"id"`
	Method     string  `json:"resolution_method"`
	Confidence float64 `json:"confidence,omitempty"`
}

// Correction is an operator's statement that the answer was not what they meant.
type Correction struct {
	At            time.Time `json:"at"`
	By            string    `json:"by"`
	Kind          string    `json:"kind"`
	Note          string    `json:"note,omitempty"`
	CorrectedAST  *ast.AST  `json:"corrected_ast,omitempty"`
	CorrectedHash string    `json:"corrected_ast_hash,omitempty"`
}

// Record is one compiled question.
type Record struct {
	TenantID        string       `json:"-"`
	ID              string       `json:"id"`
	Principal       string       `json:"principal"`
	ConversationID  string       `json:"conversation_id,omitempty"`
	Source          string       `json:"source"`
	At              time.Time    `json:"at"`
	Question        string       `json:"question"`
	Intent          string       `json:"intent,omitempty"`
	Outcome         string       `json:"outcome"`
	QueryType       string       `json:"query_type,omitempty"`
	ASTHash         string       `json:"ast_hash,omitempty"`
	CatalogVersion  string       `json:"catalog_version,omitempty"`
	ValidationCodes []string     `json:"validation_codes"`
	Entities        []Entity     `json:"entities"`
	Rows            int          `json:"rows"`
	Series          int          `json:"series"`
	DurationMs      int64        `json:"duration_ms"`
	Corrections     []Correction `json:"corrections"`
	// Query is the VALIDATED (constrained) query the question compiled to —
	// nil unless one validated. CompiledBy says who wrote it; it is set
	// exactly when Query is.
	Query      *ast.AST `json:"query,omitempty"`
	CompiledBy string   `json:"compiled_by,omitempty"`
}

// ListFilter selects records. Principal "" means every principal of the
// tenant — the caller decides who may ask for that (a tenant admin).
type ListFilter struct {
	Principal string
	Limit     int
}

// Store is the query-log store. tenant and principal always come from the
// authenticated principal, never from a request body.
type Store interface {
	// Record stores one record (normalized; an empty ID is assigned).
	Record(ctx context.Context, tenant string, r Record) (Record, error)
	// List returns the tenant's live records, newest first.
	List(ctx context.Context, tenant string, f ListFilter) ([]Record, error)
	// Get returns one live record of the tenant. principal "" means any
	// principal of the tenant — the caller decides who may ask for that (a
	// tenant admin); otherwise another principal's record, an expired one and
	// a missing one are all ErrNotFound.
	Get(ctx context.Context, tenant, principal, id string) (Record, error)
	// Correct attaches a correction to the principal's OWN record. Another
	// principal's record, an expired one and a missing one are ErrNotFound.
	Correct(ctx context.Context, tenant, principal, id string, c Correction) (Record, error)
}

// NewID returns a random record id (UUID v4 form).
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("irisquerylog: id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// ValidID reports whether id has the lowercase UUID shape NewID produces.
func ValidID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return false
			}
		}
	}
	return true
}

// Normalize bounds and checks a record for tenant. It never trusts the caller
// to have bounded anything.
func Normalize(tenant string, r Record, now time.Time) (Record, error) {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(r.Principal) == "" {
		return Record{}, fmt.Errorf("%w: a record needs a tenant scope and a principal", ErrInvalid)
	}
	if !outcomes[r.Outcome] {
		return Record{}, fmt.Errorf("%w: unknown outcome %q", ErrInvalid, r.Outcome)
	}
	if !sources[r.Source] {
		return Record{}, fmt.Errorf("%w: unknown source %q", ErrInvalid, r.Source)
	}
	if r.ID == "" {
		id, err := NewID()
		if err != nil {
			return Record{}, err
		}
		r.ID = id
	}
	if !ValidID(r.ID) {
		return Record{}, fmt.Errorf("%w: record id", ErrInvalid)
	}
	if r.ConversationID != "" && !ValidID(r.ConversationID) {
		return Record{}, fmt.Errorf("%w: conversation id", ErrInvalid)
	}
	r.TenantID = tenant
	r.Principal = clipRunes(r.Principal, MaxIDLen)
	r.Question = clipRunes(strings.TrimSpace(r.Question), MaxQuestionLen)
	r.Intent = clipRunes(r.Intent, 64)
	r.QueryType = clipRunes(r.QueryType, 64)
	r.ASTHash = clipRunes(r.ASTHash, 128)
	r.CatalogVersion = clipRunes(r.CatalogVersion, 64)
	r.ValidationCodes = boundedCodes(r.ValidationCodes)
	r.Entities = boundedEntities(r.Entities)
	r.Rows, r.Series = max(r.Rows, 0), max(r.Series, 0)
	r.DurationMs = max(r.DurationMs, 0)
	if r.At.IsZero() {
		r.At = now
	}
	if err := normalizeQuery(&r); err != nil {
		return Record{}, err
	}
	// Corrections arrive only through Correct; a record is born without any.
	r.Corrections = []Correction{}
	return r, nil
}

// normalizeQuery keeps the stored query and its author consistent: a query
// needs a known author, a record without one has no author, and the query is
// re-encoded strictly and within ast.MaxBytes so nothing unrepresentable is
// stored.
func normalizeQuery(r *Record) error {
	if r.Query == nil {
		r.CompiledBy = ""
		return nil
	}
	if !compiledBy[r.CompiledBy] {
		return fmt.Errorf("%w: unknown query author %q", ErrInvalid, r.CompiledBy)
	}
	q := r.Query.Clone()
	if q == nil {
		return fmt.Errorf("%w: the query does not re-encode", ErrInvalid)
	}
	r.Query = q
	if r.ASTHash == "" {
		r.ASTHash = q.Hash()
	}
	return nil
}

// NormalizeCorrection bounds and checks a correction.
func NormalizeCorrection(c Correction, now time.Time) (Correction, error) {
	if !ValidKind(c.Kind) {
		return Correction{}, fmt.Errorf("%w: unknown correction kind %q", ErrInvalid, c.Kind)
	}
	if strings.TrimSpace(c.By) == "" {
		return Correction{}, fmt.Errorf("%w: a correction needs its author", ErrInvalid)
	}
	c.By = clipRunes(c.By, MaxIDLen)
	c.Note = clipRunes(strings.TrimSpace(c.Note), MaxNoteLen)
	c.CorrectedHash = ""
	if c.CorrectedAST != nil {
		c.CorrectedAST = c.CorrectedAST.Clone()
		if c.CorrectedAST == nil {
			return Correction{}, fmt.Errorf("%w: corrected query does not re-encode", ErrInvalid)
		}
		c.CorrectedHash = c.CorrectedAST.Hash()
	}
	if c.Note == "" && c.CorrectedAST == nil && c.Kind == KindOther {
		return Correction{}, fmt.Errorf("%w: say what was wrong — a note or a corrected query", ErrInvalid)
	}
	if c.At.IsZero() {
		c.At = now
	}
	return c, nil
}

func boundedCodes(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, c := range in {
		c = clipRunes(strings.TrimSpace(c), 64)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == MaxCodes {
			break
		}
	}
	return out
}

func boundedEntities(in []Entity) []Entity {
	out := []Entity{}
	seen := map[[2]string]bool{}
	for _, e := range in {
		if e.Type == "" || e.ID == "" || len(e.ID) > MaxIDLen || len(e.Type) > 64 {
			continue
		}
		k := [2]string{e.Type, e.ID}
		if seen[k] {
			continue
		}
		seen[k] = true
		e.Method = clipRunes(e.Method, 64)
		if e.Confidence < 0 || e.Confidence > 1 {
			e.Confidence = 0
		}
		out = append(out, e)
		if len(out) == MaxEntities {
			break
		}
	}
	return out
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// ---- building a record from the NL pipeline ---------------------------------

// FromCompile starts a record for one compiled question: intent, outcome up to
// validation, resolved entities with their methods, and the validator's codes.
// checked is the validated query (nil unless valid); vr is nil when nothing
// compiled.
func FromCompile(source, question string, res compile.Result, checked *ast.AST, vr *validate.Result) Record {
	r := Record{Source: source, Question: question, Intent: res.Intent}
	for _, e := range res.Entities {
		r.Entities = append(r.Entities, Entity{Type: e.EntityType, ID: e.EntityID, Method: e.Method, Confidence: e.Confidence})
	}
	q := checked
	if q == nil {
		q = res.AST
	}
	if q != nil {
		r.QueryType, r.ASTHash = string(q.Type), q.Hash()
	}
	if vr != nil {
		for _, e := range vr.Errors {
			r.ValidationCodes = append(r.ValidationCodes, e.Code)
		}
	}
	switch {
	case res.Decline != "":
		r.Outcome = OutcomeDeclined
	case len(res.Clarify) > 0:
		r.Outcome = OutcomeClarify
	case res.Unparsed || res.AST == nil:
		r.Outcome = OutcomeUnparsed
	case checked == nil:
		r.Outcome = OutcomeInvalid
	default:
		r.Outcome = OutcomeCompiled
		r.Query, r.CompiledBy = checked, CompiledByGrammar
	}
	return r
}

// ByModel marks the record's query as written by the model fallback (the
// caller knows that; compile.Result does not). A record without a query is
// left alone.
func (r *Record) ByModel() {
	if r.Query != nil {
		r.CompiledBy = CompiledByModel
	}
}

// FromQuery starts a record for a client-supplied query (the execute API):
// no question, its entities marked as supplied. checked is the validated
// query (nil unless vr is valid) — the one the record keeps.
func FromQuery(q, checked *ast.AST, vr validate.Result) Record {
	r := Record{Source: SourceQueryExecute, Outcome: OutcomeInvalid}
	if q != nil {
		r.QueryType, r.ASTHash = string(q.Type), q.Hash()
		for _, e := range q.Refs {
			r.Entities = append(r.Entities, Entity{Type: e.Type, ID: e.ID, Method: MethodSupplied})
		}
	}
	for _, e := range vr.Errors {
		r.ValidationCodes = append(r.ValidationCodes, e.Code)
	}
	if vr.Valid && checked != nil {
		r.Outcome = OutcomeCompiled
		r.Query, r.CompiledBy = checked, CompiledBySupplied
		r.QueryType, r.ASTHash = string(checked.Type), checked.Hash()
	}
	return r
}

// Answered marks the record answered by rs: counts only — never the rows.
func (r *Record) Answered(rs *plan.ResultSet) {
	if rs == nil {
		return
	}
	r.Outcome = OutcomeAnswered
	r.Rows, r.Series = len(rs.Rows), len(rs.Series)
	if rs.ASTHash != "" {
		r.ASTHash = rs.ASTHash
	}
	if rs.CatalogVersion != "" {
		r.CatalogVersion = rs.CatalogVersion
	}
}

// Took stamps the elapsed time since start.
func (r *Record) Took(start time.Time) { r.DurationMs = time.Since(start).Milliseconds() }

// ---- the corrected query ----------------------------------------------------

// ErrRejected is a corrected query that does not validate in the caller's scope.
var ErrRejected = errors.New("irisquerylog: the corrected query is not valid for you")

// CheckCorrectedAST decodes a client-supplied corrected query STRICTLY
// (bounded size, no unknown fields — so a smuggled tenant field is an error)
// and validates it against the caller's scope: a foreign entity is refused
// exactly like a missing one. It returns the validated (constrained) query.
// An absent query (empty or JSON null) is (nil, zero, nil).
func CheckCorrectedAST(ctx context.Context, cat *catalog.Catalog, sc validate.Scope, raw []byte) (*ast.AST, validate.Result, error) {
	if s := strings.TrimSpace(string(raw)); s == "" || s == "null" {
		return nil, validate.Result{}, nil
	}
	q, err := ast.Decode(raw)
	if err != nil {
		return nil, validate.Result{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	checked, vr := validate.Validate(ctx, cat, sc, q)
	if !vr.Valid || checked == nil {
		return nil, vr, ErrRejected
	}
	return checked, vr, nil
}
