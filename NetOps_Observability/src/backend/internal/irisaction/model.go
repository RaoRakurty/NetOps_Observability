// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisaction is Iris's approval gate for WRITES (tracker 337 N-I4,
// design 15; IRIS_FINAL_DESIGN_2026-09-21 §3.3–3.5, IRIS_AI_DESIGN §5.4).
//
// WHAT IRIS MAY WRITE — exactly two kinds, both product/ticket writes, never a
// device (owner 2026-09-05: device writes are structurally prohibited):
//
//   - itsm_note           (`propose_itsm_update`)   one note on the ITSM ticket
//     linked to the investigation's incident (ServiceNow work note / Jira
//     comment), or — when none is linked — one new ticket for that incident;
//   - investigation_note  (`propose_investigation_note`) Iris's concluded
//     finding written into the case's own investigation memory, so a later
//     investigation can recall it as prior context.
//
// Slack/channel posts, owner changes and TAC case-opening stay human-only:
// the design declined them for the agent until each has its own evidence rule.
//
// WHY A DEVICE WRITE CANNOT BE EXPRESSED. The payload is a SEALED interface:
// only the two structs below implement it (the method is unexported). Neither
// has a field that names a device, a host, a command or a connector, and the
// decoder refuses unknown fields — so a payload that tries to address a device
// fails to decode before any policy runs. The Kind vocabulary is closed and
// every executor is registered by Kind, so there is no third path to add one
// through.
//
// THE FIVE GATES (wireless_actions.go / internal/tac, generalized):
//
//  1. PROPOSAL     only from an investigation that CONCLUDED with supported
//     evidence on a server-resolved case; the payload is built by the server
//     from that evidence (citations carried through), never from free model
//     intent; the ticket is the incident's own linked ticket, never one a
//     model named.
//  2. ELIGIBILITY  the console kill switch (IRIS_AI_ACTIONS, default off), the
//     AI add-on + investigations, and the workspace's own toggle with its kind
//     allowlist (default EMPTY) — see policy.go.
//  3. APPROVAL     a DIFFERENT, authorised person approves the exact rendered
//     payload before anything is sent; the proposer (the person Iris
//     answered) can only withdraw it. Requests expire.
//  4. EXECUTION    idempotent: the request moves proposed → executing under a
//     compare-and-set, so a retried or double-clicked approval runs once; the
//     result is stored and every later approval returns it.
//  5. VERIFICATION the outcome (executed / failed, external reference) is
//     recorded on the request, in the audit trail and in the decision ledger.
//     A note has no undo beyond a correcting follow-up note; that is stated,
//     not claimed.
//
// §3a: the tenant comes from the authenticated principal. The Postgres store
// runs inside WithTenant under FORCE-RLS; another tenant's request and one
// that does not exist are the same ErrNotFound.
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package irisaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kind is the closed vocabulary of writes Iris may propose.
type Kind string

const (
	// KindITSMNote — propose_itsm_update.
	KindITSMNote Kind = "itsm_note"
	// KindInvestigationNote — propose_investigation_note.
	KindInvestigationNote Kind = "investigation_note"
)

// Kinds lists the closed vocabulary in display order. The migration's CHECK
// names exactly these (pinned by a test).
var Kinds = []Kind{KindITSMNote, KindInvestigationNote}

// ValidKind reports whether k is in the vocabulary.
func ValidKind(k Kind) bool { return k == KindITSMNote || k == KindInvestigationNote }

// ToolName is the design's tool name for a kind (what the decision ledger and
// the audit trail record).
func ToolName(k Kind) string {
	switch k {
	case KindITSMNote:
		return "propose_itsm_update"
	case KindInvestigationNote:
		return "propose_investigation_note"
	}
	return ""
}

// KindLabel is the operator's words for a kind.
func KindLabel(k Kind) string {
	switch k {
	case KindITSMNote:
		return "Note on the incident's ticket"
	case KindInvestigationNote:
		return "Finding saved to investigation memory"
	}
	return "Unknown action"
}

// Status is a request's state.
type Status string

const (
	StatusProposed  Status = "proposed"  // waiting for a different person
	StatusDryRun    Status = "dry_run"   // the policy allows a dry run only: terminal, never executes
	StatusExecuting Status = "executing" // approved; the write is in flight (the compare-and-set claim)
	StatusExecuted  Status = "executed"  // sent; Result says where
	StatusFailed    Status = "failed"    // approved, sending failed; Result says why
	StatusRejected  Status = "rejected"  // declined (or withdrawn by its proposer)
	StatusExpired   Status = "expired"   // nobody decided before ExpiresAt
)

// Statuses lists every status (the migration's CHECK names exactly these).
var Statuses = []Status{StatusProposed, StatusDryRun, StatusExecuting, StatusExecuted, StatusFailed, StatusRejected, StatusExpired}

// Terminal reports whether no further transition is possible.
func (s Status) Terminal() bool {
	switch s {
	case StatusDryRun, StatusExecuted, StatusFailed, StatusRejected, StatusExpired:
		return true
	}
	return false
}

// Bounds.
const (
	MaxRequestsPerTenant = 500 // oldest TERMINAL requests are evicted past this
	MaxOpenPerTenant     = 50  // requests still waiting for a person
	MaxCitations         = 12
	MaxCitationChars     = 128
	MaxNoteChars         = 4000 // == notify.MaxTicketNoteChars
	MaxTitleChars        = 200
	MaxVerdictChars      = 600 // == ai.maxInvestigationVerdictChars
	MaxSkills            = 8
	MaxReasonChars       = 500
	MaxKeyChars          = 128
	DefaultTTL           = 24 * time.Hour
)

// Errors.
var (
	ErrNotFound      = errors.New("action request not found")
	ErrInvalid       = errors.New("invalid action request")
	ErrSelfApproval  = errors.New("an action Iris proposed for you must be approved by someone else")
	ErrNotPending    = errors.New("this action is no longer waiting for a decision")
	ErrExpired       = errors.New("this action expired before anyone approved it")
	ErrDenied        = errors.New("actions are not allowed for this workspace right now")
	ErrDryRunOnly    = errors.New("this workspace allows dry runs only; nothing is sent")
	ErrTooManyOpen   = fmt.Errorf("this workspace already has %d actions waiting for a decision", MaxOpenPerTenant)
	ErrReasonMissing = errors.New("say why the action is declined")
	ErrNoExecutor    = errors.New("no executor is registered for this kind of action")
)

// ITSM systems.
const (
	SystemServiceNow = "servicenow"
	SystemJira       = "jira"
)

var (
	reServiceNowNumber = regexp.MustCompile(`^[A-Z]{2,6}[0-9]{4,12}$`)
	reJiraKey          = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,19}-[0-9]{1,10}$`)
	reCitation         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/\-]{0,127}$`)
	reKey              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._\-]{0,127}$`)
)

// Payload is one proposed write. It is SEALED: only ITSMNote and
// InvestigationNote implement it, so a device-addressing payload is not a type
// that exists.
type Payload interface {
	kind() Kind
	validate() error
}

// ITSMNote is the propose_itsm_update payload: ONE note on the ticket already
// linked to the investigation's case. Every field is set by the SERVER: the
// system and ticket from the case's own ticket link (internal/ticketing — the
// ticket the RCA view opened), never a ticket a model named; the note from the
// investigation's cited evidence. Opening a ticket stays the existing human
// "Open ticket" flow; Iris adds notes to it.
type ITSMNote struct {
	System        string `json:"system"`     // servicenow | jira
	TicketRef     string `json:"ticket_ref"` // the case's linked ticket number / issue key
	CorrelationID string `json:"correlation_id"`
	Title         string `json:"title"`
	Note          string `json:"note"`
}

func (ITSMNote) kind() Kind { return KindITSMNote }

func (p ITSMNote) validate() error {
	switch p.System {
	case SystemServiceNow:
		if !reServiceNowNumber.MatchString(p.TicketRef) {
			return fmt.Errorf("%w: servicenow ticket %q", ErrInvalid, p.TicketRef)
		}
	case SystemJira:
		if !reJiraKey.MatchString(p.TicketRef) {
			return fmt.Errorf("%w: jira ticket %q", ErrInvalid, p.TicketRef)
		}
	default:
		return fmt.Errorf("%w: unknown ITSM system %q", ErrInvalid, p.System)
	}
	if !reKey.MatchString(p.CorrelationID) {
		return fmt.Errorf("%w: the case is required", ErrInvalid)
	}
	if t := strings.TrimSpace(p.Title); t == "" || len([]rune(p.Title)) > MaxTitleChars {
		return fmt.Errorf("%w: title must be 1..%d characters", ErrInvalid, MaxTitleChars)
	}
	if n := strings.TrimSpace(p.Note); n == "" || len([]rune(p.Note)) > MaxNoteChars {
		return fmt.Errorf("%w: note must be 1..%d characters", ErrInvalid, MaxNoteChars)
	}
	return nil
}

// InvestigationNote is the propose_investigation_note payload: Iris's
// concluded finding for one case, keyed by the CASE (never a device) so it is
// recalled as that case's prior context.
type InvestigationNote struct {
	CorrelationID string   `json:"correlation_id"`
	Verdict       string   `json:"verdict"`
	Skills        []string `json:"skills,omitempty"`
	Citations     []string `json:"citations,omitempty"`
}

func (InvestigationNote) kind() Kind { return KindInvestigationNote }

func (p InvestigationNote) validate() error {
	if !reKey.MatchString(p.CorrelationID) {
		return fmt.Errorf("%w: case is required", ErrInvalid)
	}
	if v := strings.TrimSpace(p.Verdict); v == "" || len([]rune(p.Verdict)) > MaxVerdictChars {
		return fmt.Errorf("%w: finding must be 1..%d characters", ErrInvalid, MaxVerdictChars)
	}
	if len(p.Skills) > MaxSkills {
		return fmt.Errorf("%w: at most %d methods", ErrInvalid, MaxSkills)
	}
	for _, s := range p.Skills {
		if !reKey.MatchString(s) {
			return fmt.Errorf("%w: method %q", ErrInvalid, s)
		}
	}
	return validCitations(p.Citations)
}

func validCitations(cs []string) error {
	if len(cs) > MaxCitations {
		return fmt.Errorf("%w: at most %d citations", ErrInvalid, MaxCitations)
	}
	for _, c := range cs {
		if !reCitation.MatchString(c) {
			return fmt.Errorf("%w: citation %q", ErrInvalid, c)
		}
	}
	return nil
}

// KindOf is a payload's kind.
func KindOf(p Payload) Kind {
	if p == nil {
		return ""
	}
	return p.kind()
}

// Validate checks a payload against its kind's rules.
func Validate(p Payload) error {
	if p == nil {
		return fmt.Errorf("%w: no payload", ErrInvalid)
	}
	return p.validate()
}

// EncodePayload is the canonical JSON of a payload — what is stored, hashed
// and shown to the approver.
func EncodePayload(p Payload) (json.RawMessage, error) {
	if err := Validate(p); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DecodePayload decodes a stored payload of the given kind. Unknown fields are
// REFUSED: a payload carrying a device, host or command key does not decode.
func DecodePayload(k Kind, raw []byte) (Payload, error) {
	dec := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return nil
	}
	switch k {
	case KindITSMNote:
		var p ITSMNote
		if err := dec(&p); err != nil {
			return nil, err
		}
		return p, p.validate()
	case KindInvestigationNote:
		var p InvestigationNote
		if err := dec(&p); err != nil {
			return nil, err
		}
		return p, p.validate()
	}
	return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, k)
}

// DryRun is what was checked before the approver sees the request. Performed
// distinguishes a real read-only probe (does the ticket still exist and is it
// open?) from a pure description (internal/tac/dryrun.go's convention).
type DryRun struct {
	Performed   bool   `json:"performed"`
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Problem     string `json:"problem,omitempty"`
}

// Result is what execution produced.
type Result struct {
	ExternalRef string `json:"external_ref,omitempty"`
	URL         string `json:"url,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Request is one proposed write and everything decided about it.
type Request struct {
	TenantID string `json:"-"`
	ID       string `json:"id"`
	Kind     Kind   `json:"kind"`
	// ProposedBy is the person Iris answered: the request reads "Iris, on
	// behalf of <ProposedBy>". They may withdraw it; they may never approve it.
	ProposedBy  string `json:"proposed_by"`
	ProposedVia string `json:"proposed_via"` // "iris"
	// DecisionID is the decision-ledger id of the answer that proposed it.
	DecisionID    string          `json:"decision_id,omitempty"`
	CorrelationID string          `json:"correlation_id"`
	Citations     []string        `json:"citations"` // proposed_from
	Payload       json.RawMessage `json:"payload"`
	Summary       string          `json:"summary"` // one operator line
	Preview       string          `json:"preview"` // the exact text that will be sent
	DryRun        DryRun          `json:"dry_run"`
	Policy        Decision        `json:"policy"`
	Status        Status          `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	DecidedBy     string          `json:"decided_by,omitempty"`
	DecidedAt     *time.Time      `json:"decided_at,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	ExecutedAt    *time.Time      `json:"executed_at,omitempty"`
	Result        *Result         `json:"result,omitempty"`
}

// Filter selects requests for a list.
type Filter struct {
	Status Status // "" = all
	Limit  int    // capped at MaxRequestsPerTenant
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n])
	}
	return string(r)
}

// cleanCitations keeps the well-formed citations, deduplicated, bounded.
func cleanCitations(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		c = strings.TrimSpace(c)
		if !reCitation.MatchString(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) == MaxCitations {
			break
		}
	}
	return out
}
