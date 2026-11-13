// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package rcaresolution records HOW an incident was resolved (tracker 337
// N-F4 residue): when an operator closes an RCA case, they may say what fixed
// it — from a closed vocabulary, with an optional short note and the change
// that was linked.
//
// WHY. "Have we seen this before?" could only point at a past case's timeline,
// because nothing recorded the fix. With a recorded resolution, similar-incident
// recall can say "last time this was fixed by a configuration rollback
// (recorded by an operator on 2026-10-02)" — as HISTORICAL evidence. A past fix
// is never a claim about the present cause, and nothing here is executed.
//
// WHAT IT IS NOT. Not the RCA verdict feedback (rcafeedback: was the engine
// right?) and not postmortem action items (work still to do). A resolution is
// a statement about what already happened.
//
// §3a. The tenant always comes from the server (the case's owning tenant, read
// under the caller's scope), never the request. Stores are tenant-keyed; the
// Postgres table is FORCE-RLS (migration 0071).
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package rcaresolution

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kind is how an incident was resolved. Closed vocabulary.
type Kind string

// The closed set, in the order the form offers them.
const (
	KindConfigRollback    Kind = "config_rollback"
	KindHardwareReplace   Kind = "hardware_replace"
	KindProviderTicket    Kind = "provider_ticket"
	KindReboot            Kind = "reboot"
	KindRoutingChange     Kind = "routing_change"
	KindCapacityAdd       Kind = "capacity_add"
	KindNoActionTransient Kind = "no_action_transient"
	KindOther             Kind = "other"
)

// Kinds lists the vocabulary in display order.
var Kinds = []Kind{KindConfigRollback, KindHardwareReplace, KindProviderTicket, KindReboot,
	KindRoutingChange, KindCapacityAdd, KindNoActionTransient, KindOther}

var kindLabels = map[Kind]string{
	KindConfigRollback:    "a configuration rollback",
	KindHardwareReplace:   "a hardware replacement",
	KindProviderTicket:    "a ticket with the provider",
	KindReboot:            "a reboot",
	KindRoutingChange:     "a routing change",
	KindCapacityAdd:       "added capacity",
	KindNoActionTransient: "no action (it cleared on its own)",
	KindOther:             "another fix",
}

// Label is the plain-language phrase for a kind ("a configuration rollback").
// An unknown kind has no label.
func Label(k Kind) string { return kindLabels[k] }

// Valid reports whether k is in the vocabulary.
func Valid(k Kind) bool { _, ok := kindLabels[k]; return ok }

// Bounds.
const (
	// NoteMax caps the free-text note (runes).
	NoteMax = 500
	// MaxPerCase bounds how many resolutions one case may carry (an operator
	// who corrects themselves adds a row; the latest leads).
	MaxPerCase = 20
)

// changeIDPattern is what a linked change id may look like: a ledger id or an
// external change number. No spaces, no markup.
var changeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}$`)

// Resolution is one recorded fix.
type Resolution struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"-"`
	CorrelationID string    `json:"correlation_id"`
	Kind          Kind      `json:"kind"`
	Note          string    `json:"note,omitempty"`
	ChangeID      string    `json:"change_id,omitempty"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

// Request is what a client may send. Everything else is server-owned.
type Request struct {
	Kind     string `json:"kind"`
	Note     string `json:"note"`
	ChangeID string `json:"change_id"`
}

// Errors.
var (
	ErrKind   = errors.New("kind must be one of: config_rollback, hardware_replace, provider_ticket, reboot, routing_change, capacity_add, no_action_transient, other")
	ErrNote   = fmt.Errorf("note must be at most %d characters of plain text", NoteMax)
	ErrChange = errors.New("change_id must be 1–64 letters, digits, '.', '_', ':' or '-'")
	ErrLimit  = fmt.Errorf("this case already has %d recorded resolutions", MaxPerCase)
	ErrOther  = errors.New("a resolution of kind \"other\" needs a short note saying what was done")
)

// FromRequest validates a request into the client-owned part of a Resolution.
// The note is REFUSED (never silently cleaned) when it holds text a reader
// cannot see or a line break: the author sees exactly what is stored.
func FromRequest(in Request) (Resolution, error) {
	k := Kind(strings.TrimSpace(in.Kind))
	if !Valid(k) {
		return Resolution{}, ErrKind
	}
	note := strings.TrimSpace(in.Note)
	if !utf8.ValidString(note) || utf8.RuneCountInString(note) > NoteMax || hasHiddenOrControl(note) {
		return Resolution{}, ErrNote
	}
	if k == KindOther && note == "" {
		return Resolution{}, ErrOther
	}
	change := strings.TrimSpace(in.ChangeID)
	if change != "" && !changeIDPattern.MatchString(change) {
		return Resolution{}, ErrChange
	}
	return Resolution{Kind: k, Note: note, ChangeID: change}, nil
}

// hasHiddenOrControl reports control characters (line breaks included),
// bidi overrides and zero-width characters.
func hasHiddenOrControl(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsControl(r):
			return true
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi embeddings / isolates
			return true
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF || r == 0x2060: // zero-width
			return true
		}
	}
	return false
}

// NormTenant is the store key for a tenant ("" stays "": the default tenant).
func NormTenant(t string) string { return strings.TrimSpace(t) }
