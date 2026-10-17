// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package orgcontext is the Org Context Store (tracker 337 N-F1, design D6):
// short, typed facts a customer writes about its OWN network ("core-02 is the
// DR site", "circuit ids start with the carrier code") that Iris reads before
// every answer.
//
// WHAT A FACT IS. One document per (scope, kind, key): scope is the whole
// tenant or one site, kind is one of nine closed kinds, the body is ≤ 2000
// bytes of plain text. A document has numbered versions; at most one is
// active, and only the active version ever reaches a prompt.
//
// TWO PEOPLE. A version becomes active only when a person OTHER than its
// author approves it, bound to the exact text reviewed (version + sha256).
// The store refuses a self-approval and the database refuses it again
// (CHECK approver_sub <> author_sub). Rollback re-activates an earlier
// APPROVED version as a new version that keeps its original author and
// approver — no text reaches a prompt without two people, while one
// administrator can still undo a bad fact in an incident.
//
// HISTORY. Versions are never rewritten: once a version leaves draft its body
// and author are frozen (a database trigger enforces it), and every state
// change is audited by the caller (no body text in the trail).
//
// §3a. Every method takes the tenant from the authenticated principal; the
// Postgres store runs inside WithTenant under the FORCE-RLS tenant_iso policy.
// A document of another tenant and one that does not exist are the same
// ErrNotFound.
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package orgcontext

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Limits (design §1.2: deliberately small — this rides every prompt).
const (
	MaxBodyBytes      = 2000
	MaxKeyBytes       = 80
	MaxDocsPerTenant  = 50
	MaxVersionsPerDoc = 200
	MaxReasonBytes    = 500
)

// Kind is the closed vocabulary of facts (design §1.2 + plan §4.1.6).
type Kind string

const (
	KindNamingConvention    Kind = "naming_convention"
	KindEscalationContact   Kind = "escalation_contact"
	KindTopologyNote        Kind = "topology_note"
	KindMaintenanceWindow   Kind = "maintenance_window"
	KindKnownFalsePositive  Kind = "known_false_positive"
	KindCriticality         Kind = "criticality"
	KindCarrierRelationship Kind = "carrier_relationship"
	KindAddressConvention   Kind = "address_convention"
	KindTerminology         Kind = "terminology"
)

// kinds is the display order; labels are the plain-language names the UI and
// the prompt use.
var kinds = []struct {
	k     Kind
	label string
}{
	{KindTopologyNote, "Network layout note"},
	{KindCriticality, "What matters most"},
	{KindMaintenanceWindow, "Maintenance window"},
	{KindKnownFalsePositive, "Known harmless alert"},
	{KindCarrierRelationship, "Carrier or provider"},
	{KindEscalationContact, "Who to escalate to"},
	{KindNamingConvention, "Naming convention"},
	{KindAddressConvention, "Addressing convention"},
	{KindTerminology, "Our terminology"},
}

// Kinds returns the closed vocabulary in display order.
func Kinds() []Kind {
	out := make([]Kind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k.k)
	}
	return out
}

// ValidKind reports whether k is in the closed vocabulary.
func ValidKind(k Kind) bool { return Label(k) != "" }

// Label is a kind's plain-language name ("" for an unknown kind).
func Label(k Kind) string {
	for _, x := range kinds {
		if x.k == k {
			return x.label
		}
	}
	return ""
}

// ScopeTenant is the whole-workspace scope; a site scope is "site:<slug>".
const ScopeTenant = "tenant"

var siteScope = regexp.MustCompile(`^site:[a-z0-9._:-]{1,120}$`)

// ValidScope reports whether s is "tenant" or "site:<slug>".
func ValidScope(s string) bool { return s == ScopeTenant || siteScope.MatchString(s) }

// SiteOf returns the site slug of a site scope ("" for the tenant scope).
func SiteOf(scope string) string {
	if scope == ScopeTenant || len(scope) < 6 {
		return ""
	}
	return scope[len("site:"):]
}

// State is a version's lifecycle state.
type State string

const (
	StateDraft      State = "draft"      // being written; only its author sees it change
	StatePending    State = "pending"    // frozen, waiting for a second person
	StateActive     State = "active"     // what Iris reads (at most one per document)
	StateSuperseded State = "superseded" // was active; replaced by a newer version
	StateRejected   State = "rejected"   // a reviewer declined it (with a reason)
	StateRetired    State = "retired"    // was active; switched off (with a reason)
)

// Version is one numbered text of a document.
type Version struct {
	Version      int        `json:"version"`
	Body         string     `json:"body"`
	BodySHA256   string     `json:"body_sha256"`
	State        State      `json:"state"`
	Author       string     `json:"author"`
	Approver     string     `json:"approver,omitempty"`
	ActivatedBy  string     `json:"activated_by,omitempty"` // who made it active (approve / rollback)
	DecidedBy    string     `json:"decided_by,omitempty"`   // who rejected or retired it
	RestoredFrom int        `json:"restored_from,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
}

// Doc is one fact with its version history (oldest first).
type Doc struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"-"`
	Scope     string    `json:"scope"`
	Kind      Kind      `json:"kind"`
	Key       string    `json:"key"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Versions  []Version `json:"versions"`
}

// Active returns the active version, if any.
func (d Doc) Active() (Version, bool) {
	for _, v := range d.Versions {
		if v.State == StateActive {
			return v, true
		}
	}
	return Version{}, false
}

// Open returns the open (draft or pending) version, if any.
func (d Doc) Open() (Version, bool) {
	for _, v := range d.Versions {
		if v.State == StateDraft || v.State == StatePending {
			return v, true
		}
	}
	return Version{}, false
}

func (d Doc) latest() int {
	n := 0
	for _, v := range d.Versions {
		if v.Version > n {
			n = v.Version
		}
	}
	return n
}

// Fact is an active version as the prompt renders it.
type Fact struct {
	DocID   string
	Version int
	Scope   string
	Kind    Kind
	Key     string
	Body    string
}

// Errors. The HTTP layer maps them; ErrNotFound covers "another tenant's".
var (
	ErrNotFound     = errors.New("orgcontext: not found")
	ErrInvalid      = errors.New("orgcontext: invalid")
	ErrExists       = errors.New("orgcontext: a fact with this place, type and name already exists")
	ErrFull         = errors.New("orgcontext: limit reached")
	ErrWrongState   = errors.New("orgcontext: not possible in the current state")
	ErrSelfApproval = errors.New("orgcontext: the author of a version cannot approve it")
	ErrNotAuthor    = errors.New("orgcontext: only the author of a draft can change it")
	ErrStale        = errors.New("orgcontext: the text changed since it was reviewed")
)

// BodySHA256 is the hash an approval binds to.
func BodySHA256(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidID reports whether id is a lower-case UUID.
func ValidID(id string) bool { return uuidRe.MatchString(id) }

// NewID returns a random (v4) UUID.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("orgcontext: id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
