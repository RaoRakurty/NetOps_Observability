// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisconvo holds Iris conversations: the server-held, structured
// state a follow-up question may refer to (tracker 337 N-C7, plan §4.1.3).
//
// What is stored is REFERENCES, never prose: the last validated query, the
// entities earlier turns named or returned, the actors and change ids the last
// change list showed. The model's words are not kept, and the client cannot
// supply any of it — a follow-up is resolved against this record only.
//
// A conversation belongs to ONE principal in ONE tenant scope: another user of
// the same tenant, or the same user in another scope (a platform owner who
// switched workspace), gets ErrNotFound — indistinguishable from an id that
// never existed. Everything is bounded: turns per conversation, conversations
// per owner, and age.
package irisconvo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"netops/backend/internal/nlquery/ast"
)

// Bounds.
const (
	MaxTurns       = 50
	MaxPerOwner    = 50
	MaxQuestionLen = 1000
	MaxEntities    = 20
	MaxActors      = 20
	MaxChangeIDs   = 20
	MaxIDLen       = 256
	TTL            = 7 * 24 * time.Hour
)

// Turn outcomes (closed).
const (
	OutcomeAnswered = "answered"
	OutcomeClarify  = "clarify"
	OutcomeDeclined = "declined"
	OutcomeUnparsed = "unparsed"
	OutcomeInvalid  = "invalid"
	OutcomeError    = "error"
)

var outcomes = map[string]bool{OutcomeAnswered: true, OutcomeClarify: true, OutcomeDeclined: true,
	OutcomeUnparsed: true, OutcomeInvalid: true, OutcomeError: true}

// Errors.
var (
	ErrNotFound = errors.New("irisconvo: conversation not found")
	ErrFull     = fmt.Errorf("irisconvo: a conversation holds at most %d turns — start a new one", MaxTurns)
	ErrInvalid  = errors.New("irisconvo: invalid")
)

// Turn is one question and what became of it.
type Turn struct {
	At       time.Time `json:"at"`
	Question string    `json:"question"`
	Intent   string    `json:"intent,omitempty"`
	Outcome  string    `json:"outcome"`
	ASTHash  string    `json:"ast_hash,omitempty"`
	QueryID  string    `json:"query_id,omitempty"`
	Rows     int       `json:"rows"`
}

// State is what the next question may point at.
type State struct {
	LastAST   *ast.AST        `json:"last_ast,omitempty"`
	Entities  []ast.EntityRef `json:"entities,omitempty"` // most recent first
	Actors    []string        `json:"actors,omitempty"`
	ChangeIDs []string        `json:"change_ids,omitempty"`
}

// Conversation is one owner's thread.
type Conversation struct {
	TenantID  string    `json:"-"`
	Owner     string    `json:"-"`
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Turns     []Turn    `json:"turns"`
	State     State     `json:"-"` // server-side only; never rendered or accepted
}

// Store is the conversation store. tenant and owner always come from the
// authenticated principal.
type Store interface {
	Create(ctx context.Context, tenant, owner string) (Conversation, error)
	Get(ctx context.Context, tenant, owner, id string) (Conversation, error)
	// Append records a turn and replaces the state, atomically.
	Append(ctx context.Context, tenant, owner, id string, t Turn, st State) (Conversation, error)
}

// NewID returns a random conversation id (UUID v4 form).
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("irisconvo: id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// ValidID reports whether id has the UUID shape NewID produces (lowercase).
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

func checkPrincipal(tenant, owner string) error {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(owner) == "" {
		return fmt.Errorf("%w: a conversation needs a tenant scope and an owner", ErrInvalid)
	}
	return nil
}

// NormalizeTurn bounds and checks a turn.
func NormalizeTurn(t Turn) (Turn, error) {
	if !outcomes[t.Outcome] {
		return Turn{}, fmt.Errorf("%w: unknown outcome %q", ErrInvalid, t.Outcome)
	}
	t.Question = clipRunes(strings.TrimSpace(t.Question), MaxQuestionLen)
	t.Intent = clipRunes(t.Intent, 64)
	t.ASTHash = clipRunes(t.ASTHash, 128)
	t.QueryID = clipRunes(t.QueryID, 128)
	if t.Rows < 0 {
		t.Rows = 0
	}
	if t.At.IsZero() {
		t.At = time.Now().UTC()
	}
	return t, nil
}

// NormalizeState bounds a state: deduplicated, capped, ids length-limited.
func NormalizeState(st State) State {
	var ents []ast.EntityRef
	seen := map[ast.EntityRef]bool{}
	for _, e := range st.Entities {
		if e.Type == "" || e.ID == "" || len(e.ID) > MaxIDLen || seen[e] {
			continue
		}
		seen[e] = true
		ents = append(ents, e)
		if len(ents) == MaxEntities {
			break
		}
	}
	st.Entities = ents
	st.Actors = boundedSet(st.Actors, MaxActors)
	st.ChangeIDs = boundedSet(st.ChangeIDs, MaxChangeIDs)
	if st.LastAST != nil {
		st.LastAST = st.LastAST.Clone()
	}
	return st
}

func boundedSet(in []string, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > MaxIDLen || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) == max {
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

func expired(c Conversation, now time.Time) bool { return now.Sub(c.UpdatedAt) > TTL }

// ---- in-memory store (file-mode deployments) --------------------------------
//
// Conversations are working state, not records: in a deployment without the
// platform database they live in memory and a restart ends them (the next
// follow-up gets ErrNotFound and the client starts a new conversation).

// MemStore is the in-memory Store.
type MemStore struct {
	mu    sync.Mutex
	now   func() time.Time
	convs map[string]*Conversation // tenant\x00owner\x00id → conversation
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{now: func() time.Time { return time.Now().UTC() }, convs: map[string]*Conversation{}}
}

func memKey(tenant, owner, id string) string { return tenant + "\x00" + owner + "\x00" + id }

// pruneLocked drops expired conversations and, past MaxPerOwner, the owner's
// least recently used ones.
func (m *MemStore) pruneLocked(tenant, owner string, room int) {
	now := m.now()
	var mine []*Conversation
	for k, c := range m.convs {
		if expired(*c, now) {
			delete(m.convs, k)
			continue
		}
		if c.TenantID == tenant && c.Owner == owner {
			mine = append(mine, c)
		}
	}
	if excess := len(mine) + room - MaxPerOwner; excess > 0 {
		sort.Slice(mine, func(i, j int) bool { return mine[i].UpdatedAt.Before(mine[j].UpdatedAt) })
		for _, c := range mine[:excess] {
			delete(m.convs, memKey(c.TenantID, c.Owner, c.ID))
		}
	}
}

// Create starts a conversation.
func (m *MemStore) Create(_ context.Context, tenant, owner string) (Conversation, error) {
	if err := checkPrincipal(tenant, owner); err != nil {
		return Conversation{}, err
	}
	id, err := NewID()
	if err != nil {
		return Conversation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(tenant, owner, 1)
	now := m.now()
	c := &Conversation{TenantID: tenant, Owner: owner, ID: id, CreatedAt: now, UpdatedAt: now}
	m.convs[memKey(tenant, owner, id)] = c
	return clone(*c), nil
}

// Get returns the caller's own live conversation.
func (m *MemStore) Get(_ context.Context, tenant, owner, id string) (Conversation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.convs[memKey(tenant, owner, id)]
	if !ok || expired(*c, m.now()) {
		return Conversation{}, ErrNotFound
	}
	return clone(*c), nil
}

// Append records a turn.
func (m *MemStore) Append(_ context.Context, tenant, owner, id string, t Turn, st State) (Conversation, error) {
	t, err := NormalizeTurn(t)
	if err != nil {
		return Conversation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.convs[memKey(tenant, owner, id)]
	if !ok || expired(*c, m.now()) {
		return Conversation{}, ErrNotFound
	}
	if len(c.Turns) >= MaxTurns {
		return Conversation{}, ErrFull
	}
	c.Turns = append(c.Turns, t)
	c.State = NormalizeState(st)
	c.UpdatedAt = m.now()
	return clone(*c), nil
}

func clone(c Conversation) Conversation {
	c.Turns = append([]Turn{}, c.Turns...) // an empty conversation renders [] not null
	c.State = NormalizeState(c.State)
	return c
}

var _ Store = (*MemStore)(nil)
