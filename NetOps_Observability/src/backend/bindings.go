package main

// bindings.go — the role_binding store: the auditable join of
// (principal → role → scope) that is the heart of PBAC
// (docs/design/saas-identity-pbac.md §1.3). A binding is the SOC2/ISO artifact:
// "who can do what, where, granted by whom, expiring when."
//
// Phase A (this file): the store + a behaviour-preserving backfill — every
// existing user becomes ONE principal with ONE binding mirroring its single
// role+tenant. The authoritative decision path is unchanged in Phase A; a
// conformance test proves the binding-derived scope matches today's
// principalTenant/isPlatformOwner. Phase B flips the decider to read bindings
// (union) and allows many bindings per principal.
//
// File-kv backed (role_bindings.json) like the other identity stores, so it
// builds offline and promotes to Postgres unchanged.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Binding effects. deny overrides allow in evaluation (§2).
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// RoleBinding grants (or denies) a role to a principal at a scope. Optional
// condition/time-bounds support tag filters and break-glass sessions (§7.1).
type RoleBinding struct {
	ID          string         `json:"id"`
	PrincipalID string         `json:"principal_id"`
	RoleID      string         `json:"role_id"`
	ScopeType   string         `json:"scope_type"` // platform | org | tenant | resource
	ScopeID     string         `json:"scope_id"`   // canonical scope id (scopes.go)
	Effect      string         `json:"effect"`     // allow | deny (default allow)
	Condition   map[string]any `json:"condition,omitempty"`
	NotBefore   *time.Time     `json:"not_before,omitempty"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"` // nil = permanent
	GrantedBy   string         `json:"granted_by,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	GrantedAt   time.Time      `json:"granted_at"`
}

// active reports whether the binding is in effect at time now.
func (b RoleBinding) active(now time.Time) bool {
	if b.NotBefore != nil && now.Before(*b.NotBefore) {
		return false
	}
	if b.ExpiresAt != nil && !now.Before(*b.ExpiresAt) {
		return false
	}
	return true
}

type bindingStore struct {
	mu       sync.RWMutex
	path     string
	bindings map[string]RoleBinding // id -> binding
	versions map[string]int64       // principal_id -> bindings_version (cache key, §3.1)
}

func newBindingStore(path string) (*bindingStore, error) {
	if path == "" {
		path = "/data/role_bindings.json"
	}
	s := &bindingStore{path: path, bindings: map[string]RoleBinding{}, versions: map[string]int64{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *bindingStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []RoleBinding
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, rb := range list {
		s.bindings[rb.ID] = rb
		s.versions[rb.PrincipalID]++
	}
	return nil
}

func (s *bindingStore) flushLocked() error {
	list := make([]RoleBinding, 0, len(s.bindings))
	for _, rb := range s.bindings {
		list = append(list, rb)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// bindingID is a stable, deterministic id for a (principal, role, scope, effect)
// tuple so backfill/sync is idempotent — re-running never duplicates a binding.
func bindingID(principalID, roleID, scopeID, effect string) string {
	return fmt.Sprintf("%s|%s|%s|%s",
		strings.ToLower(strings.TrimSpace(principalID)),
		strings.ToLower(strings.TrimSpace(roleID)),
		strings.ToLower(strings.TrimSpace(scopeID)),
		strings.ToLower(strings.TrimSpace(effect)))
}

// List returns all bindings (id order). Cross-tenant callers only.
func (s *bindingStore) List() []RoleBinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RoleBinding, 0, len(s.bindings))
	for _, rb := range s.bindings {
		out = append(out, rb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListByPrincipal returns the bindings for one principal (id order).
func (s *bindingStore) ListByPrincipal(principalID string) []RoleBinding {
	principalID = strings.ToLower(strings.TrimSpace(principalID))
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RoleBinding, 0, 2)
	for _, rb := range s.bindings {
		if strings.EqualFold(rb.PrincipalID, principalID) {
			out = append(out, rb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Version returns the principal's bindings_version (0 if none) — the cache key.
func (s *bindingStore) Version(principalID string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[strings.ToLower(strings.TrimSpace(principalID))]
}

// Add inserts (or replaces, by deterministic id) a binding and bumps the
// principal's version. GrantedAt defaults to now if unset.
func (s *bindingStore) Add(b RoleBinding) (RoleBinding, error) {
	b.PrincipalID = strings.ToLower(strings.TrimSpace(b.PrincipalID))
	if b.PrincipalID == "" {
		return RoleBinding{}, errors.New("binding requires a principal")
	}
	if strings.TrimSpace(b.RoleID) == "" {
		return RoleBinding{}, errors.New("binding requires a role")
	}
	if strings.TrimSpace(b.ScopeID) == "" {
		return RoleBinding{}, errors.New("binding requires a scope")
	}
	if b.Effect == "" {
		b.Effect = EffectAllow
	}
	if b.Effect != EffectAllow && b.Effect != EffectDeny {
		return RoleBinding{}, errors.New("binding effect must be allow or deny")
	}
	if b.ScopeType == "" {
		b.ScopeType, _ = parseScope(b.ScopeID)
	}
	if b.GrantedAt.IsZero() {
		b.GrantedAt = time.Now().UTC()
	}
	b.ID = bindingID(b.PrincipalID, b.RoleID, b.ScopeID, b.Effect)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[b.ID] = b
	s.versions[b.PrincipalID]++
	if err := s.flushLocked(); err != nil {
		return RoleBinding{}, err
	}
	return b, nil
}

// Remove deletes a binding by id and bumps the affected principal's version.
func (s *bindingStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rb, ok := s.bindings[id]
	if !ok {
		return errors.New("binding not found")
	}
	delete(s.bindings, id)
	s.versions[rb.PrincipalID]++
	return s.flushLocked()
}

// RemoveByPrincipal drops all of a principal's bindings (used when a user is
// deleted). Bumps the version.
func (s *bindingStore) RemoveByPrincipal(principalID string) error {
	principalID = strings.ToLower(strings.TrimSpace(principalID))
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, rb := range s.bindings {
		if strings.EqualFold(rb.PrincipalID, principalID) {
			delete(s.bindings, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	s.versions[principalID]++
	return s.flushLocked()
}
