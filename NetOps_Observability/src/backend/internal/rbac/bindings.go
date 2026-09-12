// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rbac

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
	"netops/backend/internal/platformdb"
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

// Principal types (PBAC Phase D, §5). user is the default; the rest are
// first-class machine identities (service_account = API token, agent =
// SPIFFE/mTLS collector, device = device-bound credential).
const (
	PrincipalUser    = "user"
	PrincipalService = "service_account"
	PrincipalAgent   = "agent"
	PrincipalDevice  = "device"
)

// ConditionBreakGlass marks a binding as an emergency-access grant.
const ConditionBreakGlass = "break_glass"

// Elevation-provider condition keys (the "second IdP for JIT access" pattern,
// 2026-09-07). An ELEVATION binding is minted by a successful sign-in through a
// provider whose kind is `elevation`; it grants nothing standing, expires on its
// own, and names where it came from:
//
//	elevation           bool   — this binding IS an elevated-access grant
//	elevation_provider  string — the IdP alias that minted it (also GrantedBy)
//	elevation_sid       string — the IdP session id (`sid`) when the token carried
//	                             one, so an upstream logout can be correlated
//	elevation_tenant    string — the tenant the grant was made IN, stamped from the
//	                             ACCOUNT (never from a claim: a claim never moves a
//	                             tenant). The gate compares it to the caller's own
//	                             tenant, so a grant can never be spent elsewhere.
const (
	ConditionElevation         = "elevation"
	ConditionElevationProvider = "elevation_provider"
	ConditionElevationSID      = "elevation_sid"
	ConditionElevationTenant   = "elevation_tenant"
)

// RoleBinding grants (or denies) a role to a principal at a scope. Optional
// condition/time-bounds support tag filters and break-glass sessions (§7.1).
type RoleBinding struct {
	ID            string         `json:"id"`
	PrincipalID   string         `json:"principal_id"`
	PrincipalType string         `json:"principal_type,omitempty"` // user (default) | service_account | agent | device
	RoleID        string         `json:"role_id"`
	ScopeType     string         `json:"scope_type"` // platform | org | tenant | resource
	ScopeID       string         `json:"scope_id"`   // canonical scope id (scopes.go)
	Effect        string         `json:"effect"`     // allow | deny (default allow)
	Condition     map[string]any `json:"condition,omitempty"`
	NotBefore     *time.Time     `json:"not_before,omitempty"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"` // nil = permanent
	GrantedBy     string         `json:"granted_by,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	GrantedAt     time.Time      `json:"granted_at"`
}

// Active reports whether the binding is in effect at time now.
func (b RoleBinding) Active(now time.Time) bool {
	if b.NotBefore != nil && now.Before(*b.NotBefore) {
		return false
	}
	if b.ExpiresAt != nil && !now.Before(*b.ExpiresAt) {
		return false
	}
	return true
}

// IsBreakGlass reports whether a binding is a break-glass grant.
func (b RoleBinding) IsBreakGlass() bool {
	if b.Condition == nil {
		return false
	}
	v, ok := b.Condition[ConditionBreakGlass].(bool)
	return ok && v
}

// IsElevation reports whether a binding is an elevation-provider grant. The
// condition survives a JSON round-trip through the kv store, where a Go bool
// comes back as a bool but a hand-written record may carry the string "true";
// both are honoured, anything else is NOT an elevation (fail-closed).
func (b RoleBinding) IsElevation() bool {
	if b.Condition == nil {
		return false
	}
	switch v := b.Condition[ConditionElevation].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// ConditionString reads a string-valued condition key ("" when absent or of
// another shape).
func (b RoleBinding) ConditionString(key string) string {
	if b.Condition == nil {
		return ""
	}
	v, _ := b.Condition[key].(string)
	return strings.TrimSpace(v)
}

// BindingStore is the file-backed role_binding registry (role_bindings.json).
type BindingStore struct {
	mu       sync.RWMutex
	path     string
	bindings map[string]RoleBinding // id -> binding
	versions map[string]int64       // principal_id -> bindings_version (cache key, §3.1)
}

func NewBindingStore(path string) (*BindingStore, error) {
	if path == "" {
		path = "/data/role_bindings.json"
	}
	s := &BindingStore{path: path, bindings: map[string]RoleBinding{}, versions: map[string]int64{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *BindingStore) load() error {
	b, err := platformdb.Load(s.path)
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

// flushViewLocked persists `view` — the register as it WOULD BE after the write
// in progress — WITHOUT touching s.bindings. Every writer builds a view, so
// there is no "flush what is in the map" path left to call by mistake.
//
// This is what lets every write persist FIRST and adopt SECOND. The old order
// changed the map and only then tried to write it, so a failed write left the
// register silently disagreeing with the disk and the next successful write
// made that disagreement durable — a purged grant that was never written out
// was gone anyway, and a grant the disk refused was in force anyway (§10).
//
// It is deliberately not a rollback. Restoring a saved copy after a failed
// write can hand a caller a header pointing at data that was mutated in the
// meantime, a trap this repo has already been bitten by. Nothing here is
// mutated and put back: the view is a separate map, adopted whole or not at
// all.
func (s *BindingStore) flushViewLocked(view map[string]RoleBinding) error {
	list := make([]RoleBinding, 0, len(view))
	for _, rb := range view {
		list = append(list, rb)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// cloneBindingsLocked returns a separate map with the same rows, the starting
// point for a view a write can be built into.
func (s *BindingStore) cloneBindingsLocked() map[string]RoleBinding {
	out := make(map[string]RoleBinding, len(s.bindings))
	for id, rb := range s.bindings {
		out[id] = rb
	}
	return out
}

// BindingID is a stable, deterministic id for a (principal, role, scope, effect)
// tuple so backfill/sync is idempotent — re-running never duplicates a binding.
func BindingID(principalID, roleID, scopeID, effect string) string {
	return fmt.Sprintf("%s|%s|%s|%s",
		strings.ToLower(strings.TrimSpace(principalID)),
		strings.ToLower(strings.TrimSpace(roleID)),
		strings.ToLower(strings.TrimSpace(scopeID)),
		strings.ToLower(strings.TrimSpace(effect)))
}

// List returns all bindings (id order). Cross-tenant callers only.
func (s *BindingStore) List() []RoleBinding {
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
func (s *BindingStore) ListByPrincipal(principalID string) []RoleBinding {
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
func (s *BindingStore) Version(principalID string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.versions[strings.ToLower(strings.TrimSpace(principalID))]
}

// Add inserts (or replaces, by deterministic id) a binding and bumps the
// principal's version. GrantedAt defaults to now if unset.
func (s *BindingStore) Add(b RoleBinding) (RoleBinding, error) {
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
	if b.PrincipalType == "" {
		b.PrincipalType = PrincipalUser
	}
	if b.ScopeType == "" {
		b.ScopeType, _ = ParseScope(b.ScopeID) // the remainder (bare id) is not needed here
	}
	if b.GrantedAt.IsZero() {
		b.GrantedAt = time.Now().UTC()
	}
	b.ID = BindingID(b.PrincipalID, b.RoleID, b.ScopeID, b.Effect)
	s.mu.Lock()
	defer s.mu.Unlock()
	view := s.cloneBindingsLocked()
	view[b.ID] = b
	if err := s.flushViewLocked(view); err != nil {
		return RoleBinding{}, err
	}
	s.bindings = view
	s.versions[b.PrincipalID]++
	return b, nil
}

// Remove deletes a binding by id and bumps the affected principal's version.
func (s *BindingStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rb, ok := s.bindings[id]
	if !ok {
		return errors.New("binding not found")
	}
	view := s.cloneBindingsLocked()
	delete(view, id)
	if err := s.flushViewLocked(view); err != nil {
		return err
	}
	s.bindings = view
	s.versions[rb.PrincipalID]++
	return nil
}

// RemoveByPrincipal drops all of a principal's bindings (used when a user is
// deleted). Bumps the version.
func (s *BindingStore) RemoveByPrincipal(principalID string) error {
	principalID = strings.ToLower(strings.TrimSpace(principalID))
	s.mu.Lock()
	defer s.mu.Unlock()
	view := s.cloneBindingsLocked()
	changed := false
	for id, rb := range view {
		if strings.EqualFold(rb.PrincipalID, principalID) {
			delete(view, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	// Persist FIRST, adopt SECOND. The other order purged the principal in
	// memory and then reported the failure to write, so the caller logged that
	// the grants "may remain" while they were in fact already gone, and the
	// next unrelated write made the loss durable.
	if err := s.flushViewLocked(view); err != nil {
		return err
	}
	s.bindings = view
	s.versions[principalID]++
	return nil
}
