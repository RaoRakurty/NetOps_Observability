// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package entityalias is the per-tenant alias table for Iris entity resolution
// (tracker 337 N-C2): "DFW" and "Dallas" both mean site:dfw-hq for THIS
// tenant. Tenant vocabulary lives here — never in the shared catalog and never
// in a model's weights.
//
// §3a: the store is a default-closed per-tenant collection (the same primitive
// sites use). The CALLER stamps TenantID from the authenticated principal
// before Put; nothing in a request body can choose the tenant. A scoped caller
// lists, reads and deletes only its own aliases, and a foreign alias is
// indistinguishable from an absent one.
package entityalias

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"netops/backend/internal/nlquery/catalog"
)

// Limits.
const (
	MaxAliasLen      = 64
	MaxPerTenant     = 2000
	MaxSourceLen     = 32
	SourceOperator   = "operator"
	SourceSuggestion = "accepted_suggestion"
)

// Alias is one tenant alias.
type Alias struct {
	TenantID   string    `json:"tenant_id"`
	EntityType string    `json:"entity_type"`
	EntityID   string    `json:"entity_id"`
	Alias      string    `json:"alias"`
	Norm       string    `json:"norm"`
	Source     string    `json:"source"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// Key is the within-tenant identity: one alias text means one thing per type.
func (a Alias) Key() string { return a.EntityType + "|" + a.Norm }

// Collection is the default-closed per-tenant store primitive
// (tenant.Collection[Alias] satisfies it).
type Collection interface {
	All(tenant string, cross bool) []Alias
	Get(tenant string, cross bool, id string) (Alias, bool)
	Upsert(rec Alias) error
	Delete(tenant string, cross bool, id string) bool
}

// Errors the HTTP layer maps onto status codes.
var (
	ErrInvalid  = errors.New("invalid alias")
	ErrFull     = fmt.Errorf("this workspace already has the maximum of %d aliases", MaxPerTenant)
	ErrNotFound = errors.New("not found")
)

// Store validates and persists aliases.
type Store struct {
	C   Collection
	Cat *catalog.Catalog
	Now func() time.Time
}

// Validate normalizes a and checks it against the catalog. It does NOT check
// that the entity is visible — the caller does, from the principal.
func (s *Store) Validate(a *Alias) error {
	a.Alias = strings.TrimSpace(a.Alias)
	a.EntityType = strings.TrimSpace(a.EntityType)
	a.EntityID = strings.TrimSpace(a.EntityID)
	if a.Alias == "" || len([]rune(a.Alias)) > MaxAliasLen {
		return fmt.Errorf("%w: an alias is 1 to %d characters", ErrInvalid, MaxAliasLen)
	}
	for _, r := range a.Alias {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: an alias is printable text", ErrInvalid)
		}
	}
	et, ok := s.Cat.Entity(a.EntityType)
	if !ok {
		return fmt.Errorf("%w: unknown entity type %q", ErrInvalid, a.EntityType)
	}
	if !regexp.MustCompile(et.IDPattern).MatchString(a.EntityID) {
		return fmt.Errorf("%w: %q is not a %s id", ErrInvalid, a.EntityID, a.EntityType)
	}
	a.Norm = catalog.NormalizeAlias(a.Alias)
	if a.Norm == "" {
		return fmt.Errorf("%w: an alias needs letters or digits", ErrInvalid)
	}
	if a.Source == "" {
		a.Source = SourceOperator
	}
	if a.Source != SourceOperator && a.Source != SourceSuggestion {
		return fmt.Errorf("%w: unknown source", ErrInvalid)
	}
	return nil
}

// Put validates and stores a (TenantID and CreatedBy already stamped by the
// caller from the principal). Re-putting the same alias text for the same
// type re-points it — idempotent by key.
func (s *Store) Put(a Alias) (Alias, error) {
	if strings.TrimSpace(a.TenantID) == "" {
		return Alias{}, fmt.Errorf("%w: no owning tenant", ErrInvalid)
	}
	if err := s.Validate(&a); err != nil {
		return Alias{}, err
	}
	if _, exists := s.C.Get(a.TenantID, false, a.Key()); !exists && len(s.C.All(a.TenantID, false)) >= MaxPerTenant {
		return Alias{}, ErrFull
	}
	a.CreatedAt = s.now()
	if err := s.C.Upsert(a); err != nil {
		return Alias{}, err
	}
	return a, nil
}

// List returns the caller's aliases. A nil or unwired store has none.
func (s *Store) List(tenant string, cross bool) []Alias {
	if s == nil || s.C == nil {
		return nil
	}
	return s.C.All(tenant, cross)
}

// Delete removes one alias by (type, alias text). A foreign or absent alias is
// ErrNotFound.
func (s *Store) Delete(tenant string, cross bool, entityType, alias string) error {
	key := entityType + "|" + catalog.NormalizeAlias(alias)
	if !s.C.Delete(tenant, cross, key) {
		return ErrNotFound
	}
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
