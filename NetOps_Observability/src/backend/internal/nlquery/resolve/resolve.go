// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package resolve turns the words an operator uses for a thing ("Dallas",
// "DFW", "edge-1", "the Comcast circuit") into RESOLVED entity references the
// query AST can carry (tracker 337 N-C2; design: iris-natural-language-
// platform.md §5 N-C2, owner Part 7).
//
// The ladder, strongest first — the first rung that matches decides:
//
//	1 canonical id     "site:dfw-hq"            confidence 1.00
//	2 tenant alias     "DFW" → site:dfw-hq       confidence 0.99
//	3 inventory name   "Dallas HQ" / "edge-1"    confidence 0.97
//	4 partial name     "dall" → the ONE match    confidence 0.70, needs confirmation
//
// A rung that yields more than one candidate is AMBIGUOUS and returns them
// all; the caller asks the operator (for a read) or refuses (for anything that
// acts). No model interpretation happens here — a model may only SUGGEST, and
// its suggestion goes back through this ladder like any other text.
//
// Every candidate comes from Lookups, which the root implements from the
// caller's OWN visible inventory and OWN aliases — another tenant's names are
// never in the candidate set, so they can never be matched.
package resolve

import (
	"context"
	"sort"
	"strings"

	"netops/backend/internal/nlquery/catalog"
)

// Resolution methods (closed vocabulary).
const (
	MethodCanonicalID   = "canonical_id"
	MethodTenantAlias   = "tenant_alias"
	MethodInventoryName = "inventory_name"
	MethodPartialName   = "partial_name"
)

// Named is one visible entity with the names an operator may use for it.
type Named struct {
	Type  string   // catalog entity type
	ID    string   // canonical id, e.g. "site:dfw-hq"
	Names []string // display name, slug, hostname …
}

// Alias is one tenant-defined alias.
type Alias struct {
	EntityType string
	EntityID   string
	Alias      string
}

// Lookups is what the root supplies, scoped to the caller.
type Lookups interface {
	// Aliases returns the caller's tenant aliases.
	Aliases(ctx context.Context) ([]Alias, error)
	// Inventory returns the caller's visible entities of the given types.
	Inventory(ctx context.Context, types []string) ([]Named, error)
	// Visible reports whether a canonical id is visible to the caller.
	Visible(ctx context.Context, entityType, id string) (bool, error)
}

// Ref is one resolved (or candidate) entity reference.
type Ref struct {
	InputText  string  `json:"input_text"`
	EntityID   string  `json:"entity_id"`
	EntityType string  `json:"entity_type"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"resolution_method"`
	// NeedsConfirmation marks a match the operator must confirm before it is
	// used to narrow a query (a partial-name match).
	NeedsConfirmation bool `json:"needs_confirmation,omitempty"`
}

// Result is the outcome for one piece of text.
type Result struct {
	Refs      []Ref `json:"refs"`
	Ambiguous bool  `json:"ambiguous"`
}

// Resolver resolves text against the catalog and the caller's lookups.
type Resolver struct {
	Cat *catalog.Catalog
	L   Lookups
}

// minPartial is the shortest text a partial-name match is attempted for; below
// it every short token would "match" something.
const minPartial = 3

// Resolve resolves one mention. types, when non-empty, restricts the entity
// types considered (the grammar knows "circuit" from context).
func (r Resolver) Resolve(ctx context.Context, text string, types []string) (Result, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Result{}, nil
	}
	allowed := func(t string) bool { return len(types) == 0 || contains(types, t) }

	// 1. canonical id.
	if i := strings.IndexByte(text, ':'); i > 0 {
		typ := r.typeForPrefix(text[:i+1])
		if typ != "" && allowed(typ) {
			vis, err := r.L.Visible(ctx, typ, text)
			if err != nil {
				return Result{}, err
			}
			if vis {
				return Result{Refs: []Ref{{InputText: text, EntityID: text, EntityType: typ, Confidence: 1, Method: MethodCanonicalID}}}, nil
			}
		}
	}
	norm := catalog.NormalizeAlias(text)

	// 2. tenant alias.
	aliases, err := r.L.Aliases(ctx)
	if err != nil {
		return Result{}, err
	}
	var hits []Ref
	for _, a := range aliases {
		if allowed(a.EntityType) && catalog.NormalizeAlias(a.Alias) == norm {
			hits = append(hits, Ref{InputText: text, EntityID: a.EntityID, EntityType: a.EntityType, Confidence: 0.99, Method: MethodTenantAlias})
		}
	}
	if len(hits) > 0 {
		return finish(hits), nil
	}

	// 3. inventory name (exact, normalized).
	inv, err := r.L.Inventory(ctx, r.searchTypes(types))
	if err != nil {
		return Result{}, err
	}
	for _, n := range inv {
		for _, name := range n.Names {
			if name != "" && catalog.NormalizeAlias(name) == norm {
				hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: n.Type, Confidence: 0.97, Method: MethodInventoryName})
				break
			}
		}
	}
	if len(hits) > 0 {
		return finish(hits), nil
	}

	// 4. partial name — only for text long enough to mean something, and
	// always flagged for confirmation.
	if len([]rune(norm)) >= minPartial {
		for _, n := range inv {
			for _, name := range n.Names {
				if nn := catalog.NormalizeAlias(name); nn != "" && (strings.HasPrefix(nn, norm) || strings.Contains(nn, " "+norm)) {
					hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: n.Type, Confidence: 0.7, Method: MethodPartialName, NeedsConfirmation: true})
					break
				}
			}
		}
	}
	return finish(hits), nil
}

// finish dedupes, orders deterministically and marks ambiguity.
func finish(hits []Ref) Result {
	seen := map[string]bool{}
	out := hits[:0]
	for _, h := range hits {
		k := h.EntityType + "\x1f" + h.EntityID
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].EntityType != out[j].EntityType {
			return out[i].EntityType < out[j].EntityType
		}
		return out[i].EntityID < out[j].EntityID
	})
	return Result{Refs: out, Ambiguous: len(out) > 1}
}

func (r Resolver) typeForPrefix(prefix string) string {
	for _, e := range r.Cat.Entities {
		if e.IDPrefix == prefix {
			return e.Name
		}
	}
	return ""
}

// searchTypes is the set of instance types an operator names directly.
func (r Resolver) searchTypes(types []string) []string {
	if len(types) > 0 {
		return types
	}
	return []string{"site", "device", "circuit", "application", "provider"}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
