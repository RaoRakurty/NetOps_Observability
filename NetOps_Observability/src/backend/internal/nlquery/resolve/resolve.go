// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package resolve turns the words an operator uses for a thing ("Dallas",
// "DFW", "edge-1", "the Comcast circuit") into RESOLVED entity references the
// query AST can carry (tracker 337 N-C2; design: iris-natural-language-
// platform.md §5 N-C2, owner Part 7).
//
// The ladder, strongest first — the first rung that matches decides:
//
//	1 canonical id     "site:dfw-hq"                    confidence 1.00
//	2 tenant alias     "DFW" → site:dfw-hq               confidence 0.99
//	3 inventory name   "Dallas HQ" / "edge-1"            confidence 0.97
//	4 topology         "the router next to edge-1"       confidence 0.90
//	5 catalog synonym  "SFDC" → the caller's Salesforce   confidence 0.95
//	                   "Xfinity" → provider:comcast (seed) confidence 0.90
//	6 partial name     "dall" → the ONE match            confidence 0.70, needs confirmation
//	7 model suggestion "dalas" → model says "Dallas"     confidence 0.50, needs confirmation
//
// A rung that yields more than one candidate is AMBIGUOUS and returns them
// all; the caller asks the operator (for a read) or refuses (for anything that
// acts). The one exception is a PLURAL topology phrase ("the switches next to
// core-1"), which names every neighbour on purpose: its result is a Set — the
// same type is a list (OR), never a guess between its members.
//
// Rungs 6 and 7 never decide anything: their candidates carry
// NeedsConfirmation and the query compiler does not use them. A model may only
// SUGGEST a name (rung 7); the suggestion goes back through rungs 1–5 like any
// other text, so it can only ever land on an entity the caller can already
// see, and it is disclosed as the model's (Disclosure, SuggestedText). The
// model is asked only when an explicit Suggester is wired and every
// deterministic rung found nothing — it never sees the caller's inventory.
//
// Every candidate comes from Lookups and Topology, which the root implements
// from the caller's OWN visible inventory, OWN aliases and OWN adjacency —
// another tenant's names are never in the candidate set, so they can never be
// matched. The only non-tenant candidates are the catalog's provider seeds:
// public carrier names, which reveal nothing about anyone.
package resolve

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"netops/backend/internal/nlquery/catalog"
)

// Resolution methods (closed vocabulary).
const (
	MethodCanonicalID     = "canonical_id"
	MethodTenantAlias     = "tenant_alias"
	MethodInventoryName   = "inventory_name"
	MethodTopology        = "topology_neighbor"
	MethodCatalogSynonym  = "catalog_synonym"
	MethodCatalogSeed     = "catalog_seed"
	MethodPartialName     = "partial_name"
	MethodModelSuggestion = "model_suggestion"
)

// Confidence per rung. A needs-confirmation rung is always below every rung
// that decides on its own.
const (
	confCanonical  = 1.0
	confAlias      = 0.99
	confInventory  = 0.97
	confSynonym    = 0.95
	confTopology   = 0.9
	confSeed       = 0.9
	confTopoUnsure = 0.8
	confPartial    = 0.7
	confModel      = 0.5
)

// SuggestionDisclosure is the note every model-suggested candidate carries.
const SuggestionDisclosure = "Suggested by the AI model, not found by Iris's own name lookup — confirm it before it is used."

// Model-rung bounds (LLM04): a suggestion is asked for only for text of a
// sensible length, and at most MaxSuggestions names are looked up.
const (
	MaxSuggestions        = 3
	MaxSuggestTextRunes   = 128
	SuggestionUnavailable = "model_unavailable"
)

// Named is one visible entity with the names an operator may use for it.
type Named struct {
	Type  string   // catalog entity type
	ID    string   // canonical id, e.g. "site:dfw-hq"
	Names []string // display name, slug, hostname …
	// Role is a device's role or type as inventory knows it ("router",
	// "firewall", "edge-router"); empty when unknown. Only the topology rung
	// reads it.
	Role string
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

// Topology is the caller's adjacency view (rung 4). nil disables the rung.
type Topology interface {
	// Neighbors returns the devices adjacent to deviceID (a canonical
	// "device:" id this ladder already resolved for the caller), restricted to
	// devices the caller may see. An adjacency source that could not be read
	// is an error — "no neighbours" must never stand in for "unknown".
	Neighbors(ctx context.Context, deviceID string) ([]Named, error)
}

// Suggester asks a model for the name an operator probably meant (rung 7).
// It is given ONLY the operator's text and the entity types asked about —
// never inventory — and returns candidate names, which the ladder then
// resolves deterministically. nil disables the rung.
type Suggester interface {
	SuggestNames(ctx context.Context, text string, types []string) ([]string, error)
}

// Ref is one resolved (or candidate) entity reference.
type Ref struct {
	InputText  string  `json:"input_text"`
	EntityID   string  `json:"entity_id"`
	EntityType string  `json:"entity_type"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"resolution_method"`
	// NeedsConfirmation marks a match the operator must confirm before it is
	// used to narrow a query (a partial-name match, a model suggestion, a
	// neighbour whose role inventory does not know).
	NeedsConfirmation bool `json:"needs_confirmation,omitempty"`
	// SuggestedText is the name the model suggested (rung 7 only).
	SuggestedText string `json:"model_suggested_text,omitempty"`
}

// Result is the outcome for one piece of text.
type Result struct {
	Refs      []Ref `json:"refs"`
	Ambiguous bool  `json:"ambiguous"`
	// Set marks a result whose refs are ALL meant (a plural topology phrase):
	// the caller uses every one of them, OR'd, and it is never ambiguous.
	Set bool `json:"set,omitempty"`
	// Disclosure is set when any candidate came from the model.
	Disclosure string `json:"disclosure,omitempty"`
	// SuggestionError is set when a model suggestion was asked for and could
	// not be had (the deterministic answer — usually nothing — stands).
	SuggestionError string `json:"suggestion_error,omitempty"`
}

// Resolver resolves text against the catalog and the caller's lookups.
type Resolver struct {
	Cat *catalog.Catalog
	L   Lookups
	// Topo enables the topology rung; nil disables it.
	Topo Topology
	// Suggest enables the model-suggestion rung; nil (the default, and always
	// the case inside the query compiler) disables it.
	Suggest Suggester
}

// minPartial is the shortest text a partial-name match (or a model
// suggestion) is attempted for; below it every short token would "match"
// something.
const minPartial = 3

// Resolve resolves one mention. types, when non-empty, restricts the entity
// types considered (the grammar knows "circuit" from context).
func (r Resolver) Resolve(ctx context.Context, text string, types []string) (Result, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Result{}, nil
	}
	res, inv, err := r.deterministic(ctx, text, types, true)
	if err != nil || len(res.Refs) > 0 {
		return res, err
	}
	norm := catalog.NormalizeAlias(text)

	// 6. partial name — only for text long enough to mean something, and
	// always flagged for confirmation.
	var hits []Ref
	if len([]rune(norm)) >= minPartial {
		for _, n := range inv {
			for _, name := range n.Names {
				if nn := catalog.NormalizeAlias(name); nn != "" && (strings.HasPrefix(nn, norm) || strings.Contains(nn, " "+norm)) {
					hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: n.Type, Confidence: confPartial, Method: MethodPartialName, NeedsConfirmation: true})
					break
				}
			}
		}
	}
	if len(hits) > 0 {
		return finish(hits), nil
	}

	// 7. model suggestion — the last resort, asked only when wired.
	return r.suggest(ctx, text, norm, types)
}

// deterministic runs rungs 1–5. inv is the caller's inventory for the types
// (for the partial rung). withTopology is false when resolving a topology
// anchor or a model suggestion: neither may chain into another relation.
func (r Resolver) deterministic(ctx context.Context, text string, types []string, withTopology bool) (Result, []Named, error) {
	allowed := func(t string) bool { return len(types) == 0 || contains(types, t) }

	// 1. canonical id.
	if i := strings.IndexByte(text, ':'); i > 0 {
		typ := r.typeForPrefix(text[:i+1])
		if typ != "" && allowed(typ) {
			vis, err := r.L.Visible(ctx, typ, text)
			if err != nil {
				return Result{}, nil, err
			}
			if vis {
				return Result{Refs: []Ref{{InputText: text, EntityID: text, EntityType: typ, Confidence: confCanonical, Method: MethodCanonicalID}}}, nil, nil
			}
		}
	}
	norm := catalog.NormalizeAlias(text)

	// 2. tenant alias.
	aliases, err := r.L.Aliases(ctx)
	if err != nil {
		return Result{}, nil, err
	}
	var hits []Ref
	for _, a := range aliases {
		if allowed(a.EntityType) && catalog.NormalizeAlias(a.Alias) == norm {
			hits = append(hits, Ref{InputText: text, EntityID: a.EntityID, EntityType: a.EntityType, Confidence: confAlias, Method: MethodTenantAlias})
		}
	}
	if len(hits) > 0 {
		return finish(hits), nil, nil
	}

	// 3. inventory name (exact, normalized).
	inv, err := r.L.Inventory(ctx, r.searchTypes(types))
	if err != nil {
		return Result{}, nil, err
	}
	for _, n := range inv {
		if nameIs(n, norm) {
			hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: n.Type, Confidence: confInventory, Method: MethodInventoryName})
		}
	}
	if len(hits) > 0 {
		return finish(hits), inv, nil
	}

	// 4. topology.
	if withTopology && r.Topo != nil && allowed("device") {
		res, ok, err := r.topology(ctx, text)
		if err != nil || ok {
			return res, inv, err
		}
	}

	// 5. catalog synonym: the caller's OWN entity by another of its public
	// names; else, for a carrier, the public seed.
	if res, ok := r.synonym(text, norm, types, aliases, inv); ok {
		return res, inv, nil
	}
	return Result{}, inv, nil
}

// topologyRe reads "the router next to edge-1" / "switches connected to
// core-1". The role noun is required (a bare "next to X" names nothing), and
// "neighbours of X" is deliberately NOT read here: in this grammar a
// neighbour is a BGP peer. Matched on the text as given — the anchor is a
// submatch of that same string, never an offset into a folded copy.
var topologyRe = regexp.MustCompile(`(?i)^(?:the\s+|our\s+|my\s+)?(router|switch|firewall|device|box|node)(s|es)?\s+(?:directly\s+)?(?:next\s+to|adjacent\s+to|connected\s+to|attached\s+to|beside|neighbou?ring)\s+(\S.*)$`)

// topology resolves rung 4. ok is false when the text is not a topology
// phrase or its anchor is not exactly one visible device.
func (r Resolver) topology(ctx context.Context, text string) (Result, bool, error) {
	m := topologyRe.FindStringSubmatch(text)
	if m == nil {
		return Result{}, false, nil
	}
	role, plural, anchorText := strings.ToLower(m[1]), m[2] != "", strings.TrimSpace(m[3])
	anchor, _, err := r.deterministic(ctx, anchorText, []string{"device"}, false)
	if err != nil {
		return Result{}, false, err
	}
	if len(anchor.Refs) != 1 || anchor.Ambiguous || anchor.Refs[0].EntityType != "device" {
		return Result{}, false, nil
	}
	anchorID := anchor.Refs[0].EntityID
	ns, err := r.Topo.Neighbors(ctx, anchorID)
	if err != nil {
		return Result{}, false, err
	}
	// Zero trust: a neighbour is used only if it is ALSO in the caller's own
	// visible inventory — an adjacency source that leaks a device the caller
	// cannot see still cannot put it in a query.
	devs, err := r.L.Inventory(ctx, []string{"device"})
	if err != nil {
		return Result{}, false, err
	}
	visible := make(map[string]bool, len(devs))
	for _, d := range devs {
		if d.Type == "device" {
			visible[d.ID] = true
		}
	}
	var hits []Ref
	unsure := false
	seen := map[string]bool{}
	for _, n := range ns {
		if n.Type != "device" || n.ID == anchorID || seen[n.ID] || !visible[n.ID] {
			continue
		}
		known := strings.TrimSpace(n.Role) != ""
		if specificRole(role) && known && !roleMatches(n.Role, role) {
			continue
		}
		seen[n.ID] = true
		unsure = unsure || (specificRole(role) && !known)
		hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: "device", Confidence: confTopology, Method: MethodTopology})
	}
	if len(hits) == 0 {
		return Result{}, false, nil
	}
	if unsure {
		// A neighbour whose role inventory does not know might not be the
		// router the operator asked about: every candidate is then confirmed
		// first, never used on its own.
		for i := range hits {
			hits[i].Confidence, hits[i].NeedsConfirmation = confTopoUnsure, true
		}
	}
	res := finish(hits)
	if plural && !unsure {
		res.Set, res.Ambiguous = true, false
	}
	return res, true, nil
}

func specificRole(role string) bool {
	return role == "router" || role == "switch" || role == "firewall"
}

// roleMatches reports whether an inventory role/type names the asked role
// ("edge-router" is a router; "l3-switch" a switch; "fw" a firewall).
func roleMatches(have, want string) bool {
	h := strings.ToLower(have)
	if strings.Contains(h, want) {
		return true
	}
	if want == "firewall" {
		for _, w := range strings.FieldsFunc(h, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if w == "fw" || w == "ngfw" {
				return true
			}
		}
	}
	return false
}

// synonym resolves rung 5.
func (r Resolver) synonym(text, norm string, types []string, aliases []Alias, inv []Named) (Result, bool) {
	var hits, seeds []Ref
	for _, typ := range []string{"provider", "application"} {
		if len(types) > 0 && !contains(types, typ) {
			continue
		}
		for _, g := range r.Cat.SynonymsOf(typ, norm) {
			terms := map[string]bool{}
			for _, t := range g.Terms {
				terms[catalog.NormalizeAlias(t)] = true
			}
			for _, a := range aliases {
				if a.EntityType == typ && terms[catalog.NormalizeAlias(a.Alias)] {
					hits = append(hits, Ref{InputText: text, EntityID: a.EntityID, EntityType: typ, Confidence: confSynonym, Method: MethodCatalogSynonym})
				}
			}
			for _, n := range inv {
				if n.Type != typ {
					continue
				}
				for _, name := range n.Names {
					if terms[catalog.NormalizeAlias(name)] {
						hits = append(hits, Ref{InputText: text, EntityID: n.ID, EntityType: typ, Confidence: confSynonym, Method: MethodCatalogSynonym})
						break
					}
				}
			}
			if g.Seed != "" {
				seeds = append(seeds, Ref{InputText: text, EntityID: g.Seed, EntityType: typ, Confidence: confSeed, Method: MethodCatalogSeed})
			}
		}
	}
	// The caller's own entity always beats the public seed.
	if len(hits) > 0 {
		return finish(hits), true
	}
	if len(seeds) > 0 {
		return finish(seeds), true
	}
	return Result{}, false
}

// suggest runs rung 7.
func (r Resolver) suggest(ctx context.Context, text, norm string, types []string) (Result, error) {
	if r.Suggest == nil || len([]rune(norm)) < minPartial || len([]rune(text)) > MaxSuggestTextRunes || r.Cat.IsVocabulary(norm) {
		return Result{}, nil
	}
	names, err := r.Suggest.SuggestNames(ctx, text, types)
	if err != nil {
		return Result{SuggestionError: SuggestionUnavailable}, nil
	}
	var hits []Ref
	asked := 0
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || len([]rune(name)) > MaxSuggestTextRunes || catalog.NormalizeAlias(name) == norm {
			continue
		}
		if asked++; asked > MaxSuggestions {
			break
		}
		res, _, err := r.deterministic(ctx, name, types, false)
		if err != nil {
			return Result{}, err
		}
		for _, h := range res.Refs {
			hits = append(hits, Ref{InputText: text, EntityID: h.EntityID, EntityType: h.EntityType, Confidence: confModel,
				Method: MethodModelSuggestion, NeedsConfirmation: true, SuggestedText: name})
		}
	}
	if len(hits) == 0 {
		return Result{}, nil
	}
	res := finish(hits)
	res.Disclosure = SuggestionDisclosure
	return res, nil
}

func nameIs(n Named, norm string) bool {
	for _, name := range n.Names {
		if name != "" && catalog.NormalizeAlias(name) == norm {
			return true
		}
	}
	return false
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
