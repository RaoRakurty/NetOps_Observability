// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package resolve

// rungs_test.go — the N-C2 remainder rungs: topology (4), catalog synonym and
// provider seed (5), model suggestion (7). Each rung has positive and negative
// cases; the ladder's ORDER is pinned (a higher rung wins); the model rung
// never decides anything; and §3a: tenant B's names, devices and adjacency
// never resolve for tenant A, whatever the rung.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// world is tenant A's view as the root would present it. foreign holds tenant
// B's devices: they are NOT in A's inventory, but the (deliberately leaky)
// adjacency fake can still report them — the resolver must drop them.
type world struct {
	aliases []Alias
	inv     []Named
	foreign []Named
	visible map[string]bool
	links   [][2]string
	topoErr error
	invErr  error
	calls   *int // Neighbors calls
}

func (w world) Aliases(context.Context) ([]Alias, error) { return w.aliases, nil }
func (w world) Inventory(_ context.Context, types []string) ([]Named, error) {
	if w.invErr != nil {
		return nil, w.invErr
	}
	var out []Named
	for _, n := range w.inv {
		if contains(types, n.Type) {
			out = append(out, n)
		}
	}
	return out, nil
}
func (w world) Visible(_ context.Context, _ string, id string) (bool, error) {
	return w.visible[id], nil
}
func (w world) Neighbors(_ context.Context, id string) ([]Named, error) {
	if w.calls != nil {
		*w.calls++
	}
	if w.topoErr != nil {
		return nil, w.topoErr
	}
	all := map[string]Named{}
	for _, n := range append(append([]Named{}, w.inv...), w.foreign...) {
		all[n.ID] = n
	}
	var out []Named
	for _, l := range w.links {
		switch id {
		case l[0]:
			out = append(out, all[l[1]])
		case l[1]:
			out = append(out, all[l[0]])
		}
	}
	return out, nil
}

func tenantA() world {
	return world{
		aliases: []Alias{
			{EntityType: "site", EntityID: "site:dfw-hq", Alias: "Dallas"},
			{EntityType: "provider", EntityID: "provider:comcast", Alias: "Comcast"},
			{EntityType: "application", EntityID: "app:salesforce", Alias: "SFDC"},
		},
		inv: []Named{
			{Type: "site", ID: "site:dfw-hq", Names: []string{"Dallas HQ", "dfw-hq"}},
			{Type: "device", ID: "device:core-1", Names: []string{"core-1"}, Role: "core-switch"},
			{Type: "device", ID: "device:edge-1", Names: []string{"edge-1"}, Role: "edge-router"},
			{Type: "device", ID: "device:edge-2", Names: []string{"edge-2"}, Role: "router"},
			{Type: "device", ID: "device:fw-1", Names: []string{"fw-1"}, Role: "ngfw"},
			{Type: "device", ID: "device:sw-9", Names: []string{"sw-9"}}, // role unknown
			{Type: "application", ID: "app:salesforce", Names: []string{"Salesforce"}},
			{Type: "application", ID: "app:m365", Names: []string{"Microsoft 365"}},
		},
		foreign: []Named{
			{Type: "device", ID: "device:gx-edge-9", Names: []string{"gx-edge-9"}, Role: "router"},
			{Type: "application", ID: "app:gx-crm", Names: []string{"Office 365"}},
		},
		visible: map[string]bool{"site:dfw-hq": true, "device:core-1": true, "provider:comcast": true},
		links: [][2]string{
			{"device:core-1", "device:edge-1"},
			{"device:core-1", "device:edge-2"},
			{"device:fw-1", "device:core-1"},
			{"device:fw-1", "device:sw-9"},
			{"device:core-1", "device:gx-edge-9"}, // the trap: a tenant-B device next to A's core
		},
	}
}

func resolverFor(w world) Resolver { return Resolver{Cat: r.Cat, L: w, Topo: w} }

func mustResolve(t *testing.T, rv Resolver, text string, types []string) Result {
	t.Helper()
	res, err := rv.Resolve(context.Background(), text, types)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", text, err)
	}
	return res
}

func ids(res Result) string {
	var out []string
	for _, x := range res.Refs {
		out = append(out, x.EntityID)
	}
	return strings.Join(out, ",")
}

// ---- rung 4: topology ----------------------------------------------------------

func TestTopologyRung(t *testing.T) {
	rv := resolverFor(tenantA())

	// Plural: EVERY router next to core-1, as a set (OR) — not the firewall,
	// and never tenant B's gx-edge-9 that the adjacency source leaked.
	res := mustResolve(t, rv, "routers next to core-1", nil)
	if !res.Set || res.Ambiguous || ids(res) != "device:edge-1,device:edge-2" {
		t.Fatalf("plural topology = %+v", res)
	}
	for _, ref := range res.Refs {
		if ref.Method != MethodTopology || ref.NeedsConfirmation || ref.Confidence != confTopology {
			t.Fatalf("topology ref = %+v", ref)
		}
	}
	// Singular with two candidates: ambiguous, asked — never guessed.
	if res := mustResolve(t, rv, "the router next to core-1", nil); !res.Ambiguous || res.Set || len(res.Refs) != 2 {
		t.Fatalf("singular with two routers must be ambiguous: %+v", res)
	}
	// Singular, exactly one: decided. "ngfw" is a firewall role.
	if res := mustResolve(t, rv, "the firewall adjacent to core-1", nil); res.Ambiguous || ids(res) != "device:fw-1" {
		t.Fatalf("one firewall = %+v", res)
	}
	// Any device: every visible neighbour, still not the foreign one.
	if res := mustResolve(t, rv, "devices connected to core-1", nil); !res.Set || ids(res) != "device:edge-1,device:edge-2,device:fw-1" {
		t.Fatalf("devices next to core-1 = %+v", res)
	}
	// A neighbour whose role inventory does not know may be the switch asked
	// about: every candidate then needs confirmation, and a plural is not a set.
	res = mustResolve(t, rv, "switches next to fw-1", nil)
	if res.Set || ids(res) != "device:core-1,device:sw-9" {
		t.Fatalf("switches next to fw-1 = %+v", res)
	}
	for _, ref := range res.Refs {
		if !ref.NeedsConfirmation || ref.Confidence >= confTopology {
			t.Fatalf("an unknown-role neighbour must need confirmation: %+v", ref)
		}
	}
}

func TestTopologyRungNegatives(t *testing.T) {
	w := tenantA()
	rv := resolverFor(w)
	for _, text := range []string{
		"router next to nowhere-9", // no such anchor
		"router next to edge",      // ambiguous anchor: no guess at either
		"router next to gx-edge-9", // tenant B's device is no anchor for A
		"neighbours of core-1",     // a neighbour is a BGP peer in this grammar
		"next to core-1",           // no role noun: names nothing
		"routers next to dfw-hq",   // a site is not a device anchor
		"routers next to site:dfw-hq",
	} {
		if res := mustResolve(t, rv, text, nil); len(res.Refs) != 0 {
			t.Errorf("%q must not resolve, got %+v", text, res)
		}
	}
	// A router asked for next to a firewall whose only router-ish neighbour is
	// a core switch: the known switch is excluded; the unknown one is offered
	// for confirmation only.
	if res := mustResolve(t, rv, "the router next to fw-1", nil); ids(res) != "device:sw-9" || !res.Refs[0].NeedsConfirmation {
		t.Fatalf("router next to fw-1 = %+v", res)
	}
	// No topology wired, or a slot that is not a device: the rung is off.
	if res := mustResolve(t, Resolver{Cat: r.Cat, L: w}, "routers next to core-1", nil); len(res.Refs) != 0 {
		t.Fatalf("no Topology must mean no topology rung: %+v", res)
	}
	if res := mustResolve(t, rv, "routers next to core-1", []string{"site"}); len(res.Refs) != 0 {
		t.Fatalf("a site slot must not take a device neighbour: %+v", res)
	}
	// An unreadable adjacency source is an error, never "no neighbours".
	w.topoErr = errors.New("lldp unread")
	if _, err := resolverFor(w).Resolve(context.Background(), "routers next to core-1", nil); err == nil {
		t.Fatal("an adjacency read failure must surface")
	}
	// …and it is only read for a topology phrase.
	n := 0
	w.topoErr, w.calls = nil, &n
	mustResolve(t, resolverFor(w), "edge-1", nil)
	mustResolve(t, resolverFor(w), "Dallas", nil)
	if n != 0 {
		t.Fatalf("adjacency read %d times for plain names", n)
	}
}

// ---- rung 5: catalog synonym + provider seed --------------------------------------

func TestSynonymRung(t *testing.T) {
	rv := resolverFor(tenantA())
	for _, c := range []struct{ text, id, method string }{
		{"Salesforce.com", "app:salesforce", MethodCatalogSynonym}, // the caller's app by another public name
		{"O365", "app:m365", MethodCatalogSynonym},                 // "Microsoft 365" in their inventory
		{"office 365", "app:m365", MethodCatalogSynonym},
		{"Xfinity", "provider:comcast", MethodCatalogSynonym}, // via their own alias "Comcast"
		{"CenturyLink", "provider:lumen", MethodCatalogSeed},  // no own entity: the public seed
		{"Level-3", "provider:lumen", MethodCatalogSeed},
		{"AT&T", "provider:att", MethodCatalogSeed},
	} {
		res := mustResolve(t, rv, c.text, nil)
		if res.Ambiguous || len(res.Refs) != 1 || res.Refs[0].EntityID != c.id || res.Refs[0].Method != c.method || res.Refs[0].NeedsConfirmation {
			t.Errorf("Resolve(%q) = %+v, want %s via %s", c.text, res, c.id, c.method)
		}
	}
	for _, c := range []struct {
		text  string
		types []string
	}{
		{"Salesforce.com", []string{"site", "device"}}, // an app synonym never fills a site/device slot
		{"CenturyLink", []string{"application"}},       // a carrier seed never fills an app slot
		{"Google Workspace", nil},                      // a synonym group the caller has no entity for, no seed
		{"latency", nil},                               // catalog vocabulary is never a name
	} {
		if res := mustResolve(t, rv, c.text, c.types); len(res.Refs) != 0 {
			t.Errorf("Resolve(%q, %v) must not resolve, got %+v", c.text, c.types, res)
		}
	}
}

// ---- ordering ---------------------------------------------------------------------

// The first rung that matches decides, even when a lower rung would also have.
func TestLadderOrderHigherRungWins(t *testing.T) {
	w := tenantA()
	w.aliases = append(w.aliases,
		Alias{EntityType: "device", EntityID: "device:edge-2", Alias: "edge-1"},               // an alias shadowing an inventory name
		Alias{EntityType: "device", EntityID: "device:sw-9", Alias: "routers next to core-1"}, // an alias shadowing a topology phrase
		Alias{EntityType: "provider", EntityID: "provider:acme-isp", Alias: "AT&T"},           // their own name beats the public seed
	)
	w.inv = append(w.inv, Named{Type: "device", ID: "device:centurylink-gw", Names: []string{"CenturyLink"}}) // inventory beats the seed
	rv := resolverFor(w)
	for _, c := range []struct{ text, id, method string }{
		{"edge-1", "device:edge-2", MethodTenantAlias},
		{"routers next to core-1", "device:sw-9", MethodTenantAlias},
		{"AT&T", "provider:acme-isp", MethodTenantAlias},
		{"CenturyLink", "device:centurylink-gw", MethodInventoryName},
		{"SFDC", "app:salesforce", MethodTenantAlias}, // alias rung, though SFDC is also a synonym
		{"site:dfw-hq", "site:dfw-hq", MethodCanonicalID},
	} {
		res := mustResolve(t, rv, c.text, nil)
		if len(res.Refs) != 1 || res.Refs[0].EntityID != c.id || res.Refs[0].Method != c.method {
			t.Errorf("Resolve(%q) = %+v, want %s via %s", c.text, res, c.id, c.method)
		}
	}
	// A deterministic answer always beats a partial one, and a partial one the
	// model: the model is not even asked.
	sg := &fakeSuggester{names: []string{"Dallas"}}
	rv.Suggest = sg
	mustResolve(t, rv, "Dallas HQ", nil)
	if res := mustResolve(t, rv, "dall", nil); len(res.Refs) != 1 || res.Refs[0].Method != MethodPartialName {
		t.Fatalf("partial must win over the model: %+v", res)
	}
	if sg.calls != 0 {
		t.Fatalf("the model was asked %d times while a deterministic rung answered", sg.calls)
	}
}

// ---- rung 7: model suggestion --------------------------------------------------------

type fakeSuggester struct {
	names []string
	err   error
	calls int
	last  string
}

func (f *fakeSuggester) SuggestNames(_ context.Context, text string, _ []string) ([]string, error) {
	f.calls++
	f.last = text
	return f.names, f.err
}

func TestModelSuggestionNeedsConfirmationAndIsDisclosed(t *testing.T) {
	sg := &fakeSuggester{names: []string{"Dallas"}}
	rv := resolverFor(tenantA())
	rv.Suggest = sg
	res := mustResolve(t, rv, "dalas", nil)
	if len(res.Refs) != 1 || res.Disclosure != SuggestionDisclosure {
		t.Fatalf("dalas = %+v", res)
	}
	ref := res.Refs[0]
	if ref.EntityID != "site:dfw-hq" || ref.Method != MethodModelSuggestion || !ref.NeedsConfirmation ||
		ref.Confidence != confModel || ref.SuggestedText != "Dallas" || ref.InputText != "dalas" {
		t.Fatalf("a model suggestion must be marked, confirmed first and disclosed: %+v", ref)
	}
	if sg.last != "dalas" {
		t.Fatalf("the model must be given only the operator's text, got %q", sg.last)
	}
}

func TestModelSuggestionNegatives(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		names []string
		err   error
		asked bool
	}{
		{"tenant B's name", "globex hq", []string{"Globex Chicago HQ"}, nil, true},
		{"tenant B's canonical id", "gx core", []string{"site:gx-chi-hq", "device:gx-edge-9"}, nil, true},
		{"tenant B's app name", "ofice 365", []string{"Office 365"}, nil, true}, // only A's "Microsoft 365" may answer
		{"a relation, not a name", "rooter near core", []string{"routers next to core-1"}, nil, true},
		{"the same text back", "zzz-unknown", []string{"zzz-unknown"}, nil, true},
		{"vocabulary is never sent", "latency", []string{"Dallas"}, nil, false},
		{"too short to ask", "dx", []string{"Dallas"}, nil, false},
	}
	for _, c := range cases {
		sg := &fakeSuggester{names: c.names, err: c.err}
		rv := resolverFor(tenantA())
		rv.Suggest = sg
		res := mustResolve(t, rv, c.text, nil)
		if c.name == "tenant B's app name" {
			// "Office 365" is a synonym of the caller's OWN Microsoft 365: the
			// only entity it may land on is A's, and still only as a suggestion.
			if ids(res) != "app:m365" || !res.Refs[0].NeedsConfirmation {
				t.Errorf("%s: %+v", c.name, res)
			}
		} else if len(res.Refs) != 0 {
			t.Errorf("%s: must not resolve, got %+v", c.name, res)
		}
		if (sg.calls > 0) != c.asked {
			t.Errorf("%s: model asked %d times, want asked=%v", c.name, sg.calls, c.asked)
		}
	}

	// A model failure is said, never an error and never a guess.
	rv := resolverFor(tenantA())
	rv.Suggest = &fakeSuggester{err: errors.New("budget spent")}
	res := mustResolve(t, rv, "dalas", nil)
	if len(res.Refs) != 0 || res.SuggestionError != SuggestionUnavailable {
		t.Fatalf("model failure = %+v", res)
	}
	// At most MaxSuggestions names are looked up, however many come back.
	many := &fakeSuggester{names: []string{"nope-1", "nope-2", "nope-3", "Dallas", "edge-1"}}
	rv.Suggest = many
	if res := mustResolve(t, rv, "qqqq", nil); len(res.Refs) != 0 {
		t.Fatalf("names past MaxSuggestions must not be looked up: %+v", res)
	}
	// Not wired (the compiler's ladder): never asked.
	if res := mustResolve(t, resolverFor(tenantA()), "dalas", nil); len(res.Refs) != 0 || res.SuggestionError != "" {
		t.Fatalf("no Suggester must mean no model rung: %+v", res)
	}
}

// §3a, all rungs at once: nothing tenant B owns is reachable from tenant A's
// ladder — not by name, synonym, adjacency or model suggestion.
func TestNoRungReachesAnotherTenant(t *testing.T) {
	rv := resolverFor(tenantA())
	rv.Suggest = &fakeSuggester{names: []string{"gx-edge-9", "Globex CRM", "device:gx-edge-9"}}
	for _, text := range []string{
		"gx-edge-9", "device:gx-edge-9", "routers next to core-1", "devices next to core-1",
		"router next to gx-edge-9", "gx edge nine", "globex crm",
	} {
		res := mustResolve(t, rv, text, nil)
		for _, ref := range res.Refs {
			if strings.HasPrefix(strings.TrimPrefix(ref.EntityID, "device:"), "gx-") || ref.EntityID == "app:gx-crm" {
				t.Fatalf("%q resolved tenant B's %s via %s", text, ref.EntityID, ref.Method)
			}
		}
	}
}

// An inventory read failure inside the topology rung surfaces.
func TestTopologyInventoryErrorPropagates(t *testing.T) {
	w := tenantA()
	rv := resolverFor(w)
	w.invErr = errors.New("discovery down")
	rv.L = w
	if _, err := rv.Resolve(context.Background(), "routers next to core-1", nil); err == nil {
		t.Fatal("an inventory failure must surface")
	}
}
