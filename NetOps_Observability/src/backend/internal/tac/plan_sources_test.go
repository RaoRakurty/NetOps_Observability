package tac

// plan_sources_test.go — THE CITATION INVARIANT.
//
// A step cites the pages that establish ITS OWN command. It does not carry the
// dialect's bibliography. That distinction was lost when a binding with no
// citation of its own inherited the plan-level `sources` list: on 2026-09-06 a
// Nokia SR Linux plan (incident c150bbc5, spine1, ospf-adjacency) came back with
// 23 steps that each carried the SAME 366 pages — 8,418 links in one preview,
// which is not a citation, it is a wall. These tests are the ratchet:
//
//   1. no step carries more than maxBindingSources citations;
//   2. no two steps in a plan share an identical citation list longer than one
//      (which is what a shared pool looks like from the outside);
//   3. no pack repeats a page inside one citation list.

import (
	"io/fs"
	"strings"
	"testing"

	tacdata "netops/backend/ai/tac"
)

// planPlatformText is a device platform string that resolves onto each authored
// dialect. Most dialects answer to their own display name; the ones that do not
// carry the string a real device reports instead.
//
// Until tracker 271 the three firewall dialects (cisco-asa, fortinet-fortios,
// paloalto-panos) were reachable from NO platform string at all — their
// vendorprofile entries declared no `platform_contains`, so DialectForPlatform
// could never land on them and the strings below resolved onto cisco/ios or onto
// nothing. Those profiles now carry detection strings, so every entry here
// resolves to its own dialect; plan_reach_test.go is the guard that keeps it
// that way for every authored dialect, not just these three.
var planPlatformText = map[string]string{
	"cisco-asa":        "Cisco Adaptive Security Appliance ASA 5525-X",
	"fortinet-fortios": "FortiGate-60F v7.2.8,build1639,240228 (GA.M)",
	"paloalto-panos":   "Palo Alto Networks PA-220 series firewall",
}

// planDevice builds a device that resolves onto one dialect, so the guard can
// walk every authored plan rather than the one the author happened to think of.
func planDevice(t *testing.T, c *Catalog, dialect string) (Device, bool) {
	t.Helper()
	p, ok := c.PlanFor(dialect)
	if !ok {
		return Device{}, false
	}
	text := p.Display
	if override, has := planPlatformText[dialect]; has {
		text = override
	}
	got, _, resolved := DialectForPlatform(text)
	if !resolved || got != dialect {
		return Device{}, false
	}
	return Device{ID: "dev-" + dialect, Hostname: "dev-" + dialect, Platform: text, TenantID: "t1"}, true
}

// sourceKey is a citation list rendered as one comparable string.
func sourceKey(src []Source) string {
	parts := make([]string, 0, len(src))
	for _, s := range src {
		parts = append(parts, normSourceURL(s.URL))
	}
	return strings.Join(parts, "|")
}

// checkCitations applies the invariant to one set of citation lists: at most
// maxBindingSources per entry, no page repeated inside one, and no two entries
// carrying the SAME list of more than one page — which is what a shared pool
// looks like from the outside.
func checkCitations(t *testing.T, where string, lists map[string][]Source) {
	t.Helper()
	shared := map[string][]string{}
	for _, id := range sortedKeys(lists) {
		src := lists[id]
		if len(src) > maxBindingSources {
			t.Errorf("%s: %q carries %d citations; at most %d may reach a step",
				where, id, len(src), maxBindingSources)
		}
		seen := map[string]bool{}
		for _, s := range src {
			k := normSourceURL(s.URL)
			if seen[k] {
				t.Errorf("%s: %q cites %s twice", where, id, s.URL)
			}
			seen[k] = true
		}
		if len(src) > 1 {
			key := sourceKey(src)
			shared[key] = append(shared[key], id)
		}
	}
	for key, ids := range shared {
		if len(ids) > 1 {
			t.Errorf("%s: %v share one identical citation list (%s) — that is a citation pool "+
				"riding on the steps, not a per-command citation", where, ids, key)
		}
	}
}

// TestNoBindingCarriesTheDialectPool proves the invariant at the SOURCE — every
// authored dialect, reachable or not — the source of truth is the plan file.
func TestNoBindingCarriesTheDialectPool(t *testing.T) {
	c := mustCatalog(t)
	for _, dialect := range c.Dialects() {
		p, ok := c.PlanFor(dialect)
		if !ok {
			t.Fatalf("dialect %s is listed but carries no plan", dialect)
		}
		lists := map[string][]Source{}
		for intent, b := range p.Bindings {
			if len(b.Sources) > 0 {
				lists[intent] = b.Sources
			}
		}
		checkCitations(t, "dialect "+dialect, lists)
	}
}

// TestNoStepCarriesTheDialectPool walks EVERY reachable dialect × EVERY class and
// proves that no step was handed the pack's bibliography.
func TestNoStepCarriesTheDialectPool(t *testing.T) {
	c := mustCatalog(t)
	walked, unreachable := 0, 0
	for _, dialect := range c.Dialects() {
		dev, ok := planDevice(t, c, dialect)
		if !ok {
			if _, expected := planPlatformText[dialect]; !expected {
				t.Errorf("dialect %s: no platform string resolves back onto it, and it is not "+
					"one of the known-unreachable dialects — add it to planPlatformText", dialect)
			}
			unreachable++
			continue
		}
		for _, cl := range c.Classes() {
			for _, optional := range []bool{false, true} {
				p, err := c.Plan(cl.ID, dev, PlanOptions{IncludeOptional: optional})
				if err != nil {
					t.Fatalf("%s/%s: plan: %v", dialect, cl.ID, err)
				}
				walked++
				lists := map[string][]Source{}
				for _, st := range append(append([]Step(nil), p.Steps...), p.Unbound...) {
					if len(st.Sources) > 0 {
						lists[st.Intent] = st.Sources
					}
				}
				checkCitations(t, dialect+"/"+cl.ID, lists)
			}
		}
	}
	t.Logf("walked %d plans across %d dialects (%d unreachable from a platform string)",
		walked, len(c.Dialects())-unreachable, unreachable)
	if walked == 0 {
		t.Fatal("no plan was walked; the guard proved nothing")
	}
}

// TestPackCitationsAreUnique reads the AUTHORED FILES, not the loaded catalog,
// so it fails on a pack that repeats a page even though the loader would fold
// it. That is the failure that actually happened: the merge appended the same
// citation set on every run and nothing noticed for six runs.
func TestPackCitationsAreUnique(t *testing.T) {
	names, err := fs.Glob(tacdata.FS, "plans/*.yaml")
	if err != nil || len(names) == 0 {
		t.Fatalf("no authored plans found: %v", err)
	}
	for _, name := range names {
		raw, rerr := fs.ReadFile(tacdata.FS, name)
		if rerr != nil {
			t.Fatalf("%s: %v", name, rerr)
		}
		doc, perr := parseYAML(string(raw))
		if perr != nil {
			t.Fatalf("%s: %v", name, perr)
		}
		check := func(where string, n *ynode) {
			items, lerr := ylist(n, "sources")
			if lerr != nil {
				t.Errorf("%s %s: %v", name, where, lerr)
				return
			}
			seen := map[string]bool{}
			for _, it := range items {
				url, uerr := ystr(it, "url")
				if uerr != nil {
					t.Errorf("%s %s: %v", name, where, uerr)
					continue
				}
				k := normSourceURL(url)
				if seen[k] {
					t.Errorf("%s %s cites %s more than once — a citation list that repeats a page "+
						"is a merge that appended instead of comparing", name, where, url)
				}
				seen[k] = true
			}
		}
		check("plan sources", doc)
		if bn, merr := ymap(doc, "bindings"); merr == nil && bn != nil {
			for _, intent := range bn.keys {
				check("binding "+intent, bn.m[intent])
			}
		}
	}
}

// TestNokiaSpine1PlanStaysReadable is the owner's own case, pinned. The numbers
// are the ones the escalation preview renders, so a regression that puts the
// pool back on the steps fails HERE with the count that made the page unusable.
func TestNokiaSpine1PlanStaysReadable(t *testing.T) {
	c := mustCatalog(t)
	dev := Device{ID: "spine1", Hostname: "spine1", Platform: "Nokia SR Linux", TenantID: "t1"}
	p, err := c.Plan("ospf-adjacency", dev, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if p.Dialect != "nokia-srlinux" {
		t.Fatalf("dialect = %q, want nokia-srlinux", p.Dialect)
	}
	links := 0
	for _, st := range p.Steps {
		links += len(st.Sources)
	}
	ceiling := len(p.Steps) * maxBindingSources
	t.Logf("nokia-srlinux spine1/ospf-adjacency: steps=%d source links=%d (ceiling %d) unbound=%d",
		len(p.Steps), links, ceiling, len(p.Unbound))
	if links > ceiling {
		t.Fatalf("the preview would render %d links across %d steps; the ceiling is %d", links, len(p.Steps), ceiling)
	}
}
