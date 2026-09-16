// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

import (
	"strings"
	"testing"
)

func defaultCatalogForLookup(t *testing.T) *Catalog {
	t.Helper()
	c, err := Default()
	if err != nil {
		t.Fatalf("Default catalogue: %v", err)
	}
	return c
}

func firstClassWithProtocol(c *Catalog, proto string) (Class, bool) {
	for _, cl := range c.Classes() {
		if strings.EqualFold(cl.Protocol, proto) && cl.ID != GenericClassID {
			return cl, true
		}
	}
	return Class{}, false
}

func TestLookupFindsTheProtocolClassForAPlainQuestion(t *testing.T) {
	c := defaultCatalogForLookup(t)
	want, ok := firstClassWithProtocol(c, "bgp")
	if !ok {
		t.Skip("catalogue carries no BGP class")
	}
	hits := c.Lookup("BGP session will not come up to the upstream", 3)
	if len(hits) == 0 {
		t.Fatal("a BGP question retrieved no TAC knowledge")
	}
	found := false
	for _, h := range hits {
		if strings.EqualFold(h.Protocol, want.Protocol) {
			found = true
			if len(h.Intents) == 0 {
				t.Errorf("hit %s carries no intents — the knowledge is the checks", h.ClassID)
			}
			for _, in := range h.Intents {
				if in.Command != "" {
					t.Errorf("no vendor was named, but %s carries a command %q", in.ID, in.Command)
				}
			}
		}
	}
	if !found {
		t.Errorf("no BGP-protocol class among %v", hits)
	}
}

func TestLookupResolvesANamedVendorToItsBoundCommands(t *testing.T) {
	c := defaultCatalogForLookup(t)
	for _, slug := range c.Dialects() {
		p, _ := c.PlanFor(slug)
		if p == nil || len(p.Bindings) == 0 {
			continue
		}
		hits := c.Lookup("BGP neighbour down on "+p.Display+" spine1", 3)
		if len(hits) == 0 {
			continue
		}
		if hits[0].Dialect != p.Display {
			t.Errorf("question named %q, hit carries dialect %q", p.Display, hits[0].Dialect)
		}
		bound := 0
		for _, h := range hits {
			for _, in := range h.Intents {
				if in.Command != "" {
					bound++
					if b, ok := p.Bound(in.ID); !ok || b.Command != in.Command {
						t.Errorf("%s: command %q is not the authored binding", in.ID, in.Command)
					}
				}
			}
		}
		if bound > 0 {
			return // one dialect with retrievable commands proves the join
		}
	}
	t.Skip("no dialect binds a command for any BGP intent")
}

func TestLookupPrefersTheLongestDialectName(t *testing.T) {
	c := defaultCatalogForLookup(t)
	var xe, ios *DialectPlan
	for _, slug := range c.Dialects() {
		p, _ := c.PlanFor(slug)
		switch p.Display {
		case "Cisco IOS-XE":
			xe = p
		case "Cisco IOS":
			ios = p
		}
	}
	if xe == nil || ios == nil {
		t.Skip("catalogue does not carry both Cisco IOS and IOS-XE")
	}
	if got := c.dialectIn("interface flapping on a Cisco IOS-XE router"); got != xe {
		t.Fatalf("IOS-XE question resolved to %v", got)
	}
}

func TestLookupRetrievesNothingForAnOffTopicQuestion(t *testing.T) {
	c := defaultCatalogForLookup(t)
	for _, q := range []string{"", "   ", "what is the weather in paris tomorrow", "please export last month's invoice"} {
		if hits := c.Lookup(q, 3); len(hits) != 0 {
			t.Errorf("%q retrieved %d TAC classes, want none", q, len(hits))
		}
	}
}

func TestLookupIsBoundedAndNilSafe(t *testing.T) {
	c := defaultCatalogForLookup(t)
	if hits := c.Lookup("interface errors optics bgp ospf cpu memory", 2); len(hits) > 2 {
		t.Errorf("limit 2 returned %d hits", len(hits))
	}
	var nilCat *Catalog
	if hits := nilCat.Lookup("bgp down", 3); hits != nil {
		t.Errorf("nil catalogue returned %v", hits)
	}
}
