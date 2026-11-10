// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"strings"
	"testing"
)

func TestFold(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Show CPU", "show cpu"},
		{"Zürich São Paulo Kraków", "zurich sao paulo krakow"},
		{"what’s wrong", "what's wrong"},
		{"“quoted”", " quoted "},
		{"edge–1", "edge-1"},
		{"STRAßE", "strasse"},
		{"日本", "日本"}, // other scripts pass through
	} {
		if got := Fold(c.in); got != c.want {
			t.Errorf("Fold(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Every fold rule of the grammar's normaliser, one row each — the rules the
// compiler had before (punctuation, sd-wan, possessives) and the new ones
// (accents, contractions, number words).
func TestNormalize(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"  Show CPU on edge-1?  ", "show cpu on edge-1"},
		{"latency, jitter; loss!", "latency jitter loss"},
		{"SD-WAN tunnels", "sdwan tunnels"},
		{"sd wan tunnels", "sdwan tunnels"},
		{"Dallas's routers", "dallas routers"},
		{"what's wrong", "what wrong"}, // the grammar has always dropped the possessive 's
		{"we're seeing loss", "we are seeing loss"},
		{"top five interfaces", "top 5 interfaces"},
		{"last twenty four hours", "last 24 hours"},
		{"last twenty-four hours", "last 24 hours"},
		{"top twenty", "top 20"},
		{"which one", "which one"}, // "one" points, it does not count
		{"ge-0/0/1 at 10.0.0.1 90% user@site at&t", "ge-0/0/1 at 10.0.0.1 90% user@site at&t"},
		{"cpu (avg) <edge-1>", "cpu avg edge-1"},
		{"memory on Zürich-fw.", "memory on zurich-fw"},
		{"  multiple    spaces  ", "multiple spaces"},
		{"", ""},
	} {
		got := Normalize(c.in)
		if got.Norm != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got.Norm, c.want)
		}
		if got.Raw != c.in {
			t.Errorf("Raw must be the question as asked: %q", got.Raw)
		}
		if strings.Join(got.Tokens, " ") != got.Norm {
			t.Errorf("Tokens %q disagree with Norm %q", got.Tokens, got.Norm)
		}
	}
}

func TestSquashFoldsNameVariants(t *testing.T) {
	for _, v := range []string{"edge1", "edge-1", "EDGE_1", "edge 1", "Edge.1", "edge–1"} {
		if got := Squash(v); got != "edge1" {
			t.Errorf("Squash(%q) = %q, want edge1", v, got)
		}
	}
	if Squash("edge-1") == Squash("edge-11") {
		t.Error("different names must not share a key")
	}
	if got := Squash("Zürich-HQ"); got != "zurichhq" {
		t.Errorf("Squash folds accents: %q", got)
	}
}

func TestTokensKeepIdentifiers(t *testing.T) {
	got := strings.Join(Tokens("CPU on edge-1. And ge-0/0/1, 10.0.0.1? Zürich!"), "|")
	if want := "cpu|on|edge-1|and|ge-0/0/1|10.0.0.1|zurich"; got != want {
		t.Errorf("Tokens = %q, want %q", got, want)
	}
}

func TestSingular(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"incidents", "incident"}, {"switches", "switch"}, {"policies", "policy"}, {"boxes", "box"},
		{"status", "status"}, {"class", "class"}, {"dns", "dns"}, {"bus", "bus"}, {"analysis", "analysis"},
		{"cpu", "cpu"}, {"devices", "device"}, {"peers", "peer"},
	} {
		if got := Singular(c.in); got != c.want {
			t.Errorf("Singular(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNumberWord(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{{"five", 5, true}, {"twenty", 20, true}, {"twenty-four", 24, true}, {"one", 0, false}, {"fivefold", 0, false}, {"twenty-ten", 0, false}} {
		got, ok := NumberWord(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NumberWord(%q) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "abc", 0}, {"abc", "acb", 1}, {"kitten", "sitting", 3}, {"cpu", "cpu_util_pct", 9},
		{"shwo", "show", 1}, {"isues", "issues", 1}, {"incidentes", "incidents", 1}, {"dalas", "dallas", 1}} { //nolint:misspell // typos under test
		if got := Distance(c.a, c.b); got != c.d {
			t.Errorf("Distance(%q,%q)=%d want %d", c.a, c.b, got, c.d)
		}
	}
}

func TestClassifierTextKeepsClausePunctuation(t *testing.T) {
	if got := ClassifierText("  What’s   DOWN?  Show me "); got != "what's down? show me" {
		t.Errorf("ClassifierText = %q", got)
	}
}
