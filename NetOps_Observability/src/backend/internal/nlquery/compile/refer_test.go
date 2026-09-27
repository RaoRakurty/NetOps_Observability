// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// refer_test.go — references to earlier turns (tracker 337 N-C7).
//
// Pinned: outside a conversation a referential phrase is NEVER framing
// vocabulary (it made "cpu on it" mean "cpu on every device"); inside one it
// binds deterministically, by type, from the server-held state only; an
// existential "there" is not a reference; and the incident on screen stays
// the referent of "it" / "they" in a change question.

import (
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

func withConv(conv *Conversation) Context {
	x := cx
	x.Conv = conv
	return x
}

func refIDs(q *ast.AST) string {
	var ids []string
	for _, r := range q.Refs {
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ",")
}

func filterOf(q *ast.AST, field string) *ast.Filter {
	for i := range q.Filters {
		if q.Filters[i].Field == field {
			return &q.Filters[i]
		}
	}
	return nil
}

func TestAReferenceWithNothingToPointAtIsNotUnderstood(t *testing.T) {
	for q, phrase := range map[string]string{
		"show cpu on it":                 "it",
		"cpu on that device":             "that device",
		"what changed there":             "there",
		"show latency on those circuits": "those circuits",
		"what else did they change":      "they",
		"memory on the same router":      "the same router",
	} {
		r := run(t, q, cx)
		if r.AST != nil || !r.Unparsed {
			t.Errorf("%q must not compile without a conversation (it would widen), got intent=%s ast=%v", q, r.Intent, r.AST != nil)
			continue
		}
		found := false
		for _, w := range r.NotUnderstood {
			found = found || w == phrase
		}
		if !found {
			t.Errorf("%q: not-understood %v must name %q", q, r.NotUnderstood, phrase)
		}
	}
}

func TestExistentialThereIsNotAReference(t *testing.T) {
	for _, q := range []string{
		"are there any incidents right now", "were there changes today", "is there packet loss on edge-1",
		"have there been any config changes this week",
	} {
		r := run(t, q, cx)
		for _, w := range r.NotUnderstood {
			if w == "there" {
				t.Errorf("%q: existential there reported as an unbound reference", q)
			}
		}
	}
}

var conv = &Conversation{
	Entities: []ast.EntityRef{
		{Type: "device", ID: "device:edge-1"},
		{Type: "circuit", ID: "circuit:c1"},
		{Type: "site", ID: "site:dfw-hq"},
		{Type: "circuit", ID: "circuit:c2"},
		{Type: "device", ID: "device:edge-2"},
	},
	Actors:    []string{"alice"},
	ChangeIDs: []string{"chg-1", "chg-2"},
}

func TestReferencesBindFromTheConversation(t *testing.T) {
	for _, tc := range []struct{ q, want string }{
		{"show cpu on it", "device:edge-1"},                         // untyped: most recent usable entity
		{"cpu on that device", "device:edge-1"},                     // typed: most recent of the type
		{"what changed there", "site:dfw-hq"},                       // there = a site
		{"show latency on those circuits", "circuit:c1,circuit:c2"}, // plural: every recent one of the type
		{"memory on the same router", "device:edge-1"},
	} {
		r := run(t, tc.q, withConv(conv))
		if r.AST == nil || r.Unparsed {
			t.Errorf("%q must compile inside the conversation, got unparsed=%v %v", tc.q, r.Unparsed, r.NotUnderstood)
			continue
		}
		if got := refIDs(r.AST); got != tc.want {
			t.Errorf("%q bound %q, want %q", tc.q, got, tc.want)
		}
		for _, e := range r.Entities {
			if e.EntityID == strings.Split(tc.want, ",")[0] && e.Method != MethodConversation {
				t.Errorf("%q: a bound reference must say it came from the conversation, got %q", tc.q, e.Method)
			}
		}
	}
}

func TestATypedReferenceNeverBindsAnotherType(t *testing.T) {
	onlySite := &Conversation{Entities: []ast.EntityRef{{Type: "site", ID: "site:dfw-hq"}}}
	if r := run(t, "cpu on that device", withConv(onlySite)); r.AST != nil || !r.Unparsed {
		t.Fatalf("a site is not 'that device': %+v", r)
	}
}

func TestWhatElseDidTheyChange(t *testing.T) {
	r := run(t, "what else did they change", withConv(conv))
	if r.AST == nil || r.AST.Type != ast.ChangeList {
		t.Fatalf("want a change list, got %+v", r)
	}
	if f := filterOf(r.AST, "actor"); f == nil || strings.Join(f.Values, ",") != "alice" {
		t.Errorf("they = the previous turn's actors, got %+v", f)
	}
	if f := filterOf(r.AST, "id"); f == nil || f.Op != "ne" || strings.Join(f.Values, ",") != "chg-1,chg-2" {
		t.Errorf("else = excluding the changes already shown, got %+v", f)
	}
	// Without actors to point at, "they" is not guessed.
	if r := run(t, "what else did they change", withConv(&Conversation{ChangeIDs: []string{"chg-1"}})); r.AST != nil {
		t.Errorf("no actors in the conversation: they must stay unbound, got %+v", r.AST)
	}
}

// With an incident on screen AND a previous change list, "they" are the
// people that list showed — the incident only takes the pronouns left over.
func TestConversationActorsOutrankTheIncidentOnScreen(t *testing.T) {
	x := withConv(&Conversation{Actors: []string{"jsmith"}, ChangeIDs: []string{"chg-1042"}})
	x.IncidentID = "11111111-2222-4333-8444-555555555555"
	r := run(t, "what else did they change", x)
	if r.AST == nil {
		t.Fatalf("must compile: %+v", r)
	}
	if f := filterOf(r.AST, "actor"); f == nil || strings.Join(f.Values, ",") != "jsmith" {
		t.Fatalf("they = the previous list's actor, got %+v", r.AST.Filters)
	}
	if r.AST.Time.Kind == ast.TimeIncident {
		t.Fatal("'what else did they change' is about the people, not the incident window")
	}
}

func TestTheIncidentOnScreenIsThePronounsReferent(t *testing.T) {
	x := cx
	x.IncidentID = "11111111-2222-4333-8444-555555555555"
	for _, q := range []string{"who changed it", "what did they change before this"} {
		r := run(t, q, x)
		if r.AST == nil || r.AST.Time.Kind != ast.TimeIncident {
			t.Errorf("%q with an incident on screen must anchor to it, got %+v", q, r)
		}
	}
}

// The client never supplies conversation state: Compile's only source for it
// is Context.Conv, which the server builds. A plain question is unchanged by
// an empty conversation.
func TestAnEmptyConversationChangesNothing(t *testing.T) {
	for _, q := range []string{"cpu on edge-1 last hour", "what changed today", "open incidents"} {
		a, b := run(t, q, cx), run(t, q, withConv(&Conversation{}))
		if (a.AST == nil) != (b.AST == nil) || (a.AST != nil && a.AST.Hash() != b.AST.Hash()) {
			t.Errorf("%q compiled differently inside an empty conversation", q)
		}
	}
}
