// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// refer.go — references to earlier turns ("that device", "it", "there",
// "those circuits", "what else did they change"), tracker 337 N-C7.
//
// The honesty rule, extended: a word that POINTS at something ("it", "that
// site", "them") carries meaning only if it can be bound to a concrete entity.
// Before this file those words were framing vocabulary, so "show cpu on it"
// compiled to CPU on EVERY device — the silent widening coverage exists to
// prevent. Now every referential occurrence must be BOUND, from the
// server-held conversation (never the client, never the transcript), or it is
// a leftover and the question is Unparsed, naming the phrase.
//
// Binding is deterministic: a typed phrase ("that site") takes the most
// recent entity of that type; an untyped one ("it") the most recent entity of
// a type the question can use; a plural ("those circuits", "them") every
// recent entity of that one type. "They" in a change question means the
// people who made the previous turn's changes.

import (
	"regexp"
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/resolve"
)

// MethodConversation marks a reference bound from an earlier turn.
const MethodConversation = "conversation"

// Bounds on what one turn may carry forward.
const (
	MaxConversationEntities = 20
	MaxConversationActors   = 20 // = validate.MaxFilterValues
	MaxConversationChanges  = 20 // = validate.MaxFilterValues
	maxPluralBind           = 10
)

// Conversation is the structured state a follow-up may point at. The server
// builds it from its own record of earlier turns; it is never prose and never
// supplied by the client.
type Conversation struct {
	// Entities, most recent first: what earlier turns asked about or returned.
	Entities []ast.EntityRef
	// Actors who made the changes the previous turn listed.
	Actors []string
	// ChangeIDs the previous turn listed ("what ELSE did they change").
	ChangeIDs []string
}

// reference is one referential phrase in the question.
type reference struct {
	phrase string
	words  []string
	typ    string // catalog entity type; "" = any type the question can use
	plural bool
	actor  bool // "they" / "them" as the people who made changes
	// singular marks "he" / "she" / "him" / "her": ONE person. It binds only
	// when the previous change list shows exactly one actor — with several,
	// picking one would be a guess and taking all would widen.
	singular bool
	bound    bool
}

var (
	demonstrativeRe = regexp.MustCompile(`\b(?:that|this|those|these|the same|same)\s+(device|router|switch|firewall|box|site|location|branch|office|circuit|link|interface|port|peer|neighbor|provider|carrier|isp|app|application)(s?)\b`)
	bareRe          = regexp.MustCompile(`\b(it|them|there|they|those|these)\b`)
	existentialPre  = regexp.MustCompile(`\b(?:is|are|was|were|any|been|be)\s+$`)
	existentialPost = regexp.MustCompile(`^\s+(?:is|are|was|were|been|be|any|a|an|some|many|no|more|anything|problems?|issues?|changes?|incidents?|outages?)\b`)
	singularActorRe = regexp.MustCompile(`\b(he|she|him|her)\b`)
	actorPronounRe  = regexp.MustCompile(`\b(?:did|have|has|had) they\b|\bthey (?:change|changed|make|made|touch|touched|push|pushed|modify|modified|deploy|deployed|edit|edited)\b|\bby them\b`)
	referTypeOf     = map[string]string{
		"device": "device", "router": "device", "switch": "device", "firewall": "device", "box": "device",
		"site": "site", "location": "site", "branch": "site", "office": "site",
		"circuit": "circuit", "link": "circuit", "interface": "interface", "port": "interface",
		"peer": "bgp_peer", "neighbor": "bgp_peer", "provider": "provider", "carrier": "provider", "isp": "provider",
		"app": "application", "application": "application",
	}
)

// findReferences returns every referential phrase in normalized text.
func findReferences(text string) []reference {
	var out []reference
	covered := make([]bool, len(text))
	for _, m := range demonstrativeRe.FindAllStringSubmatchIndex(text, -1) {
		phrase := text[m[0]:m[1]]
		lead := strings.Fields(phrase)[0]
		out = append(out, reference{phrase: phrase, words: strings.Fields(phrase),
			typ:    referTypeOf[text[m[2]:m[3]]],
			plural: lead == "those" || lead == "these" || m[5] > m[4]})
		for i := m[0]; i < m[1]; i++ {
			covered[i] = true
		}
	}
	for _, m := range singularActorRe.FindAllStringSubmatchIndex(text, -1) {
		w := text[m[2]:m[3]]
		out = append(out, reference{phrase: w, words: []string{w}, actor: true, singular: true})
	}
	actorSense := actorPronounRe.MatchString(text)
	for _, m := range bareRe.FindAllStringSubmatchIndex(text, -1) {
		if covered[m[0]] {
			continue
		}
		w := text[m[2]:m[3]]
		switch w {
		case "there":
			if existentialPre.MatchString(text[:m[0]]) || existentialPost.MatchString(text[m[1]:]) {
				continue
			}
		case "they":
			out = append(out, reference{phrase: w, words: []string{w}, actor: true})
			continue
		case "them":
			if actorSense && strings.Contains(text, "by them") {
				out = append(out, reference{phrase: w, words: []string{w}, actor: true})
				continue
			}
		}
		ref := reference{phrase: w, words: []string{w}, plural: w == "them" || w == "those" || w == "these"}
		if w == "there" {
			ref.typ = "site"
		}
		out = append(out, ref)
	}
	return out
}

// bindEntities binds the question's entity references to the conversation,
// for a path that can use the given entity types. Bound references become
// refs (and their words explained); unbound ones stay leftovers.
func (s *state) bindEntities(types []string) []resolve.Ref {
	var out []resolve.Ref
	usable := map[string]bool{}
	for _, t := range types {
		usable[t] = true
	}
	for i := range s.refs {
		r := &s.refs[i]
		if r.bound || r.actor || s.cx.Conv == nil {
			continue
		}
		var picked []ast.EntityRef
		for _, e := range s.cx.Conv.Entities {
			if !usable[e.Type] || (r.typ != "" && e.Type != r.typ) {
				continue
			}
			if len(picked) == 0 {
				picked = append(picked, e)
				if !r.plural {
					break
				}
				continue
			}
			// A plural binds every recent entity of the FIRST match's type.
			if e.Type == picked[0].Type && !containsRef(picked, e) {
				picked = append(picked, e)
			}
			if len(picked) == maxPluralBind {
				break
			}
		}
		if len(picked) == 0 {
			continue
		}
		for _, e := range picked {
			out = append(out, resolve.Ref{InputText: r.phrase, EntityID: e.ID, EntityType: e.Type, Confidence: 1, Method: MethodConversation})
		}
		s.bind(r)
	}
	return out
}

// bindActors binds "they" / "by them" in a change question to the people who
// made the previous turn's changes; ok=false when there is nothing to bind to.
func (s *state) bindActors() ([]string, bool) {
	if s.cx.Conv == nil || len(s.cx.Conv.Actors) == 0 {
		return nil, false
	}
	found := false
	for i := range s.refs {
		r := &s.refs[i]
		if !r.actor || r.bound || (r.singular && len(s.cx.Conv.Actors) != 1) {
			continue
		}
		s.bind(r)
		found = true
	}
	if !found {
		return nil, false
	}
	return s.cx.Conv.Actors, true
}

// bindIncidentPronouns binds the pronouns an on-screen incident answers ("who
// changed it", "what did they change before this") — the incident is their
// referent, and "they" is whoever made changes around it.
func (s *state) bindIncidentPronouns() {
	for i := range s.refs {
		r := &s.refs[i]
		if r.bound || r.typ != "" || r.plural {
			continue
		}
		// "he" with several people in the previous list is not the incident:
		// it is one of them, and which one is not known.
		if r.singular && s.cx.Conv != nil && len(s.cx.Conv.Actors) > 1 {
			continue
		}
		s.bind(r)
	}
}

func (s *state) bind(r *reference) {
	r.bound = true
	if s.e == nil {
		return
	}
	s.e.bind(r.words[0])
	s.e.phrase(r.phrase)
}

// requireReferences makes every referential phrase count as unexplained until
// it is bound, whatever the framing vocabulary says about its words.
func (s *state) requireReferences() {
	s.refs = findReferences(s.text)
	for _, r := range s.refs {
		s.e.require(r.words[0], r.phrase)
	}
}

func containsRef(rs []ast.EntityRef, r ast.EntityRef) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}
