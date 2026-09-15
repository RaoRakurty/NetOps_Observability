// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// lookup.go — the catalogue as KNOWLEDGE Iris reads before it answers.
//
// Until 2026-09-15 the issue-class taxonomy, the intent vocabulary and the
// per-vendor bound commands were rendered on an Iris → Knowledge page for an
// operator to read, and Iris itself never consulted them. The owner's call: the
// knowledge is Iris's, built in; an administrator should not have to read it.
// This is the retrieval half — pure, deterministic, no tenant data.
//
// Scoring mirrors the playbook retriever's shape (term hits weighted by where
// they land, a floor so an off-topic question retrieves nothing rather than a
// bad match): protocol token 4, class title 2, class summary / first-look 1,
// intent title 1 (capped). A vendor named in the question resolves to that
// dialect's authored plan, so the hit carries the actual bound commands with
// their honesty labels (verified on a capture vs documented only) and the
// consent flag for heavy collections. Commands the output-only policy removed
// are not in the catalogue, so they cannot be retrieved.

import (
	"sort"
	"strings"
	"unicode"
)

// LookupIntent is one check a vendor TAC runs for a class, with the command for
// the dialect the question named (empty when no vendor was named or the dialect
// has no binding for it).
type LookupIntent struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Area     string   `json:"area"`
	Command  string   `json:"command,omitempty"`
	Verified Verified `json:"verified,omitempty"`
	Consent  bool     `json:"consent,omitempty"`
}

// LookupHit is one issue class that matched a question.
type LookupHit struct {
	ClassID   string         `json:"class_id"`
	Title     string         `json:"title"`
	Protocol  string         `json:"protocol"`
	Summary   string         `json:"summary,omitempty"`
	FirstLook string         `json:"tac_first_look,omitempty"`
	Dialect   string         `json:"dialect,omitempty"`
	Score     int            `json:"score"`
	Intents   []LookupIntent `json:"intents"`
}

const (
	lookupFloor         = 4
	lookupIntentCap     = 3
	lookupMaxIntentsHit = 6
)

var lookupStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
	"how": true, "what": true, "why": true, "does": true, "not": true, "will": true,
	"are": true, "was": true, "from": true, "into": true, "have": true, "has": true,
	"can": true, "our": true, "you": true, "your": true, "about": true, "when": true,
	"device": true, "network": true, "issue": true, "problem": true, "troubleshoot": true,
}

// lookupTerms lowercases and splits on anything that is not a letter or digit,
// keeping protocol-sized tokens (bgp, mtu) and dropping stopwords.
func lookupTerms(s string) []string {
	f := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	out := make([]string, 0, len(f))
	seen := map[string]bool{}
	for _, t := range f {
		if len(t) < 3 || lookupStopwords[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func compact(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// dialectIn returns the authored dialect the question names, preferring the
// longest match so "Cisco IOS-XE" wins over "Cisco IOS". A vendor's product
// name alone (srlinux, junos, fortios) counts when it is distinctive (≥ 5
// characters); short product names (eos, vrp, asa) need the vendor too.
func (c *Catalog) dialectIn(question string) *DialectPlan {
	q := compact(question)
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(question), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	}) {
		words[strings.ReplaceAll(w, "-", "")] = true
	}
	var best *DialectPlan
	bestLen := 0
	for _, slug := range c.planOrder {
		p := c.plans[slug]
		if p == nil {
			continue
		}
		full := compact(p.Display)
		matched := len(full) >= 5 && strings.Contains(q, full)
		if !matched {
			parts := strings.Fields(p.Display)
			if len(parts) > 1 {
				product := compact(strings.Join(parts[1:], ""))
				if len(product) >= 5 && (strings.Contains(q, product) || words[product]) {
					matched = true
				}
			}
		}
		if !matched && len(compact(slug)) >= 5 && strings.Contains(q, compact(slug)) {
			matched = true
		}
		if matched && len(full) > bestLen {
			best, bestLen = p, len(full)
		}
	}
	return best
}

// Lookup returns the issue classes a question is about, strongest first, at
// most `limit`. It never errors: an off-topic question returns nothing.
func (c *Catalog) Lookup(query string, limit int) []LookupHit {
	if c == nil || strings.TrimSpace(query) == "" {
		return nil
	}
	terms := lookupTerms(query)
	if len(terms) == 0 {
		return nil
	}
	plan := c.dialectIn(query)
	var hits []LookupHit
	for _, cl := range c.Classes() {
		if cl.ID == GenericClassID {
			continue
		}
		proto := strings.ToLower(cl.Protocol)
		title := strings.ToLower(cl.Title)
		prose := strings.ToLower(cl.Summary + " " + cl.TACFirstLook)
		score, intentScore := 0, 0
		for _, t := range terms {
			if proto != "" && t == proto {
				score += 4
			}
			if strings.Contains(title, t) {
				score += 2
			}
			if strings.Contains(prose, t) {
				score++
			}
			for _, id := range cl.Intents {
				if in, ok := c.Intent(id); ok && intentScore < lookupIntentCap && strings.Contains(strings.ToLower(in.Title), t) {
					intentScore++
				}
			}
		}
		score += intentScore
		if score < lookupFloor {
			continue
		}
		hit := LookupHit{ClassID: cl.ID, Title: cl.Title, Protocol: cl.Protocol,
			Summary: cl.Summary, FirstLook: cl.TACFirstLook, Score: score, Intents: []LookupIntent{}}
		if plan != nil {
			hit.Dialect = plan.Display
		}
		for _, id := range cl.Intents {
			if len(hit.Intents) >= lookupMaxIntentsHit {
				break
			}
			in, ok := c.Intent(id)
			if !ok {
				continue
			}
			li := LookupIntent{ID: in.ID, Title: in.Title, Area: in.Area}
			if plan != nil {
				if b, bound := plan.Bound(in.ID); bound {
					li.Command, li.Verified, li.Consent = b.Command, b.Verified, b.Consent
				}
			}
			hit.Intents = append(hit.Intents, li)
		}
		hits = append(hits, hit)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].ClassID < hits[j].ClassID
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}
