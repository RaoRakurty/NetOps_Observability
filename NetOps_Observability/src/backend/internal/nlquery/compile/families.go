// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// families.go — the question families the grammar was missing (hybrid NLU
// plan A4), each found as a real dead end in the lab's query log:
//
//   - severity: "critical / severe / major / urgent / P1" incidents. There is
//     no severity column; owner decision D1 maps them onto verdict_tier =
//     confirmed, and the reading is disclosed every time.
//   - inventory: "how many devices are onboarded", "how many devices can you
//     see", "list the sites" → entity_count / entity_list over the caller's
//     own visible inventory.
//   - superlatives: "which interfaces are busiest" — a superlative with no
//     metric word names the metric (catalog superlatives) and a ranking; with
//     no number the top 5, disclosed.
//   - lookup: "I cannot find RETAIL", "where is edge-1" — a bare name. Found:
//     that entity, listed. Not found in the caller's scope: said so (foreign ≡
//     missing), never Unparsed.

import (
	"regexp"
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/nlquery/resolve"
)

// ---- severity ------------------------------------------------------------------

// severityRe are the severity words an operator uses for incidents.
var severityRe = regexp.MustCompile(`\b(?:critical|severe|major|urgent|high-priority|high priority|highest priority|p1|sev1|sev 1)\b`)

// SeverityMeaning is what a severity word is read as (owner decision D1).
const SeverityMeaning = "confirmed incidents"

// severityFilter adds verdict_tier = confirmed for a severity word, unless the
// question already names a tier, and discloses the reading.
func (s *state) severityFilter(q *ast.AST, text string) {
	m := severityRe.FindString(text)
	if m == "" {
		return
	}
	s.e.re(severityRe, text)
	for _, f := range q.Filters {
		if f.Field == "verdict_tier" {
			return // an explicit tier wins; the severity word adds nothing
		}
	}
	q.Filters = append(q.Filters, ast.Filter{Field: "verdict_tier", Op: "eq", Values: []string{"confirmed"}})
	s.readings = append(s.readings, lex.Reading{From: m, To: SeverityMeaning, Kind: lex.KindSeverity})
}

// ---- inventory -----------------------------------------------------------------

var (
	countLeadRe = regexp.MustCompile(`^(?:so\s+)?(?:how many|count(?: of| the| all)?|number of|the number of|total(?: number of)?)\b`)
	listLeadRe  = regexp.MustCompile(`^(?:so\s+)?(?:list|show|display|give|tell|which|what)\b`)
	// invQualRe are the words that say "the inventory you know about".
	invQualRe = regexp.MustCompile(`\b(?:onboarded|discovered|monitored|managed|visible|known|in (?:the |your |our )?inventory|can you see|do you see|you can see|you see|can i see|i can see|do we have|we have|do i have|i have|are there|there are|in total|total|altogether|all|of them)\b`)
	// invTargetRes name WHAT is counted. Only the generic nouns: a role word
	// ("routers", "firewalls") would need a role filter the inventory does not
	// carry, so it is left not understood rather than answered for every device.
	invTargetRes = []struct {
		re     *regexp.Regexp
		target string
	}{
		{regexp.MustCompile(`\b(?:devices?|boxes|nodes|network devices)\b`), "device"},
		{regexp.MustCompile(`\b(?:sites?|locations?)\b`), "site"},
		{regexp.MustCompile(`\b(?:circuits?|wan links?)\b`), "circuit"},
	}
	invPerSiteRe = regexp.MustCompile(`\b(?:per|by|for each|each|grouped by|broken down by)\s+(?:site|location)\b`)
)

// inventory compiles "how many devices …" / "list the sites …". ok is false
// when the question is not an inventory question at all.
func (s *state) inventory() (Result, bool, error) {
	count := countLeadRe.MatchString(s.text)
	if !count && !listLeadRe.MatchString(s.text) {
		return Result{}, false, nil
	}
	target := ""
	what := invPerSiteRe.ReplaceAllString(s.text, " ") // "per site" groups, it is not counted
	for _, t := range invTargetRes {
		if t.re.MatchString(what) {
			if target != "" && target != t.target {
				return Result{}, false, nil // two kinds named: not one count
			}
			target = t.target
		}
	}
	if target == "" {
		return Result{}, false, nil
	}
	refs, clarify, err := s.mentions([]string{"site", "device"})
	if err != nil {
		return Result{}, true, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "count_entities", Clarify: clarify}, true, nil
	}
	for _, t := range invTargetRes {
		if t.target == target {
			s.e.re(t.re, what)
		}
	}
	s.e.re(countLeadRe, s.text)
	s.e.re(listLeadRe, s.text)
	s.e.re(invQualRe, s.text)
	q := &ast.AST{V: 1, Type: ast.EntityList, Target: target, Refs: astRefs(refs)}
	intent := "list_entities"
	if count {
		q.Type, intent = ast.EntityCount, "count_entities"
		if target != "site" && s.e.re(invPerSiteRe, s.text) {
			q.GroupBy = []string{"site"}
		}
	}
	return Result{Intent: intent, AST: q, Entities: refs}, true, nil
}

// ---- superlatives --------------------------------------------------------------

// superlativeMetric finds a catalog superlative ("busiest", "slowest") in a
// question that names no metric: the metrics it can mean (disjoint entity
// types; the target word decides) and the word itself.
func (c Compiler) superlativeMetric(text string) ([]catalog.AliasHit, string) {
	best, word := []catalog.AliasHit(nil), ""
	for _, m := range c.Cat.Metrics {
		for _, sup := range m.Superlatives {
			if !containsPhrase(text, sup) || len(sup) < len(word) {
				continue
			}
			if len(sup) > len(word) {
				best, word = nil, sup
			}
			best = append(best, catalog.AliasHit{Kind: "metric", Name: m.Name, For: strings.Join(m.EntityTypes, ",")})
		}
	}
	return best, word
}

// DefaultSuperlativeN is how many a superlative with no number ranks.
const DefaultSuperlativeN = 5

// ---- lookup / not found ----------------------------------------------------------

// lookupRe is a bare request for one named thing.
var lookupRe = regexp.MustCompile(`^(?:i (?:cannot|can't|cant|can not|could not|couldn't|don't|dont) (?:find|see|locate)|where is|where's|wheres|find|locate|look up|lookup|search for|show me|show)\s+(?:the\s+)?(.{2,64})$`)

// NotFound names what a lookup found nothing for in the caller's scope.
type NotFound struct {
	// Name is the words as the operator typed them (their casing).
	Name string `json:"name"`
}

// lookup answers a bare name. ok is false when the question is not one.
func (c Compiler) lookup(s *state) (Result, bool, error) {
	m := lookupRe.FindStringSubmatch(s.text)
	if m == nil {
		return Result{}, false, nil
	}
	phrase := strings.TrimSpace(m[1])
	words := strings.Fields(phrase)
	if len(words) > 3 {
		return Result{}, false, nil
	}
	voc := Vocabulary(c.Cat)
	for _, w := range words {
		if voc.Has(w) || questionVocab[w] {
			return Result{}, false, nil // a word of the grammar, not a name
		}
	}
	res, err := c.R.Resolve(s.ctx, phrase, []string{"site", "device", "circuit", "application", "provider"})
	if err != nil {
		return Result{}, true, err
	}
	if len(res.Refs) > 0 && !allNeedConfirmation(res.Refs) {
		if res.Ambiguous {
			return Result{Intent: "lookup", Clarify: res.Refs}, true, nil
		}
		r := res.Refs[0]
		if r.EntityType != "site" && r.EntityType != "device" && r.EntityType != "circuit" {
			return Result{}, false, nil // no inventory answer for it; left to the rest
		}
		s.e.phrase(m[0])
		q := &ast.AST{V: 1, Type: ast.EntityList, Target: r.EntityType, Refs: astRefs([]resolve.Ref{r})}
		return Result{Intent: "lookup", AST: q, Entities: []resolve.Ref{r}}, true, nil
	}
	// Nothing the caller can see by that name. The answer is the same whether
	// it exists for someone else or nowhere (§3a), and any candidate offered
	// comes from the caller's own scope.
	out := Result{Intent: "lookup", NotFound: &NotFound{Name: rawCasing(s.raw, phrase)}}
	if len(res.Refs) > 0 {
		refs := res.Refs
		if len(refs) > resolve.MaxSuggestions {
			refs = refs[:resolve.MaxSuggestions]
		}
		out.DidYouMean = []Suggestion{{Word: phrase, Refs: refs}}
	}
	return out, true, nil
}

// rawCasing returns phrase as the operator typed it, when it can be found in
// the raw question by a case-insensitive whole match; else the folded phrase.
func rawCasing(raw, phrase string) string {
	if m := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(phrase)).FindString(raw); m != "" {
		return m
	}
	return phrase
}

// NotFoundAnswer is the answer to a lookup that found nothing in the caller's
// scope. It is the same sentence for a name another tenant has and one nobody
// has (§3a: foreign ≡ missing); the only names it offers are the caller's own
// near matches.
func NotFoundAnswer(r Result) string {
	if r.NotFound == nil {
		return ""
	}
	name := r.NotFound.Name
	var b strings.Builder
	b.WriteString("I can't find \"" + name + "\" among the devices, sites, circuits or applications you can see.")
	var names []string
	for _, d := range r.DidYouMean {
		for _, ref := range d.Refs {
			names = append(names, ref.EntityID)
		}
	}
	if len(names) > 0 {
		b.WriteString(" Did you mean " + strings.Join(names, " or ") + "?")
	}
	b.WriteString(" If \"" + name + "\" is a workspace, switch to it from the workspace menu and ask again.")
	return b.String()
}
