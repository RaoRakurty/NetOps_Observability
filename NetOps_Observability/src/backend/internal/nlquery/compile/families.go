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
	// stateLeadRe opens a question about how devices STAND ("is cedge-81 up",
	// "any devices down", "status of edge-a", "devices down in the last hour").
	stateLeadRe = regexp.MustCompile(`^(?:so\s+)?(?:is|are|any|anything|check|status of|state of|health of|(?:network )?devices?|routers?|switch(?:es)?|firewalls?|boxes|nodes)\b`)
	// invQualRe are the words that say "the inventory you know about".
	invQualRe = regexp.MustCompile(`\b(?:onboarded|discovered|monitored|managed|visible|known|in (?:the |your |our )?inventory|can you see|do you see|you can see|you see|can i see|i can see|do we have|we have|do i have|i have|(?:do|does|are) (?:we|you|i) (?:monitor|manage)(?:ing)?|we (?:monitor|manage)|are there|there are|in total|total|altogether|all|of them|that are|that is|currently|still)\b`)
	// invTargetRes name WHAT is counted.
	invTargetRes = []struct {
		re     *regexp.Regexp
		target string
	}{
		{regexp.MustCompile(`\b(?:devices?|box(?:es)?|nodes|network devices)\b`), "device"},
		{regexp.MustCompile(`\b(?:sites?|locations?)\b`), "site"},
		{regexp.MustCompile(`\b(?:circuits?|wan links?)\b`), "circuit"},
	}
	// invRoleRes are the device-type words: a device count or list filtered by
	// the device's functional type (ast.FilterDeviceType).
	invRoleRes = []struct {
		re  *regexp.Regexp
		typ string
	}{
		{regexp.MustCompile(`\brouters?\b`), "router"},
		{regexp.MustCompile(`\bswitch(?:es)?\b`), "switch"},
		{regexp.MustCompile(`\bfirewalls?\b`), "firewall"},
	}
	invPerSiteRe = regexp.MustCompile(`\b(?:per|by|for each|each|grouped by|broken down by)\s+(?:site|location)\b`)
	// invConnectedRe: "how many devices are connected" — connected to Correlix,
	// i.e. in the inventory (live 2026-11-12). Read as the inventory and
	// disclosed, because "connected" could also mean reachable: the device
	// list carries each device's reachability verdict. "connected to edge-1"
	// is topology (resolve's topology rung), never an inventory count.
	invConnectedRe   = regexp.MustCompile(`\bconnected(?:\s+to\s+(?:correlix|you|us|the platform))?\b`)
	invConnectedToRe = regexp.MustCompile(`\bconnected\s+to\s+`)
	invConnectedUsRe = regexp.MustCompile(`^(?:correlix|you|us|the platform)\b`)

	// Device liveness (ast.FilterReachability). reachDeviceRe are the words
	// only a device can be — they name the target on their own ("anything
	// unreachable"); a bare "down" also fits an incident or an interface.
	reachDownRe   = regexp.MustCompile(`\b(?:down|unreachable|offline|not responding|not reachable|unresponsive|not up)\b`)
	reachUpRe     = regexp.MustCompile(`\b(?:up|reachable|online|alive|responding)\b`)
	reachDeviceRe = regexp.MustCompile(`\b(?:unreachable|offline|not responding|not reachable|unresponsive)\b`)
	// upPhrasalRe: "up" in a phrasal verb is not a state ("pull up the devices").
	upPhrasalRe = regexp.MustCompile(`\b(?:pull|bring|look|set|show)\s+up\b`)
	// allUpRe asks whether EVERY device is up: answered with the tally, not a
	// list of the up ones.
	allUpRe = regexp.MustCompile(`^(?:so\s+)?(?:are|is)\s+(?:all|every|everything)\b`)
	// standingRe asks how one named device stands ("is vedge-1 ok").
	standingRe = regexp.MustCompile(`\b(?:ok|okay|fine|healthy|alright|good|status|state|health)\b`)
	// otherThingRe names something that is not a device as a whole: an
	// interface, a session, a circuit, an incident — never an inventory answer.
	otherThingRe = regexp.MustCompile(`\b(?:interfaces?|ports?|links?|intf|bgp|ospf|isis|peers?|neighbou?rs?|sessions?|tunnels?|circuits?|underlay|incidents?|outages?|problems?|issues?|alerts?|alarms?|cases?)\b`)
)

// ConnectedMeaning is what "connected" in a device count is read as.
const ConnectedMeaning = "devices in your inventory"

// isDeviceStateQuestion: a question about whether devices are up or down, or
// how one named device stands, that names nothing but devices. It is tried
// before the incident family, which would otherwise claim the word "down".
func isDeviceStateQuestion(text string) bool {
	if otherThingRe.MatchString(text) {
		return false
	}
	return reachDownRe.MatchString(text) || (reachUpRe.MatchString(text) && !upPhrasalRe.MatchString(text)) || standingRe.MatchString(text)
}

// reachFilter is the reachability a question asks for, or nil: a device that
// is named is listed with its verdict, never filtered out of its own answer.
func (s *state) reachFilter(namedDevice bool) *ast.Filter {
	if namedDevice || allUpRe.MatchString(s.text) {
		s.e.re(reachDownRe, s.text)
		s.e.re(reachUpRe, s.text)
		return nil
	}
	switch {
	case s.e.re(reachDownRe, s.text):
		return &ast.Filter{Field: ast.FilterReachability, Op: "eq", Values: []string{"down"}}
	case !upPhrasalRe.MatchString(s.text) && s.e.re(reachUpRe, s.text):
		return &ast.Filter{Field: ast.FilterReachability, Op: "eq", Values: []string{"up"}}
	}
	return nil
}

// inventory compiles "how many devices …" / "list the sites …" / "which
// routers are down" / "is cedge-81 up". ok is false when the question is not
// an inventory question at all.
func (s *state) inventory() (Result, bool, error) {
	count := countLeadRe.MatchString(s.text)
	stateLead := stateLeadRe.MatchString(s.text)
	if !count && !listLeadRe.MatchString(s.text) && !stateLead {
		return Result{}, false, nil
	}
	target, role := "", ""
	what := invPerSiteRe.ReplaceAllString(s.text, " ") // "per site" groups, it is not counted
	for _, t := range invTargetRes {
		if t.re.MatchString(what) {
			if target != "" && target != t.target {
				return Result{}, false, nil // two kinds named: not one count
			}
			target = t.target
		}
	}
	for _, r := range invRoleRes {
		if r.re.MatchString(what) {
			if (target != "" && target != "device") || (role != "" && role != r.typ) {
				return Result{}, false, nil
			}
			target, role = "device", r.typ
		}
	}
	if target == "" && reachDeviceRe.MatchString(s.text) {
		target = "device" // "anything unreachable": only a device can be
	}
	if (target == "" || target == "device") && otherThingRe.MatchString(s.text) {
		return Result{}, false, nil // an interface, a session, an incident: not the device inventory
	}
	refs, clarify, err := s.mentions([]string{"site", "device"})
	if err != nil {
		return Result{}, true, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "count_entities", Clarify: clarify}, true, nil
	}
	named := hasRefType(refs, "device")
	if target == "" && named && stateLead && isDeviceStateQuestion(s.text) {
		target = "device" // "is cedge-81 up", "status of edge-a"
	}
	if target == "" || (stateLead && !count && target == "device" && !named && !reachDownRe.MatchString(s.text) && !reachUpRe.MatchString(s.text) && role == "") {
		// A state lead with no state ("is device inventory enabled") is not
		// an inventory question.
		return Result{}, false, nil
	}
	if target != "device" && stateLead && !count && !listLeadRe.MatchString(s.text) {
		return Result{}, false, nil
	}
	for _, t := range invTargetRes {
		if t.target == target {
			s.e.re(t.re, what)
		}
	}
	if target == "device" && invConnectedRe.MatchString(s.text) {
		for _, loc := range invConnectedToRe.FindAllStringIndex(s.text, -1) {
			if !invConnectedUsRe.MatchString(s.text[loc[1]:]) {
				return Result{}, false, nil // "connected to edge-1": topology, not the inventory
			}
		}
		s.e.re(invConnectedRe, s.text)
		s.readings = append(s.readings, lex.Reading{From: "connected", To: ConnectedMeaning, Kind: lex.KindSynonym})
	}
	s.e.re(countLeadRe, s.text)
	s.e.re(listLeadRe, s.text)
	s.e.re(stateLeadRe, s.text)
	s.e.re(invQualRe, s.text)
	q := &ast.AST{V: 1, Type: ast.EntityList, Target: target, Refs: astRefs(refs)}
	if target == "device" {
		if role != "" {
			for _, r := range invRoleRes {
				s.e.re(r.re, what)
			}
			q.Filters = append(q.Filters, ast.Filter{Field: ast.FilterDeviceType, Op: "eq", Values: []string{role}})
		}
		if f := s.reachFilter(named); f != nil {
			q.Filters = append(q.Filters, *f)
		}
		if named {
			s.e.re(standingRe, s.text)
		}
		// The inventory has no window: liveness is the collectors' current
		// verdict (said with the answer), so a window word is not read as one.
		s.readings = dropReadings(s.readings, lex.KindWindow)
	}
	intent := "list_entities"
	if count {
		q.Type, intent = ast.EntityCount, "count_entities"
		if target != "site" && s.e.re(invPerSiteRe, s.text) {
			q.GroupBy = []string{"site"}
		}
	}
	return Result{Intent: intent, AST: q, Entities: refs}, true, nil
}

// dropReadings removes the readings of one kind.
func dropReadings(rs []lex.Reading, kind string) []lex.Reading {
	out := rs[:0]
	for _, r := range rs {
		if r.Kind != kind {
			out = append(out, r)
		}
	}
	return out
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
