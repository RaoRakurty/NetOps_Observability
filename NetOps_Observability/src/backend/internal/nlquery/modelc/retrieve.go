// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// retrieve.go — what goes in front of the model, chosen LEXICALLY (standing
// decision: no vector store): the entities the caller's own resolver finds in
// the question (their ids are the only ids the model may use), the catalog
// fragments the question's words point at (schema-RAG), and the worked
// examples that share the most words with it (example-RAG).

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/resolve"
)

// mention is one entity the caller's resolver found in the question.
type mention struct {
	input  string // the words as asked
	typ    string
	id     string
	method string
	conf   float64
}

func (m mention) key() string { return m.typ + "|" + m.id }

var (
	tokenSplitRe = regexp.MustCompile(`[^\p{L}\p{N}:/._@%'-]+`)
	identLikeRe  = regexp.MustCompile(`[0-9]`)
	durationTok  = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?(?:%|ms|s|m|h|d|w|mo|min|mins|hrs?|days?|percent)?|p[0-9]{2}|[0-9]{1,2}(?:am|pm)|[0-9]{1,2}:[0-9]{2})$`)
	// A referential phrase points at an earlier turn. The model is never given
	// the conversation, so it cannot bind one — it would have to guess.
	bareRefRe  = regexp.MustCompile(`\b(?:it|them|they|those|these)\b`)
	demonstrRe = regexp.MustCompile(`\b(?:that|this|the same|same)\s+(?:device|router|switch|firewall|box|site|location|branch|office|circuit|link|interface|port|peer|neighbor|provider|carrier|isp|app|application|incident|change|one)s?\b`)
)

// normalizeQuestion lower-cases and splits the question into tokens, keeping
// the characters identifiers are made of.
func normalizeQuestion(q string) string {
	q = strings.ToLower(q)
	var toks []string
	for _, t := range tokenSplitRe.Split(q, -1) {
		t = strings.Trim(t, ".'-")
		if t != "" {
			toks = append(toks, t)
		}
	}
	return strings.Join(toks, " ")
}

// precheckReferences refuses a question that points at an earlier turn.
func precheckReferences(text string, leftovers []string) string {
	if bareRefRe.MatchString(text) || demonstrRe.MatchString(text) {
		return RefuseReference
	}
	for _, w := range leftovers {
		if w == "there" || strings.Contains(w, " ") {
			return RefuseReference // an unbound referential phrase the grammar named
		}
	}
	return ""
}

// searchTypes are the instance types an operator names directly (resolve's
// default ladder).
var searchTypes = []string{"site", "device", "circuit", "application", "provider"}

// scanMentions finds the caller's entities in the question: longest phrase
// first, left to right, over the exact rungs of the resolution ladder only
// (canonical id, tenant alias, inventory name). A partial-name or ambiguous
// match is not a mention — the grammar asks the operator about those.
func scanMentions(ctx context.Context, cat *catalog.Catalog, l resolve.Lookups, text string) ([]mention, error) {
	aliases, err := l.Aliases(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := l.Inventory(ctx, searchTypes)
	if err != nil {
		return nil, err
	}
	byAlias := map[string][]mention{}
	for _, a := range aliases {
		k := catalog.NormalizeAlias(a.Alias)
		byAlias[k] = append(byAlias[k], mention{typ: a.EntityType, id: a.EntityID, method: resolve.MethodTenantAlias, conf: 0.99})
	}
	byName := map[string][]mention{}
	for _, n := range inv {
		seen := map[string]bool{}
		for _, name := range n.Names {
			k := catalog.NormalizeAlias(name)
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			byName[k] = append(byName[k], mention{typ: n.Type, id: n.ID, method: resolve.MethodInventoryName, conf: 0.97})
		}
	}
	toks := strings.Fields(text)
	if len(toks) > 80 {
		toks = toks[:80]
	}
	var out []mention
	seen := map[string]bool{}
	for i := 0; i < len(toks) && len(out) < MaxMentions; {
		matched := 0
		for n := min(4, len(toks)-i); n >= 1 && matched == 0; n-- {
			phrase := strings.Join(toks[i:i+n], " ")
			if n == 1 && (stopwords[phrase] || durationTok.MatchString(phrase)) {
				continue
			}
			cands, err := matchPhrase(ctx, cat, l, phrase, byAlias, byName, n)
			if err != nil {
				return nil, err
			}
			if len(uniq(cands)) != 1 {
				continue // none, or ambiguous: not a mention
			}
			m := cands[0]
			m.input = phrase
			if !seen[m.key()] {
				seen[m.key()] = true
				out = append(out, m)
			}
			matched = n
		}
		if matched == 0 {
			matched = 1
		}
		i += matched
	}
	return out, nil
}

// matchPhrase tries the exact rungs for one phrase; the first rung that
// matches decides (resolve's ladder order).
func matchPhrase(ctx context.Context, cat *catalog.Catalog, l resolve.Lookups, phrase string, byAlias, byName map[string][]mention, n int) ([]mention, error) {
	if i := strings.IndexByte(phrase, ':'); i > 0 && n == 1 {
		for _, e := range cat.Entities {
			if strings.EqualFold(e.IDPrefix, phrase[:i+1]) && contains(searchTypes, e.Name) {
				ok, err := l.Visible(ctx, e.Name, phrase)
				if err != nil {
					return nil, err
				}
				if ok {
					return []mention{{typ: e.Name, id: phrase, method: resolve.MethodCanonicalID, conf: 1}}, nil
				}
			}
		}
	}
	k := catalog.NormalizeAlias(phrase)
	if hits := byAlias[k]; len(hits) > 0 {
		return hits, nil
	}
	// A single catalog word ("edge", "router") is vocabulary, not a name, even
	// when some device happens to be called that.
	if n == 1 && len(cat.Lookup(k)) > 0 {
		return nil, nil
	}
	return byName[k], nil
}

func uniq(ms []mention) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		out[m.key()] = true
	}
	return out
}

// mergeGrammarEntities adds the entities the grammar itself resolved for this
// question (never a partial match awaiting confirmation).
func mergeGrammarEntities(ms []mention, refs []resolve.Ref) []mention {
	seen := uniq(ms)
	for _, r := range refs {
		m := mention{input: r.InputText, typ: r.EntityType, id: r.EntityID, method: r.Method, conf: r.Confidence}
		if r.NeedsConfirmation || seen[m.key()] || r.Method == compileMethodConversation || len(ms) >= MaxMentions {
			continue
		}
		seen[m.key()] = true
		ms = append(ms, m)
	}
	return ms
}

// compileMethodConversation mirrors compile.MethodConversation: an entity bound
// from an earlier turn is not something THIS question names.
const compileMethodConversation = "conversation"

// identifierTokens are the question's leftover words that look like names of
// things (a digit, or identifier punctuation) and that no resolved mention
// covers. The model's query must account for each one — as a mention or as a
// string filter value — or it would answer about everything instead.
func identifierTokens(cat *catalog.Catalog, text string, leftovers []string, ms []mention) []string {
	covered := map[string]bool{}
	for _, m := range ms {
		for _, w := range strings.Fields(normalizeQuestion(m.input)) {
			covered[w] = true
		}
	}
	words := leftovers
	if len(words) == 0 {
		words = strings.Fields(text)
	}
	var out []string
	for _, w := range words {
		for _, t := range strings.Fields(normalizeQuestion(w)) {
			if covered[t] || durationTok.MatchString(t) || commonHyphenated[t] || len(cat.Lookup(t)) > 0 {
				continue
			}
			if identLikeRe.MatchString(t) || strings.ContainsAny(t, "-_./:@") {
				out = append(out, t)
			}
		}
	}
	return out
}

// properNames are the words the operator wrote as a NAME — capitalised past
// the first word, or an acronym ("SFDC", "Direct Connect", "Cloudflare") —
// that are not catalog vocabulary and that no resolved mention covers. Like an
// identifier, each must be accounted for by the query, or the question is
// about something the caller's resolver could not find.
func properNames(cat *catalog.Catalog, question string, ms []mention) []string {
	vocab := catalogWords(cat)
	covered := map[string]bool{}
	for _, m := range ms {
		for _, w := range strings.Fields(normalizeQuestion(m.input)) {
			covered[w] = true
		}
	}
	var out []string
	seen := map[string]bool{}
	i := -1
	for _, raw := range tokenSplitRe.Split(question, -1) {
		tok := strings.Trim(raw, ".'-")
		if tok == "" {
			continue
		}
		i++
		lower := strings.ToLower(tok)
		if seen[lower] || covered[lower] || stopwords[lower] || vocab[lower] || timeWords[lower] ||
			durationTok.MatchString(lower) || commonHyphenated[lower] || (strings.HasSuffix(lower, "'s") && vocab[strings.TrimSuffix(lower, "'s")]) {
			continue
		}
		hasUpper, hasLetter := false, false
		for _, r := range tok {
			hasUpper = hasUpper || unicode.IsUpper(r)
			hasLetter = hasLetter || unicode.IsLetter(r)
		}
		acronym := hasLetter && len(tok) >= 2 && tok == strings.ToUpper(tok)
		if (hasUpper && i > 0) || acronym {
			seen[lower] = true
			out = append(out, lower)
		}
	}
	return out
}

// catalogWords is every word the catalog's own vocabulary uses.
func catalogWords(cat *catalog.Catalog) map[string]bool {
	out := map[string]bool{}
	add := func(ss ...string) {
		for _, s := range ss {
			for _, w := range strings.Fields(catalog.NormalizeAlias(s)) {
				out[w] = true
			}
		}
	}
	for _, e := range cat.Entities {
		add(e.Name)
		add(e.Aliases...)
	}
	for _, m := range cat.Metrics {
		add(m.Name, m.Unit)
		add(m.Aliases...)
	}
	for _, d := range cat.Dimensions {
		add(d.Name, d.Entity)
		add(d.Aliases...)
		for _, v := range d.Enum {
			add(v.Value)
			add(v.Aliases...)
		}
	}
	return out
}

// timeWords are calendar and clock words that are capitalised without naming
// a thing.
var timeWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`monday tuesday wednesday thursday friday saturday sunday mon tue tues wed thu thur thurs fri sat sun
		january february march april may june july august september october november december jan feb mar apr jun jul aug sep sept oct nov dec
		utc gmt am pm est edt cst cdt mst mdt pst pdt ist bst cet cest`) {
		timeWords[w] = true
	}
}

// commonHyphenated are hyphenated English words that name nothing.
var commonHyphenated = map[string]bool{
	"week-over-week": true, "day-over-day": true, "month-over-month": true, "year-over-year": true,
	"real-time": true, "up-to-date": true, "follow-up": true, "end-to-end": true, "round-trip": true,
	"one-way": true, "two-way": true, "sd-wan": true, "wi-fi": true, "e-mail": true, "top-n": true,
	"re-check": true, "non-zero": true, "hour-over-hour": true, "in-bound": true, "out-bound": true,
	"at-risk": true, "high-level": true, "per-site": true, "per-device": true, "right-now": true,
}

var stopwords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`a an the of on in at to for from by per with and or vs versus is are was were be been
		do does did has have had show list me us i we our my what which who how when where why any all every each
		over during than more less most least top this that these those it its there their them they last past
		since today yesterday week day days hour hours minute minutes month months now currently please give get see
		find tell about around near under above below between within into out up down not no only just also`) {
		stopwords[w] = true
	}
}

// fragments is the relevant slice of the catalog.
type fragments struct {
	metrics  []*catalog.Metric
	entities map[string]bool // entity types the question touches
}

// retrieveSchema picks catalog fragments by the catalog's own alias index
// (phrases up to three words) plus word overlap with metric descriptions.
func retrieveSchema(cat *catalog.Catalog, text string) fragments {
	toks := strings.Fields(text)
	score := map[string]int{}
	f := fragments{entities: map[string]bool{}}
	for i := range toks {
		for n := 1; n <= 3 && i+n <= len(toks); n++ {
			phrase := strings.Join(toks[i:i+n], " ")
			if n == 1 && stopwords[phrase] {
				continue
			}
			for _, h := range cat.Lookup(phrase) {
				switch h.Kind {
				case "metric":
					score[h.Name] += 4 * n
				case "entity":
					f.entities[h.Name] = true
				case "dimension", "enum":
					f.entities[h.For] = true
				}
			}
		}
	}
	content := map[string]bool{}
	for _, t := range toks {
		if !stopwords[t] && len(t) > 2 {
			content[t] = true
		}
	}
	for i := range cat.Metrics {
		m := &cat.Metrics[i]
		words := strings.Fields(catalog.NormalizeAlias(m.Name + " " + m.Description + " " + strings.Join(m.Aliases, " ")))
		hit := map[string]bool{}
		for _, w := range words {
			if content[w] && !hit[w] {
				hit[w] = true
				score[m.Name]++
			}
		}
	}
	for name, s := range score {
		if m, ok := cat.Metric(name); ok && s > 0 {
			f.metrics = append(f.metrics, m)
		}
	}
	sort.Slice(f.metrics, func(i, j int) bool {
		a, b := score[f.metrics[i].Name], score[f.metrics[j].Name]
		if a != b {
			return a > b
		}
		return f.metrics[i].Name < f.metrics[j].Name
	})
	if len(f.metrics) > MaxMetrics {
		f.metrics = f.metrics[:MaxMetrics]
	}
	for _, m := range f.metrics {
		for _, t := range m.EntityTypes {
			f.entities[t] = true
		}
	}
	return f
}

// retrieveExamples picks the examples sharing the most content words with the
// question, preferring ones about a metric the question points at.
func retrieveExamples(lib []Example, text string, f fragments, skip func(string) bool) []Example {
	q := contentWords(text)
	metrics := map[string]bool{}
	for _, m := range f.metrics {
		metrics[m.Name] = true
	}
	type scored struct {
		e Example
		s int
	}
	var cands []scored
	for _, e := range lib {
		if skip != nil && skip(e.ID) {
			continue
		}
		s := 0
		for w := range contentWords(normalizeQuestion(e.Question)) {
			if q[w] {
				s += 2
			}
		}
		var head struct {
			Metric string `json:"metric"`
			Target string `json:"target"`
		}
		if json.Unmarshal(e.AST, &head) == nil {
			if metrics[head.Metric] {
				s += 3
			}
			if f.entities[head.Target] {
				s++
			}
		}
		if s > 0 {
			cands = append(cands, scored{e, s})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].s != cands[j].s {
			return cands[i].s > cands[j].s
		}
		return cands[i].e.ID < cands[j].e.ID
	})
	var out []Example
	for i := 0; i < len(cands) && i < MaxExamples; i++ {
		out = append(out, cands[i].e)
	}
	return out
}

func contentWords(text string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Fields(text) {
		if !stopwords[t] && !durationTok.MatchString(t) {
			out[t] = true
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
