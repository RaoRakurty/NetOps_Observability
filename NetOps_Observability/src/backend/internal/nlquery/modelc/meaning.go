// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// meaning.go — the rephrase stage's meaning-preservation rules (hybrid NLU
// plan B1, review fix 2026-11-11). A closed vocabulary alone stops the model
// from ADDING a name or an instruction, but every grammar word is in that
// vocabulary, so "cpu on edge-1 in the last 2 hours" could still come back as
// "average cpu on edge-1 in the last 2 days" (unit swapped), "cpu above 2
// percent on edge-1" (the typed number reused as a threshold) or "open
// incidents at edge-1" (a metric question turned into a list) — each a valid,
// DIFFERENT question.
//
// So the words that carry meaning are classed, and compared per class:
//
//	time        today, last/past, hours, monday, …  word for word (synonyms folded):
//	                                                 nothing typed dropped, nothing new
//	rank        up (top/highest/most/…), down        each group present in the rephrase
//	            (bottom/lowest/least/…), worst, best exactly when present in the question;
//	                                                 "up" may stand in for a superlative
//	                                                 the grammar did not know ("flakiest")
//	comparison  up (above/over/more/>), down         each group present exactly when
//	            (below/under/less/<)                 present in the question
//	quantifier  all/every/each/any/everything        present exactly when present
//	aggregation average/mean, max/peak, p95, …       typed kept; new only as a replacement
//	metric      the metrics the catalog's aliases    typed kept (any alias of the same
//	            name                                 metric); new only as a replacement
//	enum value  open, confirmed, dns change, …       typed kept; new only as a replacement
//
// "As a replacement": the number of new aggregation / metric / enum / up-rank
// meanings is at most the number of not-understood words the rephrase left
// out ("is cpu sluggish" → "average cpu": "sluggish" replaced by "average").
// A number keeps its ROLE (window, rank size, threshold, other), read from the
// words around it in the question and in the rephrase. And the compiled query
// must be the KIND of question the operator asked (consistentKind).

import (
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/lex"
)

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

var (
	// timeWords are compared word for word, after timeFold.
	timeClassWords = wordSet(`today yesterday tonight overnight now since last ago until before after next this
		week day hour minute month year quarter second morning afternoon evening night midnight noon weekend
		recent recently lately monday tuesday wednesday thursday friday saturday sunday daily hourly weekly`)
	timeFold = map[string]string{"past": "last", "previous": "last", "hr": "hour", "hrs": "hour", "h": "hour",
		"min": "minute", "mins": "minute", "m": "minute", "d": "day", "w": "week", "mo": "month", "sec": "second",
		"mon": "monday", "tue": "tuesday", "tues": "tuesday", "wed": "wednesday", "thu": "thursday", "thur": "thursday",
		"thurs": "thursday", "fri": "friday", "sat": "saturday", "sun": "sunday"}

	// Rank groups: a rephrase may use another word of the same group, never
	// change group, add one, or drop one.
	rankGroups = map[string]map[string]bool{
		"up":    wordSet(`top highest most biggest largest busiest hottest slowest noisiest lossiest flappiest`),
		"down":  wordSet(`bottom lowest least smallest fewest quietest`),
		"worst": wordSet(`worst`),
		"best":  wordSet(`best`),
	}
	compGroups = map[string]map[string]bool{
		"up":   wordSet(`above over more greater higher exceed exceeds exceeding exceeded > >=`),
		"down": wordSet(`below under less fewer lower < <=`),
	}
	quantWords = wordSet(`all every each any everything anything everyone`)

	aggFold = map[string]string{"avg": "average", "mean": "average", "averaged": "average", "maximum": "max",
		"peak": "max", "minimum": "min", "sum": "total", "p50": "median"}
	aggWords = wordSet(`average max min total median p90 p95 p99 percentile`)

	// timeUnits follow a number that is a window ("2 hours").
	timeUnits = wordSet(`minute min hour hr h day d week w month mo second sec year`)
	// thresholdUnits follow a number that is a threshold ("80 percent").
	thresholdUnits = wordSet(`percent % ms millisecond`)
	// thresholdLead precede a number that is a threshold ("above 80").
	thresholdLead = wordSet(`above over more greater higher exceed exceeds exceeding below under less fewer lower than > < >= <=`)
	// rankLead precede a number that is a rank size ("top 5").
	rankLead = wordSet(`top bottom first which worst best highest lowest busiest most least`)
	// rankDown superlatives point down; a not-understood one is never
	// replaced by an up-ranking word.
	rankDown = wordSet(`least smallest fewest lowest best quietest bottom`)
)

// meaningWords holds the catalog side of the classification.
type meaningWords struct {
	cat *catalog.Catalog
}

func newMeaningWords(cat *catalog.Catalog) meaningWords { return meaningWords{cat: cat} }

// meanings is one text's meaning-bearing content.
type meanings struct {
	time    map[string]bool
	rank    map[string]bool // group names
	comp    map[string]bool // group names
	quant   bool
	agg     map[string]bool
	metrics map[string]bool // catalog metric names
	enums   map[string]bool // catalog dimension.value names
}

func (mw meaningWords) read(toks []string) meanings {
	m := meanings{time: map[string]bool{}, rank: map[string]bool{}, comp: map[string]bool{}, agg: map[string]bool{},
		metrics: map[string]bool{}, enums: map[string]bool{}}
	for _, t := range toks {
		w := lex.Singular(t)
		if f, ok := timeFold[w]; ok {
			w = f
		}
		if timeClassWords[w] {
			m.time[w] = true
		}
		for g, words := range rankGroups {
			if words[t] || words[w] {
				m.rank[g] = true
			}
		}
		for g, words := range compGroups {
			if words[t] || words[w] {
				m.comp[g] = true
			}
		}
		if quantWords[t] {
			m.quant = true
		}
		a := t
		if f, ok := aggFold[a]; ok {
			a = f
		}
		if aggWords[a] {
			m.agg[a] = true
		}
	}
	// Metrics and enum values by the catalog's own alias index (phrases up to
	// three words): "rtt" and "latency" are the same metric.
	for i := range toks {
		for n := 1; n <= 3 && i+n <= len(toks); n++ {
			phrase := strings.Join(toks[i:i+n], " ")
			if n == 1 && stopwords[phrase] {
				continue
			}
			for _, h := range mw.cat.Lookup(phrase) {
				switch h.Kind {
				case "metric":
					m.metrics[h.Name] = true
				case "enum":
					m.enums[h.Name] = true
				}
			}
		}
	}
	return m
}

// checkMeaning applies the class rules (file comment) to a rephrase. qToks
// and rToks are the normalised tokens of the question and the rephrase;
// droppedUnknown is how many not-understood words the rephrase left out;
// unknownSuperlative says one of those was a superlative the grammar did not
// know (an "-est" word that is not a down-ranking one).
func (mw meaningWords) checkMeaning(qToks, rToks []string, droppedUnknown int, unknownSuperlative bool) string {
	q, r := mw.read(qToks), mw.read(rToks)
	if !sameSet(q.time, r.time) || !sameSet(q.comp, r.comp) || q.quant != r.quant {
		return RefuseRewriteMeaning // a new or changed window, condition or scope
	}
	replacements := 0
	for g := range unionKeys(q.rank, r.rank) {
		switch {
		case q.rank[g] == r.rank[g]:
		case g == "up" && r.rank[g] && unknownSuperlative:
			replacements++
		default:
			return RefuseRewriteMeaning // a rank direction added, dropped or flipped
		}
	}
	for _, pair := range [][2]map[string]bool{{q.agg, r.agg}, {q.metrics, r.metrics}, {q.enums, r.enums}} {
		typed, now := pair[0], pair[1]
		for w := range typed {
			if !now[w] {
				return RefuseRewriteMeaning // an aggregation, metric or value the operator asked for is gone
			}
		}
		for w := range now {
			if !typed[w] {
				replacements++
			}
		}
	}
	if replacements > droppedUnknown {
		return RefuseRewriteMeaning // more new meaning than words it could stand for
	}
	if !sameNumberRoles(qToks, rToks) {
		return RefuseRewriteMeaning
	}
	return ""
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func unionKeys(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

// withSymbols puts back the comparison symbols the normaliser strips: "loss
// > 1%" and "loss more than 1%" both ask for "up".
func withSymbols(raw string, toks []string) []string {
	out := toks
	if strings.ContainsAny(raw, ">") {
		out = append(append([]string(nil), out...), ">")
	}
	if strings.ContainsAny(raw, "<") {
		out = append(append([]string(nil), out...), "<")
	}
	return out
}

// numberRole is the role a number plays, read from the words around it.
func numberRole(toks []string, i int) string {
	t := toks[i]
	switch {
	case strings.HasSuffix(t, "%") || strings.HasSuffix(t, "ms"):
		return "threshold"
	case strings.TrimLeft(t, "0123456789.") != "":
		return "time" // "24h", "7d", "30min"
	}
	next, prev := "", ""
	if i+1 < len(toks) {
		next = lex.Singular(toks[i+1])
	}
	if i > 0 {
		prev = toks[i-1]
	}
	switch {
	case timeUnits[next]:
		return "time"
	case thresholdUnits[next] || thresholdLead[prev]:
		return "threshold"
	case rankLead[prev]:
		return "rank"
	}
	return "other"
}

// sameNumberRoles: every number keeps exactly the roles it had.
func sameNumberRoles(qToks, rToks []string) bool {
	roles := func(toks []string) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for i, t := range toks {
			if !numberTok.MatchString(t) {
				continue
			}
			n := strings.TrimRight(t, "%abcdefghijklmnopqrstuvwxyz")
			if out[n] == nil {
				out[n] = map[string]bool{}
			}
			out[n][numberRole(toks, i)] = true
		}
		return out
	}
	q, r := roles(qToks), roles(rToks)
	if len(q) != len(r) {
		return false
	}
	for n, qr := range q {
		if !sameSet(qr, r[n]) {
			return false
		}
	}
	return true
}

// namedKinds are what the ORIGINAL question names exactly, by the catalog's
// own alias index: the metrics, and whether it names incidents or changes.
type namedKinds struct {
	metrics          map[string]bool
	incident, change bool
}

func questionKinds(cat *catalog.Catalog, text string) namedKinds {
	k := namedKinds{metrics: map[string]bool{}}
	toks := strings.Fields(text)
	for i := range toks {
		for n := 1; n <= 3 && i+n <= len(toks); n++ {
			phrase := strings.Join(toks[i:i+n], " ")
			if n == 1 && stopwords[phrase] {
				continue
			}
			for _, h := range cat.Lookup(phrase) {
				switch {
				case h.Kind == "metric":
					k.metrics[h.Name] = true
				case h.Kind == "entity" && h.Name == "incident", (h.Kind == "dimension" || h.Kind == "enum") && h.For == "incident":
					k.incident = true
				case h.Kind == "entity" && h.Name == "change", (h.Kind == "dimension" || h.Kind == "enum") && h.For == "change":
					k.change = true
				}
			}
		}
	}
	return k
}

// consistentKind: the compiled query is the kind of question the operator
// asked. A question that names a metric compiles to a query OF one of those
// metrics (never a list); one that names incidents (changes) and no metric
// compiles to an incident (change) query. A question that names none of them
// may take whatever kind its replaced words give it.
func consistentKind(k namedKinds, q *ast.AST) bool {
	metricType := q.Type == ast.MetricSeries || q.Type == ast.MetricTopK || q.Type == ast.MetricFilter || q.Type == ast.CompareWindows
	switch {
	case len(k.metrics) > 0:
		return metricType && k.metrics[q.Metric]
	case k.incident && k.change:
		return q.Type == ast.IncidentList || q.Type == ast.IncidentExplain || q.Type == ast.ChangeList
	case k.incident:
		return q.Type == ast.IncidentList || q.Type == ast.IncidentExplain
	case k.change:
		return q.Type == ast.ChangeList
	}
	return true
}
