// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"sort"
	"strings"
)

// Reading is one reinterpretation of the operator's words that Iris applied
// and must disclose ("I read 'shwo' as 'show'"). Nothing is read differently
// silently: every Reading reaches the answer and the query log.
type Reading struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Reading kinds (closed).
const (
	KindTypo      = "typo"       // a misspelt word of the closed vocabulary
	KindSynonym   = "synonym"    // another word for a catalog term
	KindSeverity  = "severity"   // a severity word mapped onto a catalog filter
	KindImplicitN = "implicit_n" // a superlative with no number ("busiest" → top 5)
	// KindWindow: a vague recency word read as a concrete window ("lately"
	// → the last 24 hours).
	KindWindow = "window"
	// KindRephrase: the fast AI model rephrased the whole question and the
	// grammar read the rephrase (hybrid NLU plan B1). From is the question,
	// To the rephrase.
	KindRephrase = "rephrase"
)

// Note is the sentence a Reading is disclosed with.
func (r Reading) Note() string {
	switch r.Kind {
	case KindSeverity:
		return "I read \"" + r.From + "\" as " + r.To + "."
	case KindImplicitN, KindWindow:
		return "I read \"" + r.From + "\" as the " + r.To + "."
	case KindRephrase:
		return "I read your question as \"" + r.To + "\" (rephrased by the AI model — check the query shown with this answer)."
	}
	return "I read \"" + r.From + "\" as \"" + r.To + "\"."
}

// Typo-repair guards (hybrid NLU plan A2). A correction is applied only when
// it is unambiguous and the word is plainly a misspelling:
//   - MinTypoLen: words of 3 letters or fewer are never corrected ("ap",
//     "dc", "isp" are too close to too much);
//   - distance ≤ 1 for 4–7 letters, ≤ 2 for 8 or more;
//   - a different first letter counts double (people rarely mistype the
//     first letter; "core" is not "more");
//   - only letters: a token with a digit or a separator is a name, an id,
//     an address or a number, never a typo of a word;
//   - the closest candidate must be UNIQUE — a tie is offered, not applied.
const (
	MinTypoLen    = 4
	maxCandidates = 3
)

// MaxTypoDistance is the largest distance a word of n letters is repaired at.
func MaxTypoDistance(n int) int {
	switch {
	case n < MinTypoLen:
		return 0
	case n < 8:
		return 1
	}
	return 2
}

// Vocab is a closed vocabulary: the words some reader of Iris gives meaning
// to. It is built from code and the catalog, never from operator data.
type Vocab struct {
	words map[string]bool
	list  []string // sorted, for deterministic candidates
}

// NewVocab builds a vocabulary from word lists. Multi-word entries contribute
// each of their words.
func NewVocab(lists ...[]string) *Vocab {
	v := &Vocab{words: map[string]bool{}}
	for _, l := range lists {
		for _, e := range l {
			for _, w := range strings.Fields(Fold(e)) {
				if !v.words[w] {
					v.words[w] = true
					v.list = append(v.list, w)
				}
			}
		}
	}
	sort.Strings(v.list)
	return v
}

// Has reports a vocabulary word, or a regular inflection of one (plural,
// singular, -ed, -ing): an inflected word is a word, not a typo, even where
// the grammar has no meaning for that form ("compared" is never "compare").
func (v *Vocab) Has(w string) bool {
	if v.words[w] || v.words[Singular(w)] || v.words[w+"s"] || v.words[w+"es"] {
		return true
	}
	for _, suf := range []string{"ed", "ing"} {
		if stem, ok := strings.CutSuffix(w, suf); ok && len(stem) >= 3 {
			if v.words[stem] || v.words[stem+"e"] || (len(stem) > 3 && stem[len(stem)-1] == stem[len(stem)-2] && v.words[stem[:len(stem)-1]]) {
				return true
			}
		}
	}
	return false
}

// Len is the number of words.
func (v *Vocab) Len() int { return len(v.list) }

// Words returns the vocabulary, sorted.
func (v *Vocab) Words() []string { return append([]string(nil), v.list...) }

func lettersOnly(w string) bool {
	for i := 0; i < len(w); i++ {
		if w[i] < 'a' || w[i] > 'z' {
			return false
		}
	}
	return w != ""
}

// Repairable reports whether w is a candidate for typo repair at all: long
// enough, letters only, not already a word of v, and not an ordinary English
// word that merely sits one letter from a vocabulary word ("slow" is not a
// misspelt "show").
func (v *Vocab) Repairable(w string) bool {
	return len(w) >= MinTypoLen && lettersOnly(w) && !v.Has(w) && !plainWords[w] && !plainWords[Singular(w)]
}

// plainWords are ordinary words an operator types that sit one edit from a
// vocabulary word. They are never "corrected": a real word is not a typo,
// even when Iris has no meaning for it (it is then simply not understood).
var plainWords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`slow slower fast faster load loads lead host hosts post posts lost lose
		gone dead live alive node nodes hold held fill full fail fails failed fall fell feel feels sees seem seems
		seen same some sure such than then them they this that what when whom whose with want wants went were
		will well wall walk talk talks tall told cold call calls called mean means meant main many make made
		more most mode model node note notes nose rose role roles rule rules rate rates race rack racks read
		reads ready real show shown shows snow slot slots spot stop stops step steps stay star start state
		store stored story site size sits sets sent send sends seen line lines lane lanes link list lift lost
		loop loops look looks took book back pack pick pink ping pings pong port part park path paths patch
		push pull pulls bill bull call cell core cost costs code codes come came case cases cash date data
		days dark deep drop drops draw time tile type types tone zone zones done down town turn turns tune
		user users uses used vlan vlans view vies wifi wire wired word words work works worse worst year
		years your yours ours hers here hear near need needs next text test tests best rest less left lens
		edge edges hops hope help helps high higher hide kind find fine five line mine nine wine wise rise
		last fast vast past mast cast easy busy body copy only over even ever every each else also able
		about above after again ago along among around away before being below between both came cannot
		could does doing done during either enough every first from have having into just keep kept know
		known like likely little long longer many maybe might much must never none often once other
		others ought quite rather really said says shall should since still their there these those
		though through under until upon very want what which while whole whose would yeah okay thanks
		thank hello please sorry check checks checked green yellow amber blue black white grey gray business
		aws azure gcp cloud clouds vpc vpcs vnet subnet subnets prefix prefixes route routes routing
		mpls ospf isis eigrp bgp evpn vxlan lacp stp lldp cdp snmp gnmi netconf syslog trap traps
		retail branch store stores bank banks clinic clinics school schools campus warehouse fire fires`) {
		m[w] = true
	}
	return m
}()

// Correct returns the one vocabulary word w is a misspelling of, or — when
// several are equally close — up to three of them as ties (to be OFFERED,
// never applied). Both are empty when w is a word, is not repairable, or is
// close to nothing.
func (v *Vocab) Correct(w string) (fix string, ties []string) {
	if !v.Repairable(w) {
		return "", nil
	}
	limit := MaxTypoDistance(len(w))
	best := limit + 1
	var at []string
	for _, c := range v.list {
		if len(c) < MinTypoLen || absInt(len(c)-len(w)) > limit {
			continue
		}
		d := Distance(w, c)
		if c[0] != w[0] {
			d++ // a different first letter counts double
		}
		switch {
		case d < best:
			best, at = d, []string{c}
		case d == best:
			at = append(at, c)
		}
	}
	switch {
	case best > limit || len(at) == 0:
		return "", nil
	case len(at) == 1:
		return at[0], nil
	}
	if len(at) > maxCandidates {
		at = at[:maxCandidates]
	}
	return "", at
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Repair is the outcome of repairing one text.
type Repair struct {
	Text     string
	Readings []Reading
	// Ties are words with several equally close candidates: offered as a
	// did-you-mean, never applied.
	Ties map[string][]string
}

// RepairText corrects the misspelt words of a space-separated text. Leading
// and trailing punctuation of a token is kept ("isues?" → "issues?"). keep,
// when set, is asked before the i-th word is changed: true leaves it as typed
// (a name the caller can see, or a free-text value such as an owner's name,
// is never "corrected" into a vocabulary word).
func (v *Vocab) RepairText(text string, keep func(i int, word string) bool) Repair {
	toks := strings.Fields(text)
	out := Repair{}
	for i, t := range toks {
		lo, hi := 0, len(t)
		for lo < hi && !isLetter(t[lo]) {
			lo++
		}
		for hi > lo && !isLetter(t[hi-1]) {
			hi--
		}
		w := t[lo:hi]
		fix, ties := v.Correct(w)
		if fix == "" && len(ties) == 0 {
			continue
		}
		if keep != nil && keep(i, w) {
			continue
		}
		if fix == "" {
			if out.Ties == nil {
				out.Ties = map[string][]string{}
			}
			out.Ties[w] = ties
			continue
		}
		toks[i] = t[:lo] + fix + t[hi:]
		out.Readings = append(out.Readings, Reading{From: w, To: fix, Kind: KindTypo})
	}
	out.Text = strings.Join(toks, " ")
	return out
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' }

// CoreWords are the operator words every reader of Iris shares: the question
// router's trigger words and the grammar's domain nouns. The grammar adds its
// own framing words and the catalog's aliases on top (compile.Vocabulary).
// Closed and code-owned; held-out phrasings never appear here (N-H3).
var coreWords = []string{
	// asking
	"show", "list", "display", "give", "tell", "find", "view", "which", "what", "where", "when", "there",
	"many", "much", "count", "number", "total", "summary", "summarize", "summarise", "overview", "report",
	"status", "state", "health", "healthy", "happening", "going", "explain", "describe", "detail", "details",
	"compare", "versus", "between", "against", "during", "before", "after", "since", "today", "yesterday",
	"tonight", "overnight", "weekend", "morning", "afternoon", "evening", "night", "hour", "hours", "minute",
	"minutes", "week", "weeks", "month", "months", "last", "past", "previous", "recent", "recently", "latest",
	"current", "currently", "right", "please", "anything", "everything", "something", "network",
	// incidents
	"incident", "incidents", "issue", "issues", "problem", "problems", "outage", "outages", "alert", "alerts",
	"failure", "failures", "correlation", "correlations", "critical", "confirmed", "suspected", "undetermined",
	"actionable", "active", "major", "open", "closed", "resolved", "ongoing", "wrong", "broken", "failing",
	"impacted", "affected", "degraded", "attention", "priority", "focus", "first", "biggest", "worst",
	"root", "cause", "caused", "troubleshoot", "playbook", "runbook", "checklist", "diagnose",
	// changes
	"change", "changes", "changed", "deploy", "deployed", "deployment", "config", "configuration", "configure",
	"policy", "policies", "rollback", "release", "touched", "modified", "edited", "pushed",
	// things
	"device", "devices", "router", "routers", "switch", "switches", "firewall", "firewalls", "interface",
	"interfaces", "port", "ports", "link", "links", "circuit", "circuits", "site", "sites", "location",
	"locations", "branch", "branches", "office", "provider", "providers", "carrier", "peer", "peers",
	"neighbor", "neighbors", "neighbour", "neighbours", "session", "sessions", "tunnel", "tunnels",
	"application", "applications", "inventory", "onboarded", "discovered", "monitored", "managed",
	// measures
	"latency", "jitter", "loss", "packet", "packets", "errors", "error", "discards", "drops", "utilization",
	"bandwidth", "throughput", "traffic", "memory", "temperature", "flapping", "flaps", "down",
	"anomaly", "anomalies", "talkers", "talker", "busiest", "highest", "lowest", "slowest", "average", "maximum",
	"minimum", "unusual", "abnormal",
	// modules / product
	"handoff", "handover", "shift", "integration", "integrations", "connector", "telemetry", "dashboard",
	"correlix", "setup", "enable",
}

// CoreVocab is the shared operator vocabulary (CoreWords).
func CoreVocab() *Vocab { return NewVocab(coreWords) }

// CoreWords returns the shared operator words (a copy).
func CoreWords() []string { return append([]string(nil), coreWords...) }

// ClassifierRepair is the router's reading WITH its typo repairs: Fold, single
// spaces, sentence punctuation kept, and misspelt core words corrected so
// "list top isues today" reaches the incident rules. The repairs are returned
// so the answer can disclose them.
func ClassifierRepair(q string) (string, []Reading) {
	// Shorthand first ("rn" → "right now"), so the router and the grammar read
	// the same words (lex.Normalize expands the same table).
	text, abbr := ExpandAbbreviations(strings.Join(strings.Fields(Fold(q)), " "))
	r := CoreVocab().RepairText(text, nil)
	return r.Text, append(abbr, r.Readings...)
}

// Exact reports a vocabulary word exactly as listed (no inflection).
func (v *Vocab) Exact(w string) bool { return v.words[w] }

// IsPlainWord reports an ordinary English word that is never repaired.
func IsPlainWord(w string) bool { return plainWords[w] || plainWords[Singular(w)] }

// Plural is the regular English plural of a word ("latency" → "latencies",
// "switch" → "switches", "packet" → "packets").
func Plural(w string) string {
	n := len(w)
	switch {
	case n == 0:
		return w
	case strings.HasSuffix(w, "y") && n > 1 && !strings.ContainsRune("aeiou", rune(w[n-2])):
		return w[:n-1] + "ies"
	case strings.HasSuffix(w, "s") || strings.HasSuffix(w, "x") || strings.HasSuffix(w, "ch") || strings.HasSuffix(w, "sh"):
		return w + "es"
	}
	return w + "s"
}
