// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package lex is Iris's ONE text normaliser (tracker 337, hybrid NLU plan A1).
//
// Before it there were three: the grammar compiler lower-cased and stripped
// punctuation, the model compiler had its own tokeniser, and the question
// router (ai.Classify) only lower-cased. A question that one of them read
// differently from the others was understood by one arm and lost by the next,
// and a fix in one never reached the rest. Everything that reads an operator's
// words now starts here:
//
//   - Fold        — lower case, accents off ("Zürich" → "zurich"), smart quotes
//     to ASCII. Length-changing, so never used to compute an offset into the
//     original text (the asciifold lesson): callers keep Raw for that.
//   - Normalize   — Fold plus the grammar's punctuation rules, "sd-wan" →
//     "sdwan", possessives, a few contractions and number words ("five" → "5").
//   - Squash      — the NAME key: every separator removed, so "edge1", "edge-1",
//     "EDGE_1" and "edge 1" are one key. Only for matching a name the caller
//     can already see; never shown back.
//   - Distance    — the restricted Damerau–Levenshtein distance (vocab.go).
//
// Stdlib only and no I/O: the nlquery import guard covers this package.
package lex

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Text is one normalised question.
type Text struct {
	// Raw is the question exactly as asked: values whose casing is data
	// (owner names) and every offset are taken from it, never from Norm.
	Raw string
	// Norm is the normalised text the grammar reads.
	Norm string
	// Tokens are Norm's words, in order.
	Tokens []string
	// Readings are the shorthand expansions that carry meaning ("rn" →
	// "right now"); the caller discloses them with the answer.
	Readings []Reading
}

// accents folds the Latin letters an operator's keyboard or a pasted site name
// carries to their ASCII base. Stdlib has no Unicode decomposition (that is
// golang.org/x/text, not on the allowlist), so the common Latin-1 and Latin
// Extended-A letters are listed; anything else passes through unchanged.
var accents = map[rune]string{
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'æ': "ae", 'ç': "c", 'ć': "c", 'č': "c", 'ď': "d", 'đ': "d",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ğ': "g", 'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ī': "i", 'į': "i", 'ı': "i",
	'ł': "l", 'ľ': "l", 'ñ': "n", 'ń': "n", 'ň': "n",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ő': "o", 'œ': "oe",
	'ř': "r", 'ś': "s", 'š': "s", 'ş': "s", 'ß': "ss", 'ť': "t", 'ţ': "t",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ū': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ý': "y", 'ÿ': "y", 'ź': "z", 'ż': "z", 'ž': "z",
	// Typography an operator pastes from a chat or a document.
	'’': "'", '‘': "'", '‛': "'", '′': "'", '“': " ", '”': " ", '„': " ",
	'–': "-", '—': "-", '‐': "-", '‑': "-", ' ': " ",
}

// Fold lower-cases s, folds accents and smart punctuation to ASCII, and leaves
// every other rune as it is. The result can be longer or shorter than s.
func Fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		r = unicode.ToLower(r)
		if a, ok := accents[r]; ok {
			b.WriteString(a)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// punctRe keeps the characters identifiers are made of (ge-0/0/1, 10.0.0.1,
// user@site, 90%, at&t) and the apostrophe the grammar's "what's" needs.
var punctRe = regexp.MustCompile(`[^a-z0-9:/._@%&' -]+`)

// contractions expands only the forms whose parts are question vocabulary.
// Every "'s" was already dropped as a possessive ("it's" → "it"), exactly as
// the grammar always read it, and "what's" never reaches here for that reason.
var contractions = map[string][]string{
	"we're": {"we", "are"}, "what're": {"what", "are"}, "where're": {"where", "are"}, "how're": {"how", "are"},
	// The negative forms of the state verbs, so "aren't established" reads as
	// the grammar's "not established".
	"aren't": {"are", "not"}, "isn't": {"is", "not"}, "wasn't": {"was", "not"}, "weren't": {"were", "not"},
	"arent": {"are", "not"}, "isnt": {"is", "not"},
}

// abbreviation is one chat-speak or NOC shorthand an operator types for a
// word the grammar knows. disclose marks the ones that carry meaning (a time,
// an object): reading "rn" as "right now" changes the window, so it is said
// with the answer (D2). The framing ones ("pls", "w/", "r") change nothing a
// query depends on and are expanded silently.
type abbreviation struct {
	to       []string
	disclose bool
	// last: expanded only as the question's final word. "atm" is chat for
	// "at the moment" at the end of a sentence ("what's down atm") but a real
	// network term before a noun ("show atm interfaces"): a token that is
	// also a domain term is never rewritten where it can be that term.
	last bool
}

// abbreviations is closed and code-owned (held-out phrasings never appear
// here, N-H3). Only whole tokens are expanded: "r1" or "u-turn" are names.
var abbreviations = map[string]abbreviation{
	"rn": {to: []string{"right", "now"}, disclose: true}, "atm": {to: []string{"right", "now"}, disclose: true, last: true},
	"yday": {to: []string{"yesterday"}, disclose: true}, "yest": {to: []string{"yesterday"}, disclose: true},
	"nbr": {to: []string{"neighbor"}, disclose: true}, "nbrs": {to: []string{"neighbors"}, disclose: true},
	"iface": {to: []string{"interface"}, disclose: true}, "ifaces": {to: []string{"interfaces"}, disclose: true},
	"cfg": {to: []string{"config"}, disclose: true},
	"pls": {to: []string{"please"}}, "plz": {to: []string{"please"}},
	"w/": {to: []string{"with"}}, "r": {to: []string{"are"}}, "u": {to: []string{"you"}},
	"ur": {to: []string{"your"}}, "thx": nil0, "ty": nil0,
}

// nil0 is an abbreviation that reads as nothing ("thx").
var nil0 = abbreviation{}

// KindAbbreviation readings say which shorthand was expanded.
const KindAbbreviation = "abbreviation"

// expandAbbreviation returns the words a token stands for and the reading to
// disclose ("" when silent); ok is false when the token is not shorthand.
func expandAbbreviation(tok string, final bool) (words []string, rd *Reading, ok bool) {
	a, ok := abbreviations[tok]
	if !ok || (a.last && !final) {
		return nil, nil, false
	}
	if a.disclose {
		rd = &Reading{From: tok, To: strings.Join(a.to, " "), Kind: KindAbbreviation}
	}
	return a.to, rd, true
}

// ExpandAbbreviations expands the shorthand tokens of a space-separated text,
// keeping each token's sentence punctuation ("rn?" → "right now?"), and
// returns the readings to disclose.
func ExpandAbbreviations(text string) (string, []Reading) {
	toks := strings.Fields(text)
	out := make([]string, 0, len(toks))
	var rds []Reading
	for i, t := range toks {
		core := strings.TrimRight(t, "?!.,;:")
		tail := t[len(core):]
		words, rd, ok := expandAbbreviation(core, i == len(toks)-1 || tail != "")
		if !ok {
			out = append(out, t)
			continue
		}
		if rd != nil {
			rds = append(rds, *rd)
		}
		if len(words) == 0 {
			if tail != "" && len(out) > 0 {
				out[len(out)-1] += tail
			}
			continue
		}
		w := append([]string(nil), words...)
		w[len(w)-1] += tail
		out = append(out, w...)
	}
	return strings.Join(out, " "), rds
}

// smallNumbers are the number words read as digits. "one" is deliberately
// absent: "that one" / "which one" point at something, they do not count it.
var smallNumbers = map[string]int{
	"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
	"eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
	"eighteen": 18, "nineteen": 19,
}

var tens = map[string]int{"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}

var units = map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}

// NumberWord reads one number word ("five", "twenty", "twenty-four").
func NumberWord(w string) (int, bool) {
	if n, ok := smallNumbers[w]; ok {
		return n, true
	}
	if n, ok := tens[w]; ok {
		return n, true
	}
	if i := strings.IndexByte(w, '-'); i > 0 {
		t, ok1 := tens[w[:i]]
		u, ok2 := units[w[i+1:]]
		if ok1 && ok2 {
			return t + u, true
		}
	}
	return 0, false
}

// Normalize is the grammar's reading of a question. It is a pure function:
// the same question always yields the same Norm.
func Normalize(q string) Text {
	s := Fold(strings.TrimSpace(q))
	s = strings.NewReplacer("?", " ", "!", " ", ",", " ", ";", " ").Replace(s)
	s = strings.NewReplacer("sd-wan", "sdwan", "sd wan", "sdwan", "'s ", " ").Replace(s + " ")
	s = punctRe.ReplaceAllString(s, " ")
	s = strings.TrimRight(s, ". ")
	raw := strings.Fields(s)
	toks := make([]string, 0, len(raw))
	var rds []Reading
	for i := 0; i < len(raw); i++ {
		w := raw[i]
		if words, rd, ok := expandAbbreviation(w, i == len(raw)-1); ok {
			toks = append(toks, words...)
			if rd != nil {
				rds = append(rds, *rd)
			}
			continue
		}
		if parts, ok := contractions[w]; ok {
			toks = append(toks, parts...)
			continue
		}
		// "twenty four" / "twenty-four" → 24; a lone "twenty" → 20.
		if t, ok := tens[w]; ok {
			if i+1 < len(raw) {
				if u, ok := units[raw[i+1]]; ok {
					toks = append(toks, strconv.Itoa(t+u))
					i++
					continue
				}
			}
			toks = append(toks, strconv.Itoa(t))
			continue
		}
		if n, ok := NumberWord(w); ok {
			toks = append(toks, strconv.Itoa(n))
			continue
		}
		toks = append(toks, w)
	}
	return Text{Raw: q, Norm: strings.Join(toks, " "), Tokens: toks, Readings: rds}
}

// Squash is the name key: Fold, then only letters and digits. Two names with
// the same key differ only in separators and case ("edge-1", "edge_1",
// "Edge 1", "edge1").
func Squash(s string) string {
	var b strings.Builder
	for _, r := range Fold(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r > unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r))) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Singular returns the singular of a regular English plural, or w itself:
// "incidents" → "incident", "switches" → "switch", "policies" → "policy".
// Words ending in "ss"/"us"/"is" are not plurals ("status", "class", "dns").
func Singular(w string) string {
	n := len(w)
	switch {
	case n <= 3 || !strings.HasSuffix(w, "s"):
		return w
	case strings.HasSuffix(w, "ss") || strings.HasSuffix(w, "us") || strings.HasSuffix(w, "is"):
		return w
	case strings.HasSuffix(w, "ies") && n > 4:
		return w[:n-3] + "y"
	case strings.HasSuffix(w, "ches") || strings.HasSuffix(w, "shes") || strings.HasSuffix(w, "xes") || strings.HasSuffix(w, "sses"):
		return w[:n-2]
	}
	return w[:n-1]
}

// tokenSplitRe splits on anything an identifier is not made of; letters of any
// script survive (a site named in another language is still one token).
var tokenSplitRe = regexp.MustCompile(`[^\p{L}\p{N}:/._@%'-]+`)

// Tokens is the identifier-preserving reading of free text: Fold, split on
// every character a name cannot contain, and trim sentence punctuation off
// each token's ends ("edge-1." → "edge-1"). The model compiler matches names
// and values with it; unlike Normalize it rewrites no word.
func Tokens(q string) []string {
	var toks []string
	for _, t := range tokenSplitRe.Split(Fold(q), -1) {
		t = strings.Trim(t, ".'-")
		if t != "" {
			toks = append(toks, t)
		}
	}
	return toks
}

// ClassifierText is the question router's reading: Fold and single spaces,
// with sentence punctuation KEPT — the router's rules read "?" as the end of a
// clause — and misspelt core words repaired (ClassifierRepair).
func ClassifierText(q string) string {
	t, _ := ClassifierRepair(q)
	return t
}
