package ai

// explain.go — the EXPLAIN skill: the words a screen used to carry.
//
// Programme: docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md (tracker 270).
// A screen states facts and offers actions; it does not teach. Every sentence
// that TAUGHT — what a KPI counts, what a chip implies, what a badge means —
// left the UI and became one file here. The `(i)` affordance next to the number
// (components/AskIris.tsx) asks Iris, Iris answers from the authored file, and
// cites it.
//
// KNOWLEDGE-AS-DATA, same stance as skills/ (skill.go):
//   - one `skills/explain/<topic>.md` per removed explanation, compiled in;
//   - server-owned content: it cannot be uploaded, and nothing in it widens what
//     the caller may run — an explanation reads NO tenant data at all, so there
//     is nothing here to scope (§3a is satisfied by construction: the answer is
//     identical for every tenant because it is a definition, not a row);
//   - LLM01/LLM03 (§15): the answer is SERVER-AUTHORED prose returned verbatim.
//     No provider is called, nothing is generated, and a topic with no file gets
//     an honest refusal — never an improvised definition. The UI renders it as
//     escaped React text (LLM02).
//
// FORMAT (the same deliberately tiny dialect the skills use):
//
//	---
//	topic: kpi.confirmed-rca
//	question: What counts as a confirmed RCA?
//	keywords: confirmed rca, confirmed verdict
//	---
//	The answer, ≤ 120 words, plain language, naming the page it belongs to.
//
// The loader enforces every one of those, INCLUDING the word cap — brevity is a
// build gate here, because an explanation that grows back into a paragraph is
// the thing this programme removed.

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

//go:embed skills/explain/*.md
var explainFS embed.FS

// explainDir is where an author adds an explanation, and what Iris cites.
const explainDir = "ai/skills/explain"

// MaxExplainWords is the authored-body cap. 120 words is roughly the longest
// answer an operator will read in a drawer without scrolling; past that the
// explanation belongs in the docs portal, which Iris already retrieves.
const MaxExplainWords = 120

// ExplainIntent is the intent stamped on an explanation answer (audit + tests).
const ExplainIntent = "explain"

// ExplainContextKey is the ui-context key AskIris sends. The frontend passes the
// topic explicitly so selection never depends on how the operator phrased it.
const ExplainContextKey = "topic"

// reExplainTopic is the topic-id shape: dotted, lowercase, hyphen-separated
// segments — `kpi.confirmed-rca`, `chip.noc-pressure`. It is also the FILE name,
// so a topic can never escape the explain directory.
var reExplainTopic = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

// reExplainAsk is the "this is a definition question" test. Keyword matching is
// gated behind it so an operational complaint that happens to contain a term
// ("bgp is down on spine1") can never be answered with a glossary entry instead
// of an investigation.
var reExplainAsk = regexp.MustCompile(`(?i)(\bwhat (is|are|does|do|counts?)\b|\bwhat'?s\b|\bwhat does\b.*\bmean\b|\bmeaning of\b|\bexplain\b|\bdefine\b|\bhow is .* (counted|derived|calculated)\b)`)

// Explanation is one authored answer.
type Explanation struct {
	Topic    string   // == the file base name
	Question string   // the canned question AskIris asks on the operator's behalf
	Keywords []string // lowercased match phrases
	Body     string   // the answer, returned VERBATIM
	File     string   // "ai/skills/explain/<topic>.md" — what Iris cites
}

// ExplainSet is the loaded corpus, immutable and shared read-only.
type ExplainSet struct {
	byTopic map[string]*Explanation
	order   []string
}

// Len is the number of authored explanations.
func (s *ExplainSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

// Topics lists every authored topic in sorted order.
func (s *ExplainSet) Topics() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// ByTopic returns the authored explanation for a topic id.
func (s *ExplainSet) ByTopic(topic string) (*Explanation, bool) {
	if s == nil {
		return nil, false
	}
	e, ok := s.byTopic[strings.ToLower(strings.TrimSpace(topic))]
	return e, ok
}

// Match finds an explanation by keyword for a free-typed DEFINITION question.
// It is deliberately narrow (see reExplainAsk) and deterministic: the
// longest-keyword match wins, ties broken by topic, so the same words always
// reach the same file.
func (s *ExplainSet) Match(question string) (*Explanation, bool) {
	if s == nil || len(s.order) == 0 {
		return nil, false
	}
	if !reExplainAsk.MatchString(question) {
		return nil, false
	}
	q := " " + strings.ToLower(strings.TrimSpace(question)) + " "
	var best *Explanation
	bestLen := 0
	for _, name := range s.order {
		e := s.byTopic[name]
		for _, k := range e.Keywords {
			if !phraseMatches(q, k) {
				continue
			}
			if len(k) > bestLen {
				best, bestLen = e, len(k)
			}
		}
	}
	return best, best != nil
}

// LoadExplanations parses and validates the whole embedded corpus. Like
// LoadSkills it FAILS on drift rather than degrading: a malformed file, a topic
// that disagrees with its file name, a duplicate, or a body over the word cap is
// a build-visible error, not a bad answer discovered by an operator.
func LoadExplanations() (*ExplainSet, error) {
	entries, err := fs.Glob(explainFS, "skills/explain/*.md")
	if err != nil {
		return nil, fmt.Errorf("explain: glob: %w", err)
	}
	sort.Strings(entries)
	set := &ExplainSet{byTopic: make(map[string]*Explanation, len(entries))}
	for _, p := range entries {
		raw, rerr := explainFS.ReadFile(p)
		if rerr != nil {
			return nil, fmt.Errorf("explain: read %s: %w", p, rerr)
		}
		base := strings.TrimSuffix(path.Base(p), ".md")
		e, perr := parseExplanation(base, string(raw))
		if perr != nil {
			return nil, fmt.Errorf("explain: %s: %w", p, perr)
		}
		if _, dup := set.byTopic[e.Topic]; dup {
			return nil, fmt.Errorf("explain: duplicate topic %q", e.Topic)
		}
		set.byTopic[e.Topic] = e
		set.order = append(set.order, e.Topic)
	}
	sort.Strings(set.order)
	return set, nil
}

// parseExplanation validates one authored file.
func parseExplanation(base, raw string) (*Explanation, error) {
	front, body, err := splitSkillFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	fields, blocks, err := parseFrontmatter(front)
	if err != nil {
		return nil, err
	}
	if len(blocks) > 0 {
		return nil, fmt.Errorf("frontmatter takes only topic, question and keywords — no list blocks")
	}
	for k := range fields {
		switch k {
		case "topic", "question", "keywords":
		default:
			return nil, fmt.Errorf("unknown frontmatter key %q (topic, question, keywords)", k)
		}
	}
	topic := strings.ToLower(strings.TrimSpace(fields["topic"]))
	if topic == "" {
		return nil, fmt.Errorf("topic: is required")
	}
	if !reExplainTopic.MatchString(topic) {
		return nil, fmt.Errorf("topic %q must match %s", topic, reExplainTopic)
	}
	if topic != base {
		return nil, fmt.Errorf("topic %q must equal the file name %q — the file name is the id AskIris sends", topic, base)
	}
	question := strings.TrimSpace(fields["question"])
	if question == "" {
		return nil, fmt.Errorf("question: is required — it is what Iris asks on the operator's behalf")
	}
	keywords := lowerList(splitCommaList(fields["keywords"]))
	if len(keywords) == 0 {
		return nil, fmt.Errorf("keywords: is required — at least one match phrase")
	}
	text := strings.TrimSpace(body)
	if text == "" {
		return nil, fmt.Errorf("body is empty — an explanation with no answer explains nothing")
	}
	if n := countWords(text); n > MaxExplainWords {
		return nil, fmt.Errorf("body is %d words; the cap is %d — an explanation that long belongs in the docs portal", n, MaxExplainWords)
	}
	return &Explanation{
		Topic: topic, Question: question, Keywords: keywords,
		Body: text, File: explainDir + "/" + base + ".md",
	}, nil
}

// countWords counts whitespace-separated tokens carrying a letter or digit, so
// a bare bullet dash never counts as a word.
func countWords(s string) int {
	n := 0
	for _, f := range strings.Fields(s) {
		if strings.ContainsFunc(f, func(r rune) bool {
			return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		}) {
			n++
		}
	}
	return n
}

// ---- answering --------------------------------------------------------------

// explainCitation is the provenance stamp: the authored file, by name, so an
// operator (or a reviewer) can go read exactly what Iris was handed. Href is
// empty on purpose — the file is not a UI route, and IrisLane renders a
// citation with no same-origin href as inert text rather than inventing a link.
func explainCitation(topic, file string) Citation {
	return Citation{ID: "explain:" + topic, Kind: "knowledge", Label: file}
}

// Answer renders one authored explanation as the grounded answer envelope.
// The body is returned VERBATIM: no provider is called and nothing is
// paraphrased, which is what makes this answer identical offline, on every
// deployment, forever.
func (e *Explanation) Answer() Answer {
	return Answer{
		Mode:            ModeProductAnswer,
		Intent:          ExplainIntent,
		Modules:         []string{},
		Title:           e.Question,
		Text:            e.Body,
		Citations:       []Citation{explainCitation(e.Topic, e.File)},
		Disclaimers:     []string{},
		EvidenceOnly:    true,
		ConfidenceLabel: "Authored",
	}
}

// explainMissingAnswer is the refusal. A topic the UI asked for but nobody
// authored is a CONTENT GAP, and saying so is the only honest answer: improvising
// a definition would put a made-up meaning behind a number an operator acts on
// (§15 LLM01/LLM03, and §10 "no silent failures").
func explainMissingAnswer(topic string) Answer {
	safe := strings.TrimSpace(topic)
	if !reExplainTopic.MatchString(strings.ToLower(safe)) {
		safe = "that"
	}
	return Answer{
		Mode:         ModeProductAnswer,
		Intent:       ExplainIntent,
		Modules:      []string{},
		Title:        "No explanation authored",
		Text:         "No explanation is written for " + safe + " yet, so I will not guess at one. Add " + explainDir + "/" + safe + ".md and I will answer from it.",
		Citations:    []Citation{},
		Disclaimers:  []string{"Explanations are authored files, never generated."},
		EvidenceOnly: true,
	}
}

// explainTopicFromAsk resolves the topic an ask names, from either shape:
//
//	uiContext["topic"]  — what components/AskIris.tsx sends (the normal path);
//	"topic=<id> …"      — the prefix form the design doc names, so the same
//	                      answer is reachable by typing it into the drawer.
//
// It returns ok=true whenever a topic was NAMED, even an unknown one: naming a
// topic is a request for an authored answer, and the honest reply to an unknown
// one is the refusal, never a fallthrough to a generated answer.
func explainTopicFromAsk(question string, uiContext map[string]string) (string, bool) {
	if t := strings.TrimSpace(uiContext[ExplainContextKey]); t != "" {
		return strings.ToLower(t), true
	}
	q := strings.TrimSpace(question)
	if !strings.HasPrefix(strings.ToLower(q), "topic=") {
		return "", false
	}
	rest := strings.TrimSpace(q[len("topic="):])
	if i := strings.IndexAny(rest, " \t\n"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return strings.ToLower(rest), true
}

// answerExplain is the orchestrator hook. It runs BEFORE Classify because an
// explanation is a lookup, not a classification: the UI already said which term
// it wants defined, and no amount of question-shape guessing improves on that.
//
// handled=false means "this ask is not an explanation" and the classic path runs
// completely unchanged — nil Explain disables the layer entirely.
func (o *Orchestrator) answerExplain(question string, uiContext map[string]string) (Answer, bool) {
	if topic, named := explainTopicFromAsk(question, uiContext); named {
		if e, ok := o.Explain.ByTopic(topic); ok {
			return e.Answer(), true
		}
		return explainMissingAnswer(topic), true
	}
	if o.Explain.Len() == 0 {
		return Answer{}, false
	}
	if e, ok := o.Explain.Match(question); ok {
		return e.Answer(), true
	}
	return Answer{}, false
}
