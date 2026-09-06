package ai

// explain_test.go — the EXPLAIN corpus and its answering rules.
//
// What matters here is not that a lookup works; it is the three promises the
// programme rests on (docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md):
//
//	1. every authored file is VALID and SHORT — brevity is a build gate, because
//	   the whole point was to stop explanations growing back into paragraphs;
//	2. a NAMED topic with no file is REFUSED, never improvised (§15 LLM01/LLM03);
//	3. keyword matching cannot hijack an operational question — "bgp is down on
//	   spine1" must still reach an investigation, not a glossary entry.

import (
	"strings"
	"testing"
)

func loadExplainT(t *testing.T) *ExplainSet {
	t.Helper()
	set, err := LoadExplanations()
	if err != nil {
		t.Fatalf("LoadExplanations: %v", err)
	}
	return set
}

func TestExplainCorpusLoadsAndIsAuthoredWell(t *testing.T) {
	set := loadExplainT(t)
	if set.Len() == 0 {
		t.Fatal("no explanations are embedded — the (i) affordance would have nothing to answer from")
	}
	for _, topic := range set.Topics() {
		e, ok := set.ByTopic(topic)
		if !ok {
			t.Fatalf("%s: listed but not retrievable", topic)
		}
		if n := countWords(e.Body); n > MaxExplainWords {
			t.Errorf("%s: body is %d words (cap %d)", topic, n, MaxExplainWords)
		}
		if !strings.HasSuffix(e.Question, "?") {
			t.Errorf("%s: question %q must read as a question", topic, e.Question)
		}
		if e.File != explainDir+"/"+topic+".md" {
			t.Errorf("%s: cites %q, not its own file", topic, e.File)
		}
		for _, k := range e.Keywords {
			if k != strings.ToLower(k) {
				t.Errorf("%s: keyword %q is not lowercased", topic, k)
			}
		}
	}
}

// Every topic is reachable BY ID, and the answer is the authored bytes — not a
// paraphrase, not a template. This is the "offline installs get the same answer"
// promise made mechanical.
func TestExplainAnswersVerbatimAndCitesItsFile(t *testing.T) {
	set := loadExplainT(t)
	o := &Orchestrator{Explain: set}
	for _, topic := range set.Topics() {
		e, _ := set.ByTopic(topic)
		ans, handled := o.answerExplain("What does this mean?", map[string]string{ExplainContextKey: topic})
		if !handled {
			t.Fatalf("%s: a named topic was not handled", topic)
		}
		if ans.Text != e.Body {
			t.Errorf("%s: answer is not the authored body verbatim", topic)
		}
		if ans.Intent != ExplainIntent || !ans.EvidenceOnly {
			t.Errorf("%s: intent=%q evidenceOnly=%v — an explanation is authored, never generated", topic, ans.Intent, ans.EvidenceOnly)
		}
		if len(ans.Citations) != 1 || ans.Citations[0].Label != e.File {
			t.Errorf("%s: must cite exactly its own file, got %+v", topic, ans.Citations)
		}
		if ans.Citations[0].Href != "" {
			t.Errorf("%s: a file is not a UI route — href must stay empty", topic)
		}
	}
}

func TestExplainRefusesAnUnauthoredTopic(t *testing.T) {
	o := &Orchestrator{Explain: loadExplainT(t)}
	ans, handled := o.answerExplain("What does this mean?", map[string]string{ExplainContextKey: "kpi.not-authored-yet"})
	if !handled {
		t.Fatal("naming a topic must always be handled — falling through would let a definition be generated")
	}
	if len(ans.Citations) != 0 {
		t.Error("a refusal must cite nothing")
	}
	for _, want := range []string{"kpi.not-authored-yet", explainDir} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("refusal must name %q so the gap is actionable; got %q", want, ans.Text)
		}
	}
	if strings.Contains(strings.ToLower(ans.Text), "probably") {
		t.Error("a refusal must not hedge into a guess")
	}
}

// A topic id is also a FILE NAME. A hostile one must never be echoed back into
// the answer (it would be the only operator-visible place a caller controls).
func TestExplainRefusalNeverEchoesAHostileTopic(t *testing.T) {
	o := &Orchestrator{Explain: loadExplainT(t)}
	for _, bad := range []string{"../../etc/passwd", "<script>alert(1)</script>", "kpi/../secret"} {
		ans, handled := o.answerExplain("", map[string]string{ExplainContextKey: bad})
		if !handled {
			t.Fatalf("%q: must be handled as a refusal", bad)
		}
		if strings.Contains(ans.Text, bad) {
			t.Errorf("%q: refusal echoed the raw topic back: %q", bad, ans.Text)
		}
	}
}

// The `topic=` prefix form of the design doc reaches the same file as the
// context key, so an operator can type what the UI sends.
func TestExplainTopicPrefixMatchesTheContextKey(t *testing.T) {
	set := loadExplainT(t)
	topic := set.Topics()[0]
	o := &Orchestrator{Explain: set}
	viaCtx, ok1 := o.answerExplain("anything", map[string]string{ExplainContextKey: topic})
	viaPrefix, ok2 := o.answerExplain("topic="+topic, nil)
	if !ok1 || !ok2 {
		t.Fatal("both forms must be handled")
	}
	if viaCtx.Text != viaPrefix.Text {
		t.Error("the topic= prefix and the topic context key must resolve to the same file")
	}
}

// The narrowness guard: keyword matching only fires on a DEFINITION question.
func TestExplainKeywordMatchNeverHijacksAnOperationalQuestion(t *testing.T) {
	set := loadExplainT(t)
	o := &Orchestrator{Explain: set}
	for _, q := range []string{
		"bgp is down on spine1",
		"why are correlated incidents piling up right now",
		"noc pressure is severe, what should I work first",
		"confirmed rca on P-5564D1 is not ticketed",
	} {
		if _, handled := o.answerExplain(q, nil); handled {
			t.Errorf("%q was answered as a definition — an operational question must reach the investigation path", q)
		}
	}
}

func TestExplainKeywordMatchAnswersADefinitionQuestion(t *testing.T) {
	set := loadExplainT(t)
	o := &Orchestrator{Explain: set}
	ans, handled := o.answerExplain("what is noc pressure?", nil)
	if !handled {
		t.Fatal("a plain definition question over an authored keyword must be answered")
	}
	if len(ans.Citations) != 1 || !strings.Contains(ans.Citations[0].Label, "chip.noc-pressure") {
		t.Errorf("wrong file cited: %+v", ans.Citations)
	}
}

// A nil corpus disables the layer: no topic named, nothing handled, and the
// classic path runs unchanged.
func TestExplainNilSetDisablesTheLayer(t *testing.T) {
	o := &Orchestrator{}
	if _, handled := o.answerExplain("what is noc pressure?", nil); handled {
		t.Error("a nil Explain set must not handle a keyword question")
	}
}

// The loader is the gate. Each of these files is exactly the drift that must
// fail the build rather than reach an operator.
func TestExplainLoaderRejectsBadAuthoring(t *testing.T) {
	long := strings.Repeat("word ", MaxExplainWords+5)
	cases := []struct{ name, base, raw, want string }{
		{"no fence", "a", "topic: a\n", "frontmatter fence"},
		{"topic disagrees with file", "a", "---\ntopic: b\nquestion: What?\nkeywords: x\n---\nBody.\n", "must equal the file name"},
		{"missing question", "a", "---\ntopic: a\nkeywords: x\n---\nBody.\n", "question: is required"},
		{"missing keywords", "a", "---\ntopic: a\nquestion: What?\n---\nBody.\n", "keywords: is required"},
		{"empty body", "a", "---\ntopic: a\nquestion: What?\nkeywords: x\n---\n\n", "body is empty"},
		{"over the word cap", "a", "---\ntopic: a\nquestion: What?\nkeywords: x\n---\n" + long + "\n", "the cap is"},
		{"unknown key", "a", "---\ntopic: a\nquestion: What?\nkeywords: x\npage: /x\n---\nBody.\n", "unknown frontmatter key"},
		{"bad topic shape", "A_b", "---\ntopic: A_b\nquestion: What?\nkeywords: x\n---\nBody.\n", "must match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseExplanation(c.base, c.raw)
			if err == nil {
				t.Fatalf("expected a load error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}
