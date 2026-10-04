// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_reference_test.go — RULE ZERO for the skill chain, mechanised
// (tracker 331; the sibling of internal/tac/reference_test.go).
//
// A `next=` rule's CONDITION names something that lives in another package, and
// in one case in another language:
//
//	signature=<id>        a protocoldiag signature, scored only for the ISSUE the
//	                      skill's own gather pinned (Analyzer.byIssue)
//	issue_id=<id>         a protocoldiag catalog issue, named as a gather literal
//	verdict:phrase=<word> a WORD of the correlation engine's own operator phrase,
//	                      i.e. of the shipped NOC signature catalogue
//
// The loader cannot check any of that: it validates shape, and every one of
// these is shape-valid right up to the moment it stops matching anything. This
// test reads the real files and does — because a rule that can never fire is
// worse than a missing one. It does not degrade the investigation loudly; it
// degrades it silently, one hop shallower, with CI green.
//
// Import-free ON PURPOSE, exactly as the TAC reference test is: the ids live in
// internal/protocoldiag, in internal/noclabel and in Python, and a cross-domain
// import to reach them would be the coupling the architecture rules forbid.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// skillRepoRoot walks up from the package directory to the repository root, so
// the test works from `go test ./...` anywhere. A tree with no repository root
// at all (a vendored or extracted source drop) skips; a tree that HAS one and is
// missing a corpus file fails, because a cross-check that did not run is exactly
// the silent gap this file exists to close.
func skillRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "src", "config", "rules.yaml")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repository root not reachable from the test working directory")
	return ""
}

func mustReadCorpus(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("%s is not readable (%v) — the skill reference check cannot be skipped away", rel, err)
	}
	return string(b)
}

var (
	// `ID: "ospf-flap-l1", IssueID: "ospf-flapping",` in protocoldiag/analyze.go.
	reDiagSignature = regexp.MustCompile(`ID:\s*"([a-z0-9-]+)",\s*IssueID:\s*"([a-z0-9-]+)"`)
	// `ID: "ospf-flapping", Protocol: ProtocolOSPF,` in protocoldiag/catalog.go.
	reDiagIssue = regexp.MustCompile(`ID:\s*"([a-z0-9-]+)",\s*Protocol:`)
	// The engine's authored operator wording, Python side: one or more adjacent
	// string literals after `"operator_phrase":`.
	reOperatorPhrase = regexp.MustCompile(`"operator_phrase":\s*\(?((?:\s*"[^"]*")+)`)
	reQuoted         = regexp.MustCompile(`"([^"]*)"`)
	// The server's NOC titles, Go side: the sigTitle map's values and the
	// SignatureTitle cascade's returns.
	reSigTitleEntry = regexp.MustCompile(`(?m)^\s*"sig\.[^"]+":\s*"([^"]*)",`)
	reTitleReturn   = regexp.MustCompile(`(?m)^\s*return\s+"([^"]+)"\s*$`)
)

// diagCorpus is the protocol-diagnostic half of the reference: every signature
// id with the issue it is scored under, and every issue id.
type diagCorpus struct {
	sigIssue map[string]string // signature id → the issue whose run scores it
	issues   map[string]bool
}

func loadDiagCorpus(t *testing.T, root string) diagCorpus {
	t.Helper()
	c := diagCorpus{sigIssue: map[string]string{}, issues: map[string]bool{}}
	for _, m := range reDiagSignature.FindAllStringSubmatch(
		mustReadCorpus(t, root, "src/backend/internal/protocoldiag/analyze.go"), -1) {
		c.sigIssue[m[1]] = m[2]
	}
	for _, m := range reDiagIssue.FindAllStringSubmatch(
		mustReadCorpus(t, root, "src/backend/internal/protocoldiag/catalog.go"), -1) {
		c.issues[m[1]] = true
	}
	if len(c.sigIssue) == 0 || len(c.issues) == 0 {
		t.Fatalf("read %d signatures and %d issues out of protocoldiag — the reference regexes have drifted",
			len(c.sigIssue), len(c.issues))
	}
	return c
}

// TestEverySkillSignatureExists proves each `signature=` value is a real
// protocoldiag signature AND that the skill's own gather can actually make it
// fire: Analyzer.Analyze scores ONLY the signatures of the issue the collection
// pinned, so a rule naming a signature from another issue is dead on arrival.
func TestEverySkillSignatureExists(t *testing.T) {
	root := skillRepoRoot(t)
	diag := loadDiagCorpus(t, root)
	set := loadTestSkills(t)

	checked := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)

		// Which issues can this method's own gather score? An explicit
		// `issue_id=` literal pins one; a diagnostic step without one runs the
		// protocol's default scenario, which we cannot narrow here, so the
		// reachability half is skipped for that method rather than guessed at.
		pinned := map[string]bool{}
		unpinned := false
		for _, g := range sk.Gather {
			if g.Tool != "run_protocol_diagnostic" {
				continue
			}
			if id := strings.TrimSpace(g.Args["issue_id"]); id != "" {
				if !diag.issues[id] {
					t.Errorf("%s: gather run_protocol_diagnostic(issue_id=%s) names an issue protocoldiag does not have",
						name, id)
				}
				pinned[id] = true
				continue
			}
			unpinned = true
		}

		for _, d := range sk.Decisions {
			if d.Kind != DecisionNext || d.Cond == nil || d.Cond.Key != CondSignature {
				continue
			}
			v := d.Cond.Value
			if v == CondSignatureNone || v == CondSignatureUncollected {
				continue // reserved outcomes, derived by the runner itself
			}
			checked++
			issue, known := diag.sigIssue[v]
			if !known {
				t.Errorf("%s: `next=%s when signature=%s` names a signature that does not exist in internal/protocoldiag; the ids it does have are %v",
					name, d.Target, v, sortedStringKeys(diag.sigIssue))
				continue
			}
			if unpinned || pinned[issue] {
				continue
			}
			t.Errorf("%s: `next=%s when signature=%s` can NEVER fire — that signature is scored only under issue %q, "+
				"and this method's gather pins %v. Analyzer.Analyze runs the signatures of the COLLECTED issue only.",
				name, d.Target, v, issue, sortedKeys(pinned))
		}
	}
	if checked == 0 {
		t.Fatal("no signature= rule was checked — the corpus or this test has drifted")
	}
	t.Logf("%d signature= rules cross-referenced against %d protocoldiag signatures / %d issues",
		checked, len(diag.sigIssue), len(diag.issues))
}

// TestEveryVerdictPhraseTokenIsProducible proves each `verdict:phrase=` token
// can still be produced by the SHIPPED wording an operator actually sees.
//
// get_rca_verdict turns `firstNonEmpty(Problem.OperatorPhrase, Problem.Title)`
// into phrase signals, and those two strings have exactly two sources:
//
//   - OperatorPhrase — the matched signature's own `operator_phrase` in the
//     correlation engine's built-in catalogue (src/correlation/catalog.py);
//   - Title — noclabel.ProblemTitle, i.e. the sigTitle map plus the
//     SignatureTitle cascade (src/backend/internal/noclabel/labels.go).
//
// Reword one NOC signature and a token can stop matching anything at all. That
// is the four-routing-rules-die-silently failure this test exists to prevent.
func TestEveryVerdictPhraseTokenIsProducible(t *testing.T) {
	root := skillRepoRoot(t)
	phrases := verdictPhraseCorpus(t, root)
	if len(phrases) < 50 {
		t.Fatalf("only %d operator-facing phrases were read — the reference regexes have drifted", len(phrases))
	}

	// The candidate token set, built with the SAME tokenizer the chain uses, so
	// this test and chainFacts can never disagree about what a phrase yields.
	token := map[string][]string{}
	for _, p := range phrases {
		for _, w := range conditionTokens(p) {
			if len(token[w]) < 3 {
				token[w] = append(token[w], p)
			}
		}
	}

	set := loadTestSkills(t)
	checked := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for _, d := range sk.Decisions {
			if d.Kind != DecisionNext || d.Cond == nil || d.Cond.Key != CondVerdictPhrase {
				continue
			}
			checked++
			if len(token[d.Cond.Value]) > 0 {
				continue
			}
			t.Errorf("%s: `next=%s when verdict:phrase=%s` matches NOTHING the engine can say. "+
				"No operator_phrase in src/correlation/catalog.py and no NOC title in "+
				"src/backend/internal/noclabel/labels.go yields the token %q, so this rule can never fire "+
				"and the investigation silently stops one hop short.",
				name, d.Target, d.Cond.Value, d.Cond.Value)
		}
	}
	if checked == 0 {
		t.Fatal("no verdict:phrase= rule was checked — the corpus or this test has drifted")
	}
	t.Logf("%d verdict:phrase= rules cross-referenced against %d operator-facing phrases (%d distinct tokens)",
		checked, len(phrases), len(token))
}

// verdictPhraseCorpus collects every string that can reach get_rca_verdict's
// `what`, from both sides of the language boundary.
func verdictPhraseCorpus(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	catalog := mustReadCorpus(t, root, "src/correlation/catalog.py")
	for _, m := range reOperatorPhrase.FindAllStringSubmatch(catalog, -1) {
		for _, q := range reQuoted.FindAllStringSubmatch(m[1], -1) {
			out = append(out, q[1])
		}
	}
	labels := mustReadCorpus(t, root, "src/backend/internal/noclabel/labels.go")
	for _, m := range reSigTitleEntry.FindAllStringSubmatch(labels, -1) {
		out = append(out, m[1])
	}
	for _, m := range reTitleReturn.FindAllStringSubmatch(labels, -1) {
		out = append(out, m[1])
	}
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
