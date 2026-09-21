// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_cases.go — BEHAVIOURAL CASES as data (tracker 331).
//
// A skill's frontmatter says what it gathers and where it hands off. Until this
// file existed, NOTHING said what the skill is supposed to DO with what it
// gathered — the loader validated key SHAPE, and the ~30 authored machine
// conditions across the corpus were never once proven to fire. A `verdict:phrase`
// rule matches a WORD in the engine's own operator phrase: reword one NOC
// signature and four routing rules die in silence with CI green and the
// investigation one hop shallower.
//
// So every skill now ships `skills/<name>/CASES.yaml`: authored fixtures of what
// the tools returned, and the hop path, selection origin, verdict wording and
// disclosures that must follow. They are loaded and validated by the SAME loader
// that reads SKILL.md, on the same terms:
//
//   - ZERO CASES IS A LOAD ERROR. A new skill cannot ship untested, exactly as a
//     dangling `next=` cannot ship at all (LoadSkills).
//   - Every expected hop must be a `next=` target the skill actually declares,
//     and must name a skill that exists — a case cannot assert a path the
//     corpus cannot take.
//   - Every fixture signal is re-validated against the SAME closed vocabulary
//     the conditions are, so a typo in a fixture fails the build instead of
//     quietly testing nothing.
//   - Each skill must carry at least one hop case, one must-NOT-hop case and one
//     disclosure case, and every case must state the verdict tokens it expects.
//
// FORMAT — the SKILL.md frontmatter dialect (`key: value` scalars and two-space
// `  - item` blocks), one case per `---`-separated document, `#` comments and
// blank lines ignored. Deliberately the same tiny, strict parser: there is no
// second dialect to learn and no general-YAML surface to be surprised by.
//
//	case: the peer is Idle so the link beneath it is the next check
//	question: why is bgp down on edge-1
//	ui:
//	  - correlation_id=case-bgp-idle
//	  - device=edge-1
//	tools:
//	  - search_logs=not_wired          # outcome per tool; unlisted tools return ok
//	signals:
//	  - state:bgp_peer=idle            # what a TOOL declared about what it read
//	evidence:
//	  - finding                        # EvidenceItem kinds the fixture returned
//	notes:
//	  - the capture was PARTIAL        # collection notes the fixture returned
//	expect_chain:
//	  - bgp-session-down entry
//	  - interface-down rule
//	expect_selected: rule              # origin of the LAST hop: rule | model | none
//	expect_reason: reports the peer Idle
//	expect_verdict:
//	  - peer
//	expect_notes:
//	  - is not available on this deployment
//	expect_never:
//	  - bgp-prefix-missing
//
// The runner (skill_cases_test.go) drives the REAL chain — the real embedded
// SKILL.md corpus, the real planner, the real Policy Engine, the real condition
// evaluator — over a registry of fixture tools built from this file. Nothing
// here mocks the thing under test.

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed skills/*/CASES.yaml
var skillCasesFS embed.FS

// skillCasesFile is the per-skill case file name, next to SKILL.md.
const skillCasesFile = "CASES.yaml"

// SkillHopExpect is one expected hop of an investigation: which method ran and
// HOW it was selected (entry | rule | model — the Chain* constants).
type SkillHopExpect struct {
	Skill    string
	Selected string
}

// SkillCase is one authored behavioural case: a fixture of what the governed
// tools returned, and the investigation that must follow from it.
type SkillCase struct {
	Name     string            // unique within the skill; names the subtest
	Question string            // the operator question for this turn
	Intent   string            // classifier intent (for the SelectSkill assertion)
	UI       map[string]string // UI context: entity name → value
	Tools    map[string]string // tool name → outcome (skillToolOutcomes)
	Signals  []string          // ToolResult.Signals the fixture tools declare
	Evidence []string          // EvidenceItem kinds the fixture tools return
	Notes    []string          // ToolResult.Notes the fixture tools return

	// ModelNext, when set, scripts the routing turn's ONE permitted reply
	// (`NEXT: <name>` / `NEXT: none`) so the model-selected path is exercised
	// deterministically. Empty means no provider directive at all: only an
	// authored rule can move the chain.
	ModelNext string

	ExpectChain    []SkillHopExpect // the whole path, first hop = this skill, entry
	ExpectSelected string           // origin of the LAST hop, or "none" when it never hopped
	ExpectReason   string           // substring of the last hop's operator-facing reason
	ExpectVerdict  []string         // tokens the final method's verdict= must state
	ExpectNotes    []string         // substrings that must reach the operator as disclosures
	ExpectNever    []string         // methods this evidence must NOT reach
	ExpectSelect   string           // SelectSkill must pick this for Question ("none" = none)
}

// caseSelectNone is the ExpectSelect / ExpectSelected value meaning "nothing".
const caseSelectNone = "none"

// caseHopOrigins is the closed vocabulary of a hop's selection origin.
var caseHopOrigins = map[string]bool{
	ChainSelectedEntry: true, ChainSelectedRule: true, ChainSelectedModel: true,
}

// caseScalarKeys / caseBlockKeys are the CLOSED key vocabulary. An unknown key
// is a load error rather than a silently ignored line — the same reason the
// frontmatter dialect rejects a typo: a case that tests nothing is worse than no
// case at all, because it reads like coverage.
var caseScalarKeys = map[string]bool{
	"case": true, "question": true, "intent": true, "model_next": true,
	"expect_selected": true, "expect_reason": true, "expect_select": true,
}

var caseBlockKeys = map[string]bool{
	"ui": true, "tools": true, "signals": true, "evidence": true, "notes": true,
	"expect_chain": true, "expect_verdict": true, "expect_notes": true, "expect_never": true,
}

// loadSkillCases reads and validates one skill's CASES.yaml. Every error names
// the skill, the case and the offending line, because the whole point of this
// file is that a drifting method fails LOUDLY.
func loadSkillCases(sk *Skill) ([]SkillCase, error) {
	p := path.Join("skills", sk.Name, skillCasesFile)
	raw, err := skillCasesFS.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("%s is missing or unreadable (%v) — every skill must ship behavioural cases", p, err)
	}
	cases, perr := parseSkillCaseFile(sk, string(raw))
	if perr != nil {
		return nil, fmt.Errorf("%s: %w", p, perr)
	}
	return cases, nil
}

// parseSkillCaseFile is loadSkillCases without the filesystem, so the failure
// modes below are unit-testable on a string.
func parseSkillCaseFile(sk *Skill, raw string) ([]SkillCase, error) {
	docs := splitCaseDocs(raw)
	if len(docs) == 0 {
		return nil, fmt.Errorf("declares ZERO cases — a method with no proven behaviour may not ship")
	}
	targets := map[string]bool{}
	for _, n := range sk.NextSkills() {
		targets[n] = true
	}
	seen := map[string]bool{}
	out := make([]SkillCase, 0, len(docs))
	for i, doc := range docs {
		c, cerr := parseSkillCase(sk, doc, targets)
		if cerr != nil {
			return nil, fmt.Errorf("case %d: %w", i+1, cerr)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("duplicate case %q", c.Name)
		}
		seen[c.Name] = true
		out = append(out, c)
	}
	if err := validateCaseCoverage(out); err != nil {
		return nil, err
	}
	return out, nil
}

// splitCaseDocs strips `#` comments and blank lines and splits the file into
// `---`-fenced case documents. A leading fence (the SPDX header's separator) and
// a trailing one are both tolerated; an empty document is dropped.
func splitCaseDocs(raw string) []string {
	var docs []string
	var cur []string
	flush := func() {
		if body := strings.TrimSpace(strings.Join(cur, "\n")); body != "" {
			docs = append(docs, strings.Join(cur, "\n"))
		}
		cur = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "---":
			flush()
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			// comment / blank — never part of a case
		default:
			cur = append(cur, line)
		}
	}
	flush()
	return docs
}

// parseSkillCase validates one case document against the closed vocabulary and
// against the SKILL's own declarations: a case may only name tools the skill
// gathers with and hops the skill authored.
func parseSkillCase(sk *Skill, doc string, targets map[string]bool) (SkillCase, error) {
	fields, blocks, err := parseFrontmatter(doc)
	if err != nil {
		return SkillCase{}, err
	}
	for k := range fields {
		if !caseScalarKeys[k] {
			if caseBlockKeys[k] {
				return SkillCase{}, fmt.Errorf("key %q takes a list, not a value", k)
			}
			return SkillCase{}, fmt.Errorf("unknown key %q (scalars: %v)", k, sortedKeys(caseScalarKeys))
		}
	}
	for k := range blocks {
		if !caseBlockKeys[k] {
			if caseScalarKeys[k] {
				return SkillCase{}, fmt.Errorf("key %q takes a value, not a list", k)
			}
			return SkillCase{}, fmt.Errorf("unknown key %q (lists: %v)", k, sortedKeys(caseBlockKeys))
		}
	}

	c := SkillCase{
		Name:         strings.TrimSpace(fields["case"]),
		Question:     strings.TrimSpace(fields["question"]),
		Intent:       strings.TrimSpace(fields["intent"]),
		ModelNext:    strings.TrimSpace(fields["model_next"]),
		ExpectReason: strings.TrimSpace(fields["expect_reason"]),
		ExpectSelect: strings.TrimSpace(fields["expect_select"]),
		UI:           map[string]string{},
		Tools:        map[string]string{},
	}
	if c.Name == "" {
		return SkillCase{}, fmt.Errorf("case: is required — name what this fixture proves")
	}
	if c.Question == "" {
		return SkillCase{}, fmt.Errorf("%s: question: is required — a case must state what the operator asked", c.Name)
	}
	named := func(format string, a ...any) error {
		return fmt.Errorf("%s: "+format, append([]any{c.Name}, a...)...)
	}

	// ── the fixture ──────────────────────────────────────────────────────
	for _, line := range blocks["ui"] {
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || v == "" {
			return SkillCase{}, named("ui %q must be entity=value", line)
		}
		if !skillEntities[k] {
			return SkillCase{}, named("ui %q is not a resolvable entity (%v)", k, sortedKeys(skillEntities))
		}
		if _, dup := c.UI[k]; dup {
			return SkillCase{}, named("ui entity %q given twice", k)
		}
		c.UI[k] = v
	}
	for _, line := range blocks["tools"] {
		name, outcome, ok := strings.Cut(line, "=")
		name, outcome = strings.TrimSpace(name), strings.TrimSpace(outcome)
		if !ok {
			return SkillCase{}, named("tools %q must be tool=outcome", line)
		}
		// The tool must be a governed read-only one. That it is actually GATHERED
		// somewhere on this case's expected path is checked in the whole-set pass,
		// where the later hops' own tool lists are loaded.
		if !skillToolAllowlist[name] {
			return SkillCase{}, named("tools names %q, which is not on the skill tool allowlist", name)
		}
		if !skillToolOutcomes[outcome] {
			return SkillCase{}, named("tool outcome %q is not one of %v", outcome, sortedKeys(skillToolOutcomes))
		}
		if _, dup := c.Tools[name]; dup {
			return SkillCase{}, named("tool %q given twice", name)
		}
		c.Tools[name] = outcome
	}
	// At least one gather tool must actually answer, or the turn is not handled
	// at all and the case would be asserting the FALLBACK path, not the method.
	answering := 0
	for _, t := range sk.Tools {
		if c.Tools[t] == "" || c.Tools[t] == "ok" {
			answering++
		}
	}
	if answering == 0 {
		return SkillCase{}, named("every tool fails — a turn that gathers nothing never reaches the method")
	}
	for _, s := range blocks["signals"] {
		if err := validateCaseSignal(s); err != nil {
			return SkillCase{}, named("signal %q: %w", s, err)
		}
		c.Signals = append(c.Signals, s)
	}
	for _, k := range blocks["evidence"] {
		if !skillEvidenceKinds[k] {
			return SkillCase{}, named("evidence kind %q is not one of %v", k, sortedKeys(skillEvidenceKinds))
		}
		c.Evidence = append(c.Evidence, k)
	}
	c.Notes = append(c.Notes, blocks["notes"]...)

	// ── the expectations ─────────────────────────────────────────────────
	for _, line := range blocks["expect_chain"] {
		name, origin, ok := strings.Cut(line, " ")
		name, origin = strings.TrimSpace(name), strings.TrimSpace(origin)
		if !ok || !caseHopOrigins[origin] {
			return SkillCase{}, named("expect_chain %q must be `<skill> <%s|%s|%s>`", line,
				ChainSelectedEntry, ChainSelectedRule, ChainSelectedModel)
		}
		c.ExpectChain = append(c.ExpectChain, SkillHopExpect{Skill: name, Selected: origin})
	}
	if len(c.ExpectChain) == 0 {
		return SkillCase{}, named("expect_chain is required — state the path this evidence must take")
	}
	if first := c.ExpectChain[0]; first.Skill != sk.Name || first.Selected != ChainSelectedEntry {
		return SkillCase{}, named("expect_chain must start at %q as the %s hop, got %q %q",
			sk.Name, ChainSelectedEntry, first.Skill, first.Selected)
	}
	hopped := map[string]bool{sk.Name: true}
	for _, h := range c.ExpectChain[1:] {
		if h.Selected == ChainSelectedEntry {
			return SkillCase{}, named("only the FIRST hop may be the %s selection", ChainSelectedEntry)
		}
		if hopped[h.Skill] {
			return SkillCase{}, named("expect_chain revisits %q — the loop can never cycle", h.Skill)
		}
		hopped[h.Skill] = true
	}
	// The hop out of THIS skill must be one this skill actually declares. A
	// later hop is checked against ITS OWN skill in the whole-set pass, where
	// the other skills are loaded.
	if len(c.ExpectChain) > 1 && !targets[c.ExpectChain[1].Skill] {
		return SkillCase{}, named("expect_chain hops to %q, which %s never declares as a next= target",
			c.ExpectChain[1].Skill, sk.Name)
	}
	c.ExpectSelected = strings.TrimSpace(fields["expect_selected"])
	switch {
	case c.ExpectSelected == "":
		return SkillCase{}, named("expect_selected is required — say how the LAST hop was chosen (%s, %s or %s)",
			ChainSelectedRule, ChainSelectedModel, caseSelectNone)
	case c.ExpectSelected == caseSelectNone:
		if len(c.ExpectChain) != 1 {
			return SkillCase{}, named("expect_selected %q contradicts a %d-hop expect_chain", caseSelectNone, len(c.ExpectChain))
		}
	case c.ExpectSelected == ChainSelectedRule || c.ExpectSelected == ChainSelectedModel:
		last := c.ExpectChain[len(c.ExpectChain)-1]
		if len(c.ExpectChain) == 1 || last.Selected != c.ExpectSelected {
			return SkillCase{}, named("expect_selected %q does not match the last hop of expect_chain", c.ExpectSelected)
		}
	default:
		return SkillCase{}, named("expect_selected %q is not one of %s, %s, %s",
			c.ExpectSelected, ChainSelectedRule, ChainSelectedModel, caseSelectNone)
	}
	if c.ModelNext != "" && c.ModelNext != caseSelectNone && !targets[c.ModelNext] {
		return SkillCase{}, named("model_next %q is not a next= target of %s — the model may only pick from the author's own list",
			c.ModelNext, sk.Name)
	}
	if c.ExpectSelected == ChainSelectedModel && c.ModelNext == "" {
		return SkillCase{}, named("expect_selected %s needs a model_next: line to script the routing turn", ChainSelectedModel)
	}
	c.ExpectVerdict = append(c.ExpectVerdict, blocks["expect_verdict"]...)
	if len(c.ExpectVerdict) == 0 {
		return SkillCase{}, named("expect_verdict is required — state what the conclusion must name")
	}
	c.ExpectNotes = append(c.ExpectNotes, blocks["expect_notes"]...)
	c.ExpectNever = append(c.ExpectNever, blocks["expect_never"]...)
	for _, n := range c.ExpectNever {
		if hopped[n] {
			return SkillCase{}, named("expect_never lists %q, which expect_chain already takes", n)
		}
	}
	return c, nil
}

// validateCaseSignal re-checks a fixture signal against the SAME closed
// vocabulary chainFacts.addSignals accepts. A signal outside it is silently
// dropped at runtime, so a case built on one would prove nothing while looking
// like proof — the exact failure this file exists to prevent.
func validateCaseSignal(raw string) error {
	key, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return fmt.Errorf("must be key=value")
	}
	switch {
	case key == CondSignature:
		if value == CondSignatureNone {
			return fmt.Errorf("%q is DERIVED from the diagnostic's outcome and can never be declared by a tool", CondSignatureNone)
		}
		if value != CondSignatureUncollected && !reCondSignature.MatchString(value) {
			return fmt.Errorf("signature %q must be %q or match %s", value, CondSignatureUncollected, reCondSignature)
		}
	case key == CondVerdictTier:
		if !skillVerdictTiers[value] {
			return fmt.Errorf("verdict tier %q is not one of %v", value, sortedKeys(skillVerdictTiers))
		}
	case key == CondVerdictPhrase:
		if !reCondToken.MatchString(value) {
			return fmt.Errorf("phrase token %q must match %s", value, reCondToken)
		}
	case strings.HasPrefix(key, CondStatePrefix):
		facet := strings.TrimPrefix(key, CondStatePrefix)
		if !validStateFact(facet, value) {
			return fmt.Errorf("state fact %q is outside the closed vocabulary (facets: %v)", raw, StateFacets())
		}
	default:
		return fmt.Errorf("key %q is not one a TOOL may declare (%s, %s, %s, %s<facet>)",
			key, CondSignature, CondVerdictTier, CondVerdictPhrase, CondStatePrefix)
	}
	return nil
}

// validateCaseCoverage is the MINIMUM every method must prove about itself. It
// is the mechanical half of "no feature is complete without tests" (§11): a
// method that only ever proves its happy path is not proven at all.
func validateCaseCoverage(cases []SkillCase) error {
	var hop, never, disclose bool
	for _, c := range cases {
		hop = hop || len(c.ExpectChain) > 1
		never = never || len(c.ExpectNever) > 0
		disclose = disclose || len(c.ExpectNotes) > 0
	}
	switch {
	case !hop:
		return fmt.Errorf("no case takes a hop — prove at least one handoff this method authored")
	case !never:
		return fmt.Errorf("no case carries expect_never — prove at least one handoff this evidence must NOT take")
	case !disclose:
		return fmt.Errorf("no case carries expect_notes — prove at least one budget/gap the operator must be told about")
	}
	return nil
}

// validateCaseGraph is the WHOLE-SET pass: a hop in any case must name a skill
// that exists AND be a handoff its own predecessor authored. It runs after every
// skill is parsed, for the same reason the `next=` drift check does — a path can
// only be validated once the whole method graph is in memory.
func validateCaseGraph(set *SkillSet) error {
	for _, name := range set.order {
		sk := set.byName[name]
		for _, c := range sk.Cases {
			for i, h := range c.ExpectChain {
				if _, ok := set.Get(h.Skill); !ok {
					return fmt.Errorf("skills: %s: case %q expects hop %d to %q, which is not a skill that exists",
						name, c.Name, i+1, h.Skill)
				}
				if i == 0 {
					continue
				}
				prev := set.byName[c.ExpectChain[i-1].Skill]
				if !containsString(prev.NextSkills(), h.Skill) {
					return fmt.Errorf("skills: %s: case %q hops %s → %s, which %s never declares as a next= target",
						name, c.Name, prev.Name, h.Skill, prev.Name)
				}
			}
			for _, n := range c.ExpectNever {
				if _, ok := set.Get(n); !ok {
					return fmt.Errorf("skills: %s: case %q lists expect_never %q, which is not a skill that exists",
						name, c.Name, n)
				}
			}
			// A fixture may only script a tool some method ON THIS PATH actually
			// gathers with — otherwise the outcome it pins could never be observed.
			gathered := map[string]bool{}
			for _, h := range c.ExpectChain {
				for _, t := range set.byName[h.Skill].Tools {
					gathered[t] = true
				}
			}
			for t := range c.Tools {
				if !gathered[t] {
					return fmt.Errorf("skills: %s: case %q scripts %q, which no method on its expected path gathers with",
						name, c.Name, t)
				}
			}
			if c.ExpectSelect != "" && c.ExpectSelect != caseSelectNone {
				if _, ok := set.Get(c.ExpectSelect); !ok {
					return fmt.Errorf("skills: %s: case %q expects SelectSkill to pick %q, which is not a skill that exists",
						name, c.Name, c.ExpectSelect)
				}
			}
		}
	}
	return nil
}

// CaseNames lists a skill's case names in authored order (tests + docs).
func (s *Skill) CaseNames() []string {
	out := make([]string, 0, len(s.Cases))
	for _, c := range s.Cases {
		out = append(out, c.Name)
	}
	return out
}

// CaseCount reports how many behavioural cases the whole corpus carries.
func (s *SkillSet) CaseCount() int {
	if s == nil {
		return 0
	}
	n := 0
	for _, name := range s.order {
		n += len(s.byName[name].Cases)
	}
	return n
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// skillCaseFiles lists the embedded case files in sorted order (loader error
// messages and the embedded-corpus test).
func skillCaseFiles() ([]string, error) {
	entries, err := fs.Glob(skillCasesFS, "skills/*/"+skillCasesFile)
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	return entries, nil
}
