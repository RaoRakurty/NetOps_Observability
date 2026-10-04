// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irishypo holds the hypotheses of one Iris investigation (tracker 337
// N-B3): the lines of investigation a skill chain opens, and what the tools it
// ran said about each one.
//
// A hypothesis moves through a CLOSED state machine:
//
//	PROPOSED ──(its testing tool ran this round)──▶ TESTING
//	TESTING  ──(the tool's outcome + server-derived facts)──▶ SUPPORTED | REJECTED | INCONCLUSIVE
//	PROPOSED ──(the investigation ended before its tool ran)──▶ INCONCLUSIVE
//
// EVERY transition is driven by a TOOL OUTCOME or a FACT THE SERVER DERIVED —
// a typed `state:` field the show-first battery read, a protocol-diagnostic
// signature id, the outcome of the gather step itself. Nothing here reads model
// text; a model cannot propose, test, support or reject a hypothesis.
//
// THE ENGINE OWNS THE CAUSE (owner rule, 2026-10-04). A hypothesis is a
// statement about what a check OBSERVED, never a root cause: the correlation
// engine alone names one. So:
//
//   - every Statement is phrased as an observation, and no text this package
//     writes asserts a cause (pinned by test);
//   - when the engine HAS a verdict (confirmed / suspected / candidate), a
//     hypothesis whose domain that verdict does not name is treated as
//     contradicting it, and can at most be INCONCLUSIVE — the evidence it found
//     stays visible beside the engine's verdict, never instead of it;
//   - resolution happens ONCE, after the whole investigation, so the engine's
//     verdict is known before any hypothesis could become SUPPORTED. There is no
//     transient "SUPPORTED then demoted" in the trace.
//
// The package is pure: no I/O, no clock, no globals. The ai package adapts its
// chain facts into Facts and its wording into Wording; the server stores the
// finished Set (store.go) per tenant.
package irishypo

import (
	"strings"
	"unicode/utf8"
)

// State is a hypothesis state. The vocabulary is closed.
type State string

// The five states (design Part 1 §13).
const (
	Proposed     State = "PROPOSED"
	Testing      State = "TESTING"
	Supported    State = "SUPPORTED"
	Rejected     State = "REJECTED"
	Inconclusive State = "INCONCLUSIVE"
)

// States lists the vocabulary in lifecycle order.
var States = []State{Proposed, Testing, Supported, Rejected, Inconclusive}

// Terminal reports whether s is a final state.
func (s State) Terminal() bool { return s == Supported || s == Rejected || s == Inconclusive }

// Bounds. The catalogue is small and closed; these are defence in depth so a
// future catalogue edit cannot make a Set unbounded.
const (
	MaxHypotheses      = 16
	MaxTransitions     = 4
	MaxEvidence        = 6
	MaxStatementLen    = 400
	maxEngineStatement = 300
)

// Condition keys a Definition may use. They mirror the ai package's closed
// condition vocabulary (`state:<facet>=<value>`, `signature=…`); the ai
// package's tests check every catalogue condition against that vocabulary.
const (
	KeyStatePrefix = "state:"
	KeySignature   = "signature"
	// SignatureAny holds when at least one known signature fired.
	SignatureAny = "any"
	// SignatureNone holds when the diagnostic captured output and nothing matched.
	SignatureNone = "none"
	// SignatureUncollected holds when the diagnostic captured nothing at all.
	SignatureUncollected = "uncollected"
	// SignatureNotCaptured holds when the diagnostic produced no capture of
	// any kind — collection is not wired here, so it never looked. Distinct
	// from SignatureNone: "nothing matched" is only true of output that exists.
	SignatureNotCaptured = "not_captured"
	// KeyToolPrefix + a tool name is the fact a non-ok gather outcome is
	// reported as (`tool:get_device_state=error`).
	KeyToolPrefix = "tool:"
	// KeyVerdictTier is the fact an engine-capped hypothesis is reported as.
	KeyVerdictTier = "verdict:tier"
)

// Cond is one machine fact a Definition tests for.
type Cond struct {
	Key   string
	Value string
}

// String renders the fact in its authored form (`state:if_oper=down`).
func (c Cond) String() string { return c.Key + "=" + c.Value }

// Facts is the server-derived state of the investigation when it ended. The ai
// package builds it from its own chain facts; nothing in it comes from a model.
type Facts struct {
	// States holds `facet=value` facts read by the show-first battery.
	States map[string]bool
	// Signatures holds the protocol-diagnostic signature ids that fired.
	Signatures map[string]bool
	// DiagUncollected: a diagnostic ran and captured nothing.
	DiagUncollected bool
	// DiagCaptured: a diagnostic captured output and scored it (the tool
	// asserted a signature id or the reserved signature=none).
	DiagCaptured bool
	// EngineTier is the correlation engine's verdict tier ("" = none in scope).
	EngineTier string
	// EnginePhrase holds the words of the engine's own verdict phrase.
	EnginePhrase map[string]bool
}

func (f Facts) holds(c Cond) bool {
	switch {
	case strings.HasPrefix(c.Key, KeyStatePrefix):
		return f.States[strings.TrimPrefix(c.Key, KeyStatePrefix)+"="+c.Value]
	case c.Key == KeySignature:
		switch c.Value {
		case SignatureAny:
			return len(f.Signatures) > 0
		case SignatureNone:
			return f.DiagCaptured && len(f.Signatures) == 0 && !f.DiagUncollected
		case SignatureUncollected:
			return f.DiagUncollected
		case SignatureNotCaptured:
			return !f.DiagCaptured && !f.DiagUncollected && len(f.Signatures) == 0
		default:
			return f.Signatures[c.Value]
		}
	}
	return false
}

func (f Facts) first(cs []Cond) (Cond, bool) {
	for _, c := range cs {
		if f.holds(c) {
			return c, true
		}
	}
	return Cond{}, false
}

// Engine is the correlation engine's verdict as Iris shows it: the ENGINE's
// tier and the ENGINE's own words, attributed to the engine. Iris never writes
// into Statement.
type Engine struct {
	// Tier is confirmed | suspected | candidate | undetermined, or "" when no
	// engine verdict was in scope for this investigation.
	Tier string `json:"tier,omitempty"`
	// Statement is the engine's own verdict line (the get_rca_verdict row),
	// bounded. Empty when there is none.
	Statement string `json:"statement,omitempty"`
	// CitationID is the evidence id of that row, so the UI can link it.
	CitationID string `json:"citation_id,omitempty"`
	// Note is the server's one sentence about what the engine has and has not
	// established.
	Note string `json:"note"`
}

// verdictTiers are the tiers at which the engine has put forward a cause.
// "undetermined" is the engine REFUSING to name one.
var verdictTiers = map[string]bool{"confirmed": true, "suspected": true, "candidate": true}

// HasVerdict reports whether the engine has put forward a cause.
func (e Engine) HasVerdict() bool { return verdictTiers[e.Tier] }

// tierLabel is the operator word for a tier.
func tierLabel(t string) string {
	switch t {
	case "confirmed":
		return "Confirmed"
	case "suspected":
		return "Suspected"
	case "candidate":
		return "Candidate"
	}
	return "Undetermined"
}

// NewEngine builds the engine block. tier is normalised against the closed
// tier set (anything else is "" — no verdict in scope); statement is the
// engine's own row, clipped.
func NewEngine(tier, statement, citationID string) Engine {
	tier = strings.ToLower(strings.TrimSpace(tier))
	if !verdictTiers[tier] && tier != "undetermined" {
		tier = ""
	}
	e := Engine{Tier: tier}
	if tier != "" {
		e.Statement = clip(strings.TrimSpace(statement), maxEngineStatement)
		e.CitationID = clip(strings.TrimSpace(citationID), 160)
	}
	switch {
	case e.HasVerdict():
		e.Note = "This is the correlation engine's verdict (" + tierLabel(tier) + "). Iris does not replace it; " +
			"the lines of investigation below are checked against it."
	case tier == "undetermined":
		e.Note = "The correlation engine has not identified a cause for this incident (status: Undetermined). " +
			"Iris does not name one; the lines of investigation below are observations only."
	default:
		e.Note = "No correlation-engine verdict is in scope for this investigation. " +
			"Iris does not name a cause; the lines of investigation below are observations only."
	}
	return e
}

// Notice is the fixed sentence every Set carries, so no rendering of the trace
// can present a hypothesis as a verdict.
const Notice = "Lines of investigation, not causes: each one records what a check observed. " +
	"Only the correlation engine names a root cause."

// Transition is one state change and the server fact that drove it.
type Transition struct {
	From  State  `json:"from,omitempty"` // "" on the PROPOSED entry
	To    State  `json:"to"`
	Round int    `json:"round"`
	Skill string `json:"skill,omitempty"` // the method whose round it happened in
	Tool  string `json:"tool,omitempty"`  // the gather step whose outcome drove it
	Fact  string `json:"fact,omitempty"`  // the machine fact, e.g. state:if_oper=down
	// Reason is the server-authored English for the fact. Never model text.
	Reason string `json:"reason"`
}

// Hypothesis is one line of investigation.
type Hypothesis struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Layer     string `json:"layer"`
	State     State  `json:"state"`
	// Evidence are the citation ids the testing tool returned — the rows the
	// operator can open to see what the check read.
	Evidence []string `json:"evidence,omitempty"`
	// EngineNote says how this hypothesis stands against the engine's verdict.
	EngineNote  string       `json:"engine_note,omitempty"`
	Transitions []Transition `json:"transitions"`
}

// Set is the hypotheses of one investigation. ID is stamped by the server that
// stores it (never by a model, never by the client).
type Set struct {
	ID         string       `json:"id,omitempty"`
	Notice     string       `json:"notice"`
	Engine     Engine       `json:"engine"`
	Hypotheses []Hypothesis `json:"hypotheses"`
}

// Wording renders facts and tool names in the operator's words. The ai package
// supplies its own (the same sentences a chain hop's reason uses), so there is
// one vocabulary of English for a fact. Nil fields fall back to the raw form.
type Wording struct {
	Fact func(Cond) string
	Tool func(string) string
}

func (w Wording) fact(c Cond) string {
	if w.Fact != nil {
		if s := strings.TrimSpace(w.Fact(c)); s != "" {
			return s
		}
	}
	return c.String()
}

func (w Wording) tool(name string) string {
	if w.Tool != nil {
		if s := strings.TrimSpace(w.Tool(name)); s != "" {
			return s
		}
	}
	return name
}

// testRecord is what the TESTING transition saw.
type testRecord struct {
	round   int
	skill   string
	tool    string
	outcome string
	cites   []string
}

// Tracker accumulates one investigation's hypotheses. It is not safe for
// concurrent use; one investigation runs on one goroutine.
type Tracker struct {
	defs   []Definition
	words  Wording
	items  []*Hypothesis
	byID   map[string]*Hypothesis
	defOf  map[string]Definition
	tested map[string]testRecord
}

// NewTracker starts an investigation over the built-in catalogue.
func NewTracker(w Wording) *Tracker { return newTracker(Catalogue(), w) }

func newTracker(defs []Definition, w Wording) *Tracker {
	t := &Tracker{defs: defs, words: w, byID: map[string]*Hypothesis{},
		defOf: map[string]Definition{}, tested: map[string]testRecord{}}
	for _, d := range defs {
		t.defOf[d.ID] = d
	}
	return t
}

// Enter records that a method is starting a round. Every catalogue hypothesis
// this method can actually TEST — its layer matches and its testing tool is in
// the round's planned gather — is PROPOSED, once per investigation.
func (t *Tracker) Enter(round int, skill, layer string, planned []string) {
	if t == nil {
		return
	}
	plan := map[string]bool{}
	for _, p := range planned {
		plan[p] = true
	}
	for _, d := range t.defs {
		if _, seen := t.byID[d.ID]; seen || len(t.items) >= MaxHypotheses {
			continue
		}
		if !d.proposedBy(layer) || !plan[d.Tool] {
			continue
		}
		h := &Hypothesis{ID: d.ID, Statement: clip(d.Statement, MaxStatementLen), Layer: layer, State: Proposed}
		h.Transitions = append(h.Transitions, Transition{To: Proposed, Round: round, Skill: skill, Tool: d.Tool,
			Reason: "the " + humanSkill(skill) + " check can test this with " + t.words.tool(d.Tool)})
		t.items = append(t.items, h)
		t.byID[d.ID] = h
	}
}

// Observe records the gather outcomes of one round: tool → outcome (ok |
// not_found | not_wired | denied | error) and tool → the citation ids it
// returned. Every PROPOSED hypothesis whose testing tool ran moves to TESTING.
func (t *Tracker) Observe(round int, skill string, outcomes map[string]string, cites map[string][]string) {
	if t == nil {
		return
	}
	for _, h := range t.items {
		if h.State != Proposed {
			continue
		}
		d := t.defOf[h.ID]
		outcome, ran := outcomes[d.Tool]
		if !ran {
			continue
		}
		rec := testRecord{round: round, skill: skill, tool: d.Tool, outcome: outcome}
		for _, c := range cites[d.Tool] {
			if len(rec.cites) >= MaxEvidence {
				break
			}
			rec.cites = append(rec.cites, c)
		}
		t.tested[h.ID] = rec
		t.move(h, Transition{To: Testing, Round: round, Skill: skill, Tool: d.Tool,
			Fact: KeyToolPrefix + d.Tool + "=" + outcome, Reason: "tested with " + t.words.tool(d.Tool)})
	}
}

// Finish resolves every hypothesis against the facts the whole investigation
// gathered and the engine's verdict, and returns the Set. Nil-safe: a nil
// Tracker returns nil.
func (t *Tracker) Finish(f Facts, engine Engine) *Set {
	if t == nil || len(t.items) == 0 {
		return nil
	}
	set := &Set{Notice: Notice, Engine: engine, Hypotheses: make([]Hypothesis, 0, len(t.items))}
	for _, h := range t.items {
		t.resolve(h, f, engine)
		out := *h
		out.Transitions = append([]Transition(nil), h.Transitions...)
		out.Evidence = append([]string(nil), h.Evidence...)
		set.Hypotheses = append(set.Hypotheses, out)
	}
	return set
}

// resolve applies the deterministic outcome rules to one hypothesis.
func (t *Tracker) resolve(h *Hypothesis, f Facts, engine Engine) {
	if h.State.Terminal() {
		return
	}
	d := t.defOf[h.ID]
	if h.State == Proposed {
		last := h.Transitions[len(h.Transitions)-1]
		t.move(h, Transition{To: Inconclusive, Round: last.Round, Skill: last.Skill,
			Reason: "never tested — the investigation ended before " + t.words.tool(d.Tool) + " ran"})
		h.EngineNote = observationNote(engine)
		return
	}
	rec := t.tested[h.ID]
	h.Evidence = rec.cites
	base := Transition{Round: rec.round, Skill: rec.skill, Tool: rec.tool}
	if rec.outcome != "ok" {
		c := Cond{Key: KeyToolPrefix + rec.tool, Value: rec.outcome}
		base.To, base.Fact, base.Reason = Inconclusive, c.String(), t.words.fact(c)+" — so this could not be tested"
		t.move(h, base)
		h.EngineNote = observationNote(engine)
		return
	}
	if c, ok := f.first(d.Unknown); ok {
		base.To, base.Fact, base.Reason = Inconclusive, c.String(), t.words.fact(c)+" — so this could not be tested"
		t.move(h, base)
		h.EngineNote = observationNote(engine)
		return
	}
	sup, isSup := f.first(d.Support)
	rej, isRej := f.first(d.Reject)
	switch {
	case isSup && isRej:
		base.To, base.Fact = Inconclusive, sup.String()+" & "+rej.String()
		base.Reason = "the evidence points both ways: " + t.words.fact(sup) + ", and " + t.words.fact(rej)
		h.EngineNote = observationNote(engine)
	case isSup && engine.HasVerdict() && !d.namedBy(f.EnginePhrase):
		// The engine has a verdict and it does not name this. The observation is
		// kept, with its evidence, but it can never stand as SUPPORTED beside —
		// let alone instead of — the engine's verdict.
		base.To, base.Fact = Inconclusive, KeyVerdictTier+"="+engine.Tier
		base.Reason = t.words.fact(sup) + ", but the correlation engine's verdict (" + tierLabel(engine.Tier) +
			") does not name this — it is kept as evidence only"
		h.EngineNote = "The engine's verdict does not name this. The observation is shown as evidence; " +
			"it does not replace or contradict the engine's verdict."
	case isSup:
		base.To, base.Fact, base.Reason = Supported, sup.String(), t.words.fact(sup)
		if engine.HasVerdict() {
			h.EngineNote = "Consistent with the correlation engine's verdict above, which alone names the cause."
		} else {
			h.EngineNote = observationNote(engine)
		}
	case isRej:
		base.To, base.Fact, base.Reason = Rejected, rej.String(), t.words.fact(rej)
		h.EngineNote = ""
	default:
		base.To = Inconclusive
		base.Reason = t.words.tool(rec.tool) + " ran but did not report on this"
		h.EngineNote = observationNote(engine)
	}
	t.move(h, base)
}

// observationNote is the engine note for a hypothesis that is only an
// observation: no verdict, or the engine refused one.
func observationNote(engine Engine) string {
	if engine.HasVerdict() {
		return ""
	}
	return "An observation, not a cause — the correlation engine has not named one."
}

// move appends a transition, enforcing the machine: only the legal edges, and
// at most MaxTransitions per hypothesis.
func (t *Tracker) move(h *Hypothesis, tr Transition) {
	if !legal(h.State, tr.To) || len(h.Transitions) >= MaxTransitions {
		return
	}
	tr.From = h.State
	h.State = tr.To
	h.Transitions = append(h.Transitions, tr)
}

// legal is the transition table.
func legal(from, to State) bool {
	switch from {
	case Proposed:
		return to == Testing || to == Inconclusive
	case Testing:
		return to == Supported || to == Rejected || to == Inconclusive
	}
	return false
}

// Legal exposes the transition table (tests + documentation).
func Legal(from, to State) bool { return legal(from, to) }

func humanSkill(name string) string { return strings.ReplaceAll(name, "-", " ") }

// clip bounds s to max bytes on a rune boundary.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
