// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// hypothesis.go — the skill chain's adapter onto investigation hypotheses
// (tracker 337 N-B3; the state machine itself is internal/irishypo).
//
// What this file does, and only this:
//
//   - each round, tell the tracker which method started and which gather steps
//     it PLANNED (so it proposes only what that method can actually test), then
//     what each step's OUTCOME was and which citation ids it returned;
//   - at the end, hand the tracker the chain's SERVER-DERIVED facts and the
//     correlation engine's verdict, exactly as get_rca_verdict read it;
//   - word every fact in the same English a chain hop's reason uses.
//
// The model takes no part. It never sees the hypotheses (they are not in any
// prompt), it cannot name one, and nothing it writes moves one.

import (
	"strings"

	"netops/backend/internal/irishypo"
)

// hypothesisWording renders facts and tools in the operator's words — the same
// sentences SkillCondition.Human gives a chain hop, so one fact reads one way.
func hypothesisWording() irishypo.Wording {
	return irishypo.Wording{
		Fact: func(c irishypo.Cond) string {
			if c.Key == irishypo.KeySignature {
				switch c.Value {
				case irishypo.SignatureAny:
					return "a known fault signature matched the device's own output"
				case irishypo.SignatureNotCaptured:
					return "the protocol diagnostic captured no output on this deployment"
				}
			}
			return SkillCondition{Key: c.Key, Value: c.Value}.Human()
		},
		Tool: ToolLabel,
	}
}

// noteDiagCapture records whether a protocol diagnostic actually captured and
// scored output: it asserted a signature id, or the reserved signature=none
// marker. "Nothing matched" is only ever true of output that exists, so a
// diagnostic that never collected can never reject a hypothesis.
func (st *chainState) noteDiagCapture(tool string, signals []string) {
	if tool != "run_protocol_diagnostic" {
		return
	}
	for i, raw := range signals {
		if i >= maxToolSignals {
			return
		}
		key, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok || strings.TrimSpace(key) != CondSignature {
			continue
		}
		value = strings.TrimSpace(value)
		if value == CondSignatureNone || (value != CondSignatureUncollected && reCondSignature.MatchString(value)) {
			st.diagCaptured = true
			return
		}
	}
}

// engineTierOrder is the precedence when more than one tier was read in one
// turn (one incident is in scope per turn, so this is defence in depth): the
// engine's strongest statement is the one shown.
var engineTierOrder = []string{"confirmed", "suspected", "candidate", "undetermined"}

// engineTier is the engine's verdict tier as the chain read it ("" = none).
func (f *chainFacts) engineTier() string {
	for _, t := range engineTierOrder {
		if f.tiers[t] {
			return t
		}
	}
	return ""
}

// hypothesisFacts snapshots the chain's facts for the tracker. Maps are copied:
// the tracker can never write back into the routing facts.
func hypothesisFacts(f *chainFacts, diagCaptured bool) irishypo.Facts {
	out := irishypo.Facts{
		States:          make(map[string]bool, len(f.states)),
		Signatures:      make(map[string]bool, len(f.signatures)),
		DiagUncollected: f.diagUncollected,
		DiagCaptured:    diagCaptured,
		EngineTier:      f.engineTier(),
		EnginePhrase:    make(map[string]bool, len(f.phrases)),
	}
	for k, v := range f.states {
		out.States[k] = v
	}
	for k, v := range f.signatures {
		out.Signatures[k] = v
	}
	for k, v := range f.phrases {
		out.EnginePhrase[k] = v
	}
	return out
}

// engineVerdictCitePrefix is the citation id of get_rca_verdict's headline row
// ("verdict:<id>"; the other rows are "verdict-affected:" etc.).
const engineVerdictCitePrefix = "verdict:"

// hypothesisEngine is the engine's verdict block: its tier and its OWN
// headline row from the gathered evidence. Nothing here is written by Iris.
func hypothesisEngine(st *chainState) irishypo.Engine {
	tier := st.facts.engineTier()
	stmt, cite := "", ""
	for _, ev := range st.bundle {
		if strings.HasPrefix(ev.CitationID, engineVerdictCitePrefix) {
			stmt, cite = ev.Text, ev.CitationID
			break
		}
	}
	return irishypo.NewEngine(tier, stmt, cite)
}

// finishHypotheses resolves the investigation's hypotheses (nil when the chain
// opened none).
func finishHypotheses(st *chainState) *irishypo.Set {
	if st == nil || st.hyp == nil {
		return nil
	}
	return st.hyp.Finish(hypothesisFacts(st.facts, st.diagCaptured), hypothesisEngine(st))
}

// plannedTools lists a round's planned gather tools.
func plannedTools(steps []plannedStep) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Tool)
	}
	return out
}
