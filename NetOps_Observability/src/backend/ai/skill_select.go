package ai

// skill_select.go — DETERMINISTIC skill selection. No model, no heuristic the
// operator cannot reproduce: the same question always picks the same skill, and
// the picker's reasoning is returned so it can be shown and tested.
//
// This is the half of the "routing inversion" fix that decides WHETHER a
// free-form question becomes a grounded, tool-gathering, cited answer. It runs
// AFTER the existing rule classifier (Classify), so every intent that already
// has a good grounded answer keeps it — skills claim only the troubleshooting
// questions that previously fell through to a less-grounded reply.

import (
	"regexp"
	"sort"
	"strings"
)

// skillExcludedIntents are the classifier intents that already have a better,
// deterministic answer. A skill never pre-empts them: dumping a troubleshooting
// method over "what is a seam" or "shift handoff" would be a regression, not
// grounding.
var skillExcludedIntents = map[string]bool{
	"product_question":           true,
	"product_navigation":         true,
	"current_state":              true,
	"shift_handoff":              true,
	"time_range_summary":         true,
	"incident_list":              true,
	"noc_focus":                  true,
	"incident_breakdown":         true,
	"top_incident":               true,
	"network_kb":                 true, // "how do I troubleshoot X" is curated general guidance, not a live investigation
	"integration_health_summary": true,
	"app_identification_summary": true,
	"flow_analytics_summary":     true,
	"cloud_app_summary":          true,
	"help":                       true,
}

// reTroubleshootCue is the "this is an operational complaint" test used to send
// an OTHERWISE UNMATCHED question to the entry method (osi-bisection) instead of
// the capability clarification. Deliberately about symptoms and impact, not
// about protocols — protocol words are already matched by a specific skill.
var reTroubleshootCue = regexp.MustCompile(`(?i)\b(down|broken|failing|failed|fails|slow|slowness|loss|lossy|latency|latent|jitter|error|errors|unreachable|timeout|timing out|timeouts|drops?|dropping|dropped|flap|flapping|degraded|degradation|outage|impacted|impaired|unstable|intermittent|not working|doesn'?t work|isn'?t working|can'?t (reach|connect|get to)|cannot (reach|connect)|no connectivity|troubleshoot|diagnose|investigate|debug|why is|why are|what'?s wrong|whats wrong)\b`)

// SkillMatch is the selection outcome: which skill, why, and how strongly.
type SkillMatch struct {
	Skill   *Skill
	Score   int
	Matched []string // the when_to_use phrases / symptom kinds that fired
	Reason  string   // human-readable selection reason (shown + tested)
}

const (
	skillKeywordWeight = 2 // a when_to_use phrase is the strong signal
	skillSymptomWeight = 1 // a symptom-kind word is corroboration
)

// SelectSkill picks the troubleshooting method for a question, or reports that
// none applies. Order:
//
//  1. An excluded intent never yields a skill.
//  2. Score every skill by its when_to_use phrases and symptom kinds; the best
//     score above zero wins (ties broken by layer order, then name, so the
//     result is stable across builds).
//  3. Otherwise, an UNMATCHED question that reads like an operational complaint
//     falls to the entry method (osi-bisection), which starts from the engine's
//     verdict and bisects by layer.
//
// The method skill never wins step 2 — it is the fallback, not a competitor.
func SelectSkill(set *SkillSet, question string, plan Plan) (SkillMatch, bool) {
	if set == nil || set.Len() == 0 {
		return SkillMatch{}, false
	}
	if skillExcludedIntents[plan.Intent] {
		return SkillMatch{}, false
	}
	q := " " + strings.ToLower(strings.TrimSpace(question)) + " "
	if strings.TrimSpace(q) == "" {
		return SkillMatch{}, false
	}

	type scored struct {
		sk      *Skill
		score   int
		matched []string
	}
	var best []scored
	for _, name := range set.Names() {
		sk := set.byName[name]
		if sk.Layer == LayerMethod {
			continue // the entry method is the fallback, never a keyword winner
		}
		var matched []string
		score := 0
		for _, phrase := range sk.WhenToUse {
			if phraseMatches(q, phrase) {
				score += skillKeywordWeight
				matched = append(matched, phrase)
			}
		}
		for _, kind := range sk.SymptomKinds {
			if phraseMatches(q, kind) {
				score += skillSymptomWeight
				matched = append(matched, kind)
			}
		}
		if score > 0 {
			best = append(best, scored{sk: sk, score: score, matched: matched})
		}
	}
	if len(best) > 0 {
		sort.SliceStable(best, func(i, j int) bool {
			if best[i].score != best[j].score {
				return best[i].score > best[j].score
			}
			if LayerRank(best[i].sk.Layer) != LayerRank(best[j].sk.Layer) {
				return LayerRank(best[i].sk.Layer) < LayerRank(best[j].sk.Layer)
			}
			return best[i].sk.Name < best[j].sk.Name
		})
		w := best[0]
		return SkillMatch{
			Skill: w.sk, Score: w.score, Matched: w.matched,
			Reason: "matched the " + string(w.sk.Layer) + "-layer method " + w.sk.Name +
				" on: " + strings.Join(w.matched, ", "),
		}, true
	}

	// No specific skill. An operational complaint still deserves a method.
	if !reTroubleshootCue.MatchString(question) {
		return SkillMatch{}, false
	}
	for _, name := range set.Names() {
		if sk := set.byName[name]; sk.Layer == LayerMethod {
			return SkillMatch{
				Skill: sk, Score: 0,
				Reason: "no single fault signature matched — starting from the entry method " + sk.Name +
					" (engine verdict first, then layer bisection)",
			}, true
		}
	}
	return SkillMatch{}, false
}

// phraseMatches reports whether a match phrase occurs in the (space-padded,
// lowercased) question. Multi-word phrases match as substrings; a single word
// must match on word boundaries so "arp" does not fire inside "sharpen".
func phraseMatches(paddedQuestion, phrase string) bool {
	p := strings.TrimSpace(strings.ToLower(phrase))
	if p == "" {
		return false
	}
	if strings.ContainsAny(p, " -") {
		return strings.Contains(paddedQuestion, p)
	}
	idx := 0
	for {
		i := strings.Index(paddedQuestion[idx:], p)
		if i < 0 {
			return false
		}
		i += idx
		before := paddedQuestion[i-1]
		after := byte(' ')
		if i+len(p) < len(paddedQuestion) {
			after = paddedQuestion[i+len(p)]
		}
		if !isWordByte(before) && !isWordByte(after) {
			return true
		}
		idx = i + 1
		if idx >= len(paddedQuestion) {
			return false
		}
	}
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
