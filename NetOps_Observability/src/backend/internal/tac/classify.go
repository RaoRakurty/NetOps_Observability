// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// classify.go — evidence → issue class.
//
// It answers the escalation screen's first question with material Correlix
// ALREADY HAS: the RCA hypotheses on the incident, the alerts that fired, the
// Iris skill that was selected, the protocol-diagnostics signature that matched,
// the catalog issue that was collected, and the incident's own log excerpts.
// Nothing is fetched from a device to classify, and nothing is asked of a model.
//
// It is DETERMINISTIC and it SHOWS ITS WORK. Every point in a class's score
// names the exact evidence reference that scored it, so the operator reads "this
// is bgp-session because BGPSessionDown fired and signature bgp-idle-unreachable
// matched" rather than a bare label. Ties break on the class id, so the same
// evidence always yields the same answer.
//
// It is also allowed to fail. When nothing scores, the answer is the `generic`
// class and the note says plainly that Correlix did not classify the incident —
// the escalation still carries the vendor baseline and the evidence timeline,
// which is worth more to a TAC engineer than a guessed class.

import (
	"sort"
	"strings"
)

// Evidence is the closed input to Classify. Every field is a list of IDS the
// platform produced — never operator free text, never model output. The caller
// assembles it from the incident it has already resolved in the principal's
// scope, so classification cannot become a way to reach another tenant's data.
type Evidence struct {
	// IncidentID and TenantID are carried through onto the result for the audit
	// record; they take no part in scoring.
	IncidentID string
	TenantID   string

	// Alerts are vmalert alert NAMES (rules.yaml).
	Alerts []string
	// Hypotheses are correlation hypothesis TEMPLATE IDS (sig.ent.*).
	Hypotheses []string
	// Signatures are protocoldiag signature ids that matched.
	Signatures []string
	// Skills are Iris skill ids that were selected for this investigation.
	Skills []string
	// Issues are protocoldiag catalog issue ids that were collected.
	Issues []string
	// LogLines are bounded log excerpts from the incident window.
	LogLines []string
}

// maxClassifyLogLines bounds the log scan (§9). A class's log_regex set is
// small and cheap, but the product of patterns and lines is not, so the line
// count is capped rather than trusted.
const maxClassifyLogLines = 500

// evidence weights. A signature is a MATCHED RULE against real device output and
// is the strongest single tell; an alert is a threshold crossing and the weakest
// structured one; a log line is a hint.
const (
	weightSignature  = 5
	weightHypothesis = 4
	weightSkill      = 3
	weightIssue      = 3
	weightAlert      = 2
	weightLog        = 1
)

// Reason is one scoring reference: what kind of evidence, and which id.
type Reason struct {
	Kind   string `json:"kind"` // signature | hypothesis | skill | issue | alert | log
	Ref    string `json:"ref"`
	Weight int    `json:"weight"`
}

// ClassMatch is one class's score with the references that produced it.
type ClassMatch struct {
	ClassID string   `json:"class_id"`
	Title   string   `json:"title"`
	Score   int      `json:"score"`
	Why     []Reason `json:"why"`
}

// Classification is Classify's answer.
type Classification struct {
	ClassID string `json:"class_id"`
	Title   string `json:"title"`
	// Protocol groups the class in the UI.
	Protocol string `json:"protocol"`
	// TACFirstLook is the class's "what TAC opens first" note.
	TACFirstLook string `json:"tac_first_look,omitempty"`
	// Classified is false when nothing scored — the honest generic path.
	Classified bool `json:"classified"`
	// Why is the winning class's evidence, strongest first.
	Why []Reason `json:"why"`
	// Alternatives are every other class that scored, strongest first. The
	// operator may override to ANY class, not only these.
	Alternatives []ClassMatch `json:"alternatives"`
	// Note is the operator-facing sentence about the outcome.
	Note string `json:"note"`
	// CatalogVersion is the taxonomy version that produced this answer.
	CatalogVersion string `json:"catalog_version"`
}

// Classify scores every class against the evidence and returns the winner, why,
// and the alternatives. It never returns an error: an unclassifiable incident is
// an ANSWER (the generic class), not a failure.
func (c *Catalog) Classify(ev Evidence) Classification {
	if c == nil {
		return Classification{
			ClassID: GenericClassID, Classified: false,
			Why: []Reason{}, Alternatives: []ClassMatch{},
			Note: "The TAC escalation catalog is not available on this build, so nothing was classified.",
		}
	}
	lines := ev.LogLines
	if len(lines) > maxClassifyLogLines {
		lines = lines[:maxClassifyLogLines]
	}

	matches := make([]ClassMatch, 0, len(c.classOrder))
	for _, id := range c.classOrder {
		cl := c.classes[id]
		if cl.ID == GenericClassID {
			continue // the fallback is never scored; it is what "nothing scored" means
		}
		why := scoreClass(cl, ev, lines)
		if len(why) == 0 {
			continue
		}
		total := 0
		for _, r := range why {
			total += r.Weight
		}
		matches = append(matches, ClassMatch{ClassID: cl.ID, Title: cl.Title, Score: total, Why: why})
	}

	// Deterministic order: score descending, then class id ascending.
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].ClassID < matches[j].ClassID
	})

	if len(matches) == 0 {
		gen := c.classes[GenericClassID]
		return Classification{
			ClassID: gen.ID, Title: gen.Title, Protocol: gen.Protocol,
			TACFirstLook: gen.TACFirstLook, Classified: false,
			Alternatives:   []ClassMatch{},
			Why:            []Reason{},
			Note:           "Correlix did not classify this incident: none of its alerts, RCA hypotheses, matched signatures or log lines map to an issue class. The escalation carries the vendor baseline and the incident's own evidence, and says so.",
			CatalogVersion: c.Version,
		}
	}

	top := matches[0]
	cl := c.classes[top.ClassID]
	note := "Classified as " + cl.Title + " from " + summariseReasons(top.Why) + "."
	if len(matches) > 1 && matches[1].Score == top.Score {
		note += " " + matches[1].Title + " scored the same on this evidence — review the alternatives before collecting."
	}
	return Classification{
		ClassID: cl.ID, Title: cl.Title, Protocol: cl.Protocol,
		TACFirstLook: cl.TACFirstLook, Classified: true,
		Why:            top.Why,
		Alternatives:   matches[1:],
		Note:           note,
		CatalogVersion: c.Version,
	}
}

// scoreClass returns the evidence references that hit this class, strongest
// first. A reference is counted ONCE even when it appears twice in the input.
func scoreClass(cl Class, ev Evidence, lines []string) []Reason {
	var why []Reason
	add := func(kind string, weight int, want, have []string) {
		if len(want) == 0 || len(have) == 0 {
			return
		}
		set := make(map[string]struct{}, len(want))
		for _, w := range want {
			set[w] = struct{}{}
		}
		seen := map[string]bool{}
		for _, h := range have {
			h = strings.TrimSpace(h)
			if h == "" || seen[h] {
				continue
			}
			if _, ok := set[h]; ok {
				seen[h] = true
				why = append(why, Reason{Kind: kind, Ref: h, Weight: weight})
			}
		}
	}
	add("signature", weightSignature, cl.Detect.Signatures, ev.Signatures)
	add("hypothesis", weightHypothesis, cl.Detect.Hypotheses, ev.Hypotheses)
	add("skill", weightSkill, cl.Detect.Skills, ev.Skills)
	add("issue", weightIssue, cl.Detect.Issues, ev.Issues)
	add("alert", weightAlert, cl.Detect.Alerts, ev.Alerts)

	// Log patterns: at most ONE point per pattern, whichever line hit first, so
	// a noisy log cannot outvote a matched signature.
	for i, re := range cl.Detect.logRE {
		for _, ln := range lines {
			if re.MatchString(ln) {
				why = append(why, Reason{Kind: "log", Ref: cl.Detect.LogRegex[i], Weight: weightLog})
				break
			}
		}
	}
	sort.SliceStable(why, func(i, j int) bool { return why[i].Weight > why[j].Weight })
	return why
}

// summariseReasons renders the winning evidence for the operator-facing note.
func summariseReasons(why []Reason) string {
	parts := make([]string, 0, 3)
	for _, r := range why {
		if len(parts) == 3 {
			break
		}
		parts = append(parts, r.Kind+" "+r.Ref)
	}
	out := strings.Join(parts, ", ")
	if len(why) > len(parts) {
		out += " and " + itoaTAC(len(why)-len(parts)) + " more"
	}
	return out
}

// itoaTAC is a tiny local int→string (§5: no reflection, no fmt for a hot path).
func itoaTAC(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
