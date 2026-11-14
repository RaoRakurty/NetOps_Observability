// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// similar_answer.go — "have we seen this before?" as an Iris ANSWER (tracker
// 337 N-F4). The recall itself (internal/incidentfp, find_similar_incidents)
// already exists; this is the router arm the AI model planner reaches for any
// phrasing of the question ("did this happen last week", "is this a repeat",
// "what fixed it last time"), so it no longer depends on an investigation
// happening to call the tool.
//
// The subject is the incident the question or the screen names; with none
// named, the top incident right now — said so in the answer, never silently.
//
// HISTORY, NEVER A CAUSE. Every answer carries the recall's caveat and a past
// case is cited as HISTORICAL evidence. "What fixed it last time" is answered
// from the fix an operator RECORDED when the past case was closed
// (internal/rcaresolution): "last time this was fixed by a configuration
// rollback (recorded by an operator on …)". A recorded fix becomes a
// recommendation card ("consider …"), labelled "No action has been executed"
// and grounded in that resolution's citation; a case with no recorded fix says
// so plainly and points at its timeline. Nothing here claims a past fix is the
// present cause or the right action — the operator confirms it applies.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// noFixRecorded is the honest limit when no matched case has a recorded fix.
const noFixRecorded = "No fix was recorded for these past cases; open one to read its timeline and any ticket."

// someFixRecorded closes an answer where only some matched cases carry a fix.
const someFixRecorded = "Cases without a recorded fix: open them to read their timeline and any ticket."

// similarSubject resolves the incident to compare: the named one, else the top
// active one. preface says which was chosen when the operator did not name it.
func (o *Orchestrator) similarSubject(ctx context.Context, p Principal, plan Plan) (subject *Problem, preface, refusal string, err error) {
	if id := plan.Entities["problem_id"]; id != "" {
		pr, gerr := o.DS.GetProblem(ctx, p, id)
		if errors.Is(gerr, ErrNotFound) {
			return nil, "", fmt.Sprintf("Problem %q isn't available in your scope.", id), nil
		}
		if gerr != nil {
			return nil, "", "", gerr
		}
		return pr, "", "", nil
	}
	probs, lerr := o.DS.ListActiveProblems(ctx, p, 100)
	if lerr != nil {
		return nil, "", "", lerr
	}
	if len(probs) == 0 {
		return nil, "", "No incident is open right now, so there is nothing to compare. Open a past case and ask \"have we seen this before?\", or name the incident by its id.", nil
	}
	ranked := make([]Problem, len(probs))
	copy(ranked, probs)
	sort.SliceStable(ranked, func(i, j int) bool { return PriorityScore(ranked[i]) > PriorityScore(ranked[j]) })
	top := ranked[0]
	return &top, fmt.Sprintf("You didn't name an incident, so I compared the top one right now: %s (%s).", top.Display(), promptLine(top.Title)), "", nil
}

// answerSimilar answers ModeSimilarIncidents.
func (o *Orchestrator) answerSimilar(ctx context.Context, p Principal, plan Plan, disc []string) (Answer, error) {
	base := Answer{Mode: ModeSimilarIncidents, Intent: plan.Intent, Modules: plan.Modules, Citations: []Citation{},
		ModeBadges: []string{"History"}}
	if o.Troubleshoot.SimilarIncidents == nil {
		base.Mode = ModeUnavailable
		base.Text = "Similar-incident recall isn't available on this deployment."
		base.Disclaimers = append(disc, "The incident fingerprint store is not wired here.")
		return base, nil
	}
	subject, preface, refusal, err := o.similarSubject(ctx, p, plan)
	if err != nil {
		return Answer{}, err
	}
	if refusal != "" {
		base.Text = refusal
		base.Disclaimers = disc
		return base, nil
	}
	res, err := o.Troubleshoot.SimilarIncidents(ctx, p, subject.ID, "")
	if errors.Is(err, ErrNotFound) {
		base.Text = fmt.Sprintf("Problem %q isn't available in your scope.", subject.Display())
		base.Disclaimers = append(disc, "Not found, or it belongs to another tenant.")
		return base, nil
	}
	if err != nil {
		return Answer{}, err
	}

	var b strings.Builder
	if preface != "" {
		b.WriteString(preface + "\n\n")
	}
	if len(res.Matches) == 0 {
		fmt.Fprintf(&b, "No earlier incident matches %s yet", subject.Display())
		if res.Examined > 0 {
			fmt.Fprintf(&b, " (%s compared)", plural(res.Examined, "closed incident"))
		}
		b.WriteString(".")
		if res.Note != "" {
			b.WriteString(" " + res.Note)
		}
	} else {
		n := len(res.Matches)
		if n > 5 {
			n = 5
		}
		fmt.Fprintf(&b, "%s look%s like %s:\n", plural(len(res.Matches), "earlier incident"), verbS(len(res.Matches)), subject.Display())
		var fixActions []string
		seenFix := map[string]bool{}
		for _, m := range res.Matches[:n] {
			label := o.pastCaseLabel(ctx, p, m.CorrelationID)
			fmt.Fprintf(&b, "• A %s match — %s on %s, matched on %s.", promptLine(m.Strength), label,
				m.OccurredAt.UTC().Format("2006-01-02"), promptLine(strings.Join(m.MatchedOn, ", ")))
			base.Citations = append(base.Citations, Citation{ID: "similar:" + m.CorrelationID, Kind: "history",
				Label: label, Href: "#/monitoring/correlations?id=" + m.CorrelationID, Class: ClassHistorical})
			if fs := fixSentence(m.Fix); fs != "" {
				cite := "resolution:" + m.CorrelationID
				b.WriteString(" " + fs)
				base.Citations = append(base.Citations, Citation{ID: cite, Kind: "resolution",
					Label: "Recorded fix for " + label, Href: "#/monitoring/correlations?id=" + m.CorrelationID,
					Class: ClassHistorical})
				if !seenFix[m.Fix.Kind] {
					seenFix[m.Fix.Kind] = true
					fixActions = append(fixActions, fmt.Sprintf("Consider %s — it resolved %s on %s. Check it applies here first: similar is not the same cause.",
						promptLine(m.Fix.Label), label, m.Fix.RecordedAt.UTC().Format("2006-01-02")))
				}
			}
			b.WriteString("\n")
		}
		if len(res.Matches) > n {
			fmt.Fprintf(&b, "…and %d more.\n", len(res.Matches)-n)
		}
		switch {
		case len(fixActions) == 0:
			b.WriteString("\n" + noFixRecorded)
		case countFixes(res.Matches[:n]) < n:
			b.WriteString("\n" + someFixRecorded)
		}
		base.NextActions = append(fixActions, "Open a past case above and compare its timeline with this one.")
	}
	base.Text = strings.TrimSpace(b.String())
	caveat := res.Caveat
	if caveat == "" {
		caveat = "Similar is not the same cause: past incidents are context, never confirmation of this one."
	}
	base.Disclaimers = append(disc, caveat)
	return base, nil
}

// pastCaseLabel is a past case's operator handle: its P-number when the
// caller's own scope can read it, else a short id.
func (o *Orchestrator) pastCaseLabel(ctx context.Context, p Principal, id string) string {
	if pr, err := o.DS.GetProblem(ctx, p, id); err == nil && pr != nil {
		if t := strings.TrimSpace(pr.Title); t != "" {
			return fmt.Sprintf("case %s (%s)", pr.Display(), promptLine(t))
		}
		return "case " + pr.Display()
	}
	return "case " + shortToken(id)
}

// countFixes counts matches carrying a recorded fix.
func countFixes(ms []SimilarMatch) int {
	n := 0
	for _, m := range ms {
		if fixSentence(m.Fix) != "" {
			n++
		}
	}
	return n
}

func verbS(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}
