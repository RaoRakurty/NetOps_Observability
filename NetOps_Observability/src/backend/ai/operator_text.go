// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// RewriteOperatorText passes every PROSE field of an answer — the words the
// asker reads — through f, in place. Identifiers (problem ids, citations,
// navigation targets, the data arm's result set, provider/model stamps) are
// never touched. The API boundary uses it to name devices by hostname instead
// of their internal `<sysName>-<address hash>` id (owner, 2026-11-23); the
// tools and the model keep working on ids. A nil f changes nothing.
func (a *Answer) RewriteOperatorText(f func(string) string) {
	if a == nil || f == nil {
		return
	}
	all := func(in []string) []string {
		if in == nil {
			return nil
		}
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = f(s)
		}
		return out
	}
	a.Text = f(a.Text)
	a.Title = f(a.Title)
	a.NextActions = all(a.NextActions)
	a.MissingEvidence = all(a.MissingEvidence)
	for i := range a.Citations { // the label is read; the id and link stay
		a.Citations[i].Label = f(a.Citations[i].Label)
	}
	for i := range a.Recommendations {
		r := &a.Recommendations[i]
		r.Title, r.Why = f(r.Title), f(r.Why)
		r.Steps = all(r.Steps)
	}
	if p := a.Problem; p != nil {
		p.Title, p.Summary, p.RootCauseHypothesis, p.ItsmNote = f(p.Title), f(p.Summary), f(p.RootCauseHypothesis), f(p.ItsmNote)
		p.Timeline = all(p.Timeline)
		p.SupportingEvidence = all(p.SupportingEvidence)
		p.ContradictingEvidence = all(p.ContradictingEvidence)
		p.MissingEvidence = all(p.MissingEvidence)
		p.WhyFirst = all(p.WhyFirst)
	}
	if c := a.CurrentState; c != nil {
		c.Summary, c.Title, c.FocusReason, c.WatchNote = f(c.Summary), f(c.Title), f(c.FocusReason), f(c.WatchNote)
		c.ActiveIncidents = all(c.ActiveIncidents)
		c.ImpactedEntities = all(c.ImpactedEntities)
		c.RecommendedFocus = all(c.RecommendedFocus)
		c.ConfidenceNotes = all(c.ConfidenceNotes)
		c.MissingData = all(c.MissingData)
	}
}
