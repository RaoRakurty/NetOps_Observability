// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// estate.go — the estate-wide seasonal question (tracker 337 N-H6 step 3):
// "what stands out against its usual level", "which interfaces are
// unusually busy for this time of day", "anything unusual compared with a
// normal Tuesday morning". It compiles to seasonal_outliers: every rolled-up
// series of the type asked (or all of them), judged at the latest closed hour
// against its own usual level.
//
// It needs BOTH an unusual-word and a seasonal phrase, so "is there anything
// unusual about vedge-51 compared to the other edges" (a peer comparison, no
// time of day) is never captured. A yes/no question about one metric ("is cpu
// on edge-1 unusual for this time of week") stays the above_baseline filter;
// a listing ("which …", "anything …") or a question with no metric becomes the
// estate answer. A window other than "now" is not this question (the answer
// is always the latest closed hour), so it is left to the other families.

import (
	"regexp"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/nlquery/seasonal"
)

var (
	estateCueRe = regexp.MustCompile(`\b(?:unusual(?:ly)?|abnormal(?:ly)?|anomalous(?:ly)?|anomal(?:y|ies)|atypical(?:ly)?|out of the ordinary|odd|strange|weird)\b`)
	// estateSeasonRe is the seasonal phrase: "for this time of week/day",
	// "than usual for the time", "compared with a normal Tuesday morning". A
	// weekday here only says "the usual for this time"; the answer's wording
	// is the tier's own, never the weekday.
	estateSeasonRe = regexp.MustCompile(`\b(?:than\s+(?:usual|normal|typical)\s+)?for\s+(?:this|the)\s+time(?:\s+of\s+(?:the\s+)?(?:day|week))?\b` +
		`|\b(?:compared?|vs\.?|versus|relative|against)(?:\s+(?:with|to))?\s+(?:an?\s+)?(?:normal|typical|usual|ordinary|average|regular)\s+` +
		`(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|weekday|weekend|day|week)(?:\s+(?:morning|afternoon|evening|night))?\b`)
	estateListRe = regexp.MustCompile(`\b(?:which|what|whats|what's|anything|any|everything|something|list|show)\b`)
	// estateNowRe is the only window the estate answer can honour.
	estateNowRe = regexp.MustCompile(`\b(?:right now|now|currently|at the moment|at present|today|this hour)\b`)
	// estateBusyRe asks about traffic: inbound and outbound rate, above only.
	estateBusyRe = regexp.MustCompile(`\b(?:busy|busier|loaded|congested|heavy|traffic)\b`)
	// estateHighRe asks for above-usual only ("unusually high").
	estateHighRe   = regexp.MustCompile(`\b(?:high|higher|elevated|spiking|spiked)\b`)
	estateTargetRe = []struct {
		re     *regexp.Regexp
		target string
	}{
		{regexp.MustCompile(`\b(?:interfaces?|ports?|intf)\b`), "interface"},
		{regexp.MustCompile(`\b(?:circuits?|underlay|transports?)\b`), "circuit"},
		{regexp.MustCompile(`\b(?:devices?|routers?|switch(?:es)?|firewalls?|box(?:es)?|nodes?)\b`), "device"},
	}
	estateVocabRe = regexp.MustCompile(`\b(?:seems?|looks?|looking|behav(?:e|es|ing)|acting|doing|happening|going on|network|estate|series|metrics?|things?|unusual|abnormal|anomalous|currently|moment|present|compared|normal|usual|typical|ordinary|average|regular|morning|afternoon|evening|night|weekday|weekend)\b`)
)

// estate compiles the estate-wide seasonal question; ok=false leaves the
// question to the other families.
func (s *state) estate() (Result, bool, error) {
	t := s.text
	if !estateCueRe.MatchString(t) || !estateSeasonRe.MatchString(t) {
		return Result{}, false, nil
	}
	if s.time.Kind != "" && !estateNowRe.MatchString(s.timeSpan) && !estateSeasonRe.MatchString(s.timeSpan) {
		return Result{}, false, nil // "unusual yesterday at 3pm for that time of week" is not "right now"
	}
	q := &ast.AST{V: 1, Type: ast.SeasonalOutliers}
	busy := estateBusyRe.MatchString(t)
	hits, alias := s.c.findMetric(t)
	if hits != nil && !(busy && estateBusyRe.MatchString(alias)) {
		// A named metric: the estate answer only when the roll-up keeps it
		// and the question is a listing — "is cpu on edge-1 unusual for
		// this time of week" stays the above_baseline filter.
		if !estateListRe.MatchString(t) {
			return Result{}, false, nil
		}
		name := ""
		for _, h := range hits {
			if _, ok := seasonal.RolledMetrics[h.Name]; ok {
				name = h.Name
				break
			}
		}
		if name == "" {
			return Result{}, false, nil
		}
		q.Metric, q.Target = name, seasonal.RolledMetrics[name]
		s.e.phrase(alias)
	}
	for _, tw := range estateTargetRe {
		if q.Target == "" && tw.re.MatchString(t) {
			q.Target = tw.target
		}
		if tw.target == q.Target {
			s.e.re(tw.re, t) // "which circuits have unusual latency": the metric's own entity
		}
	}
	if busy && q.Metric == "" {
		if q.Target != "" && q.Target != "interface" {
			return Result{}, false, nil // "unusually busy circuits": no traffic metric is rolled up for them
		}
		q.Target = "interface"
		q.Filters = []ast.Filter{{Field: ast.FilterMetric, Op: "in", Values: []string{"if_in_bps", "if_out_bps"}}}
		q.Predicate = &ast.Predicate{Op: "above_baseline"}
		s.e.re(estateBusyRe, t)
		s.readings = append(s.readings, lex.Reading{From: estateBusyRe.FindString(t), To: "inbound and outbound traffic, above their usual level", Kind: lex.KindSynonym})
	}
	if s.e.re(estateHighRe, t) {
		q.Predicate = &ast.Predicate{Op: "above_baseline"}
	}
	refs, clarify, err := s.mentions([]string{"site", "device"})
	if err != nil {
		return Result{}, true, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "unusual_now", Clarify: clarify}, true, nil
	}
	q.Refs = astRefs(refs)
	q.Limit = s.topN()
	s.e.re(estateCueRe, t)
	s.e.re(estateSeasonRe, t)
	s.e.re(estateNowRe, t)
	s.e.re(estateListRe, t)
	s.e.re(estateVocabRe, t)
	return Result{Intent: "unusual_now", AST: q, Entities: refs}, true, nil
}
