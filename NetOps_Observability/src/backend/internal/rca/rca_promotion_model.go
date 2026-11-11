// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_promotion_model.go — the promotion block of the report (#113 point 3)
// and its pure evaluation. The audited manual-promotion STORE and its handlers
// stay with the integrator in package main; the report carries the decision,
// and EvaluatePromotion derives it from the finished report alone.

import (
	"fmt"
	"strings"
	"time"
)

// PromotionRecord is one manual promotion: who, when, why. Non-secret.
type PromotionRecord struct {
	PromotedBy string `json:"promoted_by"`
	PromotedAt string `json:"promoted_at"` // UTC, canonical FmtUTC
	Note       string `json:"note,omitempty"`
}

// PromotionCriterion is one auto-promotion gate with its honest state.
type PromotionCriterion struct {
	Name   string `json:"name"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}

// PromotionStatus is the report's promotion block — the UI's single source
// for "is this an RCA document or a candidate, and why".
type PromotionStatus struct {
	Promoted bool   `json:"promoted"`
	Basis    string `json:"basis"` // auto | manual | not_promoted
	// Trigger names the auto rule that promoted it: real_outage |
	// repeat_offender | multi_site ("" when not auto-promoted).
	Trigger  string               `json:"trigger,omitempty"`
	Reason   string               `json:"reason"`
	Criteria []PromotionCriterion `json:"criteria"`
	Manual   *PromotionRecord     `json:"manual,omitempty"`
}

// PromotionMinDuration — the shortest incident an AUTO-promotion accepts. A
// blip shorter than this never self-promotes; a human may still promote it.
// 2m (owner decision 2026-07-18, was 5m): in a single-WAN-link deployment a
// total loss of app access is an outage well before 5 minutes; 2m still keeps
// sub-minute reconvergence blips out of the management tier.
const PromotionMinDuration = 2 * time.Minute

// RepeatOffenderMin / RepeatOffenderWindow — owner D3 (2026-11-11): the same
// headline cause on the same primary device this many times inside the window
// earns an RCA document even when no single occurrence met the outage rule.
const (
	RepeatOffenderMin    = 3
	RepeatOffenderWindow = 7 * 24 * time.Hour
)

// MultiSiteMin — a controller or hub outage reaching at least this many sites.
const MultiSiteMin = 2

// Promotion criterion names (stable: the UI and the integrity normalizer key on
// them).
const (
	critProduction = "production incident"
	critCause      = "network cause"
	critConfirmed  = "confirmed verdict"
	critMeasured   = "measurement sources"
	critImpact     = "user/application impact"
	critDuration   = "duration"
	critRepeat     = "repeat offender"
	critMultiSite  = "multi-site controller or hub outage"
)

// EvaluatePromotion decides the case's tier from the FINISHED report (the
// states/times there are already derived honestly) plus any manual record. A
// manual promotion is an explicit human decision and always wins. Auto
// promotion (owner D3, 2026-11-11) has three triggers, and every one of them
// requires a production incident whose headline is a network cause — never a
// background story, never a BGP peer that never came up:
//
//  1. real outage — a confirmed verdict whose confirming pair is two
//     MEASUREMENT sources, confirmed user/application impact, duration ≥ 2m;
//  2. repeat offender — the same headline cause on the same primary device
//     ≥ 3 times in 7 days;
//  3. multi-site controller/hub outage — one controller or hub affecting ≥ 2
//     sites.
//
// The reason strings are user-facing — they say exactly what is unmet and how
// to promote, never a bare refusal.
func EvaluatePromotion(rep *Report, manual *PromotionRecord) PromotionStatus {
	el := rep.Eligibility
	networkCause := el.CausalHeadline && !el.ContextOnly && !el.NeverEstablished
	causeDetail := "the leading explanation is a network cause"
	switch {
	case el.ContextOnly:
		causeDetail = "only background stories (standing security findings) — a security finding with an owner, never an RCA document"
	case el.NeverEstablished:
		causeDetail = "the only fault is a BGP peer that never came up — a configuration ticket, never an RCA document"
	case !el.CausalHeadline:
		causeDetail = "no cause has been determined"
	}
	recDetail := "repeat count not available"
	if rep.Recurrence.Known {
		recDetail = fmt.Sprintf("%d of %d occurrences of this cause on %s in the last 7 days",
			rep.Recurrence.Count7d, RepeatOffenderMin, orDefault(el.PrimaryDevice, "the primary device"))
	}
	crit := []PromotionCriterion{
		{
			Name: critProduction, Met: !rep.Validation,
			Detail: map[bool]string{true: "not a validation scenario", false: "validation scenario — never a customer RCA"}[!rep.Validation],
		},
		{Name: critCause, Met: networkCause, Detail: causeDetail},
		{
			Name: critConfirmed, Met: rep.States.Analysis == "confirmed",
			Detail: "analysis is " + orDefault(rep.States.Analysis, "unknown"),
		},
		{
			Name: critMeasured, Met: rep.ConfirmingPair.Measured,
			Detail: orDefault(rep.ConfirmingPair.Basis, "no independent confirming pair recorded"),
		},
		{
			Name: critImpact, Met: rep.States.Impact == "confirmed",
			Detail: fmt.Sprintf("impact is %s (real-user: %s, synthetic: %s)",
				orDefault(rep.States.Impact, "unknown"),
				orDefault(rep.States.ImpactRealUser, "unknown"),
				orDefault(rep.States.ImpactSynthetic, "unknown")),
		},
		{
			Name: critDuration, Met: time.Duration(rep.Times.DurationMS)*time.Millisecond >= PromotionMinDuration,
			Detail: fmt.Sprintf("%s observed; auto-promotion requires ≥ %s",
				FmtDur(time.Duration(rep.Times.DurationMS)*time.Millisecond), FmtDur(PromotionMinDuration)),
		},
		{
			Name: critRepeat, Met: rep.Recurrence.Known && rep.Recurrence.Count7d >= RepeatOffenderMin,
			Detail: recDetail,
		},
		{
			Name: critMultiSite, Met: el.ControllerOrHub && el.Sites >= MultiSiteMin,
			Detail: fmt.Sprintf("controller or hub object: %s; sites affected: %d (needs ≥ %d)",
				map[bool]string{true: "yes", false: "no"}[el.ControllerOrHub], el.Sites, MultiSiteMin),
		},
	}
	st := PromotionStatus{Criteria: crit, Manual: manual}
	if manual != nil {
		st.Promoted = true
		st.Basis = "manual"
		st.Reason = fmt.Sprintf("manually promoted by %s at %s", manual.PromotedBy, manual.PromotedAt)
		return st
	}
	met := map[string]bool{}
	for _, c := range crit {
		met[c.Name] = c.Met
	}
	gate := met[critProduction] && met[critCause]
	outage := gate
	var unmet []string
	for _, n := range []string{critProduction, critCause, critConfirmed, critMeasured, critImpact, critDuration} {
		if !met[n] {
			outage = false
			unmet = append(unmet, n)
		}
	}
	switch {
	case outage:
		st.Promoted, st.Basis, st.Trigger = true, "auto", "real_outage"
		st.Reason = "meets the real-outage criteria: confirmed verdict from two independent measurement sources, confirmed user/application impact, duration ≥ " + FmtDur(PromotionMinDuration)
		return st
	case gate && met[critRepeat]:
		st.Promoted, st.Basis, st.Trigger = true, "auto", "repeat_offender"
		st.Reason = fmt.Sprintf("repeat offender: the same cause hit %s %d times in the last 7 days (%d or more earns an RCA document)",
			orDefault(el.PrimaryDevice, "the primary device"), rep.Recurrence.Count7d, RepeatOffenderMin)
		return st
	case gate && met[critMultiSite]:
		st.Promoted, st.Basis, st.Trigger = true, "auto", "multi_site"
		st.Reason = fmt.Sprintf("multi-site outage: one controller or hub affected %d sites", el.Sites)
		return st
	}
	st.Basis = "not_promoted"
	st.Reason = "RCA documents are reserved for promoted real outages; this candidate does not meet: " +
		strings.Join(unmet, ", ") + "; and it is neither a repeat offender nor a multi-site controller or hub outage. An operator with write permission can promote it explicitly (audited)."
	return st
}

// chQuote renders one value as a single-quoted ClickHouse string literal
// (backslash first, then the quote) — the values are engine template ids and
// device names, still treated as untrusted (§3).
func chQuote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

// RecurrenceQuery returns the tenant-scoped ClickHouse read that counts how
// often this report's headline cause hit its primary device in the 7 days up
// to the END of this case's window (anchored to the case, not the wall clock,
// so a document rebuilt later counts the same history). ok=false when there is
// nothing to count (no causal headline, no primary device, no window end).
// The caller runs it under the CALLER's chTenantScope (row policies).
func (r *Report) RecurrenceQuery() (sql string, ok bool) {
	el := r.Eligibility
	end, okEnd := parseChTS(r.Times.WindowEnd)
	if el.HeadlineID == "" || el.PrimaryDevice == "" || !okEnd {
		return "", false
	}
	endLit := chQuote(end.UTC().Format("2006-01-02 15:04:05"))
	return `
SELECT count() AS repeat_count
  FROM netops.corr_current FINAL
 WHERE top_hypothesis = ` + chQuote(el.HeadlineID) + `
   AND JSONExtractString(affected, 'devices', 1) = ` + chQuote(el.PrimaryDevice) + `
   AND state != 'merged'
   AND window_end <= toDateTime64(` + endLit + `, 3, 'UTC')
   AND window_end >= toDateTime64(` + endLit + `, 3, 'UTC') - INTERVAL ` + fmt.Sprint(int(RepeatOffenderWindow.Seconds())) + ` SECOND
 FORMAT JSON`, true
}

// SetRecurrence stamps the repeat-offender count (n includes this case).
func (r *Report) SetRecurrence(n int) {
	if n < 0 {
		n = 0
	}
	r.Recurrence = rcaRecurrence{Known: true, Count7d: n}
}
