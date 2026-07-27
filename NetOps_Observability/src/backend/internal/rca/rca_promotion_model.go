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
	Promoted bool                 `json:"promoted"`
	Basis    string               `json:"basis"` // auto | manual | not_promoted
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

// EvaluatePromotion decides the case's tier from the FINISHED report (the
// states/times there are already derived honestly) plus any manual record. A
// manual promotion is an explicit human decision and always wins; auto requires
// every criterion. The reason strings are user-facing — they say exactly what
// is unmet and how to promote, never a bare refusal.
func EvaluatePromotion(rep *Report, manual *PromotionRecord) PromotionStatus {
	crit := []PromotionCriterion{
		{
			Name: "production incident", Met: !rep.Validation,
			Detail: map[bool]string{true: "not a validation scenario", false: "validation scenario — never a customer RCA"}[!rep.Validation],
		},
		{
			Name: "confirmed verdict", Met: rep.States.Analysis == "confirmed",
			Detail: "analysis is " + orDefault(rep.States.Analysis, "unknown"),
		},
		{
			Name: "user/application impact", Met: rep.States.Impact == "confirmed",
			Detail: fmt.Sprintf("impact is %s (real-user: %s, synthetic: %s)",
				orDefault(rep.States.Impact, "unknown"),
				orDefault(rep.States.ImpactRealUser, "unknown"),
				orDefault(rep.States.ImpactSynthetic, "unknown")),
		},
		{
			Name: "duration", Met: time.Duration(rep.Times.DurationMS)*time.Millisecond >= PromotionMinDuration,
			Detail: fmt.Sprintf("%s observed; auto-promotion requires ≥ %s",
				FmtDur(time.Duration(rep.Times.DurationMS)*time.Millisecond), FmtDur(PromotionMinDuration)),
		},
	}
	st := PromotionStatus{Criteria: crit, Manual: manual}
	if manual != nil {
		st.Promoted = true
		st.Basis = "manual"
		st.Reason = fmt.Sprintf("manually promoted by %s at %s", manual.PromotedBy, manual.PromotedAt)
		return st
	}
	var unmet []string
	for _, c := range crit {
		if !c.Met {
			unmet = append(unmet, c.Name)
		}
	}
	if len(unmet) == 0 {
		st.Promoted = true
		st.Basis = "auto"
		st.Reason = "meets the real-outage criteria: confirmed verdict, confirmed user/application impact, duration ≥ " + FmtDur(PromotionMinDuration)
		return st
	}
	st.Basis = "not_promoted"
	st.Reason = "RCA documents are reserved for promoted real outages; this candidate does not meet: " +
		strings.Join(unmet, ", ") + ". An operator with write permission can promote it explicitly (audited)."
	return st
}
