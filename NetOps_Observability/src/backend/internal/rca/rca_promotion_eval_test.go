package rca

// rca_promotion_eval_test.go — the pure auto-promotion criteria (#113 point 3):
// confirmed verdict · confirmed user/app impact · duration · production, and
// the manual override. The store/HTTP isolation contract stays with the
// integrator tests in package main.

import (
	"strings"
	"testing"
	"time"
)

// ---- evaluation --------------------------------------------------------------

func promoReport(analysis, impact string, dur time.Duration, validation bool) Report {
	return Report{
		Validation: validation,
		States:     ReportStates{Analysis: analysis, Impact: impact, ImpactRealUser: "unknown", ImpactSynthetic: "confirmed"},
		Times:      rcaReportTimes{DurationMS: dur.Milliseconds()},
	}
}

func TestPromotionAutoRequiresAllCriteria(t *testing.T) {
	rep := promoReport("confirmed", "confirmed", 10*time.Minute, false)
	st := EvaluatePromotion(&rep, nil)
	if !st.Promoted || st.Basis != "auto" {
		t.Fatalf("real outage must auto-promote: %+v", st)
	}

	for name, r := range map[string]Report{
		"unconfirmed verdict": promoReport("suspected", "confirmed", 10*time.Minute, false),
		"no user impact":      promoReport("confirmed", "detected", 10*time.Minute, false),
		"blip duration":       promoReport("confirmed", "confirmed", 90*time.Second, false),
		"validation scenario": promoReport("confirmed", "confirmed", 10*time.Minute, true),
	} {
		rr := r
		st := EvaluatePromotion(&rr, nil)
		if st.Promoted {
			t.Fatalf("%s must NOT auto-promote: %+v", name, st)
		}
		if st.Basis != "not_promoted" || !strings.Contains(st.Reason, "reserved for promoted real outages") {
			t.Fatalf("%s: refusal must explain the policy: %+v", name, st)
		}
	}
}

func TestPromotionManualOverrides(t *testing.T) {
	rep := promoReport("suspected", "detected", time.Minute, false)
	rec := &PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"}
	st := EvaluatePromotion(&rep, rec)
	if !st.Promoted || st.Basis != "manual" || !strings.Contains(st.Reason, "ops@acme") {
		t.Fatalf("manual promotion must win with attribution: %+v", st)
	}
}
