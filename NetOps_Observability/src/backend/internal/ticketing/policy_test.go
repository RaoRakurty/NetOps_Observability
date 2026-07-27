package ticketing

import (
	"testing"
	"time"
)

// baseFacts is a customer-facing, confirmed, critical, well-scoped object — the
// canonical ticket-worthy case. Tests mutate one field to probe each gate.
func baseFacts() CorrFacts {
	return CorrFacts{
		Verdict:           "confirmed",
		Confidence:        0.9,
		Internal:          false,
		ProbeOnly:         false,
		LowAuthorityProbe: false,
		PeakSeverity:      "crit",
		HasAffectedEntity: true,
		AffectedScope:     "edge1 Gi0/1",
	}
}

func TestEvalTicketDecision_CreatesOnConfirmedCustomerFacing(t *testing.T) {
	d := EvalDecision(baseFacts(), DefaultIncidentPolicy("t_a"), nil, time.Now())
	if !d.Create {
		t.Fatalf("expected create, got hold: %s", d.Reason)
	}
}

func TestEvalTicketDecision_Guardrails(t *testing.T) {
	now := time.Now()
	pol := DefaultIncidentPolicy("t_a")

	cases := []struct {
		name   string
		mutate func(*CorrFacts)
		policy func(*IncidentPolicy)
		link   *Link
		create bool
	}{
		{name: "undetermined held", mutate: func(f *CorrFacts) { f.Verdict = "undetermined" }},
		{name: "internal monitoring held", mutate: func(f *CorrFacts) { f.Internal = true }},
		// §11 (truthfulness epic, required test 23): a CONFIRMED validation
		// canary must never file production tickets by default...
		{name: "validation scenario held even when confirmed", mutate: func(f *CorrFacts) { f.Validation = true }},
		// ...and may act only under an explicit tenant opt-in.
		{name: "validation allowed under explicit opt-in",
			mutate: func(f *CorrFacts) { f.Validation = true },
			policy: func(p *IncidentPolicy) { p.AllowValidationScenarios = true }, create: true},
		{name: "probe-only held", mutate: func(f *CorrFacts) { f.ProbeOnly = true }},
		{name: "low-authority probe held", mutate: func(f *CorrFacts) { f.LowAuthorityProbe = true; f.ProbeOnly = true }},
		{name: "no affected entity held", mutate: func(f *CorrFacts) { f.HasAffectedEntity = false }},
		{
			name:   "suspected non-critical held",
			mutate: func(f *CorrFacts) { f.Verdict = "suspected"; f.PeakSeverity = "high" },
		},
		{
			name:   "suspected critical creates",
			mutate: func(f *CorrFacts) { f.Verdict = "suspected"; f.PeakSeverity = "crit" },
			create: true,
		},
		{
			name:   "below threshold held (min=confirmed)",
			mutate: func(f *CorrFacts) { f.Verdict = "suspected"; f.PeakSeverity = "crit" },
			policy: func(p *IncidentPolicy) { p.MinVerdict = "confirmed" },
		},
		{
			name:   "persistence not met held",
			mutate: func(f *CorrFacts) { f.WindowStart = now.Add(-10 * time.Second); f.WindowEnd = now },
			policy: func(p *IncidentPolicy) { p.RequirePersistenceSeconds = 60 },
		},
		{
			name:   "persistence met creates",
			mutate: func(f *CorrFacts) { f.WindowStart = now.Add(-120 * time.Second); f.WindowEnd = now },
			policy: func(p *IncidentPolicy) { p.RequirePersistenceSeconds = 60 },
			create: true,
		},
		{
			name: "existing open ticket held (no double-create)",
			link: &Link{Status: "open", TicketNumber: "INC0012345"},
		},
		{
			name:   "resolved within suppression window held",
			policy: func(p *IncidentPolicy) { p.SuppressFlappingSeconds = 300 },
			link: func() *Link {
				ts := now.Add(-30 * time.Second)
				return &Link{Status: "resolved", LastSyncedAt: &ts}
			}(),
		},
		{
			name:   "internal allowed by policy creates",
			mutate: func(f *CorrFacts) { f.Internal = true },
			policy: func(p *IncidentPolicy) { p.AllowInternalMonitoring = true },
			create: true,
		},
		{name: "disabled policy held", policy: func(p *IncidentPolicy) { p.Enabled = false }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFacts()
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			p := pol
			if tc.policy != nil {
				tc.policy(&p)
			}
			d := EvalDecision(f, p, tc.link, now)
			if d.Create != tc.create {
				t.Fatalf("create=%v want %v (reason=%q)", d.Create, tc.create, d.Reason)
			}
			if d.Reason == "" {
				t.Fatalf("decision must carry an operator-readable reason")
			}
		})
	}
}
