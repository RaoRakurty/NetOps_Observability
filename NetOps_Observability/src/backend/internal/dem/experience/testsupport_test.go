package experience

// testsupport_test.go — the shared builders. Everything in this package is
// PURE, so a test needs no server, no store and no clock: `now` is always an
// argument and every fixture below is a plain value.

import "time"

// testNow is the fixed clock every test reasons against. A literal rather than
// time.Now() so a test that passes today passes in a year.
var testNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func testWindow() Window { return NewWindow(testNow.Add(-time.Hour), testNow) }

// prov builds a valid provenance block at an offset from testNow.
func prov(source string, offset time.Duration) Provenance {
	at := testNow.Add(offset)
	return Provenance{
		Source: source, Producer: "test", EventAt: at, ObservedAt: at,
		Observation: ObservationObserved, DataClass: DataClassCustomerMetadata,
	}
}

// ev builds a supporting evidence item. Every test that needs a variation
// mutates the returned value, so the differences between cases are visible in
// the test rather than buried in a builder's options.
func ev(id, modality, observer string, offset time.Duration) EvidenceItem {
	return EvidenceItem{
		ID: id, TenantID: "acme", Kind: KindSyntheticResult,
		Entity: "tgt-" + id, EntityKind: "target",
		Summary: id + " observed the failure", Stance: StanceSupports,
		IndependenceGroup: modality, Observer: observer,
		Reliability: 0.9, App: "checkout",
		Provenance: prov(SourceSynthetic, offset),
	}
}

func contra(id, modality, observer string, causes []string, offset time.Duration) EvidenceItem {
	return EvidenceItem{
		ID: id, TenantID: "acme", Kind: KindServiceHealth,
		Entity: "svc-" + id, EntityKind: "service",
		Summary: id + " did not move", Stance: StanceContradicts,
		IndependenceGroup: modality, Observer: observer,
		Reliability: 0.9, App: "checkout", ContradictsCauses: causes,
		Provenance: prov(SourceServiceHTTP, offset),
	}
}

func hyp(id, cause, entity, seam, owner string) Hypothesis {
	return Hypothesis{
		ID: id, TenantID: "acme", CauseClass: cause, CauseEntity: entity,
		Seam: seam, Owner: owner, Explanation: "because " + entity + " degraded",
		FirstImpactAt: testNow.Add(-30 * time.Minute),
	}
}

// checkoutJourney is the acceptance scenario's workflow: browse → pay, both
// bound to a measured target, 99% objective, critical to the business.
func checkoutJourney() JourneyDefinition {
	j := JourneyDefinition{
		TenantID: "acme", ID: "jny-" + "0000000000000000000000000000000a",
		Name: "Checkout", App: "checkout", BusinessImportance: ImportanceCritical,
		BusinessValuePerSuccess: 40, Currency: "USD",
		EntryStepID: "browse", Version: 1,
		SLO: ExperienceSLO{SuccessPct: 99, Window: "1h"},
		Steps: []JourneyStep{
			{ID: "browse", Label: "Browse", Next: []string{"cart"}, TargetID: "dem-1"},
			{ID: "cart", Label: "Cart", Next: []string{"pay", "browse"}, TargetID: "dem-2"},
			{ID: "pay", Label: "Pay", TerminalSuccess: true, TargetID: "dem-3"},
		},
	}
	if err := j.Validate(); err != nil {
		panic("checkoutJourney fixture is invalid: " + err.Error())
	}
	return j
}
