// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aientitlement_test

import (
	"testing"

	"netops/backend/internal/aientitlement"
)

// The AI add-on (owner 2026-11-12/13): provider calls need the `iris_model`
// licence AND the platform switch; investigations also need their own switch
// and the tenant's opt-in. Evidence-only capabilities need neither.

// modelInputs: every input that applies says yes. The shipped mapping grants
// every capability to every tier, so any tier key from it works.
func modelInputs() aientitlement.Inputs {
	return aientitlement.Inputs{
		Tier: firstTier(), Env: env(map[string]string{}), Tenant: "t-a",
		Switches:      switches{assistant: map[string]bool{"t-a": true}, tools: map[string]bool{"t-a": true}},
		ModelLicensed: true, ModelsOn: true, InvestigationsOn: true,
	}
}

func firstTier() string {
	p, err := aientitlement.Default()
	if err != nil || len(p.Tiers()) == 0 {
		return ""
	}
	return p.Tiers()[0]
}

func TestModelNeedsTheLicenceThenTheSwitch(t *testing.T) {
	p, err := aientitlement.Default()
	if err != nil {
		t.Fatal(err)
	}
	in := modelInputs()
	for _, e := range []aientitlement.Entitlement{aientitlement.Model, aientitlement.Investigate} {
		if d := aientitlement.Decide(p, e, in); !d.Granted {
			t.Fatalf("%s: licensed, switched on, tenant opted in must grant: %+v", e, d)
		}
		unlicensed := in
		unlicensed.ModelLicensed = false
		unlicensed.ModelsOn = false // the licence is named first: the switch cannot be turned on without it
		if d := aientitlement.Decide(p, e, unlicensed); d.Granted || d.Reason != aientitlement.ReasonNotLicensed {
			t.Fatalf("%s: no add-on must refuse as not_licensed: %+v", e, d)
		}
		off := in
		off.ModelsOn = false
		if d := aientitlement.Decide(p, e, off); d.Granted || d.Reason != aientitlement.ReasonSwitchedOff {
			t.Fatalf("%s: licensed but switched off must refuse as switched_off: %+v", e, d)
		}
	}
}

func TestInvestigationsNeedTheirOwnSwitchAndTheTenant(t *testing.T) {
	p, _ := aientitlement.Default()
	in := modelInputs()
	in.InvestigationsOn = false
	if d := aientitlement.Decide(p, aientitlement.Investigate, in); d.Granted || d.Reason != aientitlement.ReasonSwitchedOff {
		t.Fatalf("the investigations switch off must refuse: %+v", d)
	}
	if !aientitlement.Decide(p, aientitlement.Model, in).Granted {
		t.Fatal("the investigations switch must not touch model answers")
	}
	in = modelInputs()
	in.Switches = switches{assistant: map[string]bool{"t-a": true}, tools: map[string]bool{}}
	if d := aientitlement.Decide(p, aientitlement.Investigate, in); d.Granted || d.Reason != aientitlement.ReasonTenantOff {
		t.Fatalf("a tenant that has not opted in has no investigations: %+v", d)
	}
	in.Switches = switches{assistant: map[string]bool{}, tools: map[string]bool{"t-a": true}}
	if d := aientitlement.Decide(p, aientitlement.Investigate, in); d.Granted || d.Reason != aientitlement.ReasonTenantOff {
		t.Fatalf("a tenant with the assistant off has no investigations (each turn is a model call): %+v", d)
	}
	if d := aientitlement.Decide(p, aientitlement.Model, in); d.Granted || d.Reason != aientitlement.ReasonTenantOff {
		t.Fatalf("a tenant with the assistant off has no model answers: %+v", d)
	}
}

// TestEvidenceOnlyIrisNeedsNoAddOn: without the licence and with every AI
// switch off, the assistant, natural-language questions and context authoring
// still answer — from the platform's own data.
func TestEvidenceOnlyIrisNeedsNoAddOn(t *testing.T) {
	p, _ := aientitlement.Default()
	in := modelInputs()
	in.ModelLicensed, in.ModelsOn, in.InvestigationsOn = false, false, false
	for _, e := range []aientitlement.Entitlement{aientitlement.Chat, aientitlement.NLQuery, aientitlement.ContextAuthor} {
		if d := aientitlement.Decide(p, e, in); !d.Granted {
			t.Fatalf("%s is evidence-only and free: %+v", e, d)
		}
	}
	got := aientitlement.Resolve(p, in)
	for _, e := range got {
		if e == aientitlement.Model || e == aientitlement.Investigate {
			t.Fatalf("Resolve must not offer %s without the add-on: %v", e, got)
		}
	}
}

// TestCrossTenantStillNeedsTheLicenceAndSwitch: the platform owner is not
// tenant-gated, but the licence and the switch bind every principal.
func TestCrossTenantStillNeedsTheLicenceAndSwitch(t *testing.T) {
	p, _ := aientitlement.Default()
	in := modelInputs()
	in.Cross, in.Switches = true, nil
	if !aientitlement.Decide(p, aientitlement.Investigate, in).Granted {
		t.Fatal("cross-tenant: licensed and on must grant without a tenant switch")
	}
	in.ModelsOn = false
	if aientitlement.Decide(p, aientitlement.Model, in).Granted {
		t.Fatal("cross-tenant does not bypass the platform switch")
	}
	in.ModelsOn, in.ModelLicensed = true, false
	if aientitlement.Decide(p, aientitlement.Model, in).Granted {
		t.Fatal("cross-tenant does not bypass the licence")
	}
}
