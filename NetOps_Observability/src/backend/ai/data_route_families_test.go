// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"testing"
)

// The data arm's routing options (hybrid NLU plan A4): a symptom phrasing is
// offered to the data arm ONLY as an incident list about a resolved entity
// (and never spends the model on it); a diagnosis stays with the skills; the
// router's own intent travels with every attempt so the server can record a
// question another arm answers as not_data.
func TestDataArmRoutingOptions(t *testing.T) {
	var got []DataOpts
	o := newOrch(newMockDS())
	o.NLQuery = func(_ context.Context, _ Principal, _ string, opts DataOpts) (DataAnswer, error) {
		got = append(got, opts)
		return DataAnswer{Status: DataNotData}, nil
	}
	ask := func(q string) {
		t.Helper()
		got = nil
		if _, err := o.Ask(context.Background(), tenantA(), q, nil); err != nil {
			t.Fatal(err)
		}
	}
	ask("what's wrong with edge-1")
	if len(got) != 1 || !got[0].IncidentRefOnly || got[0].AllowModel {
		t.Fatalf("a symptom phrasing is incident-ref-only and model-free: %+v", got)
	}
	ask("show me the critical incidents")
	if len(got) != 1 || got[0].IncidentRefOnly || got[0].ClassicIntent != "incident_list" {
		t.Fatalf("a listing carries the router's intent: %+v", got)
	}
	ask("why is edge-1 down")
	if len(got) != 0 {
		t.Fatalf("a diagnosis never reaches the data arm: %+v", got)
	}
	ask("how many devices are onboarded?")
	if len(got) != 1 || got[0].IncidentRefOnly {
		t.Fatalf("an inventory question goes to the data arm as a plain attempt: %+v", got)
	}
}
