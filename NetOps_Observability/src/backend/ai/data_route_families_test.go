// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
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

// Several data questions in one message are answered each on its own, in one
// answer; one part that is not data hands the whole message back.
func TestMultiQuestionDataAnswer(t *testing.T) {
	var asked []string
	o := newOrch(newMockDS())
	o.NLQuery = func(_ context.Context, _ Principal, q string, opts DataOpts) (DataAnswer, error) {
		asked = append(asked, q)
		if opts.AllowModel && !strings.Contains(q, "? ") {
			t.Errorf("a part must never spend the model: %q", q)
		}
		switch q {
		case "how many devices can you see?", "list the sites":
			return DataAnswer{Status: DataAnswered, Intent: "count_entities", Text: "answer to " + q, Notes: []string{"same note"}}, nil
		}
		return DataAnswer{Status: DataNotData}, nil
	}
	ans, err := o.Ask(context.Background(), tenantA(), "how many devices can you see? list the sites", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDataQuery || ans.Intent != IntentMultiQuestion {
		t.Fatalf("multi answer = %+v", ans)
	}
	if want := "how many devices can you see?\nanswer to how many devices can you see?\n\nlist the sites\nanswer to list the sites"; ans.Text != want {
		t.Fatalf("text = %q", ans.Text)
	}
	n := 0
	for _, d := range ans.Disclaimers {
		if d == "same note" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("a note shared by two parts is said once: %q", ans.Disclaimers)
	}
	asked = nil
	ans, err = o.Ask(context.Background(), tenantA(), "how many devices can you see? tell me a joke", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Routing policy (route_policy.go): a part nothing deterministic covers
	// hands the WHOLE message to the model — never half-answered here.
	if ans.Mode != ModeModelAnswer || ans.Routing == nil || ans.Routing.Reason != RouteReasonCompound {
		t.Fatalf("a non-data part sends the message to the model: %+v", ans)
	}
}
