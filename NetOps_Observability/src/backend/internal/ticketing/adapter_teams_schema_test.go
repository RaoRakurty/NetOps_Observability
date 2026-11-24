// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// adapter_teams_schema_test.go — tracker 455: every RCA lifecycle card the
// Teams destination posts (opened, updated, work note, resolved), captured from
// the wire, is valid against Microsoft's official Adaptive Card 1.4 schema.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/adaptivecard"
)

func TestEveryTeamsRCACardOnTheWireIsValidAgainstTheOfficialSchema(t *testing.T) {
	v, err := adaptivecard.New14(adaptivecard.TeamsHostExtensions...)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeTeamsHook(t)
	a := NewTeamsAdapterWithClient(f.srv.Client())
	cfg := f.cfg("acme")
	payloads := map[string]Payload{
		"typical": {CorrObjectID: "3e0400aa-0000-4000-8000-000000000001", Title: "Confirmed BGP session failure on cEDGE-81",
			Verdict: "confirmed", Confidence: 0.91, Summary: "peer 192.168.200.34 down", RecommendedAction: "check the WAN link",
			AffectedScope: "Site 81", RCAURL: "https://correlix.example/#/investigate/rca/x"},
		"bare": {CorrObjectID: "", Title: "Undetermined", Verdict: "undetermined"},
		"long and odd text": {CorrObjectID: "3e0400aa-0000-4000-8000-000000000002", Title: strings.Repeat("Ω \"<b>\" ", 80),
			Verdict: "suspected", Confidence: 0.5, Summary: strings.Repeat("**md** & <html> ", 200),
			RecommendedAction: strings.Repeat("step ", 200), AffectedScope: strings.Repeat("s", 900), RCAURL: "javascript:alert(1)"},
	}
	for name, p := range payloads {
		ref, err := a.CreateIncident(context.Background(), cfg, p)
		if err != nil {
			t.Fatalf("%s: create: %v", name, err)
		}
		if err := a.UpdateIncident(context.Background(), cfg, ref, p); err != nil {
			t.Fatalf("%s: update: %v", name, err)
		}
		if err := a.AddWorkNote(context.Background(), cfg, ref, "engineer on site — "+strings.Repeat("n", 1200)); err != nil {
			t.Fatalf("%s: note: %v", name, err)
		}
		if err := a.ResolveIncident(context.Background(), cfg, ref, ""); err != nil {
			t.Fatalf("%s: resolve: %v", name, err)
		}
	}
	f.mu.Lock()
	bodies := append([]string(nil), f.bodies...)
	f.mu.Unlock()
	if len(bodies) != 4*len(payloads) {
		t.Fatalf("posted %d cards, want %d", len(bodies), 4*len(payloads))
	}
	for i, b := range bodies {
		var env struct {
			Attachments []struct {
				Content any `json:"content"`
			} `json:"attachments"`
		}
		if err := json.Unmarshal([]byte(b), &env); err != nil || len(env.Attachments) != 1 {
			t.Fatalf("post %d is not the message envelope: %v %s", i, err, b)
		}
		if errs := v.ValidateCard(env.Attachments[0].Content); errs != nil {
			t.Errorf("post %d refused by the Adaptive Card 1.4 schema:\n  %s", i, strings.Join(errs, "\n  "))
		}
		if len(b) >= 28*1024 {
			t.Errorf("post %d is %d bytes, over the Teams limit", i, len(b))
		}
	}
}
