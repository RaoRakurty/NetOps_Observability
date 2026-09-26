// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_rca_result_test.go — projectRCAReport is a PURE, BOUNDED projection of
// the engine's report (tracker 337 N-B1): every value is the engine's, the
// relation class follows the engine's epistemic state, and a list over its
// bound is clipped AND flagged, never silently shortened.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/rca"
)

func reportFromJSON(t *testing.T, js string) rca.Report {
	t.Helper()
	var rep rca.Report
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestProjectRCAReportCarriesTheEnginesValues(t *testing.T) {
	rep := reportFromJSON(t, `{
	  "correlation_id":"c-1","display_id":"P-ABC123","title":"DIA loss at Dallas",
	  "states":{"analysis":"probable","root_cause_state":"under_investigation"},
	  "root_cause":{"identified":false,"statement":"not identified","possible_cause":"Comcast DIA degradation",
	    "evidence_known":["loss after handoff"],"evidence_missing":["remote probe data"]},
	  "fault_localization":{"localized":true,"statement":"at the DIA seam","object":"comcast-dfw"},
	  "causal_chain":{"available":true,"steps":[
	    {"number":1,"claim":"packet loss","causal_role":"likely origin","epistemic_state":"observed","interval":"10:17 → 10:40"},
	    {"number":2,"claim":"tunnel SLA degraded","causal_role":"propagation step","epistemic_state":"inferred","link":"followed by","contradictions":["one site healthy"]}]},
	  "hypotheses":[{"rank":1,"title":"Comcast DIA","confidence":0.91,"label":"likely","supporting":["a"],"contradicting":["b"],"missing":["c"]}],
	  "scope":{"services":["Salesforce"],"sites":["Dallas HQ"],"paths_count":2},
	  "impact_provenance":{"measures":[{"measure":"active_users","label":"Active users affected","status":"not_measured","basis":"no identity mapping"}]},
	  "ownership":{"triage_owner":"NOC","external_candidate":"Comcast","demarcation":"local_checks_pending","candidates":[{"team":"Network","reason":"DIA seam"}]}
	}`)
	got := projectRCAReport(rep)
	if got.IncidentID != "c-1" || got.Verdict != "probable" || got.RootCauseState != "under_investigation" {
		t.Fatalf("header = %+v", got)
	}
	if got.Confidence != 0.91 || got.ConfidenceLabel != "likely" {
		t.Fatalf("confidence must be the leading hypothesis's engine value: %v %q", got.Confidence, got.ConfidenceLabel)
	}
	if len(got.CausalChain) != 2 || got.CausalChain[0].Relation != ai.RelationObserved || got.CausalChain[1].Relation != ai.RelationInferred {
		t.Fatalf("chain relations = %+v", got.CausalChain)
	}
	if got.CausalChain[1].Contradictions[0] != "one site healthy" {
		t.Fatal("step contradictions must survive the projection")
	}
	if got.RootCause.Identified || got.RootCause.PossibleCause != "Comcast DIA degradation" {
		t.Fatalf("root cause = %+v", got.RootCause)
	}
	if got.Impact[0].Value != nil || got.Impact[0].Status != "not_measured" {
		t.Fatal("an unmeasured impact must stay valueless")
	}
	if got.Owner.ExternalCandidate != "Comcast" || got.Owner.Candidates[0] != "Network — DIA seam" {
		t.Fatalf("owner = %+v", got.Owner)
	}
	if got.Truncated {
		t.Fatal("nothing here exceeds a bound")
	}
}

func TestProjectRCAReportBoundsAndFlags(t *testing.T) {
	var steps, devs []string
	for i := 1; i <= ai.MaxRCAChainSteps+3; i++ {
		steps = append(steps, fmt.Sprintf(`{"number":%d,"claim":"s%d","epistemic_state":"observed"}`, i, i))
	}
	for i := 0; i < ai.MaxRCAAffectedPerSet+5; i++ {
		devs = append(devs, fmt.Sprintf(`"d%d"`, i))
	}
	rep := reportFromJSON(t, `{"correlation_id":"c-2","causal_chain":{"steps":[`+strings.Join(steps, ",")+`]},"scope":{"devices":[`+strings.Join(devs, ",")+`]}}`)
	got := projectRCAReport(rep)
	if len(got.CausalChain) != ai.MaxRCAChainSteps || len(got.Affected.Devices) != ai.MaxRCAAffectedPerSet || !got.Truncated {
		t.Fatalf("chain=%d devices=%d truncated=%v", len(got.CausalChain), len(got.Affected.Devices), got.Truncated)
	}
}

func TestAIRCAResultRejectsMalformedIDs(t *testing.T) {
	_, s := newTestServerState(t)
	claims := jwtClaims{Sub: "u", Tenant: "t-a", Role: "operator"}
	f := s.aiRCAResult(newAITestRequest(t, claims), claims)
	for _, id := range []string{"", "not-a-uuid", "11111111-2222-3333-4444-55555555555'"} {
		if _, err := f(t.Context(), ai.Principal{}, id); !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("id %q: want ErrNotFound before any read, got %v", id, err)
		}
	}
}
