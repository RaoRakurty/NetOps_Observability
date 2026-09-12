// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tac_incident_bridge_test.go — what a TAC escalation is allowed to imply about
// the evidence behind it (review 3.1-19).
//
// THE DEFECT. tacLookupIncident carried a branch that followed an incident to
// the correlation object it came from, keyed on `SourceType == "correlation"`.
// The incident store's source_type is a CLOSED vocabulary — alert, log, anomaly,
// manual, experience; anything else collapses to "manual" before the row is
// written (incident.normalizeSourceType) — so no stored incident could ever
// carry that value and the branch was dead from the day it was written. The
// escalation then went out with no correlation evidence AND no mention of the
// gap: Sources/Missing exist precisely so "an escalation built without the alert
// store must not look like one built with it", and this one did.

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnIncidentEscalationSaysTheCorrelationObjectIsMissing(t *testing.T) {
	s := &server{incidents: &fakeIncidents{rows: []Incident{{
		ID: "a1b2c3d4e5f60718", TenantID: "t_acme", Title: "BGP session flapping on edge-1",
		Severity: "high", Status: "open", SourceType: "alert", SourceID: "BGPSessionDown",
		FirstSeenAt: time.Unix(1757000000, 0).UTC(), LastSeenAt: time.Unix(1757003600, 0).UTC(),
	}}}}
	r := httptest.NewRequest("GET", "/api/troubleshoot/tac/state", nil)

	inc, found := s.tacLookupIncident(r, "t_acme", false, "a1b2c3d4e5f60718")
	if !found {
		t.Fatal("the incident register did not resolve its own id")
	}
	var sawRegister bool
	for _, src := range inc.Sources {
		if src == "incident register" {
			sawRegister = true
		}
	}
	if !sawRegister {
		t.Fatalf("Sources does not name the store that answered: %v", inc.Sources)
	}
	if len(inc.Hypotheses) != 0 || len(inc.Devices) != 0 {
		t.Fatalf("correlation facts appeared with no correlation object: %+v", inc)
	}
	if len(inc.Missing) == 0 {
		t.Fatalf("the escalation carries NO correlation evidence and says nothing about it: %+v — "+
			"Sources/Missing exist so an escalation built without a store cannot look like one built with it", inc)
	}
	var named bool
	for _, m := range inc.Missing {
		if len(m) >= len("correlation") && m[:len("correlation")] == "correlation" {
			named = true
		}
	}
	if !named {
		t.Fatalf("Missing does not name the correlation object: %v", inc.Missing)
	}
}
