// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/ticketing"
	"netops/backend/models"
)

// Owner, 2026-11-23: an RCA document, a ticket raised from an RCA and an Iris
// answer name a device by its hostname — never the internal
// `<sysName>-<address hash>` id — and only ever with a name from the reader's
// (or the owning tenant's) own devices (§3a).

func seedTwoTenantDevices(t *testing.T) *server {
	t.Helper()
	_, s := newTestServerState(t)
	s.discovery.Upsert(models.Device{ID: "cedge-81-dde8d64d", Name: "cEDGE-81", Address: "10.255.255.81", TenantID: "t_a"})
	s.discovery.Upsert(models.Device{ID: "vedge-51-79fbba30", Name: "vEdge-51", Address: "10.255.255.51", TenantID: "t_b"})
	return s
}

const twoTenantText = "Confirmed link down on cedge-81-dde8d64d:Gi2; peer vedge-51-79fbba30 saw it"

func TestOperatorTextUsesOnlyTheOwningTenantsDeviceNames(t *testing.T) {
	s := seedTwoTenantDevices(t)

	// The owning tenant's outbound text (ticket sweeper): its own device named,
	// another tenant's id left exactly as it was — never resolved to B's name.
	got := s.tenantDeviceNames("t_a").Text(twoTenantText)
	if want := "Confirmed link down on cEDGE-81:Gi2; peer vedge-51-79fbba30 saw it"; got != want {
		t.Fatalf("tenant t_a text:\n got %q\nwant %q", got, want)
	}

	// A tenant user reading about its own case: its own devices only.
	alice := jwtClaims{Sub: "alice", Role: "operator", Tenant: "t_a"}
	if got := s.callerDeviceNames(alice, "t_a").Text(twoTenantText); strings.Contains(got, "vEdge-51") || !strings.Contains(got, "cEDGE-81:Gi2") {
		t.Fatalf("tenant reader got %q", got)
	}
	// Even asking about another tenant's object, a tenant reader never gets
	// that tenant's names (its visible set has none of them).
	if got := s.callerDeviceNames(alice, "t_b").Text(twoTenantText); got != twoTenantText {
		t.Fatalf("a tenant reader must never resolve another tenant's names, got %q", got)
	}

	// The platform owner reading tenant t_a's case: narrowed to t_a, so t_b's
	// device is not named inside t_a's document.
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if got := s.callerDeviceNames(owner, "t_a").Text(twoTenantText); strings.Contains(got, "vEdge-51") || !strings.Contains(got, "cEDGE-81") {
		t.Fatalf("cross-tenant reader of t_a's case got %q", got)
	}
}

func TestRCADocumentHTMLNamesDevicesInTextOnly(t *testing.T) {
	s := seedTwoTenantDevices(t)
	doc := []byte(`<h1>Link down on cedge-81-dde8d64d:Gi2</h1><a href="#/devices/cedge-81-dde8d64d">cedge-81-dde8d64d</a>`)
	got := string(s.tenantDeviceNames("t_a").HTML(doc))
	want := `<h1>Link down on cEDGE-81:Gi2</h1><a href="#/devices/cedge-81-dde8d64d">cEDGE-81</a>`
	if got != want {
		t.Fatalf("html:\n got %s\nwant %s", got, want)
	}
}

func TestTicketPayloadNamesDevicesAndKeepsItsIDs(t *testing.T) {
	s := seedTwoTenantDevices(t)
	p := ticketing.Payload{
		CorrObjectID:     "corr-1",
		Title:            "Confirmed link down on cedge-81-dde8d64d:Gi2",
		Summary:          "cedge-81-dde8d64d Gi2 went down",
		AffectedScope:    "cedge-81-dde8d64d:Gi2",
		AffectedEntities: []string{"cedge-81-dde8d64d", "vedge-51-79fbba30"},
		EvidenceUsed:     []string{"syslog on cedge-81-dde8d64d"},
		RCAURL:           "https://c.example/#/investigate/rca/corr-1?device=cedge-81-dde8d64d",
		Signature:        "link_down",
	}
	got := p.WithOperatorText(s.tenantDeviceNames("t_a").Text)
	if got.Title != "Confirmed link down on cEDGE-81:Gi2" || got.Summary != "cEDGE-81 Gi2 went down" ||
		got.AffectedScope != "cEDGE-81:Gi2" || got.EvidenceUsed[0] != "syslog on cEDGE-81" {
		t.Fatalf("operator text not named: %+v", got)
	}
	if got.AffectedEntities[1] != "vedge-51-79fbba30" {
		t.Fatalf("another tenant's device must never be named in t_a's ticket, got %q", got.AffectedEntities[1])
	}
	if got.CorrObjectID != p.CorrObjectID || got.RCAURL != p.RCAURL || got.Signature != p.Signature {
		t.Fatalf("machine fields must be untouched: %+v", got)
	}
	if p.AffectedEntities[0] != "cedge-81-dde8d64d" {
		t.Fatal("WithOperatorText must not mutate the original payload's slices")
	}
}

func TestIrisAnswerNamesDevicesForTheAsker(t *testing.T) {
	s := seedTwoTenantDevices(t)
	ans := ai.Answer{
		Text:        "cedge-81-dde8d64d:Gi2 is down; vedge-51-79fbba30 is fine",
		NextActions: []string{"Check optics on cedge-81-dde8d64d"},
		Problem:     &ai.ProblemExplanation{ProblemID: "corr-1", Title: "Link down on cedge-81-dde8d64d"},
		Citations:   []ai.Citation{},
	}
	alice := jwtClaims{Sub: "alice", Role: "operator", Tenant: "t_a"}
	ans.RewriteOperatorText(s.callerDeviceNames(alice, "").Text)
	if ans.Text != "cEDGE-81:Gi2 is down; vedge-51-79fbba30 is fine" {
		t.Fatalf("Text = %q (own device named, another tenant's id never named)", ans.Text)
	}
	if ans.NextActions[0] != "Check optics on cEDGE-81" || ans.Problem.Title != "Link down on cEDGE-81" || ans.Problem.ProblemID != "corr-1" {
		t.Fatalf("answer = %+v / problem %+v", ans, ans.Problem)
	}
}
