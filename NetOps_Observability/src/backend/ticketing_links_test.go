// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"netops/backend/internal/ticketing"
	"testing"
)

// ticketing_links_test.go — cross-tenant isolation for the UX-1 "notified via"
// read (GET /api/tickets/links) through the real router + auth middleware
// (CLAUDE.md §3a), plus the multi-destination projection of
// GET /api/correlations/{id}/tickets (ServiceNow + PagerDuty + Slack — the
// Slack blind spot fix).

const (
	tktLinksCorrA1 = "aaaaaaaa-1111-4111-8111-111111111111"
	tktLinksCorrA2 = "aaaaaaaa-2222-4222-8222-222222222222"
	tktLinksCorrB1 = "bbbbbbbb-1111-4111-8111-111111111111"
)

func TestTicketLinksAPI_TenantIsolation(t *testing.T) {
	srv, s, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	ctx := context.Background()

	seed := []ticketing.Link{
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC0000001", SysID: "sysA1"},
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "slack", Status: "open", TicketNumber: "corrA1"},
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA2, ExternalSystem: "pagerduty", Status: "resolved", TicketNumber: "corrA2"},
		{TenantID: b.tenantID, CorrObjectID: tktLinksCorrB1, ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC0000009", SysID: "sysB1"},
	}
	for _, l := range seed {
		if err := s.ticketing.PutLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	type linkRow struct {
		CorrObjectID string `json:"corr_object_id"`
		System       string `json:"system"`
		State        string `json:"state"`
		TicketNumber string `json:"ticket_number"`
	}
	fetch := func(token string) []linkRow {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/tickets/links", token, nil)
		if st != 200 {
			t.Fatalf("GET /api/tickets/links: %d %s", st, body)
		}
		var out struct {
			Links []linkRow `json:"links"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out.Links
	}

	// A sees ONLY its own three links — B's corr id must never appear.
	aLinks := fetch(a.token)
	if len(aLinks) != 3 {
		t.Fatalf("A links = %d (%+v), want 3", len(aLinks), aLinks)
	}
	for _, l := range aLinks {
		if l.CorrObjectID == tktLinksCorrB1 {
			t.Fatalf("A's link list leaked B's correlation: %+v", l)
		}
		if l.CorrObjectID == "" || l.System == "" || l.State == "" {
			t.Fatalf("link row missing join fields: %+v", l)
		}
	}

	// B sees only its single link.
	bLinks := fetch(b.token)
	if len(bLinks) != 1 || bLinks[0].CorrObjectID != tktLinksCorrB1 {
		t.Fatalf("B links = %+v, want exactly its own", bLinks)
	}

	// The cross-tenant platform owner sees every tenant's links.
	adminLinks := fetch(admin)
	if len(adminLinks) < 4 {
		t.Fatalf("cross-tenant owner sees %d links, want >= 4", len(adminLinks))
	}
}

// TestCorrelationTickets_DestinationsAllSystems pins the Slack blind spot fix:
// the per-correlation ticket read must surface EVERY policy destination the
// object was filed to, in ticketing.TicketSystems order, while the legacy status /
// pagerduty keys keep working for older clients.
func TestCorrelationTickets_DestinationsAllSystems(t *testing.T) {
	srv, s, fix := setupTicketingTenants(t)
	a := fix["A"]
	ctx := context.Background()

	for _, l := range []ticketing.Link{
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "servicenow", Status: "open", TicketNumber: "INC0000042", SysID: "sys42"},
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "pagerduty", Status: "resolved", TicketNumber: "corrA1"},
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "slack", Status: "open", TicketNumber: "corrA1"},
		{TenantID: a.tenantID, CorrObjectID: tktLinksCorrA1, ExternalSystem: "jira", Status: "open", TicketNumber: "NOC-42", SysID: "10042"},
	} {
		if err := s.ticketing.PutLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	st, body := do(t, srv, "GET", "/api/correlations/"+tktLinksCorrA1+"/tickets", a.token, nil)
	if st != 200 {
		t.Fatalf("GET tickets: %d %s", st, body)
	}
	var out struct {
		Status       map[string]any   `json:"status"`
		PagerDuty    map[string]any   `json:"pagerduty"`
		Destinations []map[string]any `json:"destinations"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Destinations) != len(ticketing.TicketSystems) {
		t.Fatalf("destinations = %d (%+v), want all %d systems", len(out.Destinations), out.Destinations, len(ticketing.TicketSystems))
	}
	for i, want := range ticketing.TicketSystems { // servicenow, pagerduty, slack, jira
		if got := out.Destinations[i]["system"]; got != want {
			t.Fatalf("destinations[%d].system = %v, want %s", i, got, want)
		}
	}
	// Back-compat keys unchanged.
	if out.Status["ticket_number"] != "INC0000042" || out.Status["system"] != "servicenow" {
		t.Fatalf("legacy status key broken: %v", out.Status)
	}
	if out.PagerDuty == nil || out.PagerDuty["state"] != "resolved" {
		t.Fatalf("legacy pagerduty key broken: %v", out.PagerDuty)
	}

	// The other tenant's read of the same id shows nothing (no leak).
	st, body = do(t, srv, "GET", "/api/correlations/"+tktLinksCorrA1+"/tickets", fix["B"].token, nil)
	if st != 200 {
		t.Fatalf("B GET tickets: %d %s", st, body)
	}
	out = struct {
		Status       map[string]any   `json:"status"`
		PagerDuty    map[string]any   `json:"pagerduty"`
		Destinations []map[string]any `json:"destinations"`
	}{}
	_ = json.Unmarshal(body, &out)
	if len(out.Destinations) != 0 || out.Status["state"] != "not_created" {
		t.Fatalf("B sees A's destinations: %v / %v", out.Destinations, out.Status)
	}
}
