// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alert_episodes_isolation_test.go — §3a cross-org isolation guard for the
// alert-episode surface, exercised through the REAL router + auth middleware
// (org_isolation_test.go template): own-only list, cross-tenant triage → 404
// (id existence never revealed), acting-tenant override into another org
// ignored, platform owner sees all.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/models"
)

func TestAlertEpisodeCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	store := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	store.SetNowForTest(func() time.Time { return time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC) })
	s.alertEpisodes = store

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── orgs A and B, each: org → tenant → tenant-scoped operator ────────────────
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "ep-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// One device per tenant; the engine adapter derives each episode's tenant
	// from its DEVICE (never from any payload).
	s.discovery.Upsert(models.Device{ID: "dev-a", Name: "dev-a", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "dev-b", Name: "dev-b", TenantID: b.tenantID})
	s.observeAlertTransition(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: "dev-a", Summary: "A cpu"}, true)
	s.observeAlertTransition(models.Alert{Rule: "HighCPU", Severity: "critical", DeviceID: "dev-b", Summary: "B cpu"}, true)
	s.observeAlertTransition(models.Alert{Rule: "StackDisk", Severity: "warning", Summary: "platform disk"}, true)

	type listResp struct {
		Episodes []AlertEpisode `json:"episodes"`
		Total    int            `json:"total"`
	}
	list := func(token string) listResp {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/alerts/episodes", token, nil)
		if st != 200 {
			t.Fatalf("list episodes: %d %s", st, body)
		}
		var lr listResp
		if err := json.Unmarshal(body, &lr); err != nil {
			t.Fatal(err)
		}
		return lr
	}

	// ── own-only list: A sees its own episode + the platform (device-less) one,
	// and NEVER org B's. ─────────────────────────────────────────────────────────
	var aEpisodeID, bEpisodeID string
	lrA := list(a.token)
	for _, ep := range lrA.Episodes {
		switch ep.Resource {
		case "dev-a":
			aEpisodeID = ep.ID
		case "dev-b":
			t.Fatalf("TENANT LEAK: org-A user listed org-B's episode: %+v", ep)
		}
	}
	if aEpisodeID == "" {
		t.Fatalf("org-A user must see its own episode: %+v", lrA.Episodes)
	}
	for _, ep := range list(admin).Episodes { // platform owner sees all three
		if ep.Resource == "dev-b" {
			bEpisodeID = ep.ID
		}
	}
	if bEpisodeID == "" || len(list(admin).Episodes) != 3 {
		t.Fatalf("platform owner must see all episodes: %+v", list(admin).Episodes)
	}

	// ── cross-tenant triage → 404, and B's episode is untouched ─────────────────
	for _, action := range []string{"ack", "assign", "mute", "snooze", "notes"} {
		payload := map[string]any{"assignee": "x", "text": "hi", "until": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		st, body := do(t, srv, "POST", "/api/alerts/episodes/"+bEpisodeID+"/"+action, a.token, payload)
		if st != http.StatusNotFound {
			t.Fatalf("cross-tenant %s must 404 (existence hidden), got %d %s", action, st, body)
		}
	}
	for _, ep := range list(admin).Episodes {
		if ep.Resource == "dev-b" && (ep.AcknowledgedBy != "" || ep.AssignedTo != "" || ep.Muted || ep.SnoozedUntil != nil || len(ep.Notes) != 0) {
			t.Fatalf("cross-tenant triage must not mutate: %+v", ep)
		}
	}

	// ── platform (device-less) episodes are visible to a scoped caller but
	// triage-able only by the platform owner ─────────────────────────────────────
	var platformID string
	for _, ep := range lrA.Episodes {
		if ep.Resource == "" {
			platformID = ep.ID
		}
	}
	if platformID == "" {
		t.Fatalf("scoped caller must still SEE device-less stack episodes: %+v", lrA.Episodes)
	}
	if st, _ := do(t, srv, "POST", "/api/alerts/episodes/"+platformID+"/ack", a.token, map[string]any{}); st != http.StatusNotFound {
		t.Fatalf("scoped caller must not triage a platform episode: %d", st)
	}

	// ── acting-tenant override into another org is ignored for a non-owner ──────
	{
		bts, _ := json.Marshal(map[string]any{})
		httpReq, err := http.NewRequest("POST", srv.URL+"/api/alerts/episodes/"+bEpisodeID+"/ack", bytes.NewReader(bts))
		if err != nil {
			t.Fatal(err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+a.token)
		httpReq.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("acting-tenant override must not widen a scoped caller: %d", resp.StatusCode)
		}
	}

	// ── own-tenant triage works and stamps the PRINCIPAL ────────────────────────
	st, body := do(t, srv, "POST", "/api/alerts/episodes/"+aEpisodeID+"/ack", a.token, map[string]any{"acknowledged": true})
	if st != 200 {
		t.Fatalf("own-tenant ack: %d %s", st, body)
	}
	var got AlertEpisode
	if err := json.Unmarshal(body, &got); err != nil || got.AcknowledgedBy != a.user {
		t.Fatalf("actor must be the authenticated principal: %s", body)
	}
}
