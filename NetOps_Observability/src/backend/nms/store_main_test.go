package nms

import (
	"context"
	"testing"
	"time"
)

// memNMSStore enforces tenant scoping IN the store (§3a: in-memory stores have
// no RLS backstop, so the store itself is the gate).
func TestMemNMSStoreTenantScoping(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	for _, c := range []Integration{
		{Tenant: "t-a", ID: "i-a", Vendor: "generic", Enabled: true, WebhookToken: "tok-a"},
		{Tenant: "t-b", ID: "i-b", Vendor: "generic", Enabled: false},
	} {
		if err := st.Upsert(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	if got, _ := st.List(ctx, "t-a", false); len(got) != 1 || got[0].ID != "i-a" {
		t.Fatalf("t-a list: %+v", got)
	}
	if got, _ := st.List(ctx, "", true); len(got) != 2 {
		t.Fatalf("cross list: %+v", got)
	}
	// Cross-tenant get by id: not found (indistinguishable from absent).
	if _, found, _ := st.Get(ctx, "t-a", false, "i-b"); found {
		t.Fatal("t-a must not see t-b's integration")
	}
	// Cross-tenant delete: no-op.
	if deleted, _ := st.Delete(ctx, "t-a", false, "i-b"); deleted {
		t.Fatal("t-a must not delete t-b's integration")
	}
	if _, found, _ := st.Get(ctx, "t-b", false, "i-b"); !found {
		t.Fatal("t-b's integration must survive")
	}
	// Scheduler work list = enabled only, all tenants.
	if got, _ := st.ListEnabled(ctx); len(got) != 1 || got[0].ID != "i-a" {
		t.Fatalf("enabled: %+v", got)
	}
	// Webhook token resolves regardless of tenant (platform-scope lookup).
	if ic, found, _ := st.ByWebhookToken(ctx, "tok-a"); !found || ic.Tenant != "t-a" {
		t.Fatalf("token lookup: %+v found=%v", ic, found)
	}
	if _, found, _ := st.ByWebhookToken(ctx, ""); found {
		t.Fatal("empty token must never match")
	}
}

func TestCredsFromFields(t *testing.T) {
	c := credsFromFields(map[string]string{
		"api_key": "k", "username": "u", "password": "p", "token": "t",
		"client_id": "ci", "client_secret": "cs",
		"org": "o-1", "webhook_secret": "wh",
	})
	if c.APIKey != "k" || c.Username != "u" || c.Password != "p" || c.Token != "t" ||
		c.ClientID != "ci" || c.ClientSecret != "cs" {
		t.Fatalf("known fields wrong: %+v", c)
	}
	if c.Extra["org"] != "o-1" || c.Extra["webhook_secret"] != "wh" {
		t.Fatalf("extra fields wrong: %+v", c.Extra)
	}
}

func TestMemNMSStoreHealthRollup(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	if err := st.Upsert(ctx, Integration{Tenant: "t-a", ID: "i-a", Vendor: "generic"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = st.RecordRun(ctx, RunRecord{Tenant: "t-a", IntegrationID: "i-a", RunID: "r1", Started: now, Finished: now, Status: "ok", Events: 5})
	_ = st.RecordRun(ctx, RunRecord{Tenant: "t-a", IntegrationID: "i-a", RunID: "r2", Started: now, Finished: now, Status: "error", Error: "boom"})

	h, found, _ := st.Health(ctx, "t-a", false, "i-a")
	if !found {
		t.Fatal("health for existing integration")
	}
	if h.Healthy || h.LastError != "boom" || h.EventsIngested != 5 || h.ErrorRate != 0.5 {
		t.Fatalf("rollup wrong: %+v", h)
	}
	if len(h.Runs) != 2 || h.Runs[0].RunID != "r2" {
		t.Fatalf("runs (newest first) wrong: %+v", h.Runs)
	}
	// Cross-tenant health read: not found.
	if _, found, _ := st.Health(ctx, "t-b", false, "i-a"); found {
		t.Fatal("t-b must not read t-a's health")
	}
}

// State changes persist through the store seam the scheduler drives.
func TestMemNMSStoreStateUpsert(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	recs := []StateRecord{{
		EntityKey: "dev1|tunnel|t1", StateKind: "tunnel", CurrentState: "down",
		PreviousState: "up", FlapCount: 1, DeviceID: "dev1",
	}}
	if err := st.UpsertStates(ctx, "t-a", "i-a", recs); err != nil {
		t.Fatal(err)
	}
	if len(st.states) != 1 {
		t.Fatalf("state not stored: %+v", st.states)
	}
}
