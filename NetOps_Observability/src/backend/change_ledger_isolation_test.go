// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// change_ledger_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// the change ledger's producers (Iris N-D2), through the REAL router, auth
// middleware and audit middleware, plus the N-D1 proof that the Iris NL change
// read pushes every filter into the store.
//
// Proven here:
//   - an allowed mutation whose handler names its target lands in the ACTING
//     tenant's ledger only, with the target object recorded — own-only list;
//   - another org's attempt on the same device is a 404 and records nothing in
//     either ledger;
//   - the platform owner's action on a tenant's device is NOT written into that
//     tenant's ledger (owner actions stay out of tenant feeds);
//   - the ledger's `/api/dem/changes` read and the Iris NL read both stay
//     own-tenant;
//   - an actor filter reaches rows far past the fetch bound (it is applied in
//     the store, not after the limit).

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/changeledger"
	"netops/backend/internal/dem/experience"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/models"
)

func TestChangeLedgerAuditIsolation(t *testing.T) {
	srv, s, a, b := experienceFixtures(t)
	dir := t.TempDir()
	var err error
	if s.sites, err = newSitesStore(filepath.Join(dir, "sites.json")); err != nil {
		t.Fatal(err)
	}
	if s.deviceSites, err = newDeviceSiteStore(filepath.Join(dir, "device_sites.json")); err != nil {
		t.Fatal(err)
	}
	// The producers write into the fixture's ledger, and the worker drains the
	// audit queue exactly as the "change-ledger" worker does in production.
	s.changeLedger, err = changeledger.New(changeledger.Deps{
		Sink: s.experienceStore, Directory: changeLedgerDirectory{users: s.users},
		LogWarn: func(m string, f map[string]any) { t.Logf("change.ledger: %s %v", m, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.changeLedger.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	slugs := map[*orgFixture]string{}
	for name, f := range map[string]*orgFixture{"A": a, "B": b} {
		code, body := do(t, srv, "POST", "/api/sites", f.token, map[string]any{"name": "Ledger Site " + name})
		if code != 200 {
			t.Fatalf("create site %s: %d %s", name, code, body)
		}
		var saved struct {
			Slug string `json:"slug"`
		}
		if err := json.Unmarshal(body, &saved); err != nil || saved.Slug == "" {
			t.Fatalf("site %s: %s", name, body)
		}
		slugs[f] = saved.Slug
		if err := s.discovery.Upsert(models.Device{ID: "ledger-dev-" + name, Name: "ledger-dev-" + name,
			Address: "10.9.0." + map[string]string{"A": "1", "B": "2"}[name], TenantID: f.tenantID, Source: "manual"}); err != nil {
			t.Fatal(err)
		}
	}

	list := func(token string) []experience.ChangeEvent {
		t.Helper()
		code, body := do(t, srv, "GET", "/api/dem/changes?window=24h", token, nil)
		if code != 200 {
			t.Fatalf("GET /api/dem/changes: %d %s", code, body)
		}
		var resp struct {
			Changes []experience.ChangeEvent `json:"changes"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v %s", err, body)
		}
		return resp.Changes
	}
	waitFor := func(token string, n int) []experience.ChangeEvent {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got := list(token)
			if len(got) >= n || time.Now().After(deadline) {
				return got
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// A binds its own device to its own site: an allowed mutation with a target.
	if code, body := do(t, srv, "PUT", "/api/devices/ledger-dev-A/site", a.token, map[string]any{"site": slugs[a]}); code != 200 {
		t.Fatalf("A bind: %d %s", code, body)
	}
	got := waitFor(a.token, 1)
	if len(got) != 1 {
		t.Fatalf("A's ledger holds %d changes after one targeted mutation, want 1: %+v", len(got), got)
	}
	ch := got[0]
	if ch.Object != "ledger-dev-A" || ch.ObjectKind != "device" || ch.SourceSystem != experience.SourceSystemAudit ||
		ch.TenantID != a.tenantID || ch.Site != slugs[a] {
		t.Fatalf("the audited change does not record its target: %+v", ch)
	}
	if ch.ActorType != experience.ChangeActorUser || ch.ActorDisplay != a.user {
		t.Fatalf("the actor was not normalized to A's operator: type=%q id=%q display=%q", ch.ActorType, ch.ActorID, ch.ActorDisplay)
	}

	// B attacks A's device: 404, and NOTHING is recorded anywhere.
	if code, _ := do(t, srv, "PUT", "/api/devices/ledger-dev-A/site", b.token, map[string]any{"site": slugs[b]}); code != 404 {
		t.Fatalf("B bound A's device: %d", code)
	}
	if code, _ := do(t, srv, "DELETE", "/api/devices/ledger-dev-A", b.token, nil); code != 404 {
		t.Fatalf("B deleted A's device: %d", code)
	}
	// The platform owner acts on A's device: allowed, but a platform-scope
	// action is not written into a tenant's ledger.
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if code, body := do(t, srv, "DELETE", "/api/devices/ledger-dev-A/site", admin, nil); code != 200 {
		t.Fatalf("owner unbind: %d %s", code, body)
	}
	// B makes its own targeted change, so there is a later write to wait on.
	if code, body := do(t, srv, "PUT", "/api/devices/ledger-dev-B/site", b.token, map[string]any{"site": slugs[b]}); code != 200 {
		t.Fatalf("B bind own: %d %s", code, body)
	}
	bRows := waitFor(b.token, 1)
	if len(bRows) != 1 || bRows[0].Object != "ledger-dev-B" || bRows[0].TenantID != b.tenantID {
		t.Fatalf("B's ledger = %+v, want exactly its own change", bRows)
	}
	aRows := list(a.token)
	if len(aRows) != 1 || aRows[0].ID != ch.ID {
		t.Fatalf("A's ledger changed after B's 404s and the owner's action: %+v", aRows)
	}
	if n := s.changeLedger.Metrics().Count(changeledger.ProducerAudit, changeledger.OutcomeSkipped); n < 1 {
		t.Fatalf("the owner's action was not counted as skipped (skipped=%d)", n)
	}

	// The Iris NL read is own-tenant too, and by actor it finds A's change for
	// A and nothing for B.
	claimsA := jwtClaims{Sub: ch.ActorID, Tenant: a.tenantID, Role: "operator"}
	claimsB := jwtClaims{Sub: "someone", Tenant: b.tenantID, Role: "operator"}
	from := time.Now().Add(-time.Hour)
	q := plan.ChangeQuery{From: from, Actors: []string{a.user}, Limit: 10}
	rowsA, _, err := s.nlqScopeFor(newAITestRequest(t, claimsA), claimsA).Changes(context.Background(), q)
	if err != nil || len(rowsA) != 1 || rowsA[0].Object != "ledger-dev-A" || rowsA[0].Source != experience.SourceSystemAudit {
		t.Fatalf("A's NL change read by actor = %+v (err %v)", rowsA, err)
	}
	rowsB, _, err := s.nlqScopeFor(newAITestRequest(t, claimsB), claimsB).Changes(context.Background(), q)
	if err != nil || len(rowsB) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: B's NL read by A's actor = %+v (err %v)", rowsB, err)
	}
}

// The Iris NL change read pushes every filter into the store: an actor whose
// only change sits behind more than a full fetch of newer noise is still found,
// and the answer is not marked truncated.
func TestNLQChangesPushFiltersIntoTheStore(t *testing.T) {
	s, a, bClaims := nlqFixture(t)
	s.experienceStore = experience.NewFileStore("")
	ctx := context.Background()
	now := time.Now().UTC()
	rec := func(tenant, id, actor, object string, at time.Time) {
		t.Helper()
		if _, err := s.experienceStore.RecordChange(ctx, experience.ChangeEvent{
			TenantID: tenant, ID: id, Type: experience.ChangeNetwork, Actor: actor,
			Object: object, ObjectKind: "device", Summary: "change " + id, Site: "dfw-hq",
			Provenance: experience.Provenance{Source: experience.SourceManual, EventAt: at,
				Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata},
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	for i := 0; i < nlqChangeFetch+50; i++ {
		rec(a.Tenant, fmt.Sprintf("chg-%032x", i+1), "noise-bot", "dev-a", now.Add(-time.Duration(i)*time.Second))
	}
	target := fmt.Sprintf("chg-%032x", 999999)
	rec(a.Tenant, target, "John Smith", "dev-a", now.Add(-2*time.Hour))
	rec(bClaims.Tenant, fmt.Sprintf("chg-%032x", 888888), "John Smith", "dev-b", now.Add(-2*time.Hour))

	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	q := plan.ChangeQuery{From: now.Add(-3 * time.Hour), Actors: []string{"john smith"}, Limit: 10}
	rows, truncated, err := h.Changes(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != target || truncated {
		t.Fatalf("actor filter found %+v (truncated=%v) — it must be applied before the fetch bound, and never cross tenants", rows, truncated)
	}
	// Until / Objects / Sources / ExcludeIDs reach the store the same way.
	for name, q := range map[string]plan.ChangeQuery{
		"until":    {From: now.Add(-3 * time.Hour), To: now.Add(-90 * time.Minute), Limit: 10},
		"object":   {From: now.Add(-3 * time.Hour), Objects: []string{"dev-a"}, Actors: []string{"John Smith"}, Limit: 10},
		"source":   {From: now.Add(-3 * time.Hour), Sources: []string{"ledger"}, Actors: []string{"John Smith"}, Limit: 10},
		"excluded": {From: now.Add(-3 * time.Hour), Actors: []string{"John Smith"}, ExcludeIDs: []string{target}, Limit: 10},
	} {
		rows, _, err := h.Changes(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := 1
		if name == "excluded" {
			want = 0
		}
		if len(rows) != want || (want == 1 && rows[0].ID != target) {
			t.Errorf("%s: got %+v, want %d row(s)", name, rows, want)
		}
	}
	// A bounded read that DOES hit the limit says so.
	if rows, truncated, err := h.Changes(ctx, plan.ChangeQuery{From: now.Add(-3 * time.Hour), Limit: 5}); err != nil || len(rows) != 5 || !truncated {
		t.Fatalf("an unfiltered read of 5 = %d rows, truncated=%v, err=%v", len(rows), truncated, err)
	}
}
