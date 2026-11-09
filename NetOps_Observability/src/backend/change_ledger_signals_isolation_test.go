// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// change_ledger_signals_isolation_test.go — CLAUDE.md §3a rule 5 for the bridged
// change producers (Iris N-D2). A row is stamped with the corr_signals tenant_id
// column, never a tenant the signal's text claims, and the result is read back
// through the real /api/changes handler: own-only list, another tenant's id 404,
// an as_tenant walk changes nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/changeapi"
	"netops/backend/internal/changeledger"
	"netops/backend/internal/changesignals"
	"netops/backend/internal/dem/experience"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/platformdb"
)

func signalRow(tenant, source, kind, entity, attrs string, at time.Time) map[string]any {
	ts := at.UTC().Format("2006-01-02T15:04:05.000Z")
	return map[string]any{"tenant_id_s": tenant, "signal_id_s": "aaaaaaaa-0000-0000-0000-" + strings.Repeat("0", 11) + string(rune('a'+len(tenant)%26)),
		"ts_s": ts, "ingest_ts_s": ts, "source_s": source, "kind_s": kind, "entity_type_s": "device", "entity_id_s": entity,
		"site_s": "", "metric_name_s": "device_config_change", "attrs_s": attrs}
}

func bridgeWith(t *testing.T, sink changeledger.Sink, rows []changeledger.SignalChange) *changeledger.Bridge {
	t.Helper()
	warn := func(string, map[string]any) {}
	p, err := changeledger.New(changeledger.Deps{Sink: sink, LogWarn: warn})
	if err != nil {
		t.Fatal(err)
	}
	b, err := changeledger.NewBridge(changeledger.BridgeDeps{Producer: p, LogWarn: warn,
		Read: func(_ context.Context, pg changeledger.SignalPage) ([]changeledger.SignalChange, error) {
			if pg.AfterID != "" {
				return nil, nil
			}
			return rows, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBridgedChangesAreStampedFromTheRowAndTenantIsolated(t *testing.T) {
	s, a, b := nlqAPIFixture(t)
	s.experienceStore = experience.NewFileStore("")
	now := time.Now().UTC().Add(-time.Minute)

	// B's device text claims A's tenant: the column wins, and A never sees it.
	aRow, err := changesignals.FromRow(signalRow(a.Tenant, "trap", changeledger.KindDeviceConfigChange, "dev-a",
		`{"user":"alice","source":"commandline"}`, now), nil)
	if err != nil {
		t.Fatal(err)
	}
	bRow, err := changesignals.FromRow(signalRow(b.Tenant, "trap", changeledger.KindDeviceConfigChange, "dev-b",
		`{"user":"bob","tenant_id":"`+a.Tenant+`","tenant":"`+a.Tenant+`"}`, now), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridgeWith(t, s.experienceStore, []changeledger.SignalChange{aRow, bRow}).Pass(context.Background()); err != nil {
		t.Fatal(err)
	}

	list := func(c jwtClaims) ([]map[string]any, string) {
		t.Helper()
		code, out := changeAPICall(t, s, c, "/api/changes?source=device_trap")
		if code != http.StatusOK {
			t.Fatalf("list: %d %v", code, out)
		}
		raw, _ := out["changes"].([]any)
		rows := make([]map[string]any, 0, len(raw))
		for _, r := range raw {
			if m, ok := r.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
		return rows, nlqJSON(out)
	}
	aRows, aBody := list(a)
	if len(aRows) != 1 || aRows[0]["object"] != "dev-a" || strings.Contains(aBody, "dev-b") {
		t.Fatalf("TENANT LEAK or missing row in A's list: %s", aBody)
	}
	bRows, bBody := list(b)
	if len(bRows) != 1 || bRows[0]["object"] != "dev-b" || strings.Contains(bBody, "dev-a") {
		t.Fatalf("TENANT LEAK or missing row in B's list: %s", bBody)
	}
	aID, ok := aRows[0]["id"].(string)
	if !ok || aID == "" {
		t.Fatalf("no id: %v", aRows[0])
	}

	walker := b
	walker.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": b, "as_tenant walk": walker} {
		for _, p := range []string{"/api/changes/" + aID, "/api/changes/" + aID + "/diff", "/api/changes/" + aID + "?as_tenant=" + a.Tenant} {
			if code, _ := changeAPICall(t, s, c, p); code != http.StatusNotFound {
				t.Errorf("%s %s: %d, want 404", name, p, code)
			}
		}
		if rows, body := list(c); len(rows) != 1 || strings.Contains(body, "dev-a") {
			t.Errorf("%s reached A's ledger: %s", name, body)
		}
	}
	if code, out := changeAPICall(t, s, a, "/api/changes/"+aID); code != http.StatusOK || out["source_system"] != "device_trap" {
		t.Fatalf("A's own change: %d %v", code, out)
	}
}

// The site lookup runs in the signal's own tenant, so another tenant's binding on
// a same-named device is never applied.
func TestWithDeviceSiteIgnoresCloudAndForeignBindings(t *testing.T) {
	s := newWanTestServer(t, nil, nil)
	if err := s.deviceSites.Set(DeviceSiteBinding{TenantID: "acme", DeviceID: "dev", Site: "acme-hq"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, tenant, source, want string }{
		{"the owner's manual binding wins over the signal's site", "acme", "trap", "acme-hq"},
		{"tenant case is normalized before the lookup", " ACME ", "trap", "acme-hq"},
		{"another tenant's binding on a same-named device is never applied", "globex", "trap", "from-signal"},
		{"a cloud signal is not a device", "acme", "cloud", "from-signal"},
	} {
		in := s.withDeviceSite(changeledger.SignalChange{Tenant: tc.tenant, Source: tc.source, Entity: "dev", Site: "from-signal"})
		if in.Site != tc.want {
			t.Errorf("%s: site %q, want %q", tc.name, in.Site, tc.want)
		}
	}
	// A Provider device's binding is stored under its blank device tenant; the
	// signal's column says "global". One owner, so the binding applies to both.
	if err := s.deviceSites.Set(DeviceSiteBinding{DeviceID: "core", Site: "noc-hq"}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "global", " GLOBAL "} {
		if in := s.withDeviceSite(changeledger.SignalChange{Tenant: tenant, Source: "trap", Entity: "core"}); in.Site != "noc-hq" {
			t.Errorf("Provider device, tenant %q: site %q", tenant, in.Site)
		}
	}
	if err := s.deviceSites.Set(DeviceSiteBinding{TenantID: "global", DeviceID: "core-2", Site: "noc-dr"}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"", "global"} {
		if in := s.withDeviceSite(changeledger.SignalChange{Tenant: tenant, Source: "trap", Entity: "core-2"}); in.Site != "noc-dr" {
			t.Errorf("binding stamped global, signal tenant %q: site %q", tenant, in.Site)
		}
	}
	if in := s.withDeviceSite(changeledger.SignalChange{Tenant: "acme", Source: "trap", Entity: "core"}); in.Site != "" {
		t.Errorf("a tenant must not take the Provider's binding: %q", in.Site)
	}
	bare := &server{} // no device→site store: the signal's own site stands
	if in := bare.withDeviceSite(changeledger.SignalChange{Tenant: "acme", Source: "trap", Entity: "dev", Site: "from-signal"}); in.Site != "from-signal" {
		t.Fatalf("no store: site %q", in.Site)
	}
}

// The bridge against a REAL Postgres as the non-superuser role FORCE RLS applies
// to: a replay is idempotent and neither tenant reads the other's row. Gated on
// DATABASE_URL_TEST, so it runs in the pg-integration leg.
func TestBridgedChangesRLSAndIdempotencePG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := experience.NewPGStore(ps.DB())
	suffix := strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-"))
	acme, globex := "acme-"+suffix, "globex-"+suffix
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	rows := []changeledger.SignalChange{
		{Tenant: acme, SignalID: "aaaaaaaa-1111-1111-1111-111111111111", At: now, Source: "trap",
			Kind: changeledger.KindDeviceConfigChange, Entity: "dev-a", User: "alice"},
		{Tenant: globex, SignalID: "bbbbbbbb-2222-2222-2222-222222222222", At: now, Source: "cloud",
			Kind: changeledger.KindCloudAudit, Entity: "sg-1", EntityType: "cloud_resource", RequestID: "evt-1", EventName: "Edit"},
	}
	for i := 0; i < 2; i++ { // the second bridge has an empty seen set: a restart replay
		if err := bridgeWith(t, st, rows).Pass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	q := experience.ChangeQuery{Since: now.Add(-time.Hour), Until: now.Add(time.Hour), Limit: 10}
	got, err := st.ListChanges(ctx, acme, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Object != "dev-a" || got[0].SourceSystem != changeledger.ProducerDeviceTrap || got[0].TenantID != acme {
		t.Fatalf("acme's ledger: %+v", got)
	}
	got, err = st.ListChanges(ctx, globex, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Object != "sg-1" || got[0].SourceSystem != changeledger.ProducerCloudAudit {
		t.Fatalf("globex's ledger: %+v", got)
	}
}

// ---- Provider-owned devices (owner decision 2026-11-09) ----------------------

// seedProviderChanges bridges three platform-shaped signals and one of tenant's
// own: "global" and "" are stamped with the Provider, "*" is refused. A cloud
// row names an application, so the NL application seeds have something to leak.
func seedProviderChanges(t *testing.T, sink experience.Store, tenant string) {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	var rows []changeledger.SignalChange
	for _, r := range []struct{ tenant, entity, attrs string }{
		{"global", "core-global", `{"user":"noc"}`},
		{"", "core-blank", `{"user":"noc","tenant_id":"` + tenant + `"}`}, // attrs never name the owner
		{"*", "core-star", `{"user":"noc"}`},
		{tenant, "dev-own", `{"user":"alice"}`},
	} {
		row, err := changesignals.FromRow(signalRow(r.tenant, "trap", changeledger.KindDeviceConfigChange, r.entity, r.attrs, now), nil)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := bridgeWith(t, sink, rows).Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []experience.ChangeEvent{
		{TenantID: "global", ID: "chg-provider-app", Type: experience.ChangeCloud, Object: "core-cloud", App: "provider-app", Summary: "provider cloud change"},
		{TenantID: tenant, ID: "chg-own-app", Type: experience.ChangeCloud, Object: "own-cloud", App: "own-app", Summary: "own cloud change"},
	} {
		c.Provenance = experience.Provenance{Source: experience.SourceCloud, EventAt: now,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata}
		if _, err := sink.RecordChange(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
}

// changeRowsByObject maps /api/changes rows to object → change id.
func changeRowsByObject(out map[string]any) map[string]string {
	got := map[string]string{}
	raw, _ := out["changes"].([]any)
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			obj, _ := m["object"].(string)
			id, _ := m["id"].(string)
			got[obj] = id
		}
	}
	return got
}

func hasProviderObject(body string) bool {
	return strings.Contains(body, "core-global") || strings.Contains(body, "core-blank") || strings.Contains(body, "core-cloud")
}

// Every ledger read outside the DEM routes, as each kind of caller. Who holds
// isPlatformOwner reads the Provider's rows; a NON-owner in the global tenant
// resolves to the same ("global", false) and must get nothing.
func TestProviderChangesReachOnlyThePlatformOwner(t *testing.T) {
	s, a, b := nlqAPIFixture(t)
	s.experienceStore = experience.NewFileStore("")
	seedProviderChanges(t, s.experienceStore, a.Tenant)
	ctx := context.Background()
	q := plan.ChangeQuery{From: time.Now().Add(-time.Hour), Limit: 50}

	platform := jwtClaims{Sub: "root", Tenant: "global", Role: "admin"}
	provider := platform
	provider.ActingTenant = "global"
	code, out := changeAPICall(t, s, platform, "/api/changes")
	objects := changeRowsByObject(out)
	if code != http.StatusOK || objects["core-global"] == "" || objects["core-blank"] == "" || objects["core-cloud"] == "" {
		t.Fatalf("the Global view must read the Provider's rows: %d %v", code, out)
	}
	if out["note"] != changeapi.CrossNote {
		t.Fatalf("the Global view must say what it shows: %v", out["note"])
	}
	if _, star := objects["core-star"]; star {
		t.Fatalf("a wildcard signal was stamped: %v", objects)
	}
	if _, own := objects["dev-own"]; own {
		t.Fatalf("the Global view reads the Provider's ledger, not a union: %v", objects)
	}
	providerID := objects["core-global"]

	for name, c := range map[string]jwtClaims{"Global view": platform, "scoped to Provider": provider} {
		code, out := changeAPICall(t, s, c, "/api/changes")
		if code != http.StatusOK || changeRowsByObject(out)["core-global"] != providerID {
			t.Errorf("%s list: %d %v", name, code, out)
		}
		for _, p := range []string{"/api/changes/" + providerID, "/api/changes/" + providerID + "/diff"} {
			if code, out := changeAPICall(t, s, c, p); code != http.StatusOK {
				t.Errorf("%s %s: %d %v", name, p, code, out)
			}
		}
		rows, _, err := s.nlqScopeFor(newAITestRequest(t, c), c).Changes(ctx, q)
		if err != nil || !strings.Contains(nlqJSON(map[string]any{"rows": rows}), "core-global") {
			t.Errorf("%s NL read: %+v %v", name, rows, err)
		}
		seeds, err := s.nlqScopeFor(newAITestRequest(t, c), c).appSeeds(ctx)
		if err != nil || !strings.Contains(nlqJSON(map[string]any{"seeds": seeds}), "provider-app") {
			t.Errorf("%s NL application seeds: %+v %v", name, seeds, err)
		}
	}

	walkA, walkB := a, b
	walkA.ActingTenant, walkB.ActingTenant = "global", "global"
	member := jwtClaims{Sub: "ldap-user", Tenant: "global", Role: "operator"}
	memberWalk := member
	memberWalk.ActingTenant = "global"
	ownerInA := platform
	ownerInA.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{
		"tenant A": a, "tenant B": b, "A walking into Provider": walkA, "B walking into Provider": walkB,
		"non-owner in the global tenant": member, "the same, walking": memberWalk,
		"no tenant at all": {Sub: "nobody", Role: "operator"}, "the platform owner scoped to A": ownerInA,
	} {
		code, out := changeAPICall(t, s, c, "/api/changes")
		if body := nlqJSON(out); code != http.StatusOK || hasProviderObject(body) {
			t.Errorf("CROSS-TENANT LEAK: %s list: %d %s", name, code, body)
		}
		for _, p := range []string{"/api/changes/" + providerID, "/api/changes/" + providerID + "/diff", "/api/changes/" + providerID + "?as_tenant=global"} {
			if code, _ := changeAPICall(t, s, c, p); code != http.StatusNotFound {
				t.Errorf("CROSS-TENANT LEAK: %s %s: %d, want 404", name, p, code)
			}
		}
		rows, _, err := s.nlqScopeFor(newAITestRequest(t, c), c).Changes(ctx, q)
		if body := nlqJSON(map[string]any{"rows": rows}); err != nil || hasProviderObject(body) {
			t.Errorf("CROSS-TENANT LEAK: %s NL read: %s %v", name, body, err)
		}
		seeds, err := s.nlqScopeFor(newAITestRequest(t, c), c).appSeeds(ctx)
		if body := nlqJSON(map[string]any{"seeds": seeds}); err != nil || strings.Contains(body, "provider-app") {
			t.Errorf("CROSS-TENANT LEAK: %s NL application seeds: %s %v", name, body, err)
		}
	}

	// A tenant's own rows are unchanged, however it asks.
	for name, c := range map[string]jwtClaims{"tenant A": a, "A walking into Provider": walkA, "the platform owner scoped to A": ownerInA} {
		_, out := changeAPICall(t, s, c, "/api/changes")
		if got := changeRowsByObject(out); got["dev-own"] == "" || got["own-cloud"] == "" || out["note"] != nil {
			t.Errorf("%s lost its own rows: %v", name, out)
		}
		seeds, err := s.nlqScopeFor(newAITestRequest(t, c), c).appSeeds(ctx)
		if err != nil || !strings.Contains(nlqJSON(map[string]any{"seeds": seeds}), "own-app") {
			t.Errorf("%s lost its own application seed: %+v %v", name, seeds, err)
		}
	}
	if _, out := changeAPICall(t, s, b, "/api/changes"); len(changeRowsByObject(out)) != 0 {
		t.Errorf("tenant B reads an empty ledger: %v", out)
	}
}

// The same through the real router, auth middleware and withActingTenant, which
// is what honours as_tenant, and the DEM routes over the same ledger.
func TestProviderChangesOverTheRealRouter(t *testing.T) {
	srv, s, a, b := experienceFixtures(t)
	seedProviderChanges(t, s.experienceStore, a.tenantID)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	get := func(token, path string) (int, map[string]any, string) {
		t.Helper()
		code, body := do(t, srv, "GET", path, token, nil)
		var out map[string]any
		_ = json.Unmarshal(body, &out) // best-effort: a refusal is asserted by status and body
		return code, out, string(body)
	}
	code, out, body := get(admin, "/api/changes")
	providerID := changeRowsByObject(out)["core-global"]
	if code != http.StatusOK || providerID == "" {
		t.Fatalf("the platform owner's Global view: %d %s", code, body)
	}
	code, out, body = get(admin, "/api/changes?as_tenant=global")
	if code != http.StatusOK || changeRowsByObject(out)["core-global"] != providerID || out["note"] != nil {
		t.Fatalf("the platform owner scoped to Provider: %d %s", code, body)
	}
	code, out, body = get(admin, "/api/changes?as_tenant="+a.tenantID)
	if code != http.StatusOK || changeRowsByObject(out)["dev-own"] == "" || hasProviderObject(body) {
		t.Fatalf("the platform owner scoped to A: %d %s", code, body)
	}
	if code, _, body := get(admin, "/api/changes/"+providerID); code != http.StatusOK {
		t.Fatalf("the platform owner by id: %d %s", code, body)
	}

	for name, f := range map[string]*orgFixture{"A": a, "B": b} {
		for _, walk := range []string{"", "?as_tenant=global", "?as_tenant=" + a.tenantID, "?as_tenant=" + b.tenantID} {
			if code, _, body := get(f.token, "/api/changes"+walk); code != http.StatusOK || hasProviderObject(body) {
				t.Errorf("CROSS-TENANT LEAK: %s /api/changes%s: %d %s", name, walk, code, body)
			}
			for _, sub := range []string{"", "/diff"} {
				if code, _, _ := get(f.token, "/api/changes/"+providerID+sub+walk); code != http.StatusNotFound {
					t.Errorf("CROSS-TENANT LEAK: %s by id%s%s: %d, want 404", name, sub, walk, code)
				}
			}
		}
		for _, p := range []string{"/api/dem/changes?window=24h", "/api/dem/overview?window=24h", "/api/dem/incidents?window=24h"} {
			if code, _, body := get(f.token, p); hasProviderObject(body) {
				t.Errorf("CROSS-TENANT LEAK: %s %s: %d %s", name, p, code, body)
			}
		}
	}
	// as_tenant into another org is ignored: the walk reads A's own ledger.
	if _, out, body := get(a.token, "/api/changes?as_tenant="+b.tenantID); changeRowsByObject(out)["dev-own"] == "" {
		t.Errorf("as_tenant into another org must be ignored: %s", body)
	}
	// A's own row is on A's DEM feed: the checks above are not vacuous.
	if code, _, body := get(a.token, "/api/dem/changes?window=24h"); code != http.StatusOK || !strings.Contains(body, "dev-own") {
		t.Fatalf("A's DEM feed: %d %s", code, body)
	}
	// demAuthz refuses the platform tenant for everyone: the DEM feed is per-tenant.
	for _, p := range []string{"/api/dem/changes?window=24h", "/api/dem/changes?window=24h&as_tenant=global"} {
		if code, _, body := get(admin, p); code != http.StatusBadRequest || hasProviderObject(body) {
			t.Errorf("the DEM feed is not the Provider's surface: %s %d %s", p, code, body)
		}
	}

	// The operator-visibility restriction: the Global view still reads only the
	// Provider's ledger, and the DEM routes still serve the owner nothing of A.
	if _, err := s.tenants.SetOperatorRestricted(a.tenantID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tenants.SetOperatorRestricted("global", true); err == nil {
		t.Fatal("the Provider must not be operator-restricted")
	}
	code, out, body = get(admin, "/api/changes")
	if objects := changeRowsByObject(out); code != http.StatusOK || objects["core-global"] != providerID || objects["dev-own"] != "" {
		t.Fatalf("the Global view with A restricted: %d %s", code, body)
	}
	if code, _, body := get(admin, "/api/dem/changes?window=24h&as_tenant="+a.tenantID); strings.Contains(body, "dev-own") {
		t.Fatalf("the DEM feed served a restricted tenant to the owner: %d %s", code, body)
	}
	if code, _, body := get(a.token, "/api/changes"); code != http.StatusOK || !strings.Contains(body, "dev-own") {
		t.Fatalf("a restricted tenant keeps its own ledger: %d %s", code, body)
	}
}

// The Provider's rows against a REAL Postgres as the non-superuser role FORCE RLS
// applies to. Migration 0044's tenant_iso policy is what is proven: no migration
// is needed, the row is stored and read under app.tenant_id='global', and no other
// scope reaches it even by naming its tenant_id. Gated on DATABASE_URL_TEST.
func TestProviderChangesRLSPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("DATABASE_URL_TEST not set")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.DB().Close()
	st := experience.NewPGStore(ps.DB())
	acme := "acme-" + strings.ToLower(t.Name())
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	rows := []changeledger.SignalChange{
		{Tenant: "global", SignalID: "cccccccc-3333-3333-3333-333333333333", At: now, Source: "trap",
			Kind: changeledger.KindDeviceConfigChange, Entity: "core-global", User: "noc"},
		{Tenant: "", SignalID: "dddddddd-4444-4444-4444-444444444444", At: now, Source: "trap",
			Kind: changeledger.KindDeviceConfigChange, Entity: "core-blank", User: "noc"},
		{Tenant: "*", SignalID: "eeeeeeee-5555-5555-5555-555555555555", At: now, Source: "trap",
			Kind: changeledger.KindDeviceConfigChange, Entity: "core-star", User: "noc"},
		{Tenant: acme, SignalID: "ffffffff-6666-6666-6666-666666666666", At: now, Source: "trap",
			Kind: changeledger.KindDeviceConfigChange, Entity: "dev-own", User: "alice"},
	}
	for i := 0; i < 2; i++ { // the second bridge has an empty seen set: a restart replay
		if err := bridgeWith(t, st, rows).Pass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	q := experience.ChangeQuery{Since: now.Add(-time.Hour), Until: now.Add(time.Hour), Limit: 10}
	got, err := st.ListChanges(ctx, "global", q)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].TenantID != "global" || got[1].TenantID != "global" {
		t.Fatalf("the Provider's ledger, replayed: %+v", got)
	}
	if n, err := st.CountChanges(ctx, "global", q); err != nil || n != 2 {
		t.Fatalf("the Provider's count: %d %v", n, err)
	}
	byID, err := st.ListChanges(ctx, "global", experience.ChangeQuery{IDs: []string{got[0].ID}, Limit: 1})
	if err != nil || len(byID) != 1 {
		t.Fatalf("the Provider's row by id: %+v %v", byID, err)
	}
	for _, scope := range []string{acme, ""} {
		leaked, err := st.ListChanges(ctx, scope, experience.ChangeQuery{IDs: []string{got[0].ID}, Limit: 1})
		if err != nil || len(leaked) != 0 {
			t.Fatalf("CROSS-TENANT LEAK: scope %q read the Provider's row by id: %+v %v", scope, leaked, err)
		}
	}
	own, err := st.ListChanges(ctx, acme, q)
	if err != nil || len(own) != 1 || own[0].Object != "dev-own" {
		t.Fatalf("acme's ledger: %+v %v", own, err)
	}
	// The policy itself, asked in SQL that names the tenant, so the store's
	// concrete-tenant check is not what answers.
	count := func(scope string, cross bool) int {
		t.Helper()
		n := -1
		if err := ps.DB().WithTenant(ctx, scope, cross, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM dem_change_events WHERE tenant_id = 'global' AND change_id = ANY($1)`,
				[]string{got[0].ID, got[1].ID}).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for scope, want := range map[string]int{acme: 0, "": 0, "global": 2} {
		if n := count(scope, false); n != want {
			t.Errorf("RLS: app.tenant_id=%q sees %d Provider rows, want %d", scope, n, want)
		}
	}
	if n := count("", true); n != 2 {
		t.Errorf("RLS: the platform scope sees %d Provider rows, want 2", n)
	}
	// WITH CHECK: a tenant cannot write into the Provider's ledger either.
	err = ps.DB().WithTenant(ctx, acme, false, func(tx pgx.Tx) error {
		_, ierr := tx.Exec(ctx, `INSERT INTO dem_change_events (tenant_id, change_id, change_type, event_at, data)
			VALUES ('global', 'chg-forged', 'CONFIG_CHANGE', now(), '{}')`)
		return ierr
	})
	if err == nil {
		t.Fatal("RLS: a tenant wrote a row into the Provider's ledger")
	}
}
