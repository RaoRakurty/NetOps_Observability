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
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/changeledger"
	"netops/backend/internal/changesignals"
	"netops/backend/internal/dem/experience"
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
