// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"os"
	"testing"

	"netops/backend/internal/platformdb"
	"netops/backend/nms"
)

// TestPgNMSIntegrationWithoutStreams: an integration created without a stream
// list (an API create that takes the connector defaults) must save on
// Postgres — data_sources is NOT NULL and a nil slice used to be written as
// NULL ("save failed", lab 2026-10-18) — read back as "no choice", follow the
// defaults, and stay invisible to a tenant (RLS) when platform-owned.
// Gated on DATABASE_URL_TEST, run as the non-superuser app role.
func TestPgNMSIntegrationWithoutStreams(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres NMS store test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := nms.NewPGStore(ps.DB(), nil)

	in := nms.Integration{Tenant: TenantGlobal, ID: "nmsi-pgnil", Vendor: "vmanage", Product: "Cisco Catalyst SD-WAN Manager",
		DisplayName: "platform vmanage", BaseURL: "https://vmanage.example", Enabled: true, PollIntervalS: 120}
	if err := st.Upsert(ctx, in); err != nil {
		t.Fatalf("Upsert with no stream list: %v", err)
	}
	got, ok, err := st.Get(ctx, TenantGlobal, false, in.ID)
	if err != nil || !ok {
		t.Fatalf("Get own (platform) integration: ok=%v err=%v", ok, err)
	}
	if len(got.Streams) != 0 {
		t.Fatalf("streams read back %v — want none (follow the defaults)", got.Streams)
	}
	if eff := nms.Specs()["vmanage"].EffectiveStreams(got.Streams); len(eff) == 0 {
		t.Fatal("no saved choice must poll the connector defaults")
	}
	// §3a: a tenant never sees the platform's integration (RLS, not just the app).
	list, err := st.List(ctx, "t_tenant_a", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.ID == in.ID {
			t.Fatal("CROSS-SCOPE LEAK: a tenant listed the platform integration")
		}
	}
	if _, ok, err := st.Get(ctx, "t_tenant_a", false, in.ID); err != nil || ok {
		t.Fatalf("tenant Get of the platform integration: ok=%v err=%v (want not found)", ok, err)
	}
}
