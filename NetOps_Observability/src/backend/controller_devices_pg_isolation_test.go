// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/platformdb"
	"netops/backend/nms"
)

// TestPgControllerDevicesAreTenantIsolated proves migration 0060's FORCE-RLS
// is a real backstop for controller-sourced inventory, run as the
// non-superuser app role: a write filed under another tenant is refused by
// WITH CHECK even when issued directly, a tenant never reads another's rows,
// the snapshot rules hold on Postgres, and deleting the integration removes
// its devices. Gated on DATABASE_URL_TEST.
func TestPgControllerDevicesAreTenantIsolated(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres controller-device isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := nms.NewPGStore(ps.DB(), nil)
	t0 := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	d := func(key, name string) nms.ControllerDevice {
		return nms.ControllerDevice{KeyKind: nms.KeySystemIP, Key: key, Name: name, SourceSystem: "vmanage", Managed: true,
			Aliases: map[string]string{"uuid": "u-" + key}}
	}

	if err := st.ReplaceDevices(ctx, "t_retail", "int-r", []nms.ControllerDevice{d("10.255.255.40", "cEDGE-40"), d("10.255.255.20", "vEdge-20")}, t0); err != nil {
		t.Fatalf("ReplaceDevices: %v", err)
	}
	// The same system-ip in another tenant is another tenant's row.
	if err := st.ReplaceDevices(ctx, "t_acme", "int-a", []nms.ControllerDevice{d("10.255.255.40", "acme-edge")}, t0); err != nil {
		t.Fatalf("ReplaceDevices acme: %v", err)
	}

	got, err := st.Devices(ctx, "t_retail", false, "int-r")
	if err != nil || len(got) != 2 || got[0].Aliases["uuid"] == "" || got[0].TenantID != "t_retail" {
		t.Fatalf("retail read: %v %+v", err, got)
	}
	if leak, err := st.Devices(ctx, "t_acme", false, "int-r"); err != nil || len(leak) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme read retail's devices: %v %+v", err, leak)
	}
	if all, err := st.Devices(ctx, "", true, "int-a"); err != nil || len(all) != 1 || all[0].Name != "acme-edge" {
		t.Fatalf("platform read of acme: %v %+v", err, all)
	}

	// RLS WITH CHECK: a row filed under another tenant is refused even when
	// written directly in this tenant's scope.
	err = ps.DB().WithTenant(ctx, "t_acme", false, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO controller_devices (tenant_id, integration_id, device_key, key_kind) VALUES ('t_retail','int-r','10.9.9.9','system_ip')`)
		return e
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a write into another tenant must be RLS-denied (42501); got %v", err)
	}

	// Snapshot rules on Postgres: empty deletes nothing; absent survives the
	// grace; past the grace it goes.
	if err := st.ReplaceDevices(ctx, "t_retail", "int-r", nil, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Devices(ctx, "t_retail", false, "int-r"); len(got) != 2 {
		t.Fatalf("empty snapshot pruned: %+v", got)
	}
	_ = st.ReplaceDevices(ctx, "t_retail", "int-r", []nms.ControllerDevice{d("10.255.255.40", "cEDGE-40")}, t0.Add(2*time.Minute))
	if got, _ := st.Devices(ctx, "t_retail", false, "int-r"); len(got) != 2 {
		t.Fatalf("absent device dropped before its grace: %+v", got)
	}
	_ = st.ReplaceDevices(ctx, "t_retail", "int-r", []nms.ControllerDevice{d("10.255.255.40", "cEDGE-40")}, t0.Add(2*time.Minute+nms.DeviceAbsentGrace))
	if got, _ := st.Devices(ctx, "t_retail", false, "int-r"); len(got) != 1 {
		t.Fatalf("absent device kept past its grace: %+v", got)
	}

	// Deleting the integration removes its devices — and only its devices.
	_ = st.Upsert(ctx, nms.Integration{Tenant: "t_retail", ID: "int-r", Vendor: "vmanage", Product: "x", DisplayName: "x", BaseURL: "https://x"})
	if ok, err := st.Delete(ctx, "t_retail", false, "int-r"); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if left, _ := st.Devices(ctx, "", true, "int-r"); len(left) != 0 {
		t.Fatalf("devices outlived their integration: %+v", left)
	}
	if acme, _ := st.Devices(ctx, "t_acme", false, "int-a"); len(acme) != 1 {
		t.Fatal("deleting retail's integration touched acme's devices")
	}
}
