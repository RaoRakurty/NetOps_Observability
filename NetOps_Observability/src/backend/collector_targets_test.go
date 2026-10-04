// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/snmpcred"
	"netops/backend/models"
)

// collector_targets_test.go — the collector target builder must poll with the
// credential the sentinel PROVED answers, whether or not the device has a bound
// credential_ref (owner decision c, 2026-10-04), and must never thread one
// tenant's secret to another tenant's (or the platform's) device (§3a).

func targetFixture(t *testing.T) (*snmpcred.Store, *credOverrideStore) {
	t.Helper()
	dir := t.TempDir()
	creds, err := snmpcred.NewStore(filepath.Join(dir, "creds.json"), nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []snmpcred.Credential{
		{ID: "vedge-ro", Name: "vEdge RO", Version: "v2c", Community: "vedge-ro-secret"},
		{ID: "core-v3", Name: "Core v3", Version: "v3", SecurityName: "mon", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthKey: "ak", PrivProtocol: "AES128", PrivKey: "pk"},
		{ID: "acme-ro", Name: "Acme RO", Version: "v2c", Community: "acme-secret", TenantID: "acme"},
		{ID: "globex-ro", Name: "Shared name", Version: "v2c", Community: "globex-secret", TenantID: "globex"},
	} {
		if _, err := creds.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	ov, err := newCredOverrideStore(filepath.Join(dir, "overrides.json"))
	if err != nil {
		t.Fatal(err)
	}
	return creds, ov
}

// TestCollectorTargetHonoursOverrideForUnboundDevice is the regression for the
// bug proven live on 2026-10-04: four scan-discovered Cisco vEdges (no
// credential_ref), the sentinel adopted "vEdge RO" ("credential override
// adopted"), yet every poll still went out with the SNMP_COMMUNITY/"public"
// fallback because the override was only consulted inside
// `if dev.CredentialRef != ""` — collector_target_up stayed 0.
func TestCollectorTargetHonoursOverrideForUnboundDevice(t *testing.T) {
	creds, ov := targetFixture(t)
	dev := models.Device{ID: "vedge-1", Name: "vedge-1", Address: "10.40.0.11", PreferredProtocol: "snmp"}
	if err := ov.Set(credOverride{DeviceID: dev.ID, ProfileID: "vedge-ro", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tgt := snmpcred.TargetFor(dev, creds, ov)
	if tgt.Community != "vedge-ro-secret" || tgt.SNMPVersion == 3 {
		t.Fatalf("unbound device must poll with the sentinel's adopted profile, got community=%q version=%d", tgt.Community, tgt.SNMPVersion)
	}
}

func TestCollectorTargetOverrideBeatsBoundRef(t *testing.T) {
	creds, ov := targetFixture(t)
	dev := models.Device{ID: "core-1", Address: "10.40.0.1", CredentialRef: "core-v3"}
	if err := ov.Set(credOverride{DeviceID: dev.ID, ProfileID: "vedge-ro", BoundRef: "core-v3", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if tgt := snmpcred.TargetFor(dev, creds, ov); tgt.Community != "vedge-ro-secret" || tgt.SNMPVersion == 3 {
		t.Fatalf("override must win over the bound ref while it stands, got %+v", tgt)
	}
	if err := ov.Clear(dev.ID); err != nil {
		t.Fatal(err)
	}
	if tgt := snmpcred.TargetFor(dev, creds, ov); tgt.SNMPVersion != 3 || tgt.V3User != "mon" {
		t.Fatalf("with no override the bound v3 profile applies, got %+v", tgt)
	}
}

func TestCollectorTargetUnboundNoOverrideUsesPollerDefault(t *testing.T) {
	creds, ov := targetFixture(t)
	tgt := snmpcred.TargetFor(models.Device{ID: "x", Address: "10.40.0.9", TenantID: "acme", Labels: map[string]string{"gnmi": "TRUE"}}, creds, ov)
	if tgt.Community != "" || tgt.SNMPVersion != 0 {
		t.Fatalf("no profile → empty creds (poller's SNMP_COMMUNITY fallback), got %+v", tgt)
	}
	if tgt.TenantID != "acme" || !tgt.GNMICapable || tgt.Address != "10.40.0.9" {
		t.Fatalf("target identity fields lost: %+v", tgt)
	}
	// Nil stores (early boot) are tolerated.
	if tgt := snmpcred.TargetFor(models.Device{ID: "x", CredentialRef: "vedge-ro"}, nil, nil); tgt.Community != "" {
		t.Fatalf("nil stores must yield no creds, got %+v", tgt)
	}
}

// TestCollectorTargetNeverCrossesTenants: §3a — a tenant's profile is never
// used to poll another tenant's device, nor a platform-owned device, whether
// it arrives via credential_ref (id or name) or via a learned override.
func TestCollectorTargetNeverCrossesTenants(t *testing.T) {
	creds, ov := targetFixture(t)
	cases := []struct {
		name string
		dev  models.Device
		ovID string
	}{
		{"other tenant by id", models.Device{ID: "g1", TenantID: "globex", CredentialRef: "acme-ro"}, ""},
		{"other tenant by name", models.Device{ID: "g2", TenantID: "globex", CredentialRef: "Acme RO"}, ""},
		{"platform device bound to tenant profile", models.Device{ID: "p1", CredentialRef: "acme-ro"}, ""},
		{"global-tenant device bound to tenant profile", models.Device{ID: "p2", TenantID: "global", CredentialRef: "acme-ro"}, ""},
		{"override naming other tenant", models.Device{ID: "g3", TenantID: "globex"}, "acme-ro"},
		{"override naming tenant profile on platform device", models.Device{ID: "p3"}, "globex-ro"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.ovID != "" {
				if err := ov.Set(credOverride{DeviceID: c.dev.ID, ProfileID: c.ovID, Since: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			tgt := snmpcred.TargetFor(c.dev, creds, ov)
			if tgt.Community == "acme-secret" || tgt.Community == "globex-secret" {
				t.Fatalf("cross-tenant secret threaded into %+v", c.dev)
			}
		})
	}
	// Positive controls: own tenant's profile, and a platform profile on a
	// tenant device, both apply.
	if tgt := snmpcred.TargetFor(models.Device{ID: "a1", TenantID: "acme", CredentialRef: "acme-ro"}, creds, ov); tgt.Community != "acme-secret" {
		t.Fatalf("own-tenant profile must apply, got %+v", tgt)
	}
	if tgt := snmpcred.TargetFor(models.Device{ID: "a2", TenantID: "acme", CredentialRef: "vedge-ro"}, creds, ov); tgt.Community != "vedge-ro-secret" {
		t.Fatalf("platform profile must apply to a tenant device, got %+v", tgt)
	}
}
