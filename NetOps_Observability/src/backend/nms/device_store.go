// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// device_store.go — persistence for controller-sourced inventory
// (inventory.go; migration 0060_controller_devices.sql).
//
// THE PRUNE RULE. A controller is an external system and one poll can be
// wrong, so the store never deletes on a single snapshot:
//   - only a COMPLETE snapshot (Routed.DevicesComplete) is applied at all;
//   - an EMPTY snapshot deletes nothing (a controller that suddenly reports no
//     devices is far more likely broken than empty);
//   - a device a complete snapshot no longer lists is marked absent, and is
//     deleted only after DeviceAbsentGrace.
// Durable on Postgres, because the discovery source treats an empty read as
// "the controller has none" and would drop the devices (and their licence
// first-seen order) after every restart otherwise.

// DeviceAbsentGrace is how long a device a controller stopped listing stays
// in the inventory before it is removed.
const DeviceAbsentGrace = time.Hour

// DeviceStore is the persistence seam for controller devices. Writes are
// tenant-scoped: tenant is the integration's owner (the caller stamps it from
// the integration record, never from controller data).
type DeviceStore interface {
	// ReplaceDevices applies one complete snapshot for an integration.
	ReplaceDevices(ctx context.Context, tenant, integrationID string, devs []ControllerDevice, now time.Time) error
	// Devices lists an integration's present devices (absent ones in grace
	// included — they are still inventory until the grace ends).
	Devices(ctx context.Context, tenant string, cross bool, integrationID string) ([]ControllerDevice, error)
}

// ── in-memory backend ────────────────────────────────────────────────────────

type memDevice struct {
	d      ControllerDevice
	absent *time.Time
}

func (m *memStore) ReplaceDevices(_ context.Context, tenant, integrationID string, devs []ControllerDevice, now time.Time) error {
	if len(devs) == 0 {
		return nil // an empty snapshot deletes nothing
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := tenant + "\x00" + integrationID + "\x00"
	listed := make(map[string]bool, len(devs))
	for _, d := range devs {
		d.TenantID, d.IntegrationID = tenant, integrationID // owner from the integration
		k := prefix + d.Key
		listed[k] = true
		m.devices[k] = &memDevice{d: d}
	}
	for k, md := range m.devices {
		if len(k) < len(prefix) || k[:len(prefix)] != prefix || listed[k] {
			continue
		}
		switch {
		case md.absent == nil:
			t := now
			md.absent = &t
		case now.Sub(*md.absent) >= DeviceAbsentGrace:
			delete(m.devices, k)
		}
	}
	return nil
}

func (m *memStore) Devices(_ context.Context, tenant string, cross bool, integrationID string) ([]ControllerDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ControllerDevice{}
	for _, md := range m.devices {
		if md.d.IntegrationID != integrationID || (!cross && md.d.TenantID != tenant) {
			continue
		}
		out = append(out, md.d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ── Postgres backend ─────────────────────────────────────────────────────────

func (s *pgStore) ReplaceDevices(ctx context.Context, tenant, integrationID string, devs []ControllerDevice, now time.Time) error {
	if len(devs) == 0 {
		return nil // an empty snapshot deletes nothing
	}
	// TENANT-SCOPED, unlike UpsertStates: RLS WITH CHECK refuses any row whose
	// tenant_id is not the integration's owner, so a stamping bug cannot file a
	// device under another tenant.
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		keys := make([]string, 0, len(devs))
		for _, d := range devs {
			aliases, err := json.Marshal(d.Aliases)
			if err != nil {
				return err
			}
			keys = append(keys, d.Key)
			if _, err := tx.Exec(ctx, `
INSERT INTO controller_devices
   (tenant_id, integration_id, device_key, key_kind, source_system, name, mgmt_addr, serial, vendor, model,
    os, os_version, site_id, site_name, role, managed, reachable, aliases, last_seen, absent_since)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NULL)
 ON CONFLICT (tenant_id, integration_id, device_key) DO UPDATE SET
   key_kind=EXCLUDED.key_kind, source_system=EXCLUDED.source_system, name=EXCLUDED.name,
   mgmt_addr=EXCLUDED.mgmt_addr, serial=EXCLUDED.serial, vendor=EXCLUDED.vendor, model=EXCLUDED.model,
   os=EXCLUDED.os, os_version=EXCLUDED.os_version, site_id=EXCLUDED.site_id, site_name=EXCLUDED.site_name,
   role=EXCLUDED.role, managed=EXCLUDED.managed, reachable=EXCLUDED.reachable, aliases=EXCLUDED.aliases,
   last_seen=EXCLUDED.last_seen, absent_since=NULL`,
				tenant, integrationID, d.Key, string(d.KeyKind), d.SourceSystem, d.Name, d.MgmtAddr, d.Serial,
				d.Vendor, d.Model, d.OS, d.OSVersion, d.SiteID, d.SiteName, d.Role, d.Managed, d.Reachable,
				aliases, now); err != nil {
				return err
			}
		}
		// Not listed any more: start the grace clock, then delete past it.
		if _, err := tx.Exec(ctx, `UPDATE controller_devices SET absent_since=$3
 WHERE tenant_id=$1 AND integration_id=$2 AND absent_since IS NULL AND NOT (device_key = ANY($4))`,
			tenant, integrationID, now, keys); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM controller_devices
 WHERE tenant_id=$1 AND integration_id=$2 AND absent_since IS NOT NULL AND absent_since <= $3`,
			tenant, integrationID, now.Add(-DeviceAbsentGrace))
		return err
	})
}

func (s *pgStore) Devices(ctx context.Context, tenant string, cross bool, integrationID string) ([]ControllerDevice, error) {
	out := []ControllerDevice{}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id, integration_id, device_key, key_kind, source_system, name, mgmt_addr,
   serial, vendor, model, os, os_version, site_id, site_name, role, managed, reachable, aliases, last_seen
 FROM controller_devices WHERE integration_id=$1 ORDER BY device_key`, integrationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d ControllerDevice
			var kind string
			var aliases []byte
			if err := rows.Scan(&d.TenantID, &d.IntegrationID, &d.Key, &kind, &d.SourceSystem, &d.Name, &d.MgmtAddr,
				&d.Serial, &d.Vendor, &d.Model, &d.OS, &d.OSVersion, &d.SiteID, &d.SiteName, &d.Role, &d.Managed,
				&d.Reachable, &aliases, &d.LastSeen); err != nil {
				return err
			}
			d.KeyKind = KeyKind(kind)
			if len(aliases) > 0 {
				if err := json.Unmarshal(aliases, &d.Aliases); err != nil {
					return err
				}
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
