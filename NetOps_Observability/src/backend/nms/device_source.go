// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"netops/backend/models"
)

// device_source.go — controller-sourced devices as INVENTORY: the discovery
// source that turns the stored controller snapshots (device_store.go) into
// the owning tenant's devices, so device pages, metrics, alarms and incidents
// attach to them (owner 2026-10-19).
//
// Same contract as wireless.DeviceSource:
//   - only ENABLED integrations contribute;
//   - every store read is TENANT-SCOPED (§3a) — never a cross-tenant list;
//   - EVERY failure is returned: the registry treats a successful poll as the
//     complete truth for this source and prunes what it does not list, so a
//     failed read must never come back as a shorter list.

// ControllerSourceName is the discovery source name (models.Device.Source).
// It is "api" (owner 2026-10-19: "devices discovered via API call should have
// source as api") — the device came from an integration's API, not a scan.
const ControllerSourceName = "api"

const defaultControllerDeviceInterval = 60 * time.Second

// EnabledLister is the part of ConfigStore the source reads.
type EnabledLister interface {
	ListEnabled(ctx context.Context) ([]Integration, error)
	Devices(ctx context.Context, tenant string, cross bool, integrationID string) ([]ControllerDevice, error)
}

// ControllerDeviceSource implements discovery.DiscoverySource.
type ControllerDeviceSource struct {
	store    EnabledLister
	interval time.Duration
}

// NewControllerDeviceSource builds the source. A nil store is fail-closed.
func NewControllerDeviceSource(store EnabledLister, interval time.Duration) *ControllerDeviceSource {
	if interval <= 0 {
		interval = defaultControllerDeviceInterval
	}
	return &ControllerDeviceSource{store: store, interval: interval}
}

// Name implements discovery.DiscoverySource.
func (s *ControllerDeviceSource) Name() string { return ControllerSourceName }

// Interval implements discovery.DiscoverySource.
func (s *ControllerDeviceSource) Interval() time.Duration {
	if s == nil || s.interval <= 0 {
		return defaultControllerDeviceInterval
	}
	return s.interval
}

// ControllerDeviceID is the inventory id of a controller-reported device. The
// OWNER is in the hash, so the same system-ip or serial in two tenants is two
// devices (the registry cache and the tenant metric scope are keyed by id),
// and the id is stable across re-polls and a recreated integration.
func ControllerDeviceID(owner, sourceSystem string, kind KeyKind, key string) string {
	sum := sha256.Sum256([]byte(ownerOf(owner) + "\x00" + sourceSystem + "\x00" + string(kind) + "\x00" + key))
	return "ctl-" + sourceSystem + "-" + hex.EncodeToString(sum[:6])
}

// controllerRoleType maps a controller's role to the inventory device type.
func controllerRoleType(role string) string {
	switch role {
	case "edge":
		return "router"
	case "switch", "ap", "firewall", "router":
		return role
	}
	return ""
}

// ToInventoryDevice maps one controller record to an inventory device. It
// never sets PreferredProtocol (a merged SNMP twin must stay SNMP-polled) and
// files a controller site id as a label, never as the operator's site (a
// manual site always wins — owner decision 2026-10-18).
func ToInventoryDevice(ic Integration, d ControllerDevice) models.Device {
	owner := ownerOf(ic.Tenant)
	labels := map[string]string{
		"source_system":          d.SourceSystem,
		"controller_integration": ic.ID,
		"controller_key":         d.Key,
	}
	if d.KeyKind == KeySystemIP {
		labels["system_ip"] = d.Key
	}
	if d.SiteID != "" {
		labels["controller_site_id"] = d.SiteID
	}
	if d.Serial != "" {
		labels["serial"] = d.Serial
	}
	if d.Reachable != "" {
		labels["controller_reachability"] = d.Reachable
	}
	for k, v := range d.Aliases {
		labels["controller_"+k] = v
	}
	out := models.Device{
		ID:       ControllerDeviceID(owner, d.SourceSystem, d.KeyKind, d.Key),
		Name:     d.Name,
		Address:  d.MgmtAddr,
		Vendor:   d.Vendor,
		Model:    d.Model,
		OS:       d.OS,
		Type:     controllerRoleType(d.Role),
		TenantID: owner,
		Labels:   labels,
		Source:   ControllerSourceName,
		LastSeen: d.LastSeen,
	}
	if d.OSVersion != "" {
		out.OSVersion, out.OSVersionSource, out.OSVersionAt = d.OSVersion, "api:"+d.SourceSystem, d.LastSeen
	}
	if out.Name == "" {
		out.Name = d.Key
	}
	return out
}

// Poll returns the managed devices of every enabled integration.
func (s *ControllerDeviceSource) Poll(ctx context.Context) ([]models.Device, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("controller device source is not wired")
	}
	ints, err := s.store.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("controller integrations: %w", err)
	}
	// Stable order: two polls of the same estate produce the same slice.
	sort.Slice(ints, func(i, j int) bool { return Key(ints[i].Tenant, ints[i].ID) < Key(ints[j].Tenant, ints[j].ID) })
	var out []models.Device
	for _, ic := range ints {
		devs, err := s.store.Devices(ctx, ic.Tenant, false, ic.ID)
		if err != nil {
			return nil, fmt.Errorf("controller devices for %s: %w", ic.ID, err)
		}
		for _, d := range devs {
			// The controller's own nodes (vManage/vSmart/vBond, a dashboard)
			// are not devices of the managed network.
			if !d.Managed {
				continue
			}
			out = append(out, ToInventoryDevice(ic, d))
		}
	}
	return out, nil
}
