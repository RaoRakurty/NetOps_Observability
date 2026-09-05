package wireless

// devices.go — the wireless inventory AS FLEET DEVICES.
//
// # Why this file exists (owner decision, tracker 256, 2026-09-05)
//
// A wireless controller is a device and an access point is a device: one row
// each in the fleet, and ONE monitored-device entitlement each when Correlix is
// actually collecting from them. One controller with fifty APs is fifty-one
// monitored devices, not one. What is NOT counted is inventory: a controller an
// SNMP sweep merely found, an AP nobody has enabled collection for, or a whole
// estate whose NMS integration an operator switched off.
//
// Before this file, WLC/AP rows reached /api/devices as a read-time projection
// out of this store and were stamped monitored with no counting behind it — the
// device registry never saw them, so an integration could add controllers and
// access points that Correlix polls and the licence did not count.
//
// # How it participates in the ONE definition
//
// It does NOT add a second counter. DeviceSource is an ordinary
// discovery.DiscoverySource: the rows it reports enter the SAME device registry
// as every SNMP, NetBox and operator-created device, and from there the single
// definition in internal/devmon decides whether each one is monitored, the same
// dedupe collapses a controller that SNMP and the integration both found into
// one device, and the same ceiling gate is asked before an unmonitored device
// becomes monitored. Adding a source is the whole change; nothing about the
// count is re-implemented here.
//
// The source reports ONLY the wireless entities an ENABLED integration is
// polling, because that is what "Correlix is collecting from this" means for a
// device it reaches through a controller. Entities whose integration is off are
// left to the api's read-time projection, which shows them in the fleet as not
// monitored with the reason — visible, never deleted, never counted.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/models"
)

// SourceName is the discovery-source name wireless device rows carry. It is
// also the provenance internal/devmon reads: not the subnet scan, therefore a
// DECLARED device — an operator configured an integration that polls it.
const SourceName = "wireless"

// Device id prefixes. They are STRUCTURED like the wireless entity ids the
// correlation engine grounds on (identity.go), so a fleet row and a wireless
// signal name the same thing.
const (
	ControllerDeviceIDPrefix = "wlc:"
	APDeviceIDPrefix         = "ap:"
)

// Device types as the fleet table renders them.
const (
	ControllerDeviceType = "wlc"
	APDeviceType         = "ap"
)

// defaultDeviceInterval is how often the source re-reads the wireless store.
// It is an INVENTORY read, not a controller poll: the connectors refresh the
// store on their own schedule and this only has to notice the result.
const defaultDeviceInterval = 60 * time.Second

// ControllerDevice is the fleet row for a wireless controller. It is the ONE
// mapping — the registry source below and the api's read-time projection both
// call it, so a controller cannot appear with two different identities
// depending on which path produced it.
func ControllerDevice(c Controller) models.Device {
	name := c.Name
	if name == "" {
		name = c.ControllerID
	}
	return models.Device{
		ID:       ControllerDeviceIDPrefix + c.ControllerID,
		Name:     name,
		Address:  c.ManagementAddress,
		Vendor:   c.Vendor,
		Model:    c.Model,
		OS:       c.OSVersion,
		Type:     ControllerDeviceType,
		TenantID: c.TenantID,
		Source:   SourceName,
		LastSeen: c.LastSeen,
	}
}

// APDevice is the fleet row for an access point.
func APDevice(ap AccessPoint) models.Device {
	name := ap.Name
	if name == "" {
		name = ap.APID
	}
	return models.Device{
		ID:       APDeviceIDPrefix + ap.APID,
		Name:     name,
		Address:  ap.MgmtAddress,
		Vendor:   ap.Vendor,
		Model:    ap.Model,
		Type:     APDeviceType,
		TenantID: ap.TenantID,
		Source:   SourceName,
		LastSeen: ap.LastSeen,
	}
}

// ActiveTenantsFunc reports the tenants that currently have an ENABLED
// integration polling wireless inventory, as a set of tenant ids.
//
// It is INJECTED rather than read here because the answer lives in the NMS
// integration store, and this package must not import its sibling: the wireless
// canonical model is vendor-neutral and storage-only by design. An error must
// be returned, never swallowed into an empty set — see Poll.
type ActiveTenantsFunc func(ctx context.Context) (map[string]bool, error)

// DeviceSource reports the wireless entities Correlix is collecting from as
// devices, for registration in the device registry.
type DeviceSource struct {
	store    Store
	active   ActiveTenantsFunc
	interval time.Duration
}

// NewDeviceSource builds the source. A nil store or nil active-tenants function
// is fail-closed: Poll returns an error rather than reporting an empty fleet,
// because an empty successful poll PRUNES this source's devices from the
// registry and would silently un-count an estate.
func NewDeviceSource(store Store, active ActiveTenantsFunc, interval time.Duration) *DeviceSource {
	if interval <= 0 {
		interval = defaultDeviceInterval
	}
	return &DeviceSource{store: store, active: active, interval: interval}
}

// Name implements discovery.DiscoverySource.
func (s *DeviceSource) Name() string { return SourceName }

// Interval implements discovery.DiscoverySource.
func (s *DeviceSource) Interval() time.Duration {
	if s == nil || s.interval <= 0 {
		return defaultDeviceInterval
	}
	return s.interval
}

// Poll returns every controller and access point an enabled integration is
// polling, one device row each.
//
// EVERY failure is returned, and that is deliberate. The aggregator keeps its
// cache untouched on a poll error but treats a successful poll as the complete
// truth for this source, pruning anything absent from it. So a store read that
// failed for one tenant must NOT come back as a shorter list: that would stop
// counting — and stop collecting from — devices nothing is actually wrong with.
func (s *DeviceSource) Poll(ctx context.Context) ([]models.Device, error) {
	if s == nil || s.store == nil || s.active == nil {
		return nil, errors.New("wireless device source is not wired")
	}
	active, err := s.active(ctx)
	if err != nil {
		return nil, fmt.Errorf("wireless integrations: %w", err)
	}
	tenants := make([]string, 0, len(active))
	for t, on := range active {
		if on && strings.TrimSpace(t) != "" {
			tenants = append(tenants, t)
		}
	}
	// Stable order so two polls of the same estate produce the same slice and a
	// diff of the inventory is a real change, not a map iteration.
	sort.Strings(tenants)

	var out []models.Device
	for _, tenant := range tenants {
		// Scoped reads, never a cross-tenant list (§3a rule 4): the source asks
		// each tenant's store for that tenant's own rows.
		ctrls, err := s.store.ListControllers(ctx, tenant, false)
		if err != nil {
			return nil, fmt.Errorf("wireless controllers: %w", err)
		}
		for _, c := range ctrls {
			if c.TenantID == "" {
				c.TenantID = tenant
			}
			out = append(out, ControllerDevice(c))
		}
		aps, err := s.store.ListAPs(ctx, tenant, false)
		if err != nil {
			return nil, fmt.Errorf("wireless access points: %w", err)
		}
		for _, ap := range aps {
			if ap.TenantID == "" {
				ap.TenantID = tenant
			}
			out = append(out, APDevice(ap))
		}
	}
	return out, nil
}
