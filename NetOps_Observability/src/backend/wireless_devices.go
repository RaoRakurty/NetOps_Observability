package backend

// wireless_devices.go — project the wireless canonical inventory into the
// /api/devices fleet view (#128 follow-on, owner request 2026-07-26).
//
// Wired + wireless are ONE LAN domain (owner ruling), so a controller or AP is
// a first-class device row (Type "wlc" / "ap") in the same table as switches
// and routers; the Wireless page stays the RF-side lens (radios, WLANs).
//
// WHAT THIS FILE COVERS, since tracker 256 (owner decision 2026-09-05).
// Wireless entities an ENABLED integration polls are no longer projected here
// at all: wireless.DeviceSource reports them to the device registry, where the
// ONE monitored-device definition (internal/devmon) counts them, the ordinary
// dedupe collapses a controller SNMP also found, and the licence ceiling gates
// them like every other device. This projection is what is LEFT — the entities
// in the wireless store that nothing is currently polling, because their
// integration is off or was removed.
//
// They are still shown, because deleting a row from the fleet the moment an
// integration is disabled would look like the estate had shrunk. They are shown
// as NOT monitored, with the reason, and they cost no licence allowance — the
// same treatment a discovered-but-not-enabled device gets.
//
// §3a: tenant scoping is inherited from the wireless store's list methods
// (default-closed); rows carry their owning tenant.

import (
	"context"
	"strings"

	"netops/backend/internal/devmon"
	"netops/backend/internal/entitlement"
	"netops/backend/models"
	"netops/backend/nms"
	"netops/backend/wireless"
)

// wirelessDeviceRows returns the caller-visible wireless inventory as device
// rows, skipping any the device registry already holds (`existing`, the
// discovery fleet) by id OR by management address. Store errors are logged and
// yield a partial (never silent-empty-AND-unlogged) result — the fleet endpoint
// must not 500 because one projection source hiccuped; the Wireless page
// surfaces store failures.
func (s *server) wirelessDeviceRows(ctx context.Context, claims jwtClaims, existing []models.Device) []models.Device {
	if s.wireless == nil {
		return nil
	}
	tenant, cross := principalTenant(claims)
	seenAddr := make(map[string]bool, len(existing))
	seenID := make(map[string]bool, len(existing))
	for _, d := range existing {
		if a := strings.ToLower(strings.TrimSpace(d.Address)); a != "" {
			seenAddr[a] = true
		}
		if id := strings.TrimSpace(d.ID); id != "" {
			seenID[id] = true
		}
	}
	var out []models.Device

	// These rows are the ones the registry does NOT hold, i.e. the ones nothing
	// is polling. Stamping them here rather than leaving the fields blank is the
	// point: a blank reads as "unknown", and the operator's question is exactly
	// why this AP is in the list and not being collected from.
	add := func(d models.Device) {
		if a := strings.ToLower(strings.TrimSpace(d.Address)); a != "" && seenAddr[a] {
			return
		}
		if seenID[d.ID] {
			return
		}
		d.Monitored = false
		d.MonitorReason = devmon.ReasonWirelessNotPolled
		out = append(out, d)
	}

	ctrls, err := s.wireless.ListControllers(ctx, tenant, cross)
	if err != nil {
		logError("wireless", "controller projection unavailable for /api/devices",
			map[string]any{"err": err.Error()})
	}
	for _, c := range ctrls {
		add(wireless.ControllerDevice(c))
	}

	aps, err := s.wireless.ListAPs(ctx, tenant, cross)
	if err != nil {
		logError("wireless", "AP projection unavailable for /api/devices",
			map[string]any{"err": err.Error()})
	}
	for _, ap := range aps {
		add(wireless.APDevice(ap))
	}
	return out
}

// wirelessActiveTenants reports which tenants have at least one ENABLED NMS
// integration whose connector can poll wireless AP inventory — the set
// wireless.DeviceSource reports devices for, and therefore the set the licence
// counts.
//
// Enablement is the signal because it is the operator's own decision about
// whether Correlix collects from that estate: a disabled integration polls
// nothing, so its controllers and access points are inventory, not monitored
// devices. Capability is checked alongside it so an enabled SD-WAN or
// fabric-only integration in the same tenant does not make a stale wireless row
// look polled.
//
// An error is RETURNED, never turned into an empty set: the source treats an
// empty successful poll as "this estate is gone" and would un-count it.
func (s *server) wirelessActiveTenants(ctx context.Context) (map[string]bool, error) {
	if s.nms == nil {
		// The framework is off, so nothing polls wireless inventory. That is a
		// real answer, not a failure.
		return map[string]bool{}, nil
	}
	ints, err := s.nms.Store().ListEnabled(ctx)
	if err != nil {
		return nil, err
	}
	reg := s.nms.Registry()
	out := make(map[string]bool, len(ints))
	for _, ic := range ints {
		if !ic.Enabled || strings.TrimSpace(ic.Tenant) == "" {
			continue
		}
		if reg == nil {
			continue
		}
		conn, ok := reg.Get(ic.Vendor)
		if !ok || !nmsPollsWireless(conn.Spec()) {
			continue
		}
		out[ic.Tenant] = true
	}
	return out, nil
}

// nmsPollsWireless reports whether a connector declares it can report wireless
// AP inventory at all. FidelityNone is "the vendor cannot report it" — an
// honest hole, and never a reason to treat its estate as polled (capability.go:
// an unsupported capability must not render as a healthy one).
func nmsPollsWireless(spec nms.ConnectorSpec) bool {
	decl, ok := spec.CapabilityOf(nms.CapAPInventory)
	return ok && decl.Fidelity != nms.FidelityNone
}

// nmsWirelessActivationCeiling asks the MONITORED-DEVICE ceiling before an
// integration that polls wireless inventory is switched on (tracker 256, owner
// decision 2026-09-05).
//
// This is the wireless TRANSITION POINT. Every other path to a monitored device
// asks the ceiling inside the registry, in the same lock hold as the write; a
// wireless estate arrives asynchronously instead — the connector polls, the
// store fills, the source reports — so the moment an operator can be told "no"
// is the moment they enable the integration, which is the moment they ask
// Correlix to start collecting from that estate.
//
// The refusal is entitlement's structured 402 and carries unit
// "monitored_devices", so the SPA renders the same upgrade card it renders for
// a refused device. On a tier where the device ceiling is SOFT nothing is
// refused: the activation succeeds and the overage is recorded for true-up
// (internal/licence.OverageTracker), which is CheckCeiling's own rule and not
// re-decided here.
//
// A connector that cannot report wireless inventory is not gated: enabling an
// SD-WAN or fabric integration adds no wireless devices, and charging it for
// the ceiling would refuse work that costs nothing.
func (s *server) nmsWirelessActivationCeiling(spec nms.ConnectorSpec) error {
	if s.entitlements == nil || s.discovery == nil || !nmsPollsWireless(spec) {
		return nil
	}
	return entitlement.CheckCeiling(s.entitlements, entitlement.CeilingDevices, s.discovery.MonitoredCount())
}
