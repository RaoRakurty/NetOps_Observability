package backend

// wireless_devices.go — project the wireless canonical inventory into the
// /api/devices fleet view (#128 follow-on, owner request 2026-07-26).
//
// Wired + wireless are ONE LAN domain (owner ruling), so a controller or AP is
// a first-class device row (Type "wlc" / "ap") in the same table as switches
// and routers; the Wireless page stays the RF-side lens (radios, WLANs). The
// projection is read-time only — the wireless store remains the single source
// of truth and nothing is copied into the discovery store.
//
// §3a: tenant scoping is inherited from the wireless store's list methods
// (default-closed); rows carry their owning tenant. An SNMP-discovered
// controller (InferDeviceType already classifies 9800s as "wlc") keeps its
// discovery row: projection dedupes by management address so the fleet never
// shows the same box twice.

import (
	"context"
	"strings"

	"netops/backend/models"
)

// wirelessDeviceRows returns the caller-visible wireless inventory as device
// rows, skipping any whose management address is already present in `existing`
// (the discovery fleet). Store errors are logged and yield a partial (never
// silent-empty-AND-unlogged) result — the fleet endpoint must not 500 because
// one projection source hiccuped; the Wireless page surfaces store failures.
func (s *server) wirelessDeviceRows(ctx context.Context, claims jwtClaims, existing []models.Device) []models.Device {
	if s.wireless == nil {
		return nil
	}
	tenant, cross := principalTenant(claims)
	seen := make(map[string]bool, len(existing))
	for _, d := range existing {
		if a := strings.ToLower(strings.TrimSpace(d.Address)); a != "" {
			seen[a] = true
		}
	}
	var out []models.Device

	// MONITORING-BEGIN — a projected wireless row IS being collected from: the
	// NMS connector polls the controller, which is what put this row here at
	// all. Saying so keeps the fleet table honest (a blank would read as "not
	// monitored", which is false).
	//
	// KNOWN GAP, recorded rather than papered over: these rows are collected
	// through the NMS connector and are NOT counted by the device ceiling,
	// because they live in the wireless store rather than the device registry
	// that owns the count. Closing it is a product decision about whether an AP
	// is a licensed device — see docs/TRACKER.md.
	const wirelessReason = "monitoring is on: this device is polled through its wireless controller integration"
	// MONITORING-END

	ctrls, err := s.wireless.ListControllers(ctx, tenant, cross)
	if err != nil {
		logError("wireless", "controller projection unavailable for /api/devices",
			map[string]any{"err": err.Error()})
	}
	for _, c := range ctrls {
		if addr := strings.ToLower(strings.TrimSpace(c.ManagementAddress)); addr != "" && seen[addr] {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.ControllerID
		}
		out = append(out, models.Device{
			ID:       "wlc:" + c.ControllerID,
			Name:     name,
			Address:  c.ManagementAddress,
			Vendor:   c.Vendor,
			Model:    c.Model,
			OS:       c.OSVersion,
			Type:     "wlc",
			TenantID: c.TenantID,
			Source:   "wireless",
			LastSeen: c.LastSeen,

			Monitored:     true,
			MonitorReason: wirelessReason,
		})
	}

	aps, err := s.wireless.ListAPs(ctx, tenant, cross)
	if err != nil {
		logError("wireless", "AP projection unavailable for /api/devices",
			map[string]any{"err": err.Error()})
	}
	for _, ap := range aps {
		if addr := strings.ToLower(strings.TrimSpace(ap.MgmtAddress)); addr != "" && seen[addr] {
			continue
		}
		name := ap.Name
		if name == "" {
			name = ap.APID
		}
		out = append(out, models.Device{
			ID:       "ap:" + ap.APID,
			Name:     name,
			Address:  ap.MgmtAddress,
			Vendor:   ap.Vendor,
			Model:    ap.Model,
			Type:     "ap",
			TenantID: ap.TenantID,
			Source:   "wireless",
			LastSeen: ap.LastSeen,

			Monitored:     true,
			MonitorReason: wirelessReason,
		})
	}
	return out
}
