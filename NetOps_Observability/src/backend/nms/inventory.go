// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"net"
	"strings"
	"time"
	"unicode"
)

// inventory.go — controller-sourced inventory (owner 2026-10-19: when devices
// are known ONLY through a controller integration, the controller's device
// list must become the tenant's inventory devices, so device pages, metrics,
// alarms and incidents attach to them).
//
// ControllerDevice is the ONE vendor-neutral record every connector's
// inventory stream maps to — the fifth output class beside metrics, states,
// events and wireless inventory. A connector plugs in by mapping its own
// device list to it; storage, the discovery source, de-duplication and
// licence counting are shared. vManage is the first connector wired.
//
// Zero trust: everything here came from a controller, so it is validated and
// bounded (ValidateControllerDevice) before anything stores it, and the owning
// tenant is stamped by the runtime from the INTEGRATION — never from the
// payload.

// ControllerDevice is one device as a controller reports it.
type ControllerDevice struct {
	TenantID      string // the integration's owner (runtime-stamped)
	IntegrationID string
	SourceSystem  string // "vmanage", "meraki", …

	KeyKind KeyKind // what Key is (the connector's DeviceKeyKind)
	Key     string  // the controller's own key for the device (system-ip, serial, …)

	Name      string
	MgmtAddr  string // an address Correlix can reach it at, "" when the controller gives none
	Serial    string
	Vendor    string
	Model     string
	OS        string
	OSVersion string
	SiteID    string
	SiteName  string
	Role      string // "edge", "controller", "switch", "ap", …
	// Managed is false for the controller's OWN nodes (vManage/vSmart/vBond,
	// a dashboard, a DNAC cluster): they are listed, but are not devices of
	// the managed network and are not inventory by default.
	Managed   bool
	Reachable string            // "reachable" | "unreachable" | ""
	Aliases   map[string]string // other keys the controller knows it by (uuid, board_serial, …)
	LastSeen  time.Time
}

// Bounds on a single controller snapshot — a hostile or broken controller
// must not be able to grow the inventory or a row without limit.
const (
	maxControllerDevices = 20000
	maxDeviceFieldLen    = 128
	maxDeviceNameLen     = 253
	maxDeviceAliases     = 8
	maxDeviceSerialLen   = 64
)

// cleanField trims, strips control characters and caps a free-text field.
func cleanField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// cleanSerial keeps the characters a serial number is made of.
func cleanSerial(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxDeviceSerialLen {
		return ""
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}

// ValidateControllerDevice normalises one record and reports whether it is a
// device Correlix may hold: it must carry a key valid for its kind; every
// other field is cleaned and capped, and an unparseable address is dropped
// rather than stored.
func ValidateControllerDevice(d ControllerDevice) (ControllerDevice, bool) {
	d.Key = strings.TrimSpace(d.Key)
	switch d.KeyKind {
	case KeySystemIP, KeyIP:
		ip := net.ParseIP(d.Key)
		if ip == nil {
			return d, false
		}
		d.Key = ip.String()
	case KeySerial:
		if d.Key = cleanSerial(d.Key); d.Key == "" {
			return d, false
		}
	case KeyName:
		if d.Key = cleanField(d.Key, maxDeviceNameLen); d.Key == "" {
			return d, false
		}
	default:
		return d, false // an opaque key cannot be an inventory identity
	}
	d.Name = cleanField(d.Name, maxDeviceNameLen)
	if ip := net.ParseIP(strings.TrimSpace(d.MgmtAddr)); ip != nil {
		d.MgmtAddr = ip.String()
	} else {
		d.MgmtAddr = ""
	}
	d.Serial = cleanSerial(d.Serial)
	for _, f := range []*string{&d.Vendor, &d.Model, &d.OS, &d.OSVersion, &d.SiteID, &d.SiteName, &d.Role, &d.SourceSystem} {
		*f = cleanField(*f, maxDeviceFieldLen)
	}
	switch strings.ToLower(d.Reachable) {
	case "reachable", "unreachable":
		d.Reachable = strings.ToLower(d.Reachable)
	default:
		d.Reachable = ""
	}
	if len(d.Aliases) > 0 {
		out := make(map[string]string, len(d.Aliases))
		for k, v := range d.Aliases {
			if len(out) >= maxDeviceAliases {
				break
			}
			k, v = cleanField(k, 32), cleanField(v, maxDeviceFieldLen)
			if k != "" && v != "" {
				out[k] = v
			}
		}
		d.Aliases = out
	}
	return d, true
}

// ValidateSnapshot validates a whole inventory snapshot: invalid rows are
// dropped, duplicate keys keep the first row, and the snapshot is capped.
func ValidateSnapshot(devs []ControllerDevice) []ControllerDevice {
	out := make([]ControllerDevice, 0, len(devs))
	seen := make(map[string]bool, len(devs))
	for _, d := range devs {
		if len(out) >= maxControllerDevices {
			break
		}
		v, ok := ValidateControllerDevice(d)
		if !ok || seen[string(v.KeyKind)+"\x00"+v.Key] {
			continue
		}
		seen[string(v.KeyKind)+"\x00"+v.Key] = true
		out = append(out, v)
	}
	return out
}
