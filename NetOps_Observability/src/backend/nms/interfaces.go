// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"strings"
	"time"
)

// interfaces.go — controller-reported interface identity, the sixth output
// class (tracker 387 PR 13a).
//
// A controller lists each device's interfaces with their index, addresses,
// VPN and description. Those are the same facts the SNMP collector reads from
// IF-MIB and ipAddrTable, and the api feeds both into one interface bridge
// (internal/ifbridge): the ifIndex → name map that names flow and trap ports,
// and the address → device map that attributes a trap sent from an interface
// address. Owner rule 2026-10-24: the NMS is the primary source.
//
// ControllerInterface is the vendor-neutral record every connector maps its
// interface list to. Route resolves the controller's device key to the
// inventory device the integration's OWN owner owns (identity.go); a key that
// resolves to nothing, or to more than one device, is kept unresolved and
// bridges nothing. An address is never the device match itself.

// maxInterfacesPerBatch bounds one payload's interface records (vManage lists
// one device per request; an IPv4 and an IPv6 row per interface on vEdge).
const maxInterfacesPerBatch = 8192

// maxInterfaceAddrs bounds the addresses one record carries.
const maxInterfaceAddrs = 16

// ControllerInterface is one interface as a controller reports it.
type ControllerInterface struct {
	TenantID      string // the integration's owner (runtime-stamped, never the payload's)
	IntegrationID string
	SourceSystem  string // "vmanage", …

	// DeviceKey is the controller's own key for the device (vManage: the
	// system-ip); DeviceName the hostname it reports for it.
	DeviceKey  string
	DeviceName string
	// DeviceID is the inventory id the key resolved to, set by Route; "" when
	// it did not resolve. Resolve says how it went (matched, no_match,
	// ambiguous, conflict, no_index, no_resolver).
	DeviceID string
	Resolve  string

	IfIndex     string   // IF-MIB index as the controller reports it ("" = none)
	IfName      string   // the controller's name for the port
	VRF         string   // VPN / VRF ("" = not reported)
	Description string   // the operator's interface description
	Addrs       []string // raw addresses as reported ("a.b.c.d", "a.b.c.d/24", IPv6, "-")
	Time        time.Time
}

// OutcomeResolver is a DeviceResolver that also says why a key did not
// resolve. InventoryResolver implements it; a plain DeviceResolver reports
// "matched" or "no_match".
type OutcomeResolver interface {
	ResolveDeviceOutcome(tenant string, kind KeyKind, key, name string) (id string, outcome string)
}

// resolveInterfaces stamps each record's inventory device. Records past the
// bound are dropped (counted by the caller through what reaches the bridge).
func resolveInterfaces(r DeviceResolver, kind KeyKind, in []ControllerInterface) []ControllerInterface {
	if len(in) > maxInterfacesPerBatch {
		in = in[:maxInterfacesPerBatch]
	}
	out := make([]ControllerInterface, 0, len(in))
	memo := map[[2]string][2]string{}
	for _, c := range in {
		c.DeviceKey = strings.TrimSpace(c.DeviceKey)
		if len(c.Addrs) > maxInterfaceAddrs {
			c.Addrs = c.Addrs[:maxInterfaceAddrs]
		}
		c.DeviceID, c.Resolve = "", "no_resolver"
		if r != nil && kind != KeyNone && c.DeviceKey != "" {
			mk := [2]string{c.TenantID, c.DeviceKey}
			got, seen := memo[mk]
			if !seen {
				if or, ok := r.(OutcomeResolver); ok {
					got[0], got[1] = or.ResolveDeviceOutcome(c.TenantID, kind, c.DeviceKey, c.DeviceName)
				} else if id, ok := r.ResolveDevice(c.TenantID, kind, c.DeviceKey, c.DeviceName); ok {
					got = [2]string{id, string(resolveMatched)}
				} else {
					got = [2]string{"", string(resolveNoMatch)}
				}
				memo[mk] = got
			}
			c.Resolve = got[1]
			if got[1] == string(resolveMatched) {
				c.DeviceID = got[0]
			}
		}
		out = append(out, c)
	}
	return out
}
