// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "strings"

// facts.go — the inventory facts an NMS states about a device: model, site and
// role (tracker 387 PR 13a, telemetry plan §6a layer 2).
//
// The registry (device_tenant.csv) stamps model, site and role on every syslog
// line and trap, and every one of them was blank on the lab: the SNMP scan
// reads none of the three, and vManage, which knows all three, was never asked.
// Owner rule 2026-10-24: the NMS is the primary source.
//
// Each NMS vendor says these things in its own words (vManage: device-model,
// site-id, device-type vedge/vsmart/vbond/vmanage). A DeviceFactsMapper turns
// one vendor's words into Correlix's vendor-neutral InventoryFacts, so another
// integration plugs in by adding its mapper; vManage is the first. The
// connector applies its mapper when it builds ControllerDevice, so the stored
// record (controller_devices) already carries the neutral facts and FactsOf
// only re-validates them.

// Roles, the closed set of InventoryFacts.Role. The first four are an SD-WAN
// fabric's parts (owner brief 2026-11-10); the rest are the device classes
// other controllers report.
const (
	RoleEdge         = "edge"         // a forwarding device of the managed network
	RoleController   = "controller"   // a control-plane node (vSmart)
	RoleManager      = "manager"      // the management plane (vManage)
	RoleOrchestrator = "orchestrator" // the onboarding / orchestration node (vBond)
	RoleRouter       = "router"
	RoleSwitch       = "switch"
	RoleAP           = "ap"
	RoleFirewall     = "firewall"
	RoleWLC          = "wlc"
)

// NormalizeRole returns role when it is in the closed set, else "". A role
// nobody defined is never passed on to telemetry.
func NormalizeRole(role string) string {
	switch r := strings.ToLower(strings.TrimSpace(role)); r {
	case RoleEdge, RoleController, RoleManager, RoleOrchestrator,
		RoleRouter, RoleSwitch, RoleAP, RoleFirewall, RoleWLC:
		return r
	}
	return ""
}

// InventoryFacts are the vendor-neutral facts an NMS states about one device.
// "" is "the controller states none"; it is never filled by a guess.
type InventoryFacts struct {
	Model string
	// Site is the controller's own site id for the device (vManage site-id).
	// It is the device's REPORTED site: an operator's site always wins over it
	// (owner decision 2026-10-18).
	Site string
	Role string // NormalizeRole's closed set
}

// NativeDeviceFacts are a controller's own words for a device.
type NativeDeviceFacts struct {
	Model      string
	SiteID     string
	DeviceType string
}

// DeviceFactsMapper maps one NMS vendor's words onto InventoryFacts.
type DeviceFactsMapper interface {
	MapFacts(n NativeDeviceFacts) InventoryFacts
}

// VManageFacts is the Catalyst SD-WAN Manager mapper. device-type is "vedge"
// for every edge (cEdges report it too), "vsmart", "vbond" or "vmanage".
type VManageFacts struct{}

// MapFacts implements DeviceFactsMapper.
func (VManageFacts) MapFacts(n NativeDeviceFacts) InventoryFacts {
	role := ""
	switch strings.ToLower(strings.TrimSpace(n.DeviceType)) {
	case "vedge":
		role = RoleEdge
	case "vsmart":
		role = RoleController
	case "vbond":
		role = RoleOrchestrator
	case "vmanage":
		role = RoleManager
	}
	return InventoryFacts{
		Model: cleanField(n.Model, maxDeviceFieldLen),
		Site:  cleanField(n.SiteID, maxDeviceFieldLen),
		Role:  role,
	}
}

// FactsOf reads the facts a stored controller device states. The record was
// validated when it was stored; the role is checked against the closed set
// again because the store is a cache (§3: never trust cached data unvalidated).
func FactsOf(d ControllerDevice) InventoryFacts {
	return InventoryFacts{
		Model: cleanField(d.Model, maxDeviceFieldLen),
		Site:  cleanField(d.SiteID, maxDeviceFieldLen),
		Role:  NormalizeRole(d.Role),
	}
}
