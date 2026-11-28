// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "strings"

// Control-session direction (tracker 397, owner decision 2026-11-28).
//
// An SD-WAN control session has two ends: an EDGE and a CONTROLLER (vSmart,
// vBond, vManage). Both ends can report it. The 2026-11-25 drill (cEDGE-80,
// `clear sdwan control connections`) recorded what vManage actually sends:
// the CONTROLLER reports the lost session (personality=vsmart|vmanage,
// system_ip = the controller) and names the EDGE as its peer (peer-type=vedge,
// peer-system-ip = the edge). Read as-is, that says "vSmart lost its
// controller 10.255.255.80", so one edge's outage counted every controller as
// an edge that lost the same peer and headlined "controller unreachable".
//
// The engine's vocabulary is edge-centred: a control-connection loss is ON the
// edge and NAMES the controller it lost (signals.controller_peer, the
// controller_fan_in gate, the control-session rung). So a controller-reported
// session is flipped at the connector — stage [1] — into "edge <peer> lost
// controller <reporter>". An edge-reported session is already in that shape and
// is left as it is; a controller↔controller session is not an edge's loss and
// is left as it is too.

// isEdgePeerType: the peer-type words vendors use for an edge. vManage says
// "vedge" for every edge, cEdges included.
func isEdgePeerType(pt string) bool {
	switch strings.ToLower(strings.TrimSpace(pt)) {
	case "vedge", "cedge", "edge":
		return true
	}
	return false
}

// isControllerRole: the controller roles a control session can run to.
func isControllerRole(pt string) bool {
	switch strings.ToLower(strings.TrimSpace(pt)) {
	case "vsmart", "vbond", "vmanage":
		return true
	}
	return false
}

// isControlSessionKind: the state kinds that are a control session (store.go
// controlSessionKinds names the same two).
func isControlSessionKind(kind string) bool {
	return controlSessionKinds[kind]
}

// ControlSessionFlip rides on a StateChange of a control session that the
// CONTROLLER's own row reported (its peer is an edge), so the change event can
// be emitted edge-centred. Ids are the canonical (inventory) ids where the
// resolver knew them, native keys otherwise; the native keys are kept so every
// lane spells the controller by the same system-ip.
type ControlSessionFlip struct {
	EdgeID           string
	EdgeNative       string
	ControllerID     string
	ControllerNative string
}

// resolveDeviceKey is the one device-key → inventory-id lookup (canonicalize
// and the control-session flip share it). ok=false when there is no resolver,
// no key, or no match.
func resolveDeviceKey(r DeviceResolver, kind KeyKind, names *deviceNames, tenant, key string) (string, bool) {
	if r == nil || kind == KeyNone || key == "" {
		return "", false
	}
	return r.ResolveDevice(tenant, kind, key, names.get(key))
}
