// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wireless

// edges.go — canonical edge derivation (#128 Phase 5, design
// docs/Wireslessdesign.md §8). One vendor-neutral rule set turns an Inventory
// into the typed edges the correlation/path layer consumes. The rules ARE the
// architecture proof: for every deployment model the derived set must contain
// exactly the edges that deployment has — and NOT contain the ones it doesn't.
//
// The load-bearing distinction (§8.1): AP_MANAGED_BY_CONTROLLER (control/
// management association) and AP_TUNNELS_TO_CONTROLLER (client DATA
// encapsulation) are different edges. Local switching has the first and not
// the second — and that absence is a FACT of the deployment, never missing
// evidence. Collapsing them would make every FlexConnect estate mis-attribute
// client data-plane faults to the WLC.

// EdgeTypeName mirrors the Python path_graph.EdgeType vocabulary (string-typed
// in ClickHouse — no migration).
type EdgeTypeName string

const (
	EdgeAPUplinksViaPort      EdgeTypeName = "AP_UPLINKS_VIA_PORT"
	EdgeRadioOnAP             EdgeTypeName = "RADIO_ON_AP"
	EdgeBSSIDOnRadio          EdgeTypeName = "BSSID_ON_RADIO"
	EdgeBSSIDServesWLAN       EdgeTypeName = "BSSID_SERVES_WLAN"
	EdgeWLANBroadcastsSSID    EdgeTypeName = "WLAN_BROADCASTS_SSID"
	EdgeAPManagedByController EdgeTypeName = "AP_MANAGED_BY_CONTROLLER"
	EdgeAPTunnelsToController EdgeTypeName = "AP_TUNNELS_TO_CONTROLLER"
	EdgeControllerMember      EdgeTypeName = "CONTROLLER_MEMBER_OF_CLUSTER"
)

// Edge is one derived canonical edge with its contract rank (§8.2): ranks 1–5
// observed/authoritative, 6 inferred, 7 candidate.
type Edge struct {
	Type EdgeTypeName
	From string // canonical entity id
	To   string
	Rank int
}

// Authoritative reports whether the edge may be treated as observed (§3).
func (e Edge) Authoritative() bool { return e.Rank <= 5 }

// tunnelsToController decides whether client DATA is encapsulated to the
// controller for this AP: central and mixed forwarding tunnel (mixed = at
// least one WLAN's traffic rides the tunnel); local and unknown do NOT — an
// unknown forwarding mode must not fabricate a data-path edge (fail closed:
// we under-claim the topology, never invent it).
func tunnelsToController(ap AccessPoint, c *Controller) bool {
	mode := ap.ForwardingMode
	if mode == "" || mode == ForwardUnknown {
		if c != nil {
			mode = c.ForwardingDefault
		}
	}
	return mode == ForwardCentral || mode == ForwardMixed
}

// DeriveEdges computes the canonical edge set for one tenant's inventory.
// Deterministic: input order preserved, no clocks, no randomness.
func DeriveEdges(inv Inventory) []Edge {
	var out []Edge
	ctrl := map[string]*Controller{}
	for i := range inv.Controllers {
		c := &inv.Controllers[i]
		ctrl[c.ControllerID] = c
		for _, m := range c.Members {
			out = append(out, Edge{EdgeControllerMember,
				MemberEntityID(c.ControllerID, m.MemberID),
				ControllerEntityID(c.ControllerID), 1})
		}
	}
	for _, ap := range inv.APs {
		apEID := APEntityID(ap.APID)
		if ap.UplinkSwitchRef != "" && ap.UplinkPortRef != "" {
			// The rank-1 wireless↔LAN join: the uplink names an ORDINARY
			// interface entity owned by the LAN domain.
			out = append(out, Edge{EdgeAPUplinksViaPort, apEID,
				ap.UplinkSwitchRef + ":" + ap.UplinkPortRef, 1})
		}
		for _, r := range ap.Radios {
			out = append(out, Edge{EdgeRadioOnAP, RadioEntityID(ap.APID, r.Slot), apEID, 1})
		}
		c := ctrl[ap.ControllerRef]
		if ap.ControllerRef != "" && (c == nil || c.ClusterRole != ClusterControllerless) {
			out = append(out, Edge{EdgeAPManagedByController, apEID,
				ControllerEntityID(ap.ControllerRef), 3})
			if tunnelsToController(ap, c) {
				out = append(out, Edge{EdgeAPTunnelsToController, apEID,
					ControllerEntityID(ap.ControllerRef), 3})
			}
		}
	}
	for _, r := range inv.Radios {
		out = append(out, Edge{EdgeRadioOnAP, RadioEntityID(r.APID, r.Slot),
			APEntityID(r.APID), 1})
	}
	for _, b := range inv.BSSIDs {
		bEID := "bssid-" + b.BSSID
		if b.RadioRef != "" {
			out = append(out, Edge{EdgeBSSIDOnRadio, bEID, b.RadioRef, 1})
		}
		if b.WLANRef != "" {
			out = append(out, Edge{EdgeBSSIDServesWLAN, bEID, WLANEntityID(b.WLANRef), 1})
		}
	}
	for _, w := range inv.WLANs {
		if w.SSIDRef != "" {
			out = append(out, Edge{EdgeWLANBroadcastsSSID, WLANEntityID(w.WLANID),
				"ssid-" + w.SSIDRef, 1})
		}
	}
	return out
}

// HasEdge reports whether the derived set contains an edge of the given type
// between the two endpoints ("" matches any endpoint) — the proof-matrix
// helper.
func HasEdge(edges []Edge, t EdgeTypeName, from, to string) bool {
	for _, e := range edges {
		if e.Type == t && (from == "" || e.From == from) && (to == "" || e.To == to) {
			return true
		}
	}
	return false
}
