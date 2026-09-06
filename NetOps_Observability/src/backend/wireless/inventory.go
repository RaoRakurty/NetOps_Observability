// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wireless

// Inventory is one connector poll's canonical-inventory output — what a
// vendor transformer discovered this cycle. The runtime upserts it into the
// wireless store; the transformer never touches storage (nms §4 isolation:
// transformers are pure).
//
// Radios ride separately from APs because vendors report them on separate
// streams (a radio-oper poll must not clobber AP fields it did not fetch);
// the store overlays radios onto their AP by APID at read.
type Inventory struct {
	Controllers []Controller
	APs         []AccessPoint
	Radios      []Radio
	WLANs       []WLAN
	BSSIDs      []BSSID
}

// Merge appends other into inv (nil-safe on other).
func (inv *Inventory) Merge(other *Inventory) {
	if other == nil {
		return
	}
	inv.Controllers = append(inv.Controllers, other.Controllers...)
	inv.APs = append(inv.APs, other.APs...)
	inv.Radios = append(inv.Radios, other.Radios...)
	inv.WLANs = append(inv.WLANs, other.WLANs...)
	inv.BSSIDs = append(inv.BSSIDs, other.BSSIDs...)
}

// Empty reports whether the inventory carries nothing.
func (inv *Inventory) Empty() bool {
	return inv == nil || (len(inv.Controllers) == 0 && len(inv.APs) == 0 &&
		len(inv.Radios) == 0 && len(inv.WLANs) == 0 && len(inv.BSSIDs) == 0)
}
