// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"netops/backend/models"
)

// inventory_resolver.go — the DeviceResolver over Correlix inventory: maps a
// controller's key for a device (vManage system-ip, Meraki serial, …) to the
// inventory id of the same device, so a controller alarm and the device's own
// syslog/traps/flows are one entity (identity.go explains why the join is at
// ingest). The api builds an index from inventory every minute and Stores it.
//
// Tenant-strict: only devices the integration's OWN tenant owns are
// candidates — never another tenant's, never the platform realm's. A key that
// matches nothing, matches more than one device, or that two evidence tiers
// attribute to different devices, resolves to nothing (the controller's key is
// kept). A wrong merge would pin one device's outage on another.

// ownerOf is the index's spelling of an owner (tenant ids are compared
// lower-cased and trimmed, as everywhere else).
func ownerOf(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// InventoryIndex is one immutable snapshot of the candidate devices.
type InventoryIndex struct {
	// tenant → key → device id; "" marks a key two devices share (ambiguous).
	sysIP  map[string]map[string]string // device-reported SD-WAN system-ip
	addr   map[string]map[string]string // management address or interface IP
	name   map[string]map[string]string // lower-cased hostname
	serial map[string]map[string]string // upper-cased chassis serial
}

func addKey(m map[string]map[string]string, tenant, key, dev string) {
	if key == "" || dev == "" {
		return
	}
	if m[tenant] == nil {
		m[tenant] = map[string]string{}
	}
	if prev, ok := m[tenant][key]; ok && prev != dev {
		m[tenant][key] = "" // two devices claim it
		return
	}
	m[tenant][key] = dev
}

// BuildInventoryIndex indexes devices by every key a controller may use.
// sysIPs is the SD-WAN overlay's tenant → system-ip → device map; ifAddrs is
// device → interface IP set. Pure: tests drive it directly.
func BuildInventoryIndex(devs []models.Device, sysIPs map[string]map[string]string, ifAddrs map[string]map[string]string) *InventoryIndex {
	idx := &InventoryIndex{
		sysIP: map[string]map[string]string{}, addr: map[string]map[string]string{},
		name: map[string]map[string]string{}, serial: map[string]map[string]string{},
	}
	tenantOf := make(map[string]string, len(devs))
	for _, d := range devs {
		if d.ID == "" {
			continue
		}
		t := ownerOf(d.TenantID)
		tenantOf[d.ID] = t
		if ip := net.ParseIP(strings.TrimSpace(d.Address)); ip != nil {
			addKey(idx.addr, t, ip.String(), d.ID)
		}
		addKey(idx.name, t, strings.ToLower(strings.TrimSpace(d.Name)), d.ID)
		for _, s := range []string{d.SerialNumber, d.Labels["serial"]} {
			addKey(idx.serial, t, strings.ToUpper(strings.TrimSpace(s)), d.ID)
		}
	}
	for dev, ips := range ifAddrs {
		t, ok := tenantOf[dev]
		if !ok {
			continue // an address of a device no longer in inventory
		}
		for ip := range ips {
			if p := net.ParseIP(ip); p != nil {
				addKey(idx.addr, t, p.String(), dev)
			}
		}
	}
	for t, m := range sysIPs {
		for sys, dev := range m {
			// The overlay already drops ambiguous system-ips; keep its tenant
			// honest too — only a device that tenant owns.
			if tenantOf[dev] == ownerOf(t) {
				addKey(idx.sysIP, ownerOf(t), sys, dev)
			}
		}
	}
	return idx
}

// resolveOutcome is the result class counted in the resolver metric.
type resolveOutcome string

const (
	resolveMatched   resolveOutcome = "matched"
	resolveNoMatch   resolveOutcome = "no_match"
	resolveAmbiguous resolveOutcome = "ambiguous"
	resolveConflict  resolveOutcome = "conflict"
	resolveNoIndex   resolveOutcome = "no_index"
)

// lookup applies the trust ladder for kind. Every tier that knows the key
// votes; an ambiguous tier, or two tiers naming different devices, abstains.
func (idx *InventoryIndex) lookup(tenant string, kind KeyKind, key, name string) (string, resolveOutcome) {
	t := ownerOf(tenant)
	key = strings.TrimSpace(key)
	ipKey := ""
	if p := net.ParseIP(key); p != nil {
		ipKey = p.String()
	}
	type tier struct {
		m   map[string]map[string]string
		key string
	}
	nameTier := tier{idx.name, strings.ToLower(strings.TrimSpace(name))}
	var tiers []tier
	switch kind {
	case KeySystemIP:
		tiers = []tier{{idx.sysIP, ipKey}, {idx.addr, ipKey}, nameTier}
	case KeyIP:
		tiers = []tier{{idx.addr, ipKey}, nameTier}
	case KeySerial:
		tiers = []tier{{idx.serial, strings.ToUpper(key)}, nameTier}
	case KeyName:
		tiers = []tier{{idx.name, strings.ToLower(key)}}
	default:
		return "", resolveNoMatch
	}
	found := ""
	for _, tr := range tiers {
		if tr.key == "" {
			continue
		}
		dev, ok := tr.m[t][tr.key]
		switch {
		case !ok:
			continue
		case dev == "":
			return "", resolveAmbiguous
		case found != "" && found != dev:
			return "", resolveConflict
		}
		found = dev
	}
	if found == "" {
		return "", resolveNoMatch
	}
	return found, resolveMatched
}

// InventoryResolver is the runtime's DeviceResolver: a periodically rebuilt
// index plus outcome counters.
type InventoryResolver struct {
	idx      atomic.Pointer[InventoryIndex]
	outcomes [5]atomic.Int64 // indexed by resolveOutcomes()
}

// resolveOutcomes is every outcome, in exposition order.
func resolveOutcomes() [5]resolveOutcome {
	return [5]resolveOutcome{resolveMatched, resolveNoMatch, resolveAmbiguous, resolveConflict, resolveNoIndex}
}

func (r *InventoryResolver) count(o resolveOutcome) {
	for i, x := range resolveOutcomes() {
		if x == o {
			r.outcomes[i].Add(1)
			return
		}
	}
}

// Store installs a freshly built index (nil keeps every key unresolved).
func (r *InventoryResolver) Store(idx *InventoryIndex) { r.idx.Store(idx) }

// ResolveDevice implements DeviceResolver.
func (r *InventoryResolver) ResolveDevice(tenant string, kind KeyKind, key, name string) (string, bool) {
	idx := r.idx.Load()
	if idx == nil {
		r.count(resolveNoIndex) // before the first build: keep the controller key
		return "", false
	}
	id, o := idx.lookup(tenant, kind, key, name)
	r.count(o)
	return id, o == resolveMatched
}

// WriteMetrics renders the outcome counters (Prometheus exposition).
func (r *InventoryResolver) WriteMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP netops_nms_device_resolve_total Controller device keys resolved to an inventory device, by outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_nms_device_resolve_total counter\n")
	for i, o := range resolveOutcomes() {
		fmt.Fprintf(w, "netops_nms_device_resolve_total{result=%q} %d\n", o, r.outcomes[i].Load())
	}
}
