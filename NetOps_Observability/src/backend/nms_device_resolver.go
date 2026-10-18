// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/nms"
)

// nms_device_resolver.go — maps a controller's key for a device (vManage
// system-ip, Meraki serial, …) to the inventory id of the same device, so a
// controller alarm and the device's own syslog/traps/flows are one entity
// (nms/identity.go explains why the join is at ingest).
//
// Owner-strict: only devices the integration's OWN owner owns are candidates.
// A tenant's integration never matches another tenant's device or a platform
// one; a platform-owned integration matches only platform devices. A key that
// matches nothing, matches more than one device, or that two evidence tiers
// attribute to different devices, resolves to nothing (the controller's key is
// kept). A wrong merge would pin one device's outage on another.

// ownerKey is the index's spelling of a device or integration owner. The
// platform realm has two spellings — "" on devices ("untagged = platform") and
// "global" on what a Global-view principal creates — and they are one owner.
// Real tenant ids pass through untouched, so two tenants never collapse.
func ownerKey(t string) string {
	t = normTenant(t)
	if t == TenantGlobal {
		return ""
	}
	return t
}

// nmsDeviceIndex is one immutable snapshot of the candidate devices.
type nmsDeviceIndex struct {
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

// buildNMSDeviceIndex indexes devices by every key a controller may use.
// sysIPs is the SD-WAN overlay's tenant → system-ip → device map; ifAddrs is
// device → interface IP set. Pure: tests drive it directly.
func buildNMSDeviceIndex(devs []models.Device, sysIPs map[string]map[string]string, ifAddrs map[string]map[string]string) *nmsDeviceIndex {
	idx := &nmsDeviceIndex{
		sysIP: map[string]map[string]string{}, addr: map[string]map[string]string{},
		name: map[string]map[string]string{}, serial: map[string]map[string]string{},
	}
	tenantOf := make(map[string]string, len(devs))
	for _, d := range devs {
		if d.ID == "" {
			continue
		}
		t := ownerKey(d.TenantID)
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
			if tenantOf[dev] == ownerKey(t) {
				addKey(idx.sysIP, ownerKey(t), sys, dev)
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
func (idx *nmsDeviceIndex) lookup(tenant string, kind nms.KeyKind, key, name string) (string, resolveOutcome) {
	t := ownerKey(tenant)
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
	case nms.KeySystemIP:
		tiers = []tier{{idx.sysIP, ipKey}, {idx.addr, ipKey}, nameTier}
	case nms.KeyIP:
		tiers = []tier{{idx.addr, ipKey}, nameTier}
	case nms.KeySerial:
		tiers = []tier{{idx.serial, strings.ToUpper(key)}, nameTier}
	case nms.KeyName:
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

// nmsDeviceResolver is the runtime's DeviceResolver: a periodically rebuilt
// index plus outcome counters.
type nmsDeviceResolver struct {
	idx      atomic.Pointer[nmsDeviceIndex]
	outcomes [5]atomic.Int64 // indexed by resolveOutcomes()
}

// resolveOutcomes is every outcome, in exposition order.
func resolveOutcomes() [5]resolveOutcome {
	return [5]resolveOutcome{resolveMatched, resolveNoMatch, resolveAmbiguous, resolveConflict, resolveNoIndex}
}

func (r *nmsDeviceResolver) count(o resolveOutcome) {
	for i, x := range resolveOutcomes() {
		if x == o {
			r.outcomes[i].Add(1)
			return
		}
	}
}

// ResolveDevice implements nms.DeviceResolver.
func (r *nmsDeviceResolver) ResolveDevice(tenant string, kind nms.KeyKind, key, name string) (string, bool) {
	idx := r.idx.Load()
	if idx == nil {
		r.count(resolveNoIndex) // before the first build: keep the controller key
		return "", false
	}
	id, o := idx.lookup(tenant, kind, key, name)
	r.count(o)
	return id, o == resolveMatched
}

func (r *nmsDeviceResolver) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP netops_nms_device_resolve_total Controller device keys resolved to an inventory device, by outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_nms_device_resolve_total counter\n")
	for i, o := range resolveOutcomes() {
		fmt.Fprintf(w, "netops_nms_device_resolve_total{result=%q} %d\n", o, r.outcomes[i].Load())
	}
}

// nmsResolverRefresh is how often the index is rebuilt from inventory.
const nmsResolverRefresh = time.Minute

// rebuild snapshots inventory, the overlay and interface addresses. An unread
// interface-address registry builds without those rows (fewer matches, never
// wrong ones) and is logged.
func (s *server) rebuildNMSDeviceIndex(ctx context.Context) {
	if s.nmsResolver == nil || s.discovery == nil {
		return
	}
	ifaddr, err := collectors.FetchIfAddrMap(ctx)
	if err != nil {
		logWarn("nms", "interface addresses unread — controller devices are matched by system-ip and name only this cycle", map[string]any{"error": err.Error()})
		ifaddr = nil
	}
	var sys map[string]map[string]string
	if snap := s.sdwanOverlay.Load(); snap != nil {
		sys = snap.res.SystemIPs
	}
	s.nmsResolver.idx.Store(buildNMSDeviceIndex(s.discovery.Devices(), sys, ifaddr))
}

// runNMSDeviceResolver rebuilds the index every nmsResolverRefresh until ctx
// ends. Blocking: started as a supervised worker beside the NMS scheduler.
func (s *server) runNMSDeviceResolver(ctx context.Context) {
	t := time.NewTicker(nmsResolverRefresh)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		s.rebuildNMSDeviceIndex(rctx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
