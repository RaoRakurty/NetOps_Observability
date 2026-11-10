// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"sync/atomic"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/nms"
)

// trap_addr_index.go: the trap receiver's interface-address rung (tracker 387
// PR 13c'). On the lab 85 % of traps arrived from 192.168.200.33, an interface
// of cedge-81, and were filed under the bare address: evidence RCA could not
// bind to the device.
//
// The receiver asks nms.InventoryIndex.DeviceForAddress, built every minute
// from inventory and the interface addresses the SNMP collector publishes. The
// index answers a device id, never a tenant, and only for an address exactly
// one device holds (internal VPN loopbacks and shared addresses name nobody).
// The receiver still proves that device's credential before using the answer.
//
// Interface addresses are deliberately NOT exported as registry identities
// (device_tenant.csv): the registry is the tenant channel, and an address in it
// would make tenant derivation address-based for every lane that reads it
// (owner rule 2026-11-01: tenant = channel, never address).

// trapAddrIndexRefresh is how often the index is rebuilt.
const trapAddrIndexRefresh = time.Minute

// trapAddrIndex holds the current index for the receiver's callbacks: the
// address index (13c') and the per-device ifIndex → name maps (13c), both
// served from memory so the UDP receive path never waits on a network read.
type trapAddrIndex struct {
	idx   atomic.Pointer[nms.InventoryIndex]
	ifidx atomic.Pointer[map[string]map[string]string]
}

// ifName is the collectors.IfNameFunc: ifIndex on ONE device, from that
// device's own map. Another device's map is never consulted.
func (t *trapAddrIndex) ifName(deviceID, ifIndex string) (string, bool) {
	m := t.ifidx.Load()
	if m == nil {
		return "", false
	}
	n, ok := (*m)[deviceID][ifIndex]
	return n, ok && n != ""
}

// refreshIfNames swaps in a new ifIndex snapshot; an unread bridge keeps the
// last one.
func (t *trapAddrIndex) refreshIfNames(ctx context.Context, read func(context.Context) (map[string]map[string]string, error)) error {
	m, err := read(ctx)
	if err != nil {
		return err
	}
	t.ifidx.Store(&m)
	return nil
}

// resolve is the collectors.TrapAddressResolver the receiver calls.
func (t *trapAddrIndex) resolve(ip string) (string, bool) {
	dev, out := t.idx.Load().DeviceForAddress(ip)
	return dev, out == nms.AddressMatched
}

// rebuild indexes the devices and their interface addresses. An unread
// address registry keeps the previous index: losing every interface address
// for a minute because one read failed would silently un-attribute traps.
func (t *trapAddrIndex) rebuild(ctx context.Context, devs []models.Device, read func(context.Context) (map[string]map[string]string, error)) error {
	ifaddr, err := read(ctx)
	if err != nil {
		if t.idx.Load() == nil {
			t.idx.Store(nms.BuildInventoryIndex(devs, nil, nil))
		}
		return err
	}
	t.idx.Store(nms.BuildInventoryIndex(devs, nil, ifaddr))
	return nil
}

// startTrapAddressIndex wires the rung into the receiver and keeps it fresh.
func (s *server) startTrapAddressIndex(ctx context.Context) {
	if s.collectors == nil || s.discovery == nil {
		return
	}
	t := &trapAddrIndex{}
	s.collectors.SetTrapAddressResolver(t.resolve)
	s.collectors.SetTrapIfNameResolver(t.ifName)
	s.workers.start("trap-addr-index", func() {
		tick := time.NewTicker(trapAddrIndexRefresh)
		defer tick.Stop()
		for {
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := t.rebuild(rctx, s.discovery.Devices(), collectors.FetchIfAddrMap); err != nil {
				logWarn("snmptrap", "interface addresses unread: traps from an interface address keep the previous index this cycle",
					map[string]any{"error": err.Error()})
			}
			if err := t.refreshIfNames(rctx, collectors.FetchIfIndexMap); err != nil {
				logWarn("snmptrap", "ifIndex map unread: trap interfaces keep the previous names this cycle",
					map[string]any{"error": err.Error()})
			}
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	})
}
