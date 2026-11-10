// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"fmt"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/flownames"
	"netops/backend/internal/ifbridge"
	"netops/backend/models"
	"netops/backend/nms"
)

// if_bridge.go — the interface bridge as ONE map from both feeders (tracker 387
// PR 13a; internal/ifbridge holds the rules).
//
// The SNMP collector publishes interface address → ifName and ifIndex → ifName
// per device; the NMS runtime hands each controller's interface list to
// ingestNMSInterfaces, resolved to the inventory device the integration's own
// owner owns. runIfaceBridge projects the NMS rows onto the current inventory
// every minute and stores them; fetchIfBridge merges both halves for every
// consumer: the entity-resolver export (engine), the trap receiver's address
// rung and ifIndex names, the flows interface names, topology and paths.
//
// The controller-key resolver (rebuildNMSDeviceIndex) keeps reading the SNMP
// map ALONE: an address a controller reported must never help that same
// controller's key resolve, or a wrong match could feed itself.

// ifBridgeRefresh is how often the NMS rows are projected, stored and counted.
const ifBridgeRefresh = time.Minute

// samePort is the merge's port comparison: the canonical key topology uses, so
// "Gi3" (SNMP ifName) and "GigabitEthernet3" (vManage) are one port.
func samePort(a, b string) bool { return canonIface(a) == canonIface(b) }

// ifBridgeIO is the bridge's key-value IO: the collectors functions in
// production, fakes in tests (§1: every dependency explicit).
type ifBridgeIO struct {
	snmpAddr  func(context.Context) (map[string]map[string]string, error)
	snmpIndex func(context.Context) (map[string]map[string]string, error)
	snmpAlias func(context.Context) (map[string]map[string]string, error)
	snmpAges  func(context.Context) (collectors.SNMPIfRowAges, error)
	nmsRows   func(context.Context) (ifbridge.State, error)
	publish   func(context.Context, ifbridge.State) error
}

// liveIfBridgeIO is the production IO.
func liveIfBridgeIO() ifBridgeIO {
	return ifBridgeIO{
		snmpAddr: collectors.FetchIfAddrMap, snmpIndex: collectors.FetchIfIndexMap,
		snmpAlias: collectors.FetchIfAliasMap, snmpAges: collectors.FetchSNMPIfRowAges,
		nmsRows: collectors.FetchNMSIfRows, publish: collectors.PublishNMSIfRows,
	}
}

// fetchIfBridge reads both halves of the bridge and merges them. Any half that
// could not be read is an error: callers keep their previous answer rather than
// proceed on a bridge missing a feeder (tracker 307).
func fetchIfBridge(ctx context.Context) (ifbridge.Merged, error) {
	return liveIfBridgeIO().fetch(ctx, time.Now())
}

func (kv ifBridgeIO) fetch(ctx context.Context, now time.Time) (ifbridge.Merged, error) {
	nmsRows, err := kv.nmsRows(ctx)
	if err != nil {
		return ifbridge.Merged{}, fmt.Errorf("NMS interface rows unread: %w", err)
	}
	nmsRows.Sanitize(now)
	return kv.merge(ctx, nmsRows, nil)
}

// merge reads the SNMP half and merges it with the given NMS rows. owners
// (device id → owner), when given, counts shared addresses.
func (kv ifBridgeIO) merge(ctx context.Context, nmsRows ifbridge.State, owners map[string]string) (ifbridge.Merged, error) {
	addr, err := kv.snmpAddr(ctx)
	if err != nil {
		return ifbridge.Merged{}, err
	}
	idx, err := kv.snmpIndex(ctx)
	if err != nil {
		return ifbridge.Merged{}, err
	}
	alias, err := kv.snmpAlias(ctx)
	if err != nil {
		return ifbridge.Merged{}, err
	}
	ages, err := kv.snmpAges(ctx)
	if err != nil {
		return ifbridge.Merged{}, err
	}
	return ifbridge.Merge(ifbridge.SNMP{
		Addr: addr, Index: idx, Alias: alias, AddrAt: ages.Addr, IndexAt: ages.Index,
	}, nmsRows, samePort, owners), nil
}

// fetchIfAddrMap is the merged device → interface IP → ifName map.
func fetchIfAddrMap(ctx context.Context) (map[string]map[string]string, error) {
	m, err := fetchIfBridge(ctx)
	if err != nil {
		return map[string]map[string]string{}, err
	}
	return m.Addr, nil
}

// fetchIfIndexMap is the merged device → ifIndex → ifName map.
func fetchIfIndexMap(ctx context.Context) (map[string]map[string]string, error) {
	m, err := fetchIfBridge(ctx)
	if err != nil {
		return map[string]map[string]string{}, err
	}
	return m.Index, nil
}

// fetchIfaceNamesBridge is the merged bridge as the netops.iface_names export
// reads it: names, descriptions (ifalias) and the source of each name.
func fetchIfaceNamesBridge(ctx context.Context) (flownames.Bridge, error) {
	m, err := fetchIfBridge(ctx)
	if err != nil {
		return flownames.Bridge{}, err
	}
	return flownames.Bridge{Index: m.Index, Alias: m.Alias, Source: m.IndexSource}, nil
}

// ingestNMSInterfaces is the NMS runtime's interface sink (nms.Sinks). The
// owner is the integration's, stamped by the runtime from its record.
func (s *server) ingestNMSInterfaces(tenant, integrationID, sourceSystem string, ifaces []nms.ControllerInterface) {
	if s.ifBridge == nil {
		return
	}
	recs := make([]ifbridge.Record, 0, len(ifaces))
	for _, c := range ifaces {
		recs = append(recs, ifbridge.Record{
			DeviceID: c.DeviceID, Resolve: c.Resolve, At: c.Time,
			Row: ifbridge.Row{IfIndex: c.IfIndex, IfName: c.IfName, VRF: c.VRF, Alias: c.Description, Addrs: c.Addrs},
		})
	}
	s.ifBridge.Ingest(tenant, integrationID, sourceSystem, recs, time.Now())
}

// inventoryOwners maps every inventory device id to its owner.
func inventoryOwners(devs []models.Device) map[string]string {
	out := make(map[string]string, len(devs))
	for _, d := range devs {
		if d.ID != "" {
			out[d.ID] = deviceTenant(d)
		}
	}
	return out
}

// ifBridgeCycle is one minute of the bridge: project, store, count. loaded
// reports whether the persisted rows have been read back; until they have, the
// state is not stored, because writing now would overwrite rows this api has
// not yet managed to read (the SNMP side's rule, if_rows_retention.go).
func (s *server) ifBridgeCycle(ctx context.Context, kv ifBridgeIO, devs []models.Device, loaded *bool, now time.Time) {
	if !*loaded {
		st, err := kv.nmsRows(ctx)
		if err != nil {
			s.ifBridgeMetrics.ReadFailed()
			logWarn("if-bridge", "stored NMS interface rows unread: retrying next cycle, and not storing until then", map[string]any{"error": err.Error()})
		} else {
			s.ifBridge.Load(st, now)
			*loaded = true
		}
	}
	owners := inventoryOwners(devs)
	st, snap := s.ifBridge.Snapshot(owners, now)
	if *loaded {
		if err := kv.publish(ctx, st); err != nil {
			s.ifBridgeMetrics.PublishFailed()
			logError("if-bridge", "NMS interface rows not stored: consumers keep the previous rows until the next cycle", map[string]any{"error": err.Error()})
		} else {
			s.ifBridgeMetrics.Published(now.Unix())
		}
	}
	merged, err := kv.merge(ctx, st, owners)
	if err != nil {
		s.ifBridgeMetrics.ReadFailed()
		logWarn("if-bridge", "SNMP interface rows unread: the bridge counts keep their last values", map[string]any{"error": err.Error()})
		return
	}
	s.ifBridgeMetrics.Set(merged.Stats, s.ifBridge.IngestCounts(), snap)
}

// runIfaceBridge runs ifBridgeCycle every ifBridgeRefresh until ctx ends.
// Blocking: Run starts it through the drain group.
func (s *server) runIfaceBridge(ctx context.Context) {
	if s.ifBridge == nil || s.ifBridgeMetrics == nil || s.discovery == nil {
		return
	}
	t := time.NewTicker(ifBridgeRefresh)
	defer t.Stop()
	loaded := false
	kv := liveIfBridgeIO()
	for {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		s.ifBridgeCycle(cctx, kv, s.discovery.Devices(), &loaded, time.Now())
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
