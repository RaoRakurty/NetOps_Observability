// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nms_scheduler.go — main-side wiring for the NMS poll runtime (nms.Runtime,
// extracted P2 W4.17). This file owns the entrypoint transports the runtime
// fans to: the VictoriaMetrics push (env-derived URL) and the bus producer
// (per-tenant-keyed produceJSON), plus the NMS_BACKFILL env read.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/nms"
)

type nmsRuntime = nms.Runtime

// newNMSRuntime builds the runtime over main's sinks. Dormant unless
// FEATURE_NMS_INTEGRATIONS=true (main.go gates construction).
func newNMSRuntime(store nms.ConfigStore) *nmsRuntime {
	rt := nms.NewRuntime(store, nms.Sinks{
		EmitMetrics:      nmsEmitMetrics,
		ProduceEvents:    nmsProduceEvents,
		EmitMetricEvents: nmsEmitMetricEvents,
	}, durationOr("NMS_BACKFILL", nms.DefaultBackfill))
	// Worker pool + per-integration deadline (NMS-first T1): NMS_POLL_WORKERS
	// is clamped to [1,16] (default 4); NMS_POLL_DEADLINE caps one cycle
	// (default 120s; the effective deadline is min(interval, this)).
	rt.SetPoolOptions(envInt("NMS_POLL_WORKERS", nms.DefaultPollWorkers),
		durationOr("NMS_POLL_DEADLINE", nms.DefaultPollDeadline))
	return rt
}

// nmsProduceEvents publishes controller events to netops.controller_events,
// keyed by tenant for per-tenant ordering.
func nmsProduceEvents(ctx context.Context, tenant string, events []nms.ControllerEvent) (int64, error) {
	recs := make([]proxyRecord, 0, len(events))
	for _, ev := range events {
		recs = append(recs, proxyRecord{Key: tenant, Value: ev})
	}
	if _, err := produceJSON(ctx, nms.TopicControllerEvents, recs); err != nil {
		return 0, err
	}
	return int64(len(recs)), nil
}

// controllerMetricEvent is the engine's MetricEvent contract
// (collectors.MetricEvent, src/correlation handle_metric) plus the tenant the
// integration belongs to. SNMP events carry no tenant — the aggregator's
// metrics lane derives it from the device registry — but a controller-only
// device is in no registry, so the integration's tenant is stamped here and
// the record travels the bus bridge (like controller events) instead of the
// metrics HTTP lane, which resets tenant_id. The metric lane is not
// registry-anchored, so the engine accepts the claim unless the registry
// contradicts it.
type controllerMetricEvent struct {
	collectors.MetricEvent
	TenantID string `json:"tenant_id"`
}

// nmsEmitMetricEvents forwards a connector's canonical device_* samples to the
// correlation engine's metric lane (source-equivalence E3), keyed by tenant.
// collection_path via_controller puts them in the controller authority bucket
// (verdicts.py), so a relayed counter never pairs with the controller's other
// evidence as an independent witness.
func nmsEmitMetricEvents(ctx context.Context, tenant string, metrics []nms.ControllerMetric) error {
	recs := make([]proxyRecord, 0, len(metrics))
	for _, m := range metrics {
		family, ok := nms.CanonicalDeviceMetricFamily(m.Name)
		dev := strings.TrimSpace(m.Tags["device"])
		if !ok || dev == "" || m.Time.IsZero() {
			continue
		}
		recs = append(recs, proxyRecord{Key: tenant, Value: controllerMetricEvent{
			MetricEvent: collectors.MetricEvent{
				ObserverType:   "controller",
				ModalityClass:  "device_telemetry",
				CollectionPath: "via_controller",
				Device:         dev,
				Vendor:         m.SourceSystem,
				IfName:         m.Tags["ifName"],
				SignalFamily:   family,
				Metric:         m.Name,
				Value:          m.Value,
				Unit:           m.Unit,
				TS:             m.Time.UTC().Format(time.RFC3339Nano),
			},
			TenantID: tenant,
		}})
	}
	if len(recs) == 0 {
		return nil
	}
	_, err := produceJSON(ctx, nms.TopicMetrics, recs)
	return err
}

// nmsEmitMetrics pushes Prometheus exposition lines to VictoriaMetrics
// (same lane as collectors/poller.go emitMetrics; that helper is unexported in
// a sibling package, so the ~15 lines are mirrored here).
func nmsEmitMetrics(ctx context.Context, lines []string) error {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", ""))
	if base == "" {
		return nil // no metrics backend configured — not an error
	}
	url := strings.TrimRight(base, "/") + "/api/v1/import/prometheus"
	body := strings.Join(lines, "\n") + "\n"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	// The hardened internal-backend client, NOT a bare &http.Client{}: with
	// vmauth in front of VictoriaMetrics this hop is https with URL-userinfo
	// credentials, and the bare client failed the mesh CA (2026-08-05).
	resp, err := backendHTTPClient(5 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode >= 300 {
		return fmt.Errorf("victoria import: status %d", resp.StatusCode)
	}
	return nil
}

// --- controller → inventory device join (nms/inventory_resolver.go) ---

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
	s.nmsResolver.Store(nms.BuildInventoryIndex(s.discovery.Devices(), sys, ifaddr))
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

// --- trap receiver interface-address rung and ifIndex names ---
//
// The trap receiver's interface-address rung (tracker 387
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

// runTrapAddressIndex wires the rung and the ifIndex names into the receiver
// and keeps them fresh until ctx ends. Blocking: Run starts it through the
// drain group.
func (s *server) runTrapAddressIndex(ctx context.Context) {
	if s.collectors == nil || s.discovery == nil {
		return
	}
	t := &trapAddrIndex{}
	s.collectors.SetTrapAddressResolver(t.resolve)
	s.collectors.SetTrapIfNameResolver(t.ifName)
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
}
