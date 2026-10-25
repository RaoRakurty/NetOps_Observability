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
	"time"

	"netops/backend/collectors"
	"netops/backend/nms"
)

type nmsRuntime = nms.Runtime

// newNMSRuntime builds the runtime over main's sinks. Dormant unless
// FEATURE_NMS_INTEGRATIONS=true (main.go gates construction).
func newNMSRuntime(store nms.ConfigStore) *nmsRuntime {
	rt := nms.NewRuntime(store, nms.Sinks{
		EmitMetrics:   nmsEmitMetrics,
		ProduceEvents: nmsProduceEvents,
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
