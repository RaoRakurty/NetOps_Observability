package main

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

	"netops/backend/nms"
)

type nmsRuntime = nms.Runtime

// newNMSRuntime builds the runtime over main's sinks. Dormant unless
// FEATURE_NMS_INTEGRATIONS=true (main.go gates construction).
func newNMSRuntime(store nms.ConfigStore) *nmsRuntime {
	return nms.NewRuntime(store, nms.Sinks{
		EmitMetrics:   nmsEmitMetrics,
		ProduceEvents: nmsProduceEvents,
	}, durationOr("NMS_BACKFILL", nms.DefaultBackfill))
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
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("victoria import: status %d", resp.StatusCode)
	}
	return nil
}
