package main

// cloud_monitor_eval.go — main-side wiring for the cloud monitor evaluator
// (cloud.MonitorEvaluator, extracted P2 W4.18): the production seams (the
// tenant-scoped cloud inventory, shared vmQuery, the notifier) and the
// CLOUD_MONITOR_EVAL_SECONDS env read.

import (
	"context"
	"strconv"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/models"
)

const cloudMonitorDefaultIntervalS = 60

// newCloudMonitorEvaluator wires the production seams: the tenant-scoped cloud
// inventory and the shared vmQuery/notify plumbing.
func newCloudMonitorEvaluator(s *server, interval time.Duration) *cloud.MonitorEvaluator {
	return cloud.NewMonitorEvaluator(s.cloudMonitors, cloud.MonitorEvalDeps{
		ResourceIDs: func(ctx context.Context, tenant string) ([]string, error) {
			res, err := s.cloud.ListResources(ctx, tenant, false)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(res))
			for _, r := range res {
				ids = append(ids, r.ResourceID)
			}
			return ids, nil
		},
		Query:   vmQuery,
		Fire:    func(a models.Alert) { s.notifier.Dispatch(a) },
		Resolve: func(a models.Alert) { s.notifier.DispatchResolve(a) },
	}, interval)
}

// cloudMonitorEvalInterval reads CLOUD_MONITOR_EVAL_SECONDS (default 60;
// "0"/"off" disables the loop → returns 0).
func cloudMonitorEvalInterval() time.Duration {
	raw := strings.ToLower(strings.TrimSpace(envOr("CLOUD_MONITOR_EVAL_SECONDS", strconv.Itoa(cloudMonitorDefaultIntervalS))))
	if raw == "0" || raw == "off" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 5 {
		n = cloudMonitorDefaultIntervalS
	}
	return time.Duration(n) * time.Second
}
