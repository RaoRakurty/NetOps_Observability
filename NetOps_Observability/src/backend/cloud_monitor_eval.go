// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
		Query: vmQuery,
		// The dispatcher is the PLATFORM-GLOBAL channel list (a cross-tenant,
		// platform-admin audience): the platform operator keeps receiving a
		// tenant's monitor edges exactly as before. The alert has no platform
		// `layer` label, so the global PagerDuty key's PlatformScopeFilter
		// never pages for it.
		Fire:    func(a models.Alert) { s.notifier.Dispatch(a) },
		Resolve: func(a models.Alert) { s.notifier.DispatchResolve(a) },
		// Tracker 359 (owner decision 2026-11-12): the SAME edges also go to
		// the owning tenant's own RCA lanes — a cloud monitor is a watch the
		// tenant set up itself. The tenant is the evaluator's loop tenant.
		TenantFire:    s.tenantWatchFire,
		TenantResolve: s.tenantWatchResolve,
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
