// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tenant_watch_delivery.go — main-side wiring for notify.TenantWatchRouter
// (tracker 359, owner decision 2026-11-12): a tenant's OWN watch alerts — its
// BGP-watch prefix classes and its cloud monitors, never BGP peer-down — reach
// that tenant's own incident-policy (RCA) lanes, one message per episode,
// through the platform dispatcher's bounded/retrying delivery pool.
//
// Routing authority is the tenant the SERVER stamped: each evaluator passes its
// own loop tenant. The lane config is read from that tenant's key only, and the
// platform realm (""/"global", the Provider) never resolves — its "" key is the
// platform's own config, not a customer's.
//
// Works the same on-prem and cloud-hosted: the lanes are outbound HTTPS to the
// tenant's own Slack webhook / PagerDuty Events v2 key, through safehttp.

import (
	"netops/backend/internal/applog"
	"netops/backend/internal/owner"
	"netops/backend/models"
	"netops/backend/notify"
)

// tenantWatchFire / tenantWatchResolve are the ONE entry to the tenant watch
// router (nil-safe: a server without one delivers to no tenant lane). tenant
// must be the server-stamped owner — every caller passes its evaluator's own
// tenant, never a label or request value.
func (s *server) tenantWatchFire(tenant string, a models.Alert) {
	s.tenantWatch.Fire(tenant, a)
}

func (s *server) tenantWatchResolve(tenant string, a models.Alert) {
	s.tenantWatch.Resolve(tenant, a)
}

// tenantWatchLanes resolves ONE tenant's lanes that are enabled AND opted
// into watch alerts, from that tenant's own incident-policy (RCA) config.
func (s *server) tenantWatchLanes(tenant string) []notify.TenantLane {
	if s.itsmCfg == nil || owner.IsPlatform(tenant) {
		return nil
	}
	cfg, ok := s.itsmCfg.ConfigFor(tenant)
	if !ok {
		return nil
	}
	return tenantWatchLanesFrom(cfg)
}

// tenantWatchLanesFrom is the pure lane decision: enabled, secret present,
// and opted in (Slack default ON, PagerDuty default OFF).
func tenantWatchLanesFrom(cfg itsmConfig) []notify.TenantLane {
	out := make([]notify.TenantLane, 0, 2)
	if cfg.Slack.Enabled && cfg.Slack.WebhookURL != "" && cfg.Slack.WatchAlertsOn() {
		out = append(out, notify.TenantLane{System: notify.TenantLaneSlack, Secret: cfg.Slack.WebhookURL})
	}
	if cfg.PagerDuty.Enabled && cfg.PagerDuty.RoutingKey != "" && cfg.PagerDuty.WatchAlertsOn() {
		out = append(out, notify.TenantLane{System: notify.TenantLanePagerDuty, Secret: cfg.PagerDuty.RoutingKey})
	}
	return out
}

// newTenantWatchRouter wires the router over the platform dispatcher's
// delivery pool and the tenants' own lane config.
func newTenantWatchRouter(s *server) *notify.TenantWatchRouter {
	return notify.NewTenantWatchRouter(s.notifier, notify.TenantWatchDeps{
		Lanes: s.tenantWatchLanes,
		Log: func(level, msg string, fields map[string]any) {
			applog.Log(level, "notify", msg, fields)
		},
	})
}
