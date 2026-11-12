// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bgp_alerts_audience_test.go — tracker 359: who a tenant's BGP-watch alert
// actually reaches.
//
// Tenants have no alert channels today. The notifier the evaluator rides holds
// the PLATFORM-GLOBAL channel list (platform-admin configured, a cross-tenant
// audience), so the alert reaches the platform operator — and the one global
// destination that PAGES, the PagerDuty key, is wrapped in
// notify.PlatformScopeFilter, which forwards only platform self-health
// (`layer` ∈ PlatformLayers). This pins the half of that statement the code
// enforces: a customer BGP alert, fired or resolved, never pages the platform
// key, and it carries the evaluator's tenant (never a platform layer) so a
// future per-tenant router has the attribution it needs.

import (
	"sync"
	"testing"
	"time"

	"netops/backend/internal/bgpwatch"
	"netops/backend/models"
	"netops/backend/notify"
)

// bgpAudienceProbe records every send/resolve that gets past the filter.
type bgpAudienceProbe struct {
	mu       sync.Mutex
	sent     []models.Alert
	resolved []models.Alert
}

func (p *bgpAudienceProbe) Name() string { return "pagerduty" }

func (p *bgpAudienceProbe) Send(a models.Alert) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, a)
	return nil
}

func (p *bgpAudienceProbe) SendResolve(a models.Alert) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolved = append(p.resolved, a)
	return nil
}

func TestBGPWatchAlertsNeverPageThePlatformKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cleared := now.Add(time.Minute)
	cases := map[string]bgpwatch.Alert{
		"prefix origin change (hijack)": {
			ID: "bgp:acme:203.0.113.0/24:origin_change", Rule: "bgp_origin_change", Severity: bgpwatch.SevHigh,
			Tenant: "acme", Resource: "203.0.113.0/24", Class: bgpwatch.ClassOriginChange,
			Summary: "origin changed", FiredAt: now,
			Labels: map[string]string{"prefix": "203.0.113.0/24", "class": "origin_change", "source": "bgp-watch"},
		},
		"peer down": {
			ID: "bgp:acme:peer:r1|192.0.2.1", Rule: "bgp_peer_down", Severity: bgpwatch.SevHigh,
			Tenant: "acme", Resource: "r1", Class: bgpwatch.ClassNone, FiredAt: now,
			Labels: map[string]string{"device": "r1", "peer": "192.0.2.1", "source": "bgp-watch"},
		},
		"peer back up (resolution)": {
			ID: "bgp:acme:peer:r1|192.0.2.1", Rule: "bgp_peer_down", Severity: bgpwatch.SevHigh,
			Tenant: "acme", Resource: "r1", FiredAt: now, Resolved: true, ResolvedAt: &cleared,
		},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			a := bgpWatchAlertToModel(in)
			if got := a.Labels["tenant"]; got != "acme" {
				t.Fatalf("tenant label = %q, want the evaluator's tenant %q", got, "acme")
			}
			if layer, ok := a.Labels["layer"]; ok {
				t.Fatalf("customer BGP alert carries layer=%q — a platform layer would page the global key", layer)
			}

			probe := &bgpAudienceProbe{}
			key := notify.NewPlatformScopeFilter(probe)
			if err := key.Send(a); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if err := key.SendResolve(a); err != nil {
				t.Fatalf("SendResolve: %v", err)
			}
			if len(probe.sent) != 0 || len(probe.resolved) != 0 {
				t.Fatalf("tenant BGP alert reached the platform paging key: sent=%d resolved=%d",
					len(probe.sent), len(probe.resolved))
			}
		})
	}
}
