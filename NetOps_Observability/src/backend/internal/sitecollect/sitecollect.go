// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package sitecollect publishes which site every inventory device belongs to,
// so a rule can tell "collection was lost for a whole site" apart from "one
// device is down" (tracker 368).
//
// On 2026-10-20 every SNMP target of one lab site stopped answering at the same
// minute and nobody was told for four days: DeviceUnreachable fires once per
// device and names no site, CollectorAllTargetsUnreachable only sees a whole
// collector, and the page-tier vantages (MonitoredSourcesSilent,
// NMSIngestSilent) only see a whole estate or a whole integration.
//
// The judgement itself is PromQL in src/config/rules.yaml (SiteCollectionLost):
// this package only publishes the membership series
//
//	netops_device_site_info{device, tenant_id, site, site_label} 1
//
// on the api's own /metrics scrape. Keeping the arithmetic in the rule means it
// is unit-tested with promtool beside every other rule, and this package never
// reads VictoriaMetrics (no unscoped metric read exists for it).
//
// The same snapshot answers the alert's OWNER (Owns): a (tenant, site) pair is
// believed only when the api itself published it. A label on an alert is
// telemetry, never an owner (§3a).
package sitecollect

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Membership is one device's resolved site, as the api's site rule decided it.
type Membership struct {
	Device    string // inventory device id (the `device` label of collector series)
	Tenant    string // owning tenant, lower-cased
	Site      string // site key (siteres.Site.Key) — stable, groups devices
	SiteLabel string // what a person reads ("Site 50 · from vManage")
}

// Resolver returns every inventory device's site. Devices without a site are
// simply omitted: a device with no site belongs to no site's count.
type Resolver func(ctx context.Context) ([]Membership, error)

// Metrics names, exported for the rule-coverage tests.
const (
	MetricInfo      = "netops_device_site_info"
	MetricRefreshOK = "netops_device_site_refresh_ok"
	MetricRefreshAt = "netops_device_site_refresh_timestamp_seconds"
)

// Publisher holds the last resolved snapshot. The zero value is not usable;
// build one with New.
type Publisher struct {
	resolve Resolver
	now     func() time.Time

	mu    sync.RWMutex
	rows  []Membership
	pairs map[string]map[string]bool // tenant → site → present
	ok    bool                       // last refresh succeeded
	at    time.Time                  // time of the last SUCCESSFUL refresh
}

// New returns a Publisher over resolve. now may be nil (time.Now).
func New(resolve Resolver, now func() time.Time) *Publisher {
	if now == nil {
		now = time.Now
	}
	return &Publisher{resolve: resolve, now: now}
}

// Refresh resolves the snapshot once. On failure the PREVIOUS snapshot is kept
// (a transient error must not make every site vanish and its alert resolve) and
// refresh_ok reads 0 so the failure is observable.
func (p *Publisher) Refresh(ctx context.Context) error {
	if p == nil || p.resolve == nil {
		return fmt.Errorf("sitecollect: no resolver")
	}
	rows, err := p.resolve(ctx)
	if err != nil {
		p.mu.Lock()
		p.ok = false
		p.mu.Unlock()
		return fmt.Errorf("sitecollect: resolve sites: %w", err)
	}
	clean := make([]Membership, 0, len(rows))
	pairs := map[string]map[string]bool{}
	seen := map[string]bool{}
	for _, r := range rows {
		r.Device = strings.TrimSpace(r.Device)
		r.Tenant = strings.ToLower(strings.TrimSpace(r.Tenant))
		r.Site = strings.TrimSpace(r.Site)
		r.SiteLabel = strings.TrimSpace(r.SiteLabel)
		if r.Device == "" || r.Site == "" || seen[r.Device] {
			continue // no site, or a duplicate id: one series per device
		}
		seen[r.Device] = true
		if r.SiteLabel == "" {
			r.SiteLabel = r.Site
		}
		clean = append(clean, r)
		if pairs[r.Tenant] == nil {
			pairs[r.Tenant] = map[string]bool{}
		}
		pairs[r.Tenant][r.Site] = true
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].Device < clean[j].Device })
	p.mu.Lock()
	p.rows, p.pairs, p.ok, p.at = clean, pairs, true, p.now()
	p.mu.Unlock()
	return nil
}

// Run refreshes every interval until ctx ends. Each failure is reported through
// onErr (never swallowed); the loop keeps going.
func (p *Publisher) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	if interval <= 0 {
		interval = time.Minute
	}
	tick := func() {
		rctx, cancel := context.WithTimeout(ctx, interval)
		defer cancel()
		if err := p.Refresh(rctx); err != nil && onErr != nil {
			onErr(err)
		}
	}
	tick()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// Owns reports whether (tenant, site) is a pair the api itself published in its
// last snapshot. A forged or stale pair resolves to false (platform-only).
func (p *Publisher) Owns(tenant, site string) bool {
	if p == nil {
		return false
	}
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	site = strings.TrimSpace(site)
	if site == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pairs[tenant][site]
}

// WriteMetrics writes the snapshot in Prometheus text format. The refresh
// gauges are written EVERY scrape, including before the first refresh, so a
// vanished series still means a scrape failure rather than "no sites".
func (p *Publisher) WriteMetrics(w io.Writer) {
	if p == nil {
		return
	}
	p.mu.RLock()
	rows, ok, at := p.rows, p.ok, p.at
	p.mu.RUnlock()
	okv, ts := 0, int64(0)
	if ok {
		okv = 1
	}
	if !at.IsZero() {
		ts = at.Unix()
	}
	fmt.Fprintf(w, "# HELP %s Whether the last device-site resolution succeeded (1) or not (0).\n", MetricRefreshOK)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricRefreshOK)
	fmt.Fprintf(w, "%s %d\n", MetricRefreshOK, okv)
	fmt.Fprintf(w, "# HELP %s Unix time of the last successful device-site resolution (0 = never).\n", MetricRefreshAt)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricRefreshAt)
	fmt.Fprintf(w, "%s %d\n", MetricRefreshAt, ts)
	fmt.Fprintf(w, "# HELP %s The site each inventory device belongs to (always 1); joins collector_target_up for SiteCollectionLost.\n", MetricInfo)
	fmt.Fprintf(w, "# TYPE %s gauge\n", MetricInfo)
	for _, r := range rows {
		fmt.Fprintf(w, "%s{device=\"%s\",tenant_id=\"%s\",site=\"%s\",site_label=\"%s\"} 1\n",
			MetricInfo, escape(r.Device), escape(r.Tenant), escape(r.Site), escape(r.SiteLabel))
	}
}

// escape is the Prometheus text-format label-value escape: backslash, double
// quote and line feed. Go's %q is NOT it (it emits \u escapes the format does
// not define), and a site label is operator- or controller-supplied text.
func escape(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
