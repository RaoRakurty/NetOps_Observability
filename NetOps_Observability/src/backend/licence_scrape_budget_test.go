// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/alertwebhook"
	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
)

// licence_scrape_budget_test.go — /metrics may not wait on a database.
//
// The licence usage bars need a watched-prefix count, and on the Postgres
// backend that count goes through the pool. Before this budget existed the read
// was bounded only by the SCRAPE'S OWN request context, so a pool-acquire stall
// parked the scrape — and with it the alert-delivery heartbeat and the
// engine-liveness counters, which CLAUDE.md's monitoring section names as the
// two things that must keep working when everything else is down. A usage bar
// is not allowed to cost us those.

// stallingWatchStore is a bgpWatchStore whose List never answers until its
// context is cancelled — the pool-acquire stall, reproduced at the seam the
// bgpWatchStore interface already provides.
type stallingWatchStore struct{}

func (s *stallingWatchStore) List(ctx context.Context, _ string, _ bool) ([]bgpWatchEntry, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *stallingWatchStore) Add(context.Context, string, bgpWatchEntry) error { return nil }
func (s *stallingWatchStore) Delete(context.Context, string, string) (bool, error) {
	return false, nil
}

// TestLicenceUsageScrapeHonoursItsBudget: the measurement gives up on time and
// reports the ceiling it could not count as NOT MEASURED — an absent key, never
// a reassuring zero.
func TestLicenceUsageScrapeHonoursItsBudget(t *testing.T) {
	_, s := newTestServerState(t)
	s.bgpWatch = &stallingWatchStore{}

	// context.Background(): no deadline of its own, which is what a scrape's
	// request context effectively is. The budget has to come from us — and the
	// assertion has to be made from OUTSIDE the call, because without the budget
	// the call never returns at all.
	done := make(chan licence.Usage, 1)
	go func() { done <- s.licenceUsageScrape(context.Background()) }()

	var u licence.Usage
	select {
	case u = <-done:
	case <-time.After(licenceScrapeBudget + 15*time.Second):
		t.Fatal("the usage measurement never returned; a scrape must not wait on a stalled store")
	}

	if _, ok := u[entitlement.CeilingWatchedPrefixes]; ok {
		t.Fatalf("a ceiling that ran out of budget must be reported as NOT MEASURED (key absent), got %v", u)
	}
	if _, ok := u[entitlement.CeilingDevices]; !ok {
		t.Fatalf("the ceilings that CAN be measured must still be measured: %v", u)
	}
}

// TestMetricsScrapeSurvivesAStalledWatchlist is the whole point: the scrape
// answers, and the lines the watchdog and the alert rules read are in it.
func TestMetricsScrapeSurvivesAStalledWatchlist(t *testing.T) {
	_, s := newTestServerState(t)
	s.alerts = alerts.NewEngine("", nil) // the exporter reads it; the harness leaves it nil
	// Production builds this UNCONDITIONALLY (see newServer) precisely so the
	// heartbeat series exists even when the receiver is off; the test harness
	// does not, so wire it here or the assertion below would be vacuous.
	s.vmalertWebhookMetrics = alertwebhook.NewMetrics()
	s.bgpWatch = &stallingWatchStore{}

	w := httptest.NewRecorder()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		done <- time.Since(start)
	}()

	// Generous: the assertion is "bounded at all", not "fast". Before the
	// budget existed this select hit its timeout every time, because nothing in
	// the chain had a deadline.
	select {
	case elapsed := <-done:
		if elapsed > licenceScrapeBudget+5*time.Second {
			t.Fatalf("/metrics took %s against a stalled watchlist", elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("/metrics never answered: a stalled watchlist read parked the scrape that carries the alert-delivery heartbeat and the engine-liveness counters")
	}

	out := w.Body.String()
	for _, want := range []string{
		// The delivery chain's end-to-end proof (CLAUDE.md monitoring, layer 2).
		"netops_alert_webhook_heartbeat_timestamp_seconds",
		"netops_alert_webhook_enabled",
		// The liveness the 2026-09-02 post-mortem added.
		"netops_devices_total",
		"netops_monitored_devices_total",
		// The licence family still renders — the LIMIT is always known.
		`netops_licence_ceiling{ceiling="watched_prefixes"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("/metrics lost %q while the watchlist was stalled:\n%s", want, out)
		}
	}
	if strings.Contains(out, `netops_licence_usage{ceiling="watched_prefixes"`) {
		t.Fatalf("the ceiling that could not be counted must have NO usage series — a fabricated 0 would be divided by the soft-overage rules:\n%s", out)
	}
}
