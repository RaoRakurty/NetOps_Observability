// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

// delivery_test.go — END TO END: a vmalert POST through the real
// alertwebhook receiver, routed by this package's Router over this package's
// Store, landing on httptest ntfy and Twilio servers.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/alertwebhook"
	"netops/backend/models"
)

type nopDispatcher struct{}

func (nopDispatcher) Dispatch(models.Alert)        {}
func (nopDispatcher) DispatchResolve(models.Alert) {}

type e2e struct {
	*routerRig
	h       http.HandlerFunc
	metrics *alertwebhook.Metrics
	logs    *logSpy
	token   string
	clock   *time.Time
	mu      *sync.Mutex
}

func newE2E(t *testing.T, mut func(*Config)) *e2e {
	t.Helper()
	return newE2EBoot(t, mut, nil)
}

func newE2EBoot(t *testing.T, mut func(*Config), boot bootHook) *e2e {
	t.Helper()
	r := newRouterRigBoot(t, mut, boot)
	m := alertwebhook.NewMetrics()
	logs := &logSpy{}
	tok := "hook-" + strings.Repeat("z", 24)
	mu := &sync.Mutex{}
	h, err := alertwebhook.Handler(alertwebhook.Deps{
		Dispatcher:            nopDispatcher{},
		Token:                 tok,
		HostRouter:            r.router,
		Now:                   func() time.Time { mu.Lock(); defer mu.Unlock(); return *r.clock },
		Sleep:                 func(time.Duration) {},
		WarningDigestInterval: 30 * time.Minute,
		Metrics:               m,
		Log:                   logs.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &e2e{routerRig: r, h: h, metrics: m, logs: logs, token: tok, clock: r.clock, mu: mu}
}

func (e *e2e) advance(d time.Duration) {
	e.mu.Lock()
	*e.clock = e.clock.Add(d)
	e.mu.Unlock()
}

func (e *e2e) post(t *testing.T, name, tier string) {
	t.Helper()
	body := fmt.Sprintf(`[{"labels":{"alertname":%q,"severity":"critical","layer":"platform","tier":%q},`+
		`"annotations":{"summary":"%s summary"},"startsAt":"2026-11-11T11:55:00Z"}]`, name, tier, name)
	req := httptest.NewRequest(http.MethodPost, alertwebhook.AlertsPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.token)
	w := httptest.NewRecorder()
	e.h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("receiver answered %d: %s", w.Code, w.Body.String())
	}
}

func (e *e2e) metricsText() string {
	var b strings.Builder
	e.metrics.Write(&b)
	return b.String()
}

// A PAGE reaches ntfy once and every SMS recipient once.
func TestEndToEndPageReachesNtfyAndEverySMSRecipient(t *testing.T) {
	e := newE2E(t, nil)
	e.post(t, "CorrelationConsumerDead", "page")
	n := e.ntfy.await(t, 1)[0]
	if !strings.Contains(n.Title, "[PAGE] CorrelationConsumerDead") || n.Auth != "Bearer "+fakeSecret("ntfy") {
		t.Fatalf("ntfy push: %+v", n)
	}
	sms := e.twilio.await(t, 2)
	for _, s := range sms {
		if !strings.HasPrefix(s.Body, "Correlix [PAGE] CorrelationConsumerDead") {
			t.Fatalf("sms body: %q", s.Body)
		}
	}
	e.ntfy.quiet(t)
	e.twilio.quiet(t)
	if !strings.Contains(e.metricsText(), "netops_alert_webhook_host_route_enabled 1") {
		t.Fatal("a routed page tier must read enabled=1")
	}
}

// Warnings are digested to the warning-tier channels only — never SMS by
// default — and the digest leaves once per window.
func TestEndToEndWarningDigestGoesToNtfyOnly(t *testing.T) {
	e := newE2E(t, nil)
	e.post(t, "VectorComponentErrors", "")
	e.post(t, "DiskHeadroomLow", "")
	e.ntfy.quiet(t)
	e.advance(31 * time.Minute)
	e.post(t, "AnotherWarning", "")
	d := e.ntfy.await(t, 1)[0]
	if !strings.Contains(d.Body, "VectorComponentErrors") || !strings.Contains(d.Body, "DiskHeadroomLow") {
		t.Fatalf("digest body: %q", d.Body)
	}
	e.twilio.quiet(t)
}

// The administrator routed the warning tier nowhere: warnings are counted as
// unrouted (a choice), never as not_configured (a fault), and pages still go.
func TestEndToEndUnroutedWarningIsAChoiceNotAFault(t *testing.T) {
	e := newE2E(t, func(c *Config) { c.Ntfy.Tiers.Warning = false })
	e.post(t, "SomeWarning", "")
	e.ntfy.quiet(t)
	txt := e.metricsText()
	if !strings.Contains(txt, "netops_alert_webhook_host_unrouted_total 1") ||
		!strings.Contains(txt, `reason="not_configured"} 0`) {
		t.Fatalf("unrouted accounting wrong:\n%s", txt)
	}
	e.post(t, "IngestPipelineSilent", "page")
	e.ntfy.await(t, 1)
}

// NOTHING configured: no request leaves, not_configured is counted, the gauge
// reads 0, and the log says where to fix it.
func TestEndToEndUnconfiguredIsLoud(t *testing.T) {
	e := newE2E(t, func(c *Config) { c.Ntfy.Enabled = false; c.SMS.Enabled = false })
	e.post(t, "ClickHouseWritesRejected", "page")
	e.post(t, "AlertDeliveryBroken", "page")
	e.ntfy.quiet(t)
	e.twilio.quiet(t)
	txt := e.metricsText()
	if !strings.Contains(txt, "netops_alert_webhook_host_route_enabled 0") ||
		!strings.Contains(txt, `reason="not_configured"} 2`) {
		t.Fatalf("unconfigured accounting wrong:\n%s", txt)
	}
	if e.logs.count("Platform → Platform alerts") != 1 {
		t.Fatalf("the not-configured line must name the GUI location exactly once:\n%s", e.logs.all())
	}
}

// THE ENV PATH IS BLOCKED. A retired env topic/server pointing at a live
// server is never used: with nothing configured in the store, that server
// receives nothing.
func TestEndToEndRetiredEnvIsIgnored(t *testing.T) {
	envNtfy := newFakeProvider(t)
	t.Setenv("PLATFORM_ALERTS_NTFY_TOPIC", "env-topic")
	t.Setenv("PLATFORM_ALERTS_NTFY_SERVER", envNtfy.srv.URL)
	t.Setenv("PLATFORM_ALERTS_NTFY_TOKEN", fakeSecret("env"))
	t.Setenv("WATCHDOG_NTFY_TOPIC", "watchdog-topic")
	e := newE2E(t, func(c *Config) { c.Ntfy.Enabled = false; c.SMS.Enabled = false })
	e.post(t, "CorrelationConsumerDead", "page")
	envNtfy.quiet(t)
	e.ntfy.quiet(t)
	if !strings.Contains(e.metricsText(), "netops_alert_webhook_host_route_enabled 0") {
		t.Fatal("env must not make the route read as configured")
	}
	// And the same process, configured in the store, delivers to the STORE's
	// destination — never the env one.
	cur := e.store.Current()
	cur.Ntfy.Enabled = true
	if err := e.store.Save(cur, true); err == nil {
		t.Fatal("the fake server is http; Save must refuse it (https only)")
	}
	e.kv.put(t, sealedForKV(t, liveConfig(e.ntfy, e.twilio)))
	if err := e.store.Refresh(); err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Minute) // past the cool-down for the identical alert
	e.post(t, "CorrelationConsumerDead", "page")
	if got := e.ntfy.await(t, 1)[0]; got.Path != "/corr-platform-test" {
		t.Fatalf("delivered to %q", got.Path)
	}
	envNtfy.quiet(t)
}

// The store becomes unreadable AFTER a good read: pages keep flowing to the
// last good destinations.
func TestEndToEndUnreadableStoreKeepsDelivering(t *testing.T) {
	e := newE2E(t, nil)
	e.kv.setLoadErr(errors.New("pg: down"))
	if err := e.store.Refresh(); err == nil {
		t.Fatal("refresh must fail")
	}
	e.post(t, "NMSIngestSilent", "page")
	e.ntfy.await(t, 1)
	e.twilio.await(t, 2)
	var b strings.Builder
	WriteMetrics(&b, e.store, e.router)
	if !strings.Contains(b.String(), "netops_platform_alert_store_readable 0") ||
		!strings.Contains(b.String(), "netops_platform_alert_store_read_failures_total 1") ||
		!strings.Contains(b.String(), "netops_platform_alert_page_routed 1") {
		t.Fatalf("config metrics:\n%s", b.String())
	}
}

// Page-tier storm vs. the SMS cap: past the cap the SMS is refused LOCALLY
// (no request to Twilio, counted as budget_exhausted, logged as an ERROR for
// a page) while ntfy still carries every page.
func TestEndToEndSMSCapHoldsDuringAPageStorm(t *testing.T) {
	e := newE2E(t, func(c *Config) { c.SMS.MaxPerHour = 4; c.SMS.To = []string{phoneA} })
	for i := 0; i < 6; i++ {
		e.post(t, fmt.Sprintf("CorrConsumerRestartLoop%d", i), "page")
	}
	e.ntfy.await(t, 6)
	e.twilio.await(t, 4)
	e.twilio.quiet(t)
	if !strings.Contains(e.metricsText(), `reason="budget_exhausted"} 2`) {
		t.Fatalf("SMS refusals must be counted:\n%s", e.metricsText())
	}
	if e.logs.count("error: platform alert push SKIPPED") != 2 {
		t.Fatalf("a page refused by the SMS cap is an ERROR line:\n%s", e.logs.all())
	}
}

// A Twilio 5xx on a page is retried for THAT recipient only; ntfy is not
// re-sent.
func TestEndToEndRetryIsPerRecipient(t *testing.T) {
	e := newE2E(t, func(c *Config) { c.SMS.To = []string{phoneA} })
	e.twilio.setStatus(503)
	e.post(t, "AlertDeliveryBroken", "page")
	e.ntfy.await(t, 1)
	got := e.twilio.await(t, 5) // 1 send + 4 retries (hostMaxAttempts)
	for _, c := range got {
		if c.To != phoneA {
			t.Fatalf("retry went to %q", c.To)
		}
	}
	e.ntfy.quiet(t)
}
