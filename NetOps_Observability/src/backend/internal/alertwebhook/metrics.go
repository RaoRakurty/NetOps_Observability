package alertwebhook

// metrics.go — the receiver's Prometheus surface (§10: every service emits
// metrics, no silent failures).
//
// Stdlib only, in the shape of src/backend/integration_metrics.go: atomic
// counters plus a Write(io.Writer) the api's /metrics handler calls. There are
// no labels, so nothing a notifier sends can drive cardinality.

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"netops/backend/notify"
)

// Metrics is the receiver's counter set. Every method is nil-safe, so a
// metric-less deployment (or a test) needs no branching at the call sites.
type Metrics struct {
	requests        atomic.Int64
	unauthorized    atomic.Int64
	malformed       atomic.Int64
	alertsReceived  atomic.Int64
	dispatched      atomic.Int64
	suppressed      atomic.Int64
	droppedTenant   atomic.Int64
	droppedCustomer atomic.Int64
	heartbeats      atomic.Int64
	heartbeatAt     atomic.Int64 // unix seconds of the last heartbeat, 0 = never
	enabled         atomic.Int64 // 0/1 — is the receiver wired at all

	// Host-monitoring route (hostroute.go). The tier label set is CLOSED
	// (page/warning/resolved) and the route label is a constant, so nothing a
	// notifier sends can drive cardinality — the same rule the label-free
	// counters above follow.
	hostPushedPage     atomic.Int64
	hostPushedWarning  atomic.Int64
	hostPushedResolved atomic.Int64
	hostPushedDigest   atomic.Int64
	hostFailed         atomic.Int64 // the push was attempted and errored
	hostNotConfigured  atomic.Int64 // no topic wired: nothing was attempted
	hostQueueFull      atomic.Int64 // bounded queue full: the push was dropped
	hostRouteEnabled   atomic.Int64 // 0/1 — is the host route wired at all

	// Noise + rate-limit control (2026-09-03, digest.go / pushbudget.go).
	hostRateLimited     atomic.Int64 // the server answered 429: budget, not fault
	hostRetries         atomic.Int64 // page-tier re-sends after a transient failure
	hostBudgetExhausted atomic.Int64 // refused locally by the token bucket
	hostDigestFolded    atomic.Int64 // warnings aggregated instead of pushed
	hostDigestOverflow  atomic.Int64 // distinct alertnames past the digest cap

	// budget is the live token bucket, read (not stored) by Write so the
	// remaining-tokens gauge refills between pushes instead of freezing at the
	// value of the last take. atomic because Write runs on the /metrics
	// goroutine while the receiver's own path takes tokens.
	budget atomic.Pointer[notify.PushBudget]
}

// NewMetrics builds the counter set. It is constructed even when the receiver
// is DISABLED, so /metrics always carries netops_alert_webhook_enabled — the
// difference between "0 alerts delivered because nothing fired" and "0 alerts
// delivered because the receiver was never wired" must be visible.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) inc(c *atomic.Int64) {
	if m != nil {
		c.Add(1)
	}
}

func (m *Metrics) add(c *atomic.Int64, n int64) {
	if m != nil && n != 0 {
		c.Add(n)
	}
}

// incHostPushed counts one delivered push under its tier. An unknown tier is
// counted as warning rather than minting a new series — the label set stays
// closed even if a caller drifts.
func (m *Metrics) incHostPushed(tier string) {
	if m == nil {
		return
	}
	switch tier {
	case tierPage:
		m.hostPushedPage.Add(1)
	case tierResolved:
		m.hostPushedResolved.Add(1)
	case tierDigest:
		m.hostPushedDigest.Add(1)
	default:
		m.hostPushedWarning.Add(1)
	}
}

// attachBudget hands Write the live token bucket. Called once, at Handler
// construction, before the receiver serves anything. A nil bucket means the
// operator disabled the guard, and the gauge then reads -1 — "not enforced" is
// a different fact from "empty" and must not look like one.
func (m *Metrics) attachBudget(b *notify.PushBudget) {
	if m == nil {
		return
	}
	m.budget.Store(b)
}

// PushBudgetRemaining exposes the gauge value for tests and any future
// in-process health surface. -1 = no budget configured.
func (m *Metrics) PushBudgetRemaining() int {
	if m == nil {
		return -1
	}
	return m.budget.Load().Remaining()
}

func (m *Metrics) setHostRouteEnabled(on bool) {
	if m == nil {
		return
	}
	if on {
		m.hostRouteEnabled.Store(1)
		return
	}
	m.hostRouteEnabled.Store(0)
}

// HostPushed returns the per-tier delivered-push counts (page, warning,
// resolved). Exported for tests and any future in-process health surface.
func (m *Metrics) HostPushed() (int64, int64, int64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.hostPushedPage.Load(), m.hostPushedWarning.Load(), m.hostPushedResolved.Load()
}

func (m *Metrics) setEnabled(on bool) {
	if m == nil {
		return
	}
	if on {
		m.enabled.Store(1)
		return
	}
	m.enabled.Store(0)
}

// recordHeartbeat stamps the delivery-chain probe's receipt.
func (m *Metrics) recordHeartbeat(at time.Time) {
	if m == nil {
		return
	}
	m.heartbeats.Add(1)
	m.heartbeatAt.Store(at.Unix())
}

// HeartbeatAt returns the unix seconds of the last heartbeat (0 = never).
// Exported for tests and for any future in-process health surface.
func (m *Metrics) HeartbeatAt() int64 {
	if m == nil {
		return 0
	}
	return m.heartbeatAt.Load()
}

// Write emits the family in Prometheus text format. Nil-safe.
func (m *Metrics) Write(w io.Writer) {
	if m == nil || w == nil {
		return
	}
	c := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	g := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	c("netops_alert_webhook_requests_total", "Requests received on the vmalert Alertmanager-v2 webhook.", m.requests.Load())
	c("netops_alert_webhook_unauthorized_total", "Webhook requests refused for a bad or missing shared secret.", m.unauthorized.Load())
	c("netops_alert_webhook_malformed_total", "Webhook requests refused for an unparseable or oversize body.", m.malformed.Load())
	c("netops_alert_webhook_alerts_received_total", "Alerts parsed out of accepted webhook requests.", m.alertsReceived.Load())
	c("netops_alert_webhook_dispatched_total", "Alerts fanned out to the notification channels.", m.dispatched.Load())
	c("netops_alert_webhook_suppressed_total", "Alerts suppressed by the cool-down window (duplicate of a recent delivery).", m.suppressed.Load())
	c("netops_alert_webhook_dropped_tenant_total", "Alerts DROPPED for carrying a tenant/org label on the platform-global path (CLAUDE.md 3a).", m.droppedTenant.Load())
	c("netops_alert_webhook_dropped_customer_total", "Alerts DROPPED for naming a customer-network object (device/interface/peer) on the platform-global path (CLAUDE.md 3a; #103 — those page through the tenant-scoped RCA lane).", m.droppedCustomer.Load())
	c("netops_alert_webhook_heartbeat_total", "AlertingHeartbeat receipts (delivery-chain probe, never fanned out).", m.heartbeats.Load())
	// The end-to-end assertion: the api is scraped by VictoriaMetrics (job
	// netops-api, target api:8080), so this gauge lands in VM automatically and
	// `time() - netops_alert_webhook_heartbeat_timestamp_seconds > 5m` proves
	// the WHOLE chain — vmalert evaluated, the notifier posted, this receiver
	// accepted. No other signal in the stack covers the notification path
	// itself, which is exactly why 13 firing alerts were delivered nowhere for
	// months without anything noticing.
	g("netops_alert_webhook_heartbeat_timestamp_seconds", "Unix time of the last AlertingHeartbeat received (0 = never).", m.heartbeatAt.Load())
	g("netops_alert_webhook_enabled", "1 when the vmalert webhook receiver is wired and serving, 0 when it is not (VMALERT_WEBHOOK_TOKEN unset).", m.enabled.Load())

	// ── host-monitoring route (hostroute.go) ────────────────────────────────
	// Labelled families, emitted by hand for the same reason the rest of this
	// file is: stdlib only, one HELP/TYPE header per family, every series
	// present from the first scrape so "0 pushes" is a value and not a gap.
	fmt.Fprintf(w, "# HELP netops_alert_webhook_pushed_total Platform alerts pushed to a self-health route (the host-monitoring phone channel), by tier.\n")
	fmt.Fprintf(w, "# TYPE netops_alert_webhook_pushed_total counter\n")
	for _, s := range []struct {
		tier string
		v    int64
	}{
		{tierPage, m.hostPushedPage.Load()},
		{tierWarning, m.hostPushedWarning.Load()},
		{tierResolved, m.hostPushedResolved.Load()},
		{tierDigest, m.hostPushedDigest.Load()},
	} {
		fmt.Fprintf(w, "netops_alert_webhook_pushed_total{route=%q,tier=%q} %d\n", RouteHostMonitoring, s.tier, s.v)
	}
	fmt.Fprintf(w, "# HELP netops_alert_webhook_push_failures_total Platform alert pushes that did not reach the self-health route, by reason.\n")
	fmt.Fprintf(w, "# TYPE netops_alert_webhook_push_failures_total counter\n")
	for _, s := range []struct {
		reason string
		v      int64
	}{
		{"send_error", m.hostFailed.Load()},
		{"rate_limited", m.hostRateLimited.Load()},
		{"budget_exhausted", m.hostBudgetExhausted.Load()},
		{"not_configured", m.hostNotConfigured.Load()},
		{"queue_full", m.hostQueueFull.Load()},
	} {
		fmt.Fprintf(w, "netops_alert_webhook_push_failures_total{route=%q,reason=%q} %d\n", RouteHostMonitoring, s.reason, s.v)
	}
	g("netops_alert_webhook_host_route_enabled", "1 when platform alerts are pushed to the host-monitoring channel, 0 when no topic is configured (PLATFORM_ALERTS_NTFY_TOPIC / WATCHDOG_NTFY_TOPIC unset).", m.hostRouteEnabled.Load())

	// ── noise + rate-limit control (digest.go / pushbudget.go) ──────────────
	c("netops_alert_webhook_push_retries_total", "Page-tier host-route pushes re-sent after a transient failure (429/5xx/transport), with capped backoff.", m.hostRetries.Load())
	c("netops_alert_webhook_digest_alerts_total", "Warning-tier alerts folded into the periodic digest instead of being pushed individually.", m.hostDigestFolded.Load())
	c("netops_alert_webhook_digest_overflow_total", "Distinct warning rules dropped from a digest window for exceeding its bounded entry cap.", m.hostDigestOverflow.Load())
	// The gauge the operator watches when pushes go missing: a floor of the
	// page reserve means warnings are being held back on purpose; 0 means even
	// a page would now be refused locally rather than by the server.
	// SHARED with the product notification channel: this is the budget of the
	// push SERVER, not of this route's topic (notify/pushbudget.go). The
	// per-server view, including the product channel's own draw, is
	// netops_notify_push_budget_remaining{server}.
	g("netops_alert_webhook_push_budget_remaining", "Outbound push tokens left this hour for the host-monitoring route's push server, SHARED with the product notification channel (-1 = no budget configured; PLATFORM_ALERTS_PUSH_BUDGET).", int64(m.budget.Load().Remaining()))
}
