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
)

// Metrics is the receiver's counter set. Every method is nil-safe, so a
// metric-less deployment (or a test) needs no branching at the call sites.
type Metrics struct {
	requests       atomic.Int64
	unauthorized   atomic.Int64
	malformed      atomic.Int64
	alertsReceived atomic.Int64
	dispatched     atomic.Int64
	suppressed     atomic.Int64
	droppedTenant  atomic.Int64
	heartbeats     atomic.Int64
	heartbeatAt    atomic.Int64 // unix seconds of the last heartbeat, 0 = never
	enabled        atomic.Int64 // 0/1 — is the receiver wired at all
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
}
