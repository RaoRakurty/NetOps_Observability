package main

import (
	"fmt"
	"io"
	"sync/atomic"
)

// integration_metrics.go — Prometheus counters for the ITSM Integration Platform
// (#43), emitted via /metrics. Per-tenant breakdowns live in the
// integration_events ledger (queryable); these are the stack-wide health signals
// a NOC dashboards/alerts on (delivery success, webhook rejects, drift activity).

type integrationMetrics struct {
	webhookReceived atomic.Int64 // inbound events recorded (post-verify)
	webhookRejected atomic.Int64 // webhook auth/signature rejections
	inboundApplied  atomic.Int64 // inbound events that drove an incident change
	inboundDropped  atomic.Int64 // inbound events dropped (stale / terminal-nms-wins / unmapped / …)
	driftInbound    atomic.Int64 // reconciler re-drove an external change (case A)
	driftOutbound   atomic.Int64 // reconciler pushed a resolve to ITSM (case B)
}

func (s *server) intgWebhookReceived() {
	if s.intMetrics != nil {
		s.intMetrics.webhookReceived.Add(1)
	}
}
func (s *server) intgWebhookRejected() {
	if s.intMetrics != nil {
		s.intMetrics.webhookRejected.Add(1)
	}
}
func (s *server) intgInbound(applied bool) {
	if s.intMetrics == nil {
		return
	}
	if applied {
		s.intMetrics.inboundApplied.Add(1)
	} else {
		s.intMetrics.inboundDropped.Add(1)
	}
}
func (s *server) intgDrift(outbound bool) {
	if s.intMetrics == nil {
		return
	}
	if outbound {
		s.intMetrics.driftOutbound.Add(1)
	} else {
		s.intMetrics.driftInbound.Add(1)
	}
}

func (m *integrationMetrics) write(w io.Writer) {
	c := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	c("netops_integration_webhook_received_total", "Inbound ITSM webhook events recorded (post-verify).", m.webhookReceived.Load())
	c("netops_integration_webhook_rejected_total", "Inbound ITSM webhooks rejected (bad token/signature).", m.webhookRejected.Load())
	c("netops_integration_inbound_applied_total", "Inbound events that drove an incident change.", m.inboundApplied.Load())
	c("netops_integration_inbound_dropped_total", "Inbound events dropped (stale/terminal/unmapped).", m.inboundDropped.Load())
	c("netops_integration_drift_inbound_total", "Drift reconciler re-drove an external change (ITSM→NMS).", m.driftInbound.Load())
	c("netops_integration_drift_outbound_total", "Drift reconciler pushed a resolve to ITSM (NMS→ITSM).", m.driftOutbound.Load())
}
