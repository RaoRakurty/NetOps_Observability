package collectors

// Probe events — Correlation Engine v2 build ⑦ (#67).
//
// Every active-measurement observation (STAMP, ICMP/TCP/HTTP synthetics) is
// forwarded to the platform bus as a structured event — POSTed to the Vector
// aggregator's HTTP source (PROBE_EVENT_SINK_URL, → topic netops.probes) in
// addition to the VictoriaMetrics gauges emitMetrics already ships. The
// correlation engine consumes the topic and turns each event into an
// active_probe-modality signal with vantage-agent observer provenance — the
// evidence class device telemetry cannot supply (gray failures are invisible
// to SNMP counters; rca-market-research.md, verified 3-0).
//
// Same pattern as the SNMP trap forwarder: best-effort POST with a bounded
// timeout, never blocking the measurement loop.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// ProbeEvent is one active-measurement observation. Field names are the wire
// contract with src/correlation handle_probe — change them only together.
//
// The enrichment block is optional (omitempty): synthetic HTTP/TCP checks fill
// what they measured, STAMP/ICMP leave it empty. The correlation side
// (synthetic_normalize.py) degrades gracefully when fields are absent —
// coarse-but-correct semantic kinds from ok/loss_pct alone.
type ProbeEvent struct {
	Kind     string  `json:"kind"`   // stamp | icmp | tcp | http
	Prober   string  `json:"prober"` // observer id (vantage-point instance)
	Target   string  `json:"target"` // host[:port] / URL as configured
	OK       bool    `json:"ok"`
	RTTms    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms,omitempty"`
	LossPct  float64 `json:"loss_pct"`
	TS       string  `json:"ts"` // RFC3339Nano event time (sender clock)

	// Synthetic application-experience enrichment (docs/
	// application-experience-correlation.md). A zero timing means the phase
	// did not occur (IP literal → no DNS, plain http → no TLS) and is omitted.
	SiteID       string  `json:"site_id,omitempty"`    // vantage site (PROBER_SITE_ID)
	FailClass    string  `json:"fail_class,omitempty"` // dns|tls|connect_refused|connect_timeout|timeout|reset|unknown
	StatusCode   int     `json:"status_code,omitempty"`
	Method       string  `json:"method,omitempty"`
	Path         string  `json:"path,omitempty"`
	DNSMs        float64 `json:"dns_ms,omitempty"`
	TCPConnectMs float64 `json:"tcp_connect_ms,omitempty"`
	TLSMs        float64 `json:"tls_ms,omitempty"`
	TTFBMs       float64 `json:"ttfb_ms,omitempty"`
	TotalMs      float64 `json:"total_ms,omitempty"`
	// Pointer: 0 and negative days (expired) are meaningful values, distinct
	// from "no TLS / not measured".
	CertDaysToExpiry *float64 `json:"cert_days_to_expiry,omitempty"`
	CertSubject      string   `json:"cert_subject,omitempty"`
	CertIssuer       string   `json:"cert_issuer,omitempty"`
}

// probeEventSink returns the bus ingest URL for probe events. Defaults to the
// Vector aggregator's probe source; PROBE_EVENT_SINK_URL=off disables.
func probeEventSink() string {
	v := os.Getenv("PROBE_EVENT_SINK_URL")
	switch v {
	case "":
		return "http://vector-aggregator:8689/"
	case "off", "false", "disabled":
		return ""
	}
	return v
}

// proberSite is the operator-declared site/vantage label for this prober
// (PROBER_SITE_ID). Optional: empty means the event carries no site token and
// the correlation side simply skips site grounding.
func proberSite() string {
	return os.Getenv("PROBER_SITE_ID")
}

// proberID identifies this vantage point as an observer (PROBER_ID, falling
// back to the container hostname). Evidence independence (§4.5) buckets by
// this id, so two collectors on the same compose stack must not share one.
// ProberID is the exported form of proberID: the vantage identity (PROBER_ID) that
// every published path is attributed to. Exported because the path contract's §2.2
// identity includes the vantage, so the API and the path registry both need it.
func ProberID() string { return proberID() }

func proberID() string {
	if v := os.Getenv("PROBER_ID"); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "prober"
}

// forwardProbeEvents POSTs each event to the bus ingest source. Best-effort:
// a failed POST is dropped (the VM gauges remain the rendering source of
// truth; the bus lane is evidence for the correlation engine).
func forwardProbeEvents(ctx context.Context, events []ProbeEvent) {
	sink := probeEventSink()
	if sink == "" || len(events) == 0 {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, ev := range events {
		body, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		// #nosec G704 -- sink is the operator-configured Vector bus source, not user input
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
	}
}
