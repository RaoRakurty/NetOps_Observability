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
type ProbeEvent struct {
	Kind     string  `json:"kind"`   // stamp | icmp | tcp | http
	Prober   string  `json:"prober"` // observer id (vantage-point instance)
	Target   string  `json:"target"` // host[:port] / URL as configured
	OK       bool    `json:"ok"`
	RTTms    float64 `json:"rtt_ms"`
	JitterMs float64 `json:"jitter_ms,omitempty"`
	LossPct  float64 `json:"loss_pct"`
	TS       string  `json:"ts"` // RFC3339Nano event time (sender clock)
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

// proberID identifies this vantage point as an observer (PROBER_ID, falling
// back to the container hostname). Evidence independence (§4.5) buckets by
// this id, so two collectors on the same compose stack must not share one.
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
