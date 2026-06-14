package collectors

// Metric events — the live metric signal lane for the correlation engine.
//
// The SNMP stats collector already ships every sampled metric to VictoriaMetrics
// (the dashboard/PromQL/history store — emitMetrics, poller.go). That path stays
// the source of truth for rendering. Separately, this file forwards a FILTERED,
// CANONICAL subset of those samples — only the RCA-relevant families — to the
// platform bus as structured MetricEvents, POSTed to the Vector aggregator's
// metrics HTTP source (METRIC_EVENT_SINK_URL → topic netops.metrics). The
// correlation engine consumes that topic and runs its CUSUM / z-score episode
// detector to produce device_telemetry-modality signals.
//
// Why filtered, not a raw firehose: correlation needs RCA signal context, not
// every counter on every interface. The allowlist below is the ownership/volume
// gate — interface state/counters/errors/discards, BGP peer state, device
// CPU/memory/temperature. Everything else stays in VictoriaMetrics only.
//
// Same shape and contract as probe_events.go: best-effort, bounded-timeout POST
// that never blocks the poll loop; the VM gauges remain the rendering source of
// truth if the bus POST is dropped. Canonical normalization lives here, in typed
// and tested Go — not in a regex-heavy collector YAML chain.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// MetricEvent is one canonical metric sample forwarded to the correlation bus.
// Field names are the wire contract with src/correlation handle_metric — change
// them only together. Provenance fields carry the observer/modality model so the
// correlation engine can stamp signals without guessing (correlation-engine.md).
type MetricEvent struct {
	// Provenance (the observer/modality independence model).
	ObserverType   string `json:"observer_type"`   // always "device" for SNMP poll
	ModalityClass  string `json:"modality_class"`  // always "device_telemetry"
	CollectionPath string `json:"collection_path"` // "snmp_poll"

	// Identity.
	Device string `json:"device"`           // operator-assigned device id
	Vendor string `json:"vendor,omitempty"` // resolved from sysObjectID
	IfName string `json:"if_name,omitempty"` // interface families only
	Index  string `json:"index,omitempty"`  // table row index (ifIndex / scalar)
	Peer   string `json:"peer,omitempty"`   // BGP families: remote peer address

	// Signal.
	SignalFamily string  `json:"signal_family"` // interface | bgp | device_resource
	Metric       string  `json:"metric"`        // canonical name, e.g. device_if_in_octets
	Value        float64 `json:"value"`
	Unit         string  `json:"unit,omitempty"`
	TS           string  `json:"ts"` // RFC3339Nano event time (poll clock)
}

// metricMeta is the per-family classification: which RCA signal family a metric
// belongs to and its unit. A metric name absent from this map is NOT forwarded
// to the bus (the filter) — it remains in VictoriaMetrics only.
type metricMeta struct {
	family string
	unit   string
}

// rcaMetricFamilies is the EXPLICIT, DOCUMENTED allowlist of metric names that
// reach the correlation bus. Keep it intentional and minimal (the volume/RCA
// gate). Add families here deliberately as the correlation catalog grows; do not
// widen it to the full counter set. gNMI-owned families (e.g. device_mem_percent
// on Nokia SRL, BGP per-AFI) arrive via the gnmic lane in Phase 2, not here.
var rcaMetricFamilies = map[string]metricMeta{
	// Interface state + counters + errors + discards (IF-MIB).
	"device_if_oper_status":  {"interface", "state"},
	"device_if_admin_status": {"interface", "state"},
	"device_if_in_octets":    {"interface", "bytes"},
	"device_if_out_octets":   {"interface", "bytes"},
	"device_if_in_errors":    {"interface", "errors"},
	"device_if_out_errors":   {"interface", "errors"},
	"device_if_in_discards":  {"interface", "discards"},
	"device_if_out_discards": {"interface", "discards"},
	"device_if_speed":        {"interface", "mbps"},
	// BGP peer state (BGP4-MIB) — discrete control-plane RCA evidence.
	"device_bgp_peer_state":      {"bgp", "state"},
	"device_bgp_fsm_transitions": {"bgp", "transitions"},
	// Device resource health.
	"device_cpu_percent":  {"device_resource", "percent"},
	"device_mem_percent":  {"device_resource", "percent"},
	"device_temp_celsius": {"device_resource", "celsius"},
}

// buildMetricEvent constructs a canonical MetricEvent for a sample, or returns
// ok=false when the metric is not in the RCA allowlist (the bus filter). The
// caller already holds device/vendor/index/ifName from the SNMP walk.
func buildMetricEvent(metric, device, vendor, index, ifName string, value int64, tsMillis int64) (MetricEvent, bool) {
	meta, ok := rcaMetricFamilies[metric]
	if !ok {
		return MetricEvent{}, false
	}
	ev := MetricEvent{
		ObserverType:   "device",
		ModalityClass:  "device_telemetry",
		CollectionPath: "snmp_poll",
		Device:         device,
		Vendor:         vendor,
		SignalFamily:   meta.family,
		Metric:         metric,
		Value:          float64(value),
		Unit:           meta.unit,
		TS:             time.UnixMilli(tsMillis).UTC().Format(time.RFC3339Nano),
	}
	switch meta.family {
	case "interface":
		ev.IfName = ifName
		ev.Index = index
	case "bgp":
		// BGP4-MIB tables are indexed by the remote peer address.
		ev.Peer = index
		ev.Index = index
	default:
		ev.Index = index
	}
	return ev, true
}

// metricEventSink returns the bus ingest URL for metric events. Defaults to the
// Vector aggregator's metrics source; METRIC_EVENT_SINK_URL=off disables the
// lane (VM remote_write is unaffected — it is a separate path).
func metricEventSink() string {
	v := os.Getenv("METRIC_EVENT_SINK_URL")
	switch v {
	case "":
		return "http://vector-aggregator:8690/"
	case "off", "false", "disabled":
		return ""
	}
	return v
}

// forwardMetricEvents POSTs the batch as newline-delimited JSON (one event per
// line) to the bus ingest source. Best-effort: a failed POST is dropped (the VM
// gauges remain the rendering source of truth; the bus lane is RCA evidence).
func forwardMetricEvents(ctx context.Context, events []MetricEvent) {
	sink := metricEventSink()
	if sink == "" || len(events) == 0 {
		return
	}
	body, err := encodeMetricNDJSON(events)
	if err != nil {
		return
	}
	// #nosec G704 -- sink is the operator-configured Vector bus source, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sink, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// encodeMetricNDJSON serializes events as newline-delimited JSON. json.Encoder
// already appends a newline after each value, so the result is NDJSON the Vector
// http_server source decodes (codec json + newline_delimited framing).
func encodeMetricNDJSON(events []MetricEvent) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
