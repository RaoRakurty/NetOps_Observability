// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// health.go — connector health metrics (NMS-first T1, contract C4).
//
// When an NMS integration is the ONLY source a tenant has, a connector that
// stops delivering is the whole tenant going dark — and nothing said so: the
// run history lived in Postgres where no alert rule reads it. These series
// are what the NMSIngestSilent page and the NMSIntegrationDown warning are
// written against.
//
// They are rendered on the api's OWN scrape (/metrics), never pushed through
// the /api/v1/import lane the controller data uses. That is deliberate: when
// the api dies a scraped series goes STALE (absent), which a rule can see; a
// pushed gauge would freeze at its last value and claim the connector was
// fine forever.
//
// Labels are EXACTLY tenant_id, integration_id, vendor (+ stream/result on
// the run counter, lane on the sink counter). Never display_name, base_url,
// error text or usernames (operator-typed, possibly sensitive, unbounded) —
// and never device / hostname / source: the tenant metrics scope matches on
// those labels, so carrying one would hand a scoped tenant these platform
// series (metrics_query.go metricsScopeFilters).
//
// Integration ids are unique only per tenant (PK (tenant_id, integration_id),
// migration 0020), so every key is the (tenant, id) pair.

// Poll results — the closed set the run counter's result label and every
// StreamResult.Status draw from.
const (
	ResultOK              = "ok"
	ResultError           = "error"
	ResultAuthFailed      = "auth_failed"
	ResultUnreachable     = "unreachable"
	ResultTimeout         = "timeout"
	ResultCircuitOpen     = "circuit_open"
	ResultSkippedDeadline = "skipped_deadline"
)

// PollResults is the closed result set, in exposition order.
func PollResults() []string {
	return []string{ResultOK, ResultError, ResultAuthFailed, ResultUnreachable, ResultTimeout, ResultCircuitOpen, ResultSkippedDeadline}
}

// Run statuses (RunRecord.Status).
const (
	RunStatusOK      = "ok"
	RunStatusPartial = "partial" // some streams delivered, some did not (or a sink refused)
	RunStatusError   = "error"
	// RunStatusBusy is returned (never recorded) when a poll of the same
	// integration is already running.
	RunStatusBusy = "busy"
)

// Sink lanes — the sink counter's lane label.
const (
	LaneMetrics  = "metrics"
	LaneEvents   = "events"
	LaneStates   = "states"
	LaneDevices  = "devices"
	LaneWireless = "wireless"
)

// SinkLanes is the closed lane set, in exposition order.
func SinkLanes() []string {
	return []string{LaneMetrics, LaneEvents, LaneStates, LaneDevices, LaneWireless}
}

// streamLabelUnknown stands in for a saved stream name the connector does not
// declare (the API does not validate the saved list): the label set stays
// bounded by the connector's own streams.
const streamLabelUnknown = "unknown"

// classifyPollError maps a poll/login error onto the closed result set, and
// reports whether it is a TRIPPING class for the circuit breaker (the
// controller is down, failing, or refusing us). Order matters: a login that
// timed out or could not connect is wrapped in ErrAuthFailed but is a
// transport fact, not a credential one, so transport classes win.
func classifyPollError(err error) (result string, tripping bool) {
	if err == nil {
		return ResultOK, false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ResultTimeout, true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return ResultTimeout, true
	}
	if errors.Is(err, context.Canceled) {
		return ResultError, false // shutdown, not the controller's fault
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) {
		return ResultUnreachable, true
	}
	var se *HTTPStatusError
	if errors.As(err, &se) && se.Code >= http.StatusInternalServerError {
		return ResultError, true // 5xx: the controller is up but failing
	}
	if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrUnauthorized) {
		return ResultAuthFailed, true
	}
	return ResultError, false
}

// runHealth is what one finished cycle tells the health registry.
type runHealth struct {
	Streams    []StreamResult
	Duration   time.Duration
	Finished   time.Time
	Delivered  bool // ≥1 stream delivered AND the correlation lanes (metrics, events) accepted it
	Failed     bool // the run status is error (nothing delivered)
	AuthFailed bool
	SinkFailed []string // lanes that refused this run's output
	// Devices is set when the cycle produced a COMPLETE inventory snapshot.
	Devices *deviceCounts
	Circuit BreakerState
}

type deviceCounts struct{ reported, unreachable int }

type integrationHealth struct {
	tenant, id, vendor string
	streams            map[string]bool // stream labels to zero-fill
	runs               map[[2]string]int64
	lastSuccess        time.Time
	pollDuration       time.Duration
	pollInterval       time.Duration
	everSucceeded      bool
	consecutiveFails   int
	circuitOpen        bool
	devicesReported    int
	devicesUnreachable int
	authFailures       int64
	sinkFailures       map[string]int64
}

// HealthMetrics is the connector-health registry. Mutex-guarded; keyed by
// (tenant, integration id).
type HealthMetrics struct {
	mu      sync.Mutex
	ints    map[string]*integrationHealth
	enabled map[string]int // vendor → enabled integrations
	vendors []string       // every registered vendor (zero-filled)
}

// NewHealthMetrics builds an empty registry over the registered vendors.
func NewHealthMetrics(vendors []string) *HealthMetrics {
	v := append([]string(nil), vendors...)
	sort.Strings(v)
	return &HealthMetrics{ints: map[string]*integrationHealth{}, enabled: map[string]int{}, vendors: v}
}

func (h *HealthMetrics) entryLocked(tenant, id, vendor string) *integrationHealth {
	k := Key(tenant, id)
	e, ok := h.ints[k]
	if !ok {
		e = &integrationHealth{tenant: tenant, id: id, vendor: vendor,
			streams: map[string]bool{}, runs: map[[2]string]int64{}, sinkFailures: map[string]int64{}}
		h.ints[k] = e
	}
	e.vendor = vendor
	return e
}

// enabledIntegration is what Sync needs to know about one enabled integration.
type enabledIntegration struct {
	Tenant, ID, Vendor string
	Interval           time.Duration
	Streams            []string // stream LABELS (already bounded to the spec)
	// LastSuccess seeds a NEWLY seen entry from the store (connector_health
	// .last_success), so an api restart in the middle of a controller outage
	// does not reset ever_succeeded to 0 and silence the page. Ignored for an
	// entry the registry already holds.
	LastSuccess time.Time
}

// Known reports whether the registry already holds the integration (the
// runtime seeds only unknown ones from the store).
func (h *HealthMetrics) Known(tenant, id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.ints[Key(tenant, id)]
	return ok
}

// Sync installs the current enabled set: entries for integrations no longer
// enabled are pruned (their series disappear rather than freezing), new ones
// appear zero-filled (ever_succeeded 0, last_success 0), and the per-vendor
// enabled gauge is recomputed.
func (h *HealthMetrics) Sync(enabled []enabledIntegration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	keep := make(map[string]bool, len(enabled))
	h.enabled = map[string]int{}
	for _, ei := range enabled {
		keep[Key(ei.Tenant, ei.ID)] = true
		h.enabled[ei.Vendor]++
		_, known := h.ints[Key(ei.Tenant, ei.ID)]
		e := h.entryLocked(ei.Tenant, ei.ID, ei.Vendor)
		if !known && !ei.LastSuccess.IsZero() {
			e.lastSuccess, e.everSucceeded = ei.LastSuccess, true
		}
		e.pollInterval = ei.Interval
		for _, s := range ei.Streams {
			e.streams[s] = true
		}
	}
	for k := range h.ints {
		if !keep[k] {
			delete(h.ints, k)
		}
	}
}

// Record folds one finished cycle into the integration's series.
func (h *HealthMetrics) Record(tenant, id, vendor string, interval time.Duration, rh runHealth) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.entryLocked(tenant, id, vendor)
	if interval > 0 {
		e.pollInterval = interval
	}
	for _, s := range rh.Streams {
		e.streams[s.Stream] = true
		e.runs[[2]string{s.Stream, s.Status}]++
	}
	e.pollDuration = rh.Duration
	if rh.Delivered {
		e.lastSuccess = rh.Finished
		e.everSucceeded = true
	}
	if rh.Failed {
		e.consecutiveFails++
	} else {
		e.consecutiveFails = 0
	}
	if rh.AuthFailed {
		e.authFailures++
	}
	for _, lane := range rh.SinkFailed {
		e.sinkFailures[lane]++
	}
	if rh.Devices != nil {
		e.devicesReported, e.devicesUnreachable = rh.Devices.reported, rh.Devices.unreachable
	}
	e.circuitOpen = rh.Circuit != BreakerClosed
}

// RecordSinkFailure counts a sink refusal outside a poll cycle (the webhook
// path shares the sinks).
func (h *HealthMetrics) RecordSinkFailure(tenant, id, vendor, lane string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entryLocked(tenant, id, vendor).sinkFailures[lane]++
}

type healthMetricDef struct {
	name, typ, help string
	value           func(e *integrationHealth) float64
}

func boolF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func healthGauges() []healthMetricDef {
	return []healthMetricDef{
		{"netops_nms_last_success_timestamp_seconds", "gauge", "Unix time of the integration's last cycle that delivered data (0 = never).",
			func(e *integrationHealth) float64 {
				if e.lastSuccess.IsZero() {
					return 0
				}
				return float64(e.lastSuccess.UnixNano()) / 1e9
			}},
		{"netops_nms_poll_duration_seconds", "gauge", "Wall time of the integration's last poll cycle.",
			func(e *integrationHealth) float64 { return e.pollDuration.Seconds() }},
		{"netops_nms_poll_interval_seconds", "gauge", "The integration's configured poll interval (after the floor).",
			func(e *integrationHealth) float64 { return e.pollInterval.Seconds() }},
		{"netops_nms_ever_succeeded", "gauge", "1 once the integration has delivered data at least once (seeded from connector_health across api restarts).",
			func(e *integrationHealth) float64 { return boolF(e.everSucceeded) }},
		{"netops_nms_consecutive_failures", "gauge", "Poll cycles in a row that delivered nothing.",
			func(e *integrationHealth) float64 { return float64(e.consecutiveFails) }},
		{"netops_nms_circuit_open", "gauge", "1 while the integration's circuit breaker is open or half-open (polling suspended).",
			func(e *integrationHealth) float64 { return boolF(e.circuitOpen) }},
		{"netops_nms_devices_reported", "gauge", "Devices in the integration's last complete inventory snapshot.",
			func(e *integrationHealth) float64 { return float64(e.devicesReported) }},
		{"netops_nms_devices_unreachable", "gauge", "Devices the controller reported unreachable in its last complete inventory snapshot.",
			func(e *integrationHealth) float64 { return float64(e.devicesUnreachable) }},
		{"netops_nms_auth_failures_total", "counter", "Poll cycles whose controller login failed.",
			func(e *integrationHealth) float64 { return float64(e.authFailures) }},
	}
}

func (h *HealthMetrics) sortedLocked() []*integrationHealth {
	out := make([]*integrationHealth, 0, len(h.ints))
	for _, e := range h.ints {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tenant != out[j].tenant {
			return out[i].tenant < out[j].tenant
		}
		return out[i].id < out[j].id
	})
	return out
}

func baseLabels(e *integrationHealth) string {
	return fmt.Sprintf(`tenant_id="%s",integration_id="%s",vendor="%s"`,
		sanitizeLabelValue(e.tenant), sanitizeLabelValue(e.id), sanitizeLabelValue(e.vendor))
}

// WriteMetrics renders every series (Prometheus exposition), deterministic
// order, every known label combination zero-filled so a rate() sees the first
// increment and an absent series always means "not exported" (api down).
func (h *HealthMetrics) WriteMetrics(w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ents := h.sortedLocked()
	var b strings.Builder

	b.WriteString("# HELP netops_nms_poll_runs_total NMS poll stream outcomes per cycle, by stream and result.\n")
	b.WriteString("# TYPE netops_nms_poll_runs_total counter\n")
	for _, e := range ents {
		streams := make([]string, 0, len(e.streams))
		for s := range e.streams {
			streams = append(streams, s)
		}
		sort.Strings(streams)
		for _, s := range streams {
			for _, r := range PollResults() {
				fmt.Fprintf(&b, "netops_nms_poll_runs_total{%s,stream=\"%s\",result=\"%s\"} %d\n",
					baseLabels(e), sanitizeLabelValue(s), r, e.runs[[2]string{s, r}])
			}
		}
	}
	for _, d := range healthGauges() {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", d.name, d.help, d.name, d.typ)
		for _, e := range ents {
			fmt.Fprintf(&b, "%s{%s} %s\n", d.name, baseLabels(e), strconv.FormatFloat(d.value(e), 'f', -1, 64))
		}
	}
	b.WriteString("# HELP netops_nms_sink_failures_total NMS output a sink refused, by lane.\n")
	b.WriteString("# TYPE netops_nms_sink_failures_total counter\n")
	for _, e := range ents {
		for _, lane := range SinkLanes() {
			fmt.Fprintf(&b, "netops_nms_sink_failures_total{%s,lane=\"%s\"} %d\n", baseLabels(e), lane, e.sinkFailures[lane])
		}
	}
	b.WriteString("# HELP netops_nms_integrations_enabled Enabled NMS integrations, by vendor.\n")
	b.WriteString("# TYPE netops_nms_integrations_enabled gauge\n")
	for _, v := range h.vendors {
		fmt.Fprintf(&b, "netops_nms_integrations_enabled{vendor=\"%s\"} %d\n", sanitizeLabelValue(v), h.enabled[v])
	}
	_, _ = io.WriteString(w, b.String()) // best-effort: a scrape that hung up has nothing to report to
}
