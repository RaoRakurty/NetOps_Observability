// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/url"
	"strings"
	"time"
)

// vmanage_metrics.go — the fleet-wide metric streams.
//
// The real-time /dataservice/device/* APIs answer one device per call and take
// seconds each, so they cannot carry a fabric's metrics. vManage keeps its own
// statistics database and answers ONE aggregation query for the whole fabric
// (verified on 20.6.1, 2026-10-18: approute 150 rows / 0.9 s, interface 234,
// system 33). Each stream asks for 10-minute buckets behind a watermark:
//   - vManage lands statistics 15–30 min late, so only buckets older than
//     vmanageAggSettle are read — a bucket is read once, after it is complete;
//   - the checkpoint is the end of the last bucket read, so a restart or an
//     outage resumes where it stopped (bounded by vmanageAggMaxLag) and no
//     bucket is counted twice;
//   - every value is a GAUGE for its bucket. vManage's octet/error/drop columns
//     are per-interval amounts, never device counters, so nothing here is a
//     `_total`.
// counters and certs change slowly and are read on their own cadence.

const (
	vmanageAggBucket = 10 * time.Minute
	vmanageAggSettle = 30 * time.Minute
	// vmanageAggMaxWindow bounds one query (rows = series × buckets); catch-up
	// after an outage walks forward a window per poll.
	vmanageAggMaxWindow = 30 * time.Minute
	// vmanageAggFirstRun is what a new integration reads on its first poll.
	vmanageAggFirstRun = time.Hour
	// vmanageAggMaxLag: older than this is not caught up — a dashboard wants
	// the present, and vManage's own retention for statistics is short.
	vmanageAggMaxLag  = 24 * time.Hour
	vmanageAggTimeFmt = "2006-01-02T15:04:05 UTC"
)

// vmAggSpec is one statistics index and what to aggregate from it.
type vmAggSpec struct {
	index   string
	group   []string    // aggregation.field, in order
	metrics [][2]string // {property, avg|sum|max|min}
}

var vmAppRouteAgg = vmAggSpec{
	index: "approute", group: []string{"name"},
	metrics: [][2]string{{"latency", "avg"}, {"jitter", "avg"}, {"loss_percentage", "avg"},
		{"vqoe_score", "avg"}, {"tx_octets", "sum"}, {"rx_octets", "sum"}},
}

// vmanageAggregations: stream → query. "statistics" is the pre-2026-10-18 name
// of the approute stream, kept so a saved integration keeps working.
var vmanageAggregations = map[string]vmAggSpec{
	"approute":   vmAppRouteAgg,
	"statistics": vmAppRouteAgg,
	"interfaces": {
		index: "interface", group: []string{"vdevice_name", "interface"},
		metrics: [][2]string{{"rx_kbps", "avg"}, {"tx_kbps", "avg"}, {"rx_errors", "sum"}, {"tx_errors", "sum"},
			{"rx_drops", "sum"}, {"tx_drops", "sum"}, {"up_capacity_percentage", "max"}},
	},
	"system": {
		index: "system", group: []string{"vdevice_name"},
		metrics: [][2]string{{"cpu_idle", "avg"}, {"mem_util", "max"}, {"disk_used", "max"},
			{"disk_avail", "min"}, {"min5_avg", "avg"}},
	},
}

// vmanageAggQuery is the 20.x aggregation body for buckets in [start, end).
func vmanageAggQuery(s vmAggSpec, start, end time.Time) string {
	fields := make([]map[string]any, 0, len(s.group))
	for i, f := range s.group {
		fields = append(fields, map[string]any{"property": f, "sequence": i + 1})
	}
	metrics := make([]map[string]any, 0, len(s.metrics))
	for _, m := range s.metrics {
		metrics = append(metrics, map[string]any{"property": m[0], "type": m[1]})
	}
	q, _ := json.Marshal(map[string]any{ // discard: marshalling an in-memory value cannot fail
		"query": map[string]any{"condition": "AND", "rules": []map[string]any{{
			// "between" is inclusive; end-1s keeps the next bucket out.
			"value": []string{start.UTC().Format(vmanageAggTimeFmt), end.Add(-time.Second).UTC().Format(vmanageAggTimeFmt)},
			"field": "entry_time", "type": "date", "operator": "between",
		}}},
		"aggregation": map[string]any{
			"field": fields,
			"histogram": map[string]any{"property": "entry_time", "type": "minute",
				"interval": int(vmanageAggBucket / time.Minute), "order": "asc"},
			"metrics": metrics,
		},
	})
	return string(q)
}

// vmanageAggWindow returns the next closed window after the checkpoint, or
// ok=false when no new bucket has settled yet.
func vmanageAggWindow(cp Checkpoint, now time.Time) (start, end time.Time, ok bool) {
	end = now.Add(-vmanageAggSettle).Truncate(vmanageAggBucket)
	start = cp.LastEventTime.Truncate(vmanageAggBucket)
	if cp.LastEventTime.IsZero() {
		start = end.Add(-vmanageAggFirstRun)
	}
	if floor := end.Add(-vmanageAggMaxLag); start.Before(floor) {
		start = floor
	}
	if end.Sub(start) > vmanageAggMaxWindow {
		end = start.Add(vmanageAggMaxWindow)
	}
	return start, end, end.After(start)
}

func pollVManageAggregation(ctx context.Context, in PollInput, s vmAggSpec) ([][]byte, Checkpoint, error) {
	start, end, ok := vmanageAggWindow(in.Checkpoint, nowUTC())
	if !ok {
		return nil, in.Checkpoint, nil // nothing has settled since the last read
	}
	path := "/dataservice/statistics/" + s.index + "/aggregation?query=" + url.QueryEscape(vmanageAggQuery(s, start, end))
	body, err := fetch(ctx, in, path)
	if err != nil {
		return nil, in.Checkpoint, err
	}
	return [][]byte{body}, Checkpoint{LastEventTime: end, LastSeq: in.Checkpoint.LastSeq + 1}, nil
}

// vmanageSlowStreams are fleet-wide snapshots that change slowly: read on
// their own cadence, not every poll.
var vmanageSlowStreams = map[string]struct {
	every time.Duration
	paths []string
}{
	"counters": {10 * time.Minute, []string{"/dataservice/device/counters"}},
	"certs":    {time.Hour, []string{"/dataservice/system/device/vedges", "/dataservice/system/device/controllers"}},
}

func pollVManageSlow(ctx context.Context, in PollInput, every time.Duration, paths []string) ([][]byte, Checkpoint, error) {
	now := nowUTC()
	if !in.Checkpoint.LastEventTime.IsZero() && now.Sub(in.Checkpoint.LastEventTime) < every {
		return nil, in.Checkpoint, nil // not due
	}
	out := make([][]byte, 0, len(paths))
	for _, p := range paths {
		body, err := fetch(ctx, in, p)
		if err != nil {
			return nil, in.Checkpoint, err
		}
		out = append(out, body)
	}
	return out, Checkpoint{LastEventTime: now, LastSeq: in.Checkpoint.LastSeq + 1}, nil
}

// --- transformers -----------------------------------------------------------

func vmMetricTags(tenant, integrationID string, kv ...string) map[string]string {
	t := map[string]string{"tenant_id": tenant, "integration_id": integrationID, "source_system": "vmanage"}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			t[kv[i]] = kv[i+1]
		}
	}
	return t
}

func vmMetric(tenant, integrationID, name string, v float64, unit string, ts time.Time, tags map[string]string) ControllerMetric {
	return ControllerMetric{TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
		Name: name, Value: v, Unit: unit, Time: ts, Tags: tags}
}

// vmBucketRate turns a per-bucket amount into a per-second rate.
func vmBucketRate(v vmNum) float64 { return float64(v) / vmanageAggBucket.Seconds() }

// vmParseTunnelName splits an approute name "<ip>:<color>-<ip>:<color>".
// Colours contain hyphens ("biz-internet"); system-ips never do.
func vmParseTunnelName(name string) (lip, lcol, rip, rcol string, ok bool) {
	lip, rest, ok1 := strings.Cut(name, ":")
	i := strings.LastIndexByte(rest, ':')
	if !ok1 || i < 0 {
		return "", "", "", "", false
	}
	mid, rcol := rest[:i], rest[i+1:]
	j := strings.LastIndexByte(mid, '-')
	if j < 0 {
		return "", "", "", "", false
	}
	lcol, rip = mid[:j], mid[j+1:]
	if net.ParseIP(lip) == nil || net.ParseIP(rip) == nil || lcol == "" || rcol == "" {
		return "", "", "", "", false
	}
	return lip, lcol, rip, rcol, true
}

func vmAggRows(raw []byte, v any) error {
	return json.Unmarshal(raw, &struct {
		Data any `json:"data"`
	}{Data: v})
}

func vmanageAppRouteAggTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var rows []struct {
		EntryTime vmNum  `json:"entry_time"`
		Count     vmNum  `json:"count"`
		Name      string `json:"name"`
		Latency   vmNum  `json:"latency"`
		Jitter    vmNum  `json:"jitter"`
		Loss      vmNum  `json:"loss_percentage"`
		QoE       vmNum  `json:"vqoe_score"`
		TxOctets  vmNum  `json:"tx_octets"`
		RxOctets  vmNum  `json:"rx_octets"`
	}
	if err := vmAggRows(raw, &rows); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		lip, lcol, rip, rcol, ok := vmParseTunnelName(r.Name)
		if !ok || r.Count <= 0 {
			continue // untrusted controller output: no parsable tunnel, or an empty bucket
		}
		ts := vmTime(int64(r.EntryTime))
		tags := vmMetricTags(tenant, integrationID, "device", lip, "tunnel", r.Name, "peer", rip,
			"transport", lcol+"-"+rcol, "local_color", lcol, "remote_color", rcol)
		b.Metrics = append(b.Metrics,
			vmMetric(tenant, integrationID, "controller_metric_tunnel_latency_ms", float64(r.Latency), "ms", ts, tags),
			vmMetric(tenant, integrationID, "controller_metric_tunnel_jitter_ms", float64(r.Jitter), "ms", ts, tags),
			vmMetric(tenant, integrationID, "controller_metric_tunnel_loss_pct", float64(r.Loss), "percent", ts, tags),
			vmMetric(tenant, integrationID, "controller_metric_tunnel_qoe", float64(r.QoE), "score", ts, tags),
			vmMetric(tenant, integrationID, "controller_metric_tunnel_rx_bps", vmBucketRate(r.RxOctets)*8, "bps", ts, tags),
			vmMetric(tenant, integrationID, "controller_metric_tunnel_tx_bps", vmBucketRate(r.TxOctets)*8, "bps", ts, tags),
		)
	}
	return b, nil
}

func vmanageInterfaceAggTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var rows []struct {
		EntryTime vmNum  `json:"entry_time"`
		Count     vmNum  `json:"count"`
		Device    string `json:"vdevice_name"`
		Interface string `json:"interface"`
		RxKbps    vmNum  `json:"rx_kbps"`
		TxKbps    vmNum  `json:"tx_kbps"`
		RxErrors  vmNum  `json:"rx_errors"`
		TxErrors  vmNum  `json:"tx_errors"`
		RxDrops   vmNum  `json:"rx_drops"`
		TxDrops   vmNum  `json:"tx_drops"`
		Util      vmNum  `json:"up_capacity_percentage"`
	}
	if err := vmAggRows(raw, &rows); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		if net.ParseIP(r.Device) == nil || strings.TrimSpace(r.Interface) == "" || r.Count <= 0 {
			continue
		}
		ts := vmTime(int64(r.EntryTime))
		tags := vmMetricTags(tenant, integrationID, "device", r.Device, "interface", r.Interface)
		m := func(name string, v float64, unit string) ControllerMetric {
			return vmMetric(tenant, integrationID, "controller_metric_interface_"+name, v, unit, ts, tags)
		}
		b.Metrics = append(b.Metrics,
			m("rx_bps", float64(r.RxKbps)*1000, "bps"),
			m("tx_bps", float64(r.TxKbps)*1000, "bps"),
			m("rx_errors_per_sec", vmBucketRate(r.RxErrors), "per_second"),
			m("tx_errors_per_sec", vmBucketRate(r.TxErrors), "per_second"),
			m("rx_drops_per_sec", vmBucketRate(r.RxDrops), "per_second"),
			m("tx_drops_per_sec", vmBucketRate(r.TxDrops), "per_second"),
			m("util_pct", float64(r.Util), "percent"),
		)
	}
	return b, nil
}

func vmanageSystemAggTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var rows []struct {
		EntryTime vmNum  `json:"entry_time"`
		Count     vmNum  `json:"count"`
		Device    string `json:"vdevice_name"`
		CPUIdle   vmNum  `json:"cpu_idle"`
		MemUtil   vmNum  `json:"mem_util"`
		DiskUsed  vmNum  `json:"disk_used"`
		DiskAvail vmNum  `json:"disk_avail"`
		Load5     vmNum  `json:"min5_avg"`
	}
	if err := vmAggRows(raw, &rows); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		if net.ParseIP(r.Device) == nil || r.Count <= 0 {
			continue
		}
		ts := vmTime(int64(r.EntryTime))
		tags := vmMetricTags(tenant, integrationID, "device", r.Device)
		m := func(name string, v float64, unit string) ControllerMetric {
			return vmMetric(tenant, integrationID, "controller_metric_device_"+name, v, unit, ts, tags)
		}
		// mem_util is a fraction on 20.x; a release that reports percent is
		// taken as-is rather than shown as 3600 %.
		mem := float64(r.MemUtil)
		if mem <= 1 {
			mem *= 100
		}
		b.Metrics = append(b.Metrics,
			m("cpu_pct", clampPct(100-float64(r.CPUIdle)), "percent"),
			m("mem_pct", clampPct(mem), "percent"),
			m("load5", float64(r.Load5), "load"),
		)
		if total := float64(r.DiskUsed + r.DiskAvail); total > 0 {
			b.Metrics = append(b.Metrics, m("disk_pct", clampPct(float64(r.DiskUsed)/total*100), "percent"))
		}
	}
	return b, nil
}

func clampPct(v float64) float64 { return math.Max(0, math.Min(100, v)) }

func vmanageCountersTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var rows []struct {
		SystemIP string `json:"system-ip"`
		CtrlUp   *vmNum `json:"number-vsmart-control-connections"`
		CtrlWant *vmNum `json:"expectedControlConnections"`
		OMPUp    *vmNum `json:"ompPeersUp"`
		OMPDown  *vmNum `json:"ompPeersDown"`
		BFDUp    *vmNum `json:"bfdSessionsUp"`
		BFDDown  *vmNum `json:"bfdSessionsDown"`
		Reboots  *vmNum `json:"rebootCount"`
		Crashes  *vmNum `json:"crashCount"`
	}
	if err := vmAggRows(raw, &rows); err != nil {
		return Batch{}, err
	}
	ts := nowUTC()
	var b Batch
	for _, r := range rows {
		if net.ParseIP(r.SystemIP) == nil {
			continue
		}
		tags := vmMetricTags(tenant, integrationID, "device", r.SystemIP)
		// A counter a device does not report (controllers have no BFD) is
		// absent, never a zero that reads as "all sessions down".
		for _, f := range []struct {
			name string
			v    *vmNum
		}{
			{"control_connections", r.CtrlUp}, {"control_connections_expected", r.CtrlWant},
			{"omp_peers_up", r.OMPUp}, {"omp_peers_down", r.OMPDown},
			{"bfd_sessions_up", r.BFDUp}, {"bfd_sessions_down", r.BFDDown},
			{"reboots", r.Reboots}, {"crashes", r.Crashes},
		} {
			if f.v != nil {
				b.Metrics = append(b.Metrics, vmMetric(tenant, integrationID, "controller_metric_device_"+f.name, float64(*f.v), "count", ts, tags))
			}
		}
	}
	return b, nil
}

// vmanageCertsTransform: one expiry timestamp per provisioned device. Rows
// with no system-ip are unclaimed chassis tokens, not devices.
func vmanageCertsTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var rows []struct {
		DeviceType string `json:"deviceType"`
		SystemIP   string `json:"system-ip"`
		HostName   string `json:"host-name"`
		Validity   string `json:"validity"`
		CertState  string `json:"vedgeCertificateState"`
		ExpiresMS  vmNum  `json:"expirationDateLong"`
	}
	if err := vmAggRows(raw, &rows); err != nil {
		return Batch{}, err
	}
	ts := nowUTC()
	var b Batch
	for _, r := range rows {
		if net.ParseIP(r.SystemIP) == nil || r.ExpiresMS <= 0 {
			continue
		}
		tags := vmMetricTags(tenant, integrationID, "device", r.SystemIP, "device_name", r.HostName,
			"device_type", strings.ToLower(r.DeviceType), "validity", strings.ToLower(r.Validity), "cert_state", strings.ToLower(r.CertState))
		b.Metrics = append(b.Metrics, vmMetric(tenant, integrationID, "controller_metric_cert_expiry_timestamp_seconds",
			math.Floor(float64(r.ExpiresMS)/1000), "seconds", ts, tags))
	}
	return b, nil
}
