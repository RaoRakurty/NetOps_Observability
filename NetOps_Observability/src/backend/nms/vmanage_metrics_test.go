// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Rows below are trimmed from a live 20.6.1 (2026-10-18), values kept.

func withNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := nowUTC
	nowUTC = func() time.Time { return now }
	t.Cleanup(func() { nowUTC = prev })
}

type recordingVManage struct {
	mu    sync.Mutex
	paths []string
	query []string
	body  map[string]string // path → response
}

func (f *recordingVManage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.query = append(f.query, r.URL.Query().Get("query"))
	f.mu.Unlock()
	b, ok := f.body[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(b)) // discard: a test server write to a live client
}

func pollWith(t *testing.T, f *recordingVManage, stream string, cp Checkpoint) ([][]byte, Checkpoint, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return vmanagePoller().Poll(context.Background(), PollInput{Base: srv.URL, Stream: stream, Do: srv.Client(), Checkpoint: cp})
}

func metricsByName(b Batch) map[string][]ControllerMetric {
	out := map[string][]ControllerMetric{}
	for _, m := range b.Metrics {
		out[m.Name] = append(out[m.Name], m)
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestVManageAggWindow(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 47, 0, 0, time.UTC)
	settled := time.Date(2026, 10, 18, 12, 10, 0, 0, time.UTC) // floor10(now-30m)

	// First run: one hour back, capped to one window per poll.
	s, e, ok := vmanageAggWindow(Checkpoint{}, now)
	if !ok || !s.Equal(settled.Add(-time.Hour)) || !e.Equal(s.Add(vmanageAggMaxWindow)) {
		t.Fatalf("first run [%v,%v) ok=%v", s, e, ok)
	}
	// Steady state: resumes exactly at the checkpoint, ends at the settled edge.
	s, e, ok = vmanageAggWindow(Checkpoint{LastEventTime: settled.Add(-10 * time.Minute)}, now)
	if !ok || !s.Equal(settled.Add(-10*time.Minute)) || !e.Equal(settled) {
		t.Fatalf("steady [%v,%v) ok=%v", s, e, ok)
	}
	// Nothing new has settled: no query.
	if _, _, ok = vmanageAggWindow(Checkpoint{LastEventTime: settled}, now); ok {
		t.Fatal("a window that has not settled must not be read")
	}
	// A checkpoint ahead of the settled edge (an older build stamped "now")
	// waits rather than reading unsettled buckets.
	if _, _, ok = vmanageAggWindow(Checkpoint{LastEventTime: now}, now); ok {
		t.Fatal("a checkpoint past the settled edge must wait")
	}
	// After a long outage catch-up starts at the max-lag floor, not the checkpoint.
	s, _, ok = vmanageAggWindow(Checkpoint{LastEventTime: now.Add(-72 * time.Hour)}, now)
	if !ok || !s.Equal(settled.Add(-vmanageAggMaxLag)) {
		t.Fatalf("outage start %v", s)
	}
}

func TestVManageAggregationPollAsksForClosedBucketsOnce(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 47, 0, 0, time.UTC)
	withNow(t, now)
	f := &recordingVManage{body: map[string]string{"/dataservice/statistics/interface/aggregation": `{"data":[]}`}}
	cp := Checkpoint{LastEventTime: time.Date(2026, 10, 18, 11, 50, 0, 0, time.UTC), LastSeq: 4}

	raw, next, err := pollWith(t, f, "interfaces", cp)
	if err != nil || len(raw) != 1 {
		t.Fatalf("raw=%d err=%v", len(raw), err)
	}
	if want := time.Date(2026, 10, 18, 12, 10, 0, 0, time.UTC); !next.LastEventTime.Equal(want) || next.LastSeq != 5 {
		t.Fatalf("checkpoint %+v — want the window end %v", next, want)
	}
	var q struct {
		Query struct {
			Rules []struct {
				Value    []string `json:"value"`
				Operator string   `json:"operator"`
			} `json:"rules"`
		} `json:"query"`
		Aggregation struct {
			Field []struct {
				Property string `json:"property"`
				Sequence int    `json:"sequence"`
			} `json:"field"`
			Histogram struct {
				Interval int `json:"interval"`
			} `json:"histogram"`
			Metrics []struct{ Property, Type string } `json:"metrics"`
		} `json:"aggregation"`
	}
	if err := json.Unmarshal([]byte(f.query[0]), &q); err != nil {
		t.Fatal(err)
	}
	r := q.Query.Rules[0]
	if r.Operator != "between" || r.Value[0] != "2026-10-18T11:50:00 UTC" || r.Value[1] != "2026-10-18T12:09:59 UTC" {
		t.Fatalf("time rule %+v", r)
	}
	if len(q.Aggregation.Field) != 2 || q.Aggregation.Field[0].Property != "vdevice_name" || q.Aggregation.Field[1].Sequence != 2 {
		t.Fatalf("group %+v", q.Aggregation.Field)
	}
	if q.Aggregation.Histogram.Interval != 10 || len(q.Aggregation.Metrics) != 7 {
		t.Fatalf("histogram/metrics %+v", q.Aggregation)
	}

	// Polled again at once: the window has not moved, so no call is made.
	raw, again, err := pollWith(t, f, "interfaces", next)
	if err != nil || raw != nil || again != next || len(f.paths) != 1 {
		t.Fatalf("second poll raw=%v cp=%+v calls=%d err=%v", raw, again, len(f.paths), err)
	}
}

func TestVManageAggregationErrorKeepsCheckpoint(t *testing.T) {
	withNow(t, time.Date(2026, 10, 18, 12, 47, 0, 0, time.UTC))
	f := &recordingVManage{body: map[string]string{}} // 404 for everything
	cp := Checkpoint{LastEventTime: time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC), LastSeq: 9}
	_, next, err := pollWith(t, f, "system", cp)
	if err == nil || next != cp {
		t.Fatalf("a failed read must not advance the watermark: err=%v next=%+v", err, next)
	}
}

func TestVManageParseTunnelName(t *testing.T) {
	lip, lcol, rip, rcol, ok := vmParseTunnelName("10.255.255.100:biz-internet-10.255.255.20:public-internet")
	if !ok || lip != "10.255.255.100" || lcol != "biz-internet" || rip != "10.255.255.20" || rcol != "public-internet" {
		t.Fatalf("%q %q %q %q %v", lip, lcol, rip, rcol, ok)
	}
	for _, bad := range []string{"", "x", "10.0.0.1:mpls", "a:b-c:d", "10.0.0.1:-10.0.0.2:mpls", `10.0.0.1:mpls-10.0.0.2:`} {
		if _, _, _, _, ok := vmParseTunnelName(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestVManageAppRouteAggregation(t *testing.T) {
	raw := `{"data":[
	 {"entry_time":1792330800000,"count":120,"name":"10.255.255.100:biz-internet-10.255.255.40:biz-internet","vqoe_score":8,"jitter":3.125,"rx_octets":0,"loss_percentage":12.9,"latency":11.34,"tx_octets":980571},
	 {"entry_time":1792330800000,"count":0,"name":"10.255.255.100:mpls-10.255.255.40:mpls","latency":1},
	 {"entry_time":1792330800000,"count":5,"name":"<script>","latency":1}]}`
	for _, stream := range []string{"approute", "statistics"} {
		b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", stream, []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		by := metricsByName(b)
		if len(b.Metrics) != 6 {
			t.Fatalf("%s: %d metrics — want 6 from the one valid, non-empty bucket", stream, len(b.Metrics))
		}
		m := by["controller_metric_tunnel_tx_bps"][0]
		if !near(m.Value, 980571.0*8/600) || m.Unit != "bps" {
			t.Fatalf("tx_bps %v", m.Value)
		}
		if m.Tags["device"] != "10.255.255.100" || m.Tags["peer"] != "10.255.255.40" || m.Tags["transport"] != "biz-internet-biz-internet" || m.Tags["tenant_id"] != "t1" {
			t.Fatalf("tags %v", m.Tags)
		}
		if !m.Time.Equal(time.UnixMilli(1792330800000).UTC()) {
			t.Fatalf("stamped %v — want the bucket time", m.Time)
		}
		if by["controller_metric_tunnel_loss_pct"][0].Value != 12.9 {
			t.Fatal("loss")
		}
		for _, x := range b.Metrics {
			if strings.HasSuffix(x.Name, "_total") {
				t.Fatalf("%s: a per-bucket amount is a gauge, never a counter", x.Name)
			}
		}
	}
}

func TestVManageInterfaceAggregation(t *testing.T) {
	raw := `{"data":[
	 {"entry_time":1792330800000,"count":2,"vdevice_name":"10.255.255.100","interface":"ge0/0","tx_kbps":39.5,"rx_kbps":23,"tx_errors":0,"rx_errors":60,"rx_drops":6,"tx_drops":0,"up_capacity_percentage":0.004},
	 {"entry_time":1792330800000,"count":2,"vdevice_name":"vedge-x","interface":"ge0/1","rx_kbps":1},
	 {"entry_time":1792330800000,"count":2,"vdevice_name":"10.255.255.100","interface":" ","rx_kbps":1}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "interfaces", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	by := metricsByName(b)
	if len(b.Metrics) != 7 {
		t.Fatalf("%d metrics", len(b.Metrics))
	}
	if by["controller_metric_interface_tx_bps"][0].Value != 39500 || by["controller_metric_interface_rx_bps"][0].Value != 23000 {
		t.Fatal("kbps → bps")
	}
	if !near(by["controller_metric_interface_rx_errors_per_sec"][0].Value, 0.1) || !near(by["controller_metric_interface_rx_drops_per_sec"][0].Value, 0.01) {
		t.Fatal("per-bucket errors/drops → per second")
	}
	if g := by["controller_metric_interface_util_pct"][0]; g.Value != 0.004 || g.Tags["interface"] != "ge0/0" {
		t.Fatalf("util %+v", g)
	}
}

func TestVManageSystemAggregation(t *testing.T) {
	raw := `{"data":[
	 {"entry_time":1792330800000,"count":10,"vdevice_name":"10.255.255.1","disk_avail":12858408960.0,"disk_used":2236592128,"cpu_idle":89.75,"mem_util":0.36,"min5_avg":1.33},
	 {"entry_time":1792330800000,"count":10,"vdevice_name":"10.255.255.2","cpu_idle":"95","mem_util":42}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "system", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, m := range b.Metrics {
		got[m.Tags["device"]+" "+m.Name] = m.Value
	}
	want := map[string]float64{
		"10.255.255.1 controller_metric_device_cpu_pct":  10.25,
		"10.255.255.1 controller_metric_device_mem_pct":  36,
		"10.255.255.1 controller_metric_device_load5":    1.33,
		"10.255.255.1 controller_metric_device_disk_pct": 2236592128.0 / (2236592128 + 12858408960) * 100,
		"10.255.255.2 controller_metric_device_cpu_pct":  5,
		"10.255.255.2 controller_metric_device_mem_pct":  42, // already a percent
		"10.255.255.2 controller_metric_device_load5":    0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got) // .2 reports no disk: no disk_pct, never 0 %
	}
	for k, v := range want {
		if !near(got[k], v) {
			t.Errorf("%s = %v want %v", k, got[k], v)
		}
	}
}

func TestVManageCountersOnlyWhatIsReported(t *testing.T) {
	withNow(t, time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	raw := `{"data":[
	 {"system-ip":"10.255.255.1","number-vsmart-control-connections":1,"expectedControlConnections":1,"rebootCount":1,"crashCount":0},
	 {"system-ip":"10.255.255.100","number-vsmart-control-connections":"2","expectedControlConnections":2,"ompPeersUp":1,"ompPeersDown":0,"bfdSessionsUp":12,"bfdSessionsDown":0,"rebootCount":0,"crashCount":0},
	 {"system-ip":"bogus","rebootCount":3}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "counters", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, m := range b.Metrics {
		got[m.Tags["device"]+" "+strings.TrimPrefix(m.Name, "controller_metric_device_")] = m.Value
	}
	if len(got) != 4+8 {
		t.Fatalf("got %d: %v", len(got), got)
	}
	if _, ok := got["10.255.255.1 bfd_sessions_down"]; ok {
		t.Fatal("a controller has no BFD: the counter must be absent, not a zero")
	}
	if got["10.255.255.100 bfd_sessions_up"] != 12 || got["10.255.255.100 control_connections"] != 2 || got["10.255.255.1 reboots"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestVManageCertsStream(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	withNow(t, now)
	f := &recordingVManage{body: map[string]string{
		"/dataservice/system/device/vedges": `{"data":[
		 {"deviceType":"vedge","validity":"valid","vedgeCertificateState":"certinstalled","expirationDateLong":2100746094000,"system-ip":"10.255.255.51","host-name":"vEdge-51"},
		 {"deviceType":"vedge","validity":"valid","vedgeCertificateState":"tokengenerated","expirationDate":"NA","expirationDateLong":null}]}`,
		"/dataservice/system/device/controllers": `{"data":[
		 {"deviceType":"vsmart","validity":"valid","expirationDateLong":"1846465888000","system-ip":"10.255.255.2","host-name":"vSmart"}]}`,
	}}
	raw, next, err := pollWith(t, f, "certs", Checkpoint{})
	if err != nil || len(raw) != 2 || !next.LastEventTime.Equal(now) {
		t.Fatalf("raw=%d next=%+v err=%v", len(raw), next, err)
	}
	var all []ControllerMetric
	for _, r := range raw {
		b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "certs", r)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b.Metrics...)
	}
	if len(all) != 2 {
		t.Fatalf("%d — an unclaimed chassis token is not a device", len(all))
	}
	if all[0].Value != 2100746094 || all[0].Tags["cert_state"] != "certinstalled" || all[1].Value != 1846465888 || all[1].Tags["device_type"] != "vsmart" {
		t.Fatalf("%+v", all)
	}

	// Within the hour: not due, no call.
	withNow(t, now.Add(59*time.Minute))
	raw, again, err := pollWith(t, f, "certs", next)
	if err != nil || raw != nil || again != next || len(f.paths) != 2 {
		t.Fatalf("not-due poll raw=%v calls=%d err=%v", raw, len(f.paths), err)
	}
	withNow(t, now.Add(61*time.Minute))
	if raw, _, err = pollWith(t, f, "certs", next); err != nil || len(raw) != 2 {
		t.Fatalf("due poll raw=%d err=%v", len(raw), err)
	}
}

func TestVManageSlowStreamFailureKeepsCheckpoint(t *testing.T) {
	withNow(t, time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	f := &recordingVManage{body: map[string]string{"/dataservice/system/device/vedges": `{"data":[]}`}}
	_, next, err := pollWith(t, f, "certs", Checkpoint{})
	if err == nil || !next.LastEventTime.IsZero() {
		t.Fatalf("half a snapshot must not count as read: err=%v next=%+v", err, next)
	}
}

// Every default stream must be one the poller and transformer handle — a
// default that answers "not supported" is a stream the fabric silently lacks.
func TestVManageDefaultStreamsAreAllServed(t *testing.T) {
	withNow(t, time.Date(2026, 10, 18, 12, 47, 0, 0, time.UTC))
	inv := `{"data":[{"system-ip":"10.255.255.20","device-type":"vedge","reachability":"reachable"}]}`
	f := &recordingVManage{body: map[string]string{}}
	for _, p := range []string{"/dataservice/alarms", "/dataservice/event", "/dataservice/device/counters",
		"/dataservice/system/device/vedges", "/dataservice/system/device/controllers",
		"/dataservice/device/control/connections", "/dataservice/device/bfd/sessions"} {
		f.body[p] = `{"data":[]}`
	}
	f.body["/dataservice/device"] = inv
	for _, idx := range []string{"approute", "interface", "system"} {
		f.body["/dataservice/statistics/"+idx+"/aggregation"] = `{"data":[]}`
	}
	spec, ok := Specs()["vmanage"]
	if !ok {
		t.Fatal("no vmanage spec")
	}
	for _, s := range spec.Streams {
		raw, _, err := pollWith(t, f, s, Checkpoint{})
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		for _, r := range raw {
			if _, err := (VManageAutoTransformer{}).TransformStream("t1", "i1", s, r); err != nil {
				t.Errorf("%s transform: %v", s, err)
			}
		}
	}
	// The aggregation query is URL-escaped JSON, never sent raw.
	for _, q := range f.query {
		if q != "" && !json.Valid([]byte(q)) {
			t.Errorf("query not JSON: %q", q)
		}
	}
}
