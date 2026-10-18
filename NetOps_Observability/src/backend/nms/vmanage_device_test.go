// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Row shapes sampled from a live vManage 20.6.1 (2026-10-18).
const (
	bfdRows = `{"data":[
{"src-ip":"172.16.40.40","dst-ip":"192.1.2.1","color":"mpls","vdevice-name":"10.255.255.40","system-ip":"10.255.255.51","site-id":50,"transitions":0,"vdevice-host-name":"cEDGE-40","local-color":"mpls","detect-multiplier":"7","vdevice-dataKey":"bk1","proto":"ipsec","lastupdated":1792297577971,"state":"up","tx-interval":1000},
{"color":"biz-internet","vdevice-name":"10.255.255.40","system-ip":"10.255.255.52","site-id":"50","vdevice-host-name":"cEDGE-40","local-color":"mpls","detect-multiplier":"7","vdevice-dataKey":"k2","state":"down","lastupdated":1792297577971}]}`
	controlRows   = `{"data":[{"vdevice-name":"10.255.255.40","system-ip":"10.255.255.2","remote-color":"default","site-id":250,"controller-group-id":0,"vdevice-host-name":"cEDGE-40","local-color":"mpls","peer-type":"vsmart","protocol":"dtls","vdevice-dataKey":"ck1","lastupdated":1792297580059,"state":"up"}]}`
	tunnelRows    = `{"data":[{"dest-ip":"192.1.2.1","vdevice-name":"10.255.255.40","rx_pkts":56453,"system-ip":"10.255.255.51","remote-color":"mpls","tx_octets":4161406,"vdevice-host-name":"cEDGE-40","tunnel-protocol":"ipsec","local-color":"mpls","tx_pkts":56453,"vdevice-dataKey":"tk1","rx_octets":5762115,"lastupdated":1792297582040}]}`
	inventoryRows = `{"data":[
{"system-ip":"10.255.255.40","device-type":"vedge","reachability":"reachable"},
{"system-ip":"10.255.255.20","device-type":"vedge","reachability":"reachable"},
{"system-ip":"10.255.255.2","device-type":"vsmart","reachability":"reachable"},
{"system-ip":"10.255.255.99","device-type":"vedge","reachability":"unreachable"},
{"system-ip":"10.0.0.1&deviceId=x","device-type":"vedge","reachability":"reachable"}]}`
)

type perDeviceFake struct {
	mu      sync.Mutex
	queried map[string][]string // path → deviceIds asked
	failIP  string
	status  int // forced status for every per-device call, 0 = normal
}

func (f *perDeviceFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/dataservice/device" {
		_, _ = w.Write([]byte(inventoryRows))
		return
	}
	id := r.URL.Query().Get("deviceId")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest) // what every real vManage answers
		return
	}
	f.mu.Lock()
	f.queried[r.URL.Path] = append(f.queried[r.URL.Path], id)
	f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if id == f.failIP {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(bfdRows))
}

func pollStream(t *testing.T, f *perDeviceFake, stream string) ([][]byte, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	raw, _, err := vmanagePoller().Poll(context.Background(), PollInput{Base: srv.URL, Stream: stream, Do: srv.Client()})
	return raw, err
}

func TestVManagePerDeviceStreamsAskEachReachableDevice(t *testing.T) {
	f := &perDeviceFake{queried: map[string][]string{}}
	raw, err := pollStream(t, f, "bfd")
	if err != nil {
		t.Fatal(err)
	}
	got := f.queried["/dataservice/device/bfd/sessions"]
	sort.Strings(got)
	if strings.Join(got, ",") != "10.255.255.20,10.255.255.40" {
		t.Fatalf("bfd asked %v — want the two reachable edges only (no controller, no unreachable, no non-IP)", got)
	}
	if len(raw) != 2 {
		t.Fatalf("payloads %d", len(raw))
	}
	f.queried = map[string][]string{}
	if _, err := pollStream(t, f, "control_connections"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.queried["/dataservice/device/control/connections"]); n != 3 {
		t.Fatalf("control connections asked %d devices, want 3 (edges + vSmart)", n)
	}
}

func TestVManageOneFailingDeviceDoesNotBlankTheFabric(t *testing.T) {
	f := &perDeviceFake{queried: map[string][]string{}, failIP: "10.255.255.20"}
	raw, err := pollStream(t, f, "tunnels")
	if err != nil || len(raw) != 1 {
		t.Fatalf("raw=%d err=%v", len(raw), err)
	}
}

func TestVManageEveryDeviceFailingIsAnError(t *testing.T) {
	f := &perDeviceFake{queried: map[string][]string{}, status: http.StatusInternalServerError}
	if _, err := pollStream(t, f, "bfd"); err == nil || !strings.Contains(err.Error(), "every device failed") {
		t.Fatalf("want an every-device error, got %v", err)
	}
}

func TestVManagePerDevice401ReauthenticatesTheSession(t *testing.T) {
	f := &perDeviceFake{queried: map[string][]string{}, status: http.StatusUnauthorized}
	if _, err := pollStream(t, f, "bfd"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestRotateWindowCoversALargeFabricAcrossCycles(t *testing.T) {
	ids := make([]string, 5)
	for i := range ids {
		ids[i] = fmt.Sprint(i)
	}
	seen := map[string]bool{}
	for c := 0; c < 3; c++ {
		w := rotateWindow(ids, c, 2)
		if len(w) != 2 {
			t.Fatalf("window %v", w)
		}
		for _, id := range w {
			seen[id] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("3 cycles of 2 covered %d of 5", len(seen))
	}
	if got := rotateWindow(ids, 7, 10); len(got) != 5 {
		t.Fatalf("small fabric must be returned whole: %v", got)
	}
}

func TestVManageDeviceRowsBecomeStatesAndMetrics(t *testing.T) {
	tr := VManageAutoTransformer{}
	b, err := tr.Transform("t-a", "int-1", []byte(bfdRows))
	if err != nil || len(b.States) != 2 || len(b.Events) != 0 {
		t.Fatalf("bfd: states=%d events=%d err=%v", len(b.States), len(b.Events), err)
	}
	if s := b.States[0]; s.StateKind != "bfd" || s.CurrentState != "up" || s.DeviceID != "10.255.255.40" || s.SiteID != "50" || s.TenantID != "t-a" {
		t.Fatalf("bfd state %+v", s)
	}
	if b.States[1].CurrentState != "down" || b.States[1].SiteID != "50" {
		t.Fatalf("bfd down / string site-id: %+v", b.States[1])
	}
	b, err = tr.Transform("t-a", "int-1", []byte(controlRows))
	if err != nil || len(b.States) != 1 || b.States[0].StateKind != "control_conn" || b.States[0].Data["peer_type"] != "vsmart" {
		t.Fatalf("control: %+v err=%v", b.States, err)
	}
	b, err = tr.Transform("t-a", "int-1", []byte(tunnelRows))
	if err != nil || len(b.Metrics) != 4 || len(b.Events) != 0 {
		t.Fatalf("tunnels: metrics=%d events=%d err=%v", len(b.Metrics), len(b.Events), err)
	}
	vals := map[string]float64{}
	for _, m := range b.Metrics {
		vals[m.Name] = m.Value
		if m.Tags["device"] != "10.255.255.40" || m.Tags["tenant_id"] != "t-a" {
			t.Fatalf("tags %v", m.Tags)
		}
	}
	if vals["controller_metric_tunnel_rx_octets_total"] != 5762115 || vals["controller_metric_tunnel_tx_packets_total"] != 56453 {
		t.Fatalf("values %v", vals)
	}
}

func TestVManageAlarmsStillReachTheAlarmParser(t *testing.T) {
	b, err := VManageAutoTransformer{}.Transform("t-a", "i", []byte(`{"data":[{"uuid":"u1","eventname":"bfd-state-change","type":"bfd","severity":"Critical","system_ip":"10.255.255.40","active":true}]}`))
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("alarm path broken: %+v %v", b, err)
	}
}
