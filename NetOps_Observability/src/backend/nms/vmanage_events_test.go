// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Row shapes sampled from a live vManage 20.6.1 (2026-10-18), scrubbed.
const (
	eventRows = `{"data":[
{"system_ip":"10.255.255.81","entry_time":"1792332646000","eventname":"bgp-peer-state-change","component":"VPN","severity_level":"major","host_name":"cEDGE-81","details":"host-name=cEDGE-81; peer=192.168.200.34; bgp-new-state=idle;","id":"ev1","tenant":"default"},
{"system_ip":"10.255.255.81","entry_time":"1792332700000","eventname":"bgp-peer-state-change","component":"VPN","severity_level":"minor","host_name":"cEDGE-81","details":"peer=192.168.200.34; bgp-new-state=established;","id":"ev2"},
{"system_ip":"not-an-ip","entry_time":"1","eventname":"x","id":"ev3"},
{"system_ip":"10.255.255.81","entry_time":"1","eventname":"cpu-usage","component":"System","severity_level":"low","id":""}]}`
	inventoryRowsFull = `{"data":[
{"system-ip":"10.255.255.1","host-name":"vManage","device-type":"vmanage","reachability":"reachable","state":"green","state_description":"All daemons up","site-id":"250","version":"20.6.1","lastupdated":"1792271807366"},
{"system-ip":"10.255.255.40","host-name":"cEDGE-40","device-type":"vedge","reachability":"unreachable","state":"red","site-id":"40"}]}`
)

func TestVManageEventsAreParsedAsEventsNotAlarms(t *testing.T) {
	b, err := VManageAutoTransformer{}.TransformStream("t-a", "i", "events", []byte(eventRows))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 2 {
		t.Fatalf("events %d — want the two valid rows (no id / no valid device are dropped)", len(b.Events))
	}
	if e := b.Events[0]; e.EventID != "ev1" || e.Severity != "high" || e.DeviceID != "10.255.255.81" || e.TenantID != "t-a" {
		t.Fatalf("event %+v", e)
	}
	if len(b.States) != 2 {
		t.Fatalf("bgp states %d", len(b.States))
	}
	// THE regression: an idle peer was stored as "up" because event rows carry
	// no `active` flag and the alarms parser treated that as "cleared".
	if b.States[0].StateKind != "bgp" || b.States[0].CurrentState != "down" {
		t.Fatalf("bgp idle must be down: %+v", b.States[0])
	}
	if b.States[1].CurrentState != "up" {
		t.Fatalf("bgp established must be up: %+v", b.States[1])
	}
}

func TestVManageInventoryNeverBecomesAlarms(t *testing.T) {
	b, err := VManageAutoTransformer{}.TransformStream("t-a", "i", "inventory", []byte(inventoryRowsFull))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 0 {
		t.Fatalf("inventory produced %d events — it is not an alarm source", len(b.Events))
	}
	got := map[string]string{}
	for _, s := range b.States {
		got[s.EntityKey+"/"+s.StateKind] = s.CurrentState
	}
	want := map[string]string{
		"10.255.255.1/reachability": "reachable", "10.255.255.1/device_health": "green",
		"10.255.255.40/reachability": "unreachable", "10.255.255.40/device_health": "red",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestVManageAlarmsStillParseByStream(t *testing.T) {
	b, err := VManageAutoTransformer{}.TransformStream("t-a", "i", "alarms", []byte(`{"data":[{"uuid":"u1","eventname":"bfd-state-change","type":"bfd","severity":"Critical","system_ip":"10.255.255.40","active":true,"entry_time":1792296403391}]}`))
	if err != nil || len(b.Events) != 1 || len(b.States) != 1 || b.States[0].CurrentState != "down" {
		t.Fatalf("alarm path: %+v %v", b, err)
	}
}

func TestVManageCursorQueryAsksOnlyForNewRows(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	cp := Checkpoint{LastEventTime: time.UnixMilli(1792332000000).UTC()}
	_, next, err := vmanagePoller().Poll(context.Background(), PollInput{Base: srv.URL, Stream: "events", Do: srv.Client(), Checkpoint: cp})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/dataservice/event" {
		t.Fatalf("path %s", gotPath)
	}
	var q struct {
		Query struct {
			Rules []struct {
				Value    []string `json:"value"`
				Field    string   `json:"field"`
				Operator string   `json:"operator"`
			} `json:"rules"`
		} `json:"query"`
	}
	if err := json.Unmarshal([]byte(gotQuery), &q); err != nil || len(q.Query.Rules) != 1 {
		t.Fatalf("query %q: %v", gotQuery, err)
	}
	r := q.Query.Rules[0]
	wantMs := strconv.FormatInt(cp.LastEventTime.Add(-vmanageCursorOverlap).UnixMilli(), 10)
	if r.Field != "entry_time" || r.Operator != "greater" || len(r.Value) != 1 || r.Value[0] != wantMs {
		t.Fatalf("rule %+v, want entry_time greater %s", r, wantMs)
	}
	if !next.LastEventTime.After(cp.LastEventTime) {
		t.Fatalf("cursor did not advance: %v", next.LastEventTime)
	}
}

func TestVManageCursorFirstRunUsesTheBackfill(t *testing.T) {
	var q string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ = url.QueryUnescape(r.URL.RawQuery)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	before := nowUTC().Add(-time.Hour - vmanageCursorOverlap - time.Minute).UnixMilli()
	if _, _, err := vmanagePoller().Poll(context.Background(), PollInput{Base: srv.URL, Stream: "alarms", Do: srv.Client(), Backfill: time.Hour}); err != nil {
		t.Fatal(err)
	}
	i := strings.Index(q, `"value":["`)
	if i < 0 {
		t.Fatalf("no cursor in %q", q)
	}
	ms, _ := strconv.ParseInt(q[i+10:i+23], 10, 64)
	if ms < before {
		t.Fatalf("first run reached back further than the backfill: %d < %d", ms, before)
	}
}

func TestSDWANTransitionsBecomeEvents(t *testing.T) {
	at := time.UnixMilli(1792332646000).UTC()
	rec := func(kind string) StateRecord {
		return StateRecord{EntityKey: "k-" + kind, StateKind: kind, DeviceID: "10.255.255.40", SiteID: "40", LastSeen: at}
	}
	evs := SDWANStateChangeEvents("t-a", "i", "vmanage", []StateChange{
		{Record: rec("bfd"), From: "up", To: "down"},
		{Record: rec("control_conn"), From: "down", To: "up"},
		{Record: rec("device_health"), From: "green", To: "yellow"},
		{Record: rec("ap_join"), From: "up", To: "down"}, // wireless: not ours
		{Record: rec("omp"), From: "up", To: "up"},       // no transition
	})
	if len(evs) != 3 {
		t.Fatalf("events %d, want 3", len(evs))
	}
	if evs[0].NormalizedEventType != "controller_bfd_down" || evs[0].Severity != "high" || evs[0].EvidenceRole != RoleDiscriminating || evs[0].TenantID != "t-a" {
		t.Fatalf("bfd down %+v", evs[0])
	}
	if evs[1].Severity != "info" || evs[1].EvidenceRole != RoleSupporting {
		t.Fatalf("a recovery supports, it is not a fault: %+v", evs[1])
	}
	if evs[2].Severity != "warn" {
		t.Fatalf("yellow health %+v", evs[2])
	}
	if evs[0].EventID == SDWANStateChangeEvents("t-a", "i", "vmanage", []StateChange{{Record: rec("bfd"), From: "up", To: "down"}})[0].EventID == false {
		t.Fatal("event id must be deterministic across re-runs")
	}
}

func TestRunPollRoutesVManageByStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			_, _ = w.Write([]byte(`{"token":"jwt-1"}`))
		case "/dataservice/device":
			_, _ = w.Write([]byte(inventoryRowsFull))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	conn, _ := NewRegistry().Get("vmanage")
	cfg := IntegrationConfig{Tenant: "t-a", IntegrationID: "int-vm", Vendor: "vmanage", BaseURL: srv.URL,
		Streams: []string{"inventory"}, Creds: Credentials{Username: "ro", Password: "pw"}}
	res, _, err := RunPollSession(context.Background(), conn, cfg, NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry()), NewMemCheckpoints(), NewPipeline(1000), Session{})
	if err != nil || len(res.Errors) != 0 {
		t.Fatalf("run: %v %v", err, res.Errors)
	}
	if len(res.Routed.Events) != 0 || len(res.Routed.States) != 4 {
		t.Fatalf("inventory via the runtime: events=%d states=%d — want 0 events, 4 states", len(res.Routed.Events), len(res.Routed.States))
	}
}
