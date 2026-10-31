// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"testing"
	"time"
)

// Rows trimmed from a live 20.6.1 (2026-10-18), values kept.

func TestVManageQoSAggregation(t *testing.T) {
	raw := `{"data":[
	 {"entry_time":1792336200000,"count":2,"vdevice_name":"10.255.255.100","interface":"ge0/0","queue_name":"Queue0","queued_pkts":7,"drop_in_kbps":1.5,"red_drop_pkts":0,"drop_in_pps":2,"tail_drop_pkts":120,"tx_bytes_in_kbps":800},
	 {"entry_time":1792336200000,"count":2,"vdevice_name":"10.255.255.100","interface":"ge0/0","queue_name":"","tx_bytes_in_kbps":1},
	 {"entry_time":1792336200000,"count":2,"vdevice_name":"not-an-ip","interface":"ge0/0","queue_name":"Queue1","tx_bytes_in_kbps":1}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "qos", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	by := metricsByName(b)
	if len(b.Metrics) != 6 {
		t.Fatalf("%d metrics — want 6 from the one valid queue row", len(b.Metrics))
	}
	m := by["controller_metric_qos_tx_bps"][0]
	if m.Value != 800000 || m.Tags["queue"] != "Queue0" || m.Tags["interface"] != "ge0/0" || m.Tags["device"] != "10.255.255.100" {
		t.Fatalf("%+v", m)
	}
	if by["controller_metric_qos_drop_bps"][0].Value != 1500 || !near(by["controller_metric_qos_tail_drops_per_sec"][0].Value, 0.2) ||
		by["controller_metric_qos_queue_depth_pkts"][0].Value != 7 {
		t.Fatal("drops / depth")
	}
}

func TestVManageHardwareHealth(t *testing.T) {
	raw := `{"data":[
	 {"device-model":"vedge-cloud","system-ip":"10.255.255.51","host-name":"vEdge-51","site-id":"50","hardwareState":"normal","lastupdated":1792296433015},
	 {"system-ip":"10.255.255.52","hardwareState":"Error"},
	 {"system-ip":"10.255.255.53","hardwareState":"unknown"},
	 {"system-ip":"","hardwareState":"error"}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "hardware", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.States) != 2 || b.States[0].CurrentState != "normal" || b.States[1].CurrentState != "error" || b.States[0].SiteID != "50" {
		t.Fatalf("%+v", b.States)
	}
	// A transition into error is a fault event; into warning a minor one.
	rec := StateRecord{StateKind: "hardware_health", EntityKey: "10.255.255.52", DeviceID: "10.255.255.52", LastSeen: time.Unix(1, 0)}
	evs := SDWANStateChangeEvents(Specs()["vmanage"], "t1", "i1", []StateChange{{Record: rec, From: "normal", To: "error"}, {Record: rec, From: "normal", To: "warning"}})
	if len(evs) != 2 || evs[0].Severity != "high" || evs[0].EvidenceRole != RoleDiscriminating || evs[1].Severity != "warn" {
		t.Fatalf("%+v", evs)
	}
}

func TestVManageAuditLog(t *testing.T) {
	raw := `{"data":[
	 {"logid":"a1","entry_time":1792296264537,"logmodule":"template","logfeature":"template-device-config","loguser":"admin","logmessage":"Template vEdge-50-DT successfully attached to device 10.255.255.51","logdeviceid":"10.255.255.51"},
	 {"logid":"a2","entry_time":1792296259723,"logmodule":"template","logmessage":"Completed template push to device.","logdeviceid":"vedge-4c353382-ddc5"},
	 {"logid":"a3","entry_time":1792296179404,"logmodule":"template","logmessage":"Template VEdge-VPN200 edited","logdeviceid":null},
	 {"logid":"a4","entry_time":1792340077517,"logmodule":"user","loguser":"admin","logmessage":"Authentication succeeded for admin","logdeviceid":"10.255.255.1"},
	 {"logid":"a5","entry_time":1792340077518,"logmodule":"user","loguser":"bob","logmessage":"Authentication failed for bob","logdeviceid":"10.255.255.1"},
	 {"logid":"","logmodule":"vsmart-policy","logmessage":"x","logdeviceid":"10.255.255.2"}]}`
	b, err := VManageAutoTransformer{}.TransformStream("t1", "i1", "audit", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 2 {
		t.Fatalf("%d events — want the device change and the failed login: %+v", len(b.Events), b.Events)
	}
	c, f := b.Events[0], b.Events[1]
	if c.NormalizedEventType != "controller_policy_change" || c.DeviceID != "10.255.255.51" || c.EventID != "audit:a1" || c.CorrelationHints["user"] != "admin" {
		t.Fatalf("change %+v", c)
	}
	if f.NormalizedEventType != "controller_alarm" || f.Severity != "warn" || f.DeviceID != "10.255.255.1" {
		t.Fatalf("failed login %+v", f)
	}
	if c.DedupeKey == "" || c.DedupeKey == f.DedupeKey {
		t.Fatal("dedupe keys")
	}
}
