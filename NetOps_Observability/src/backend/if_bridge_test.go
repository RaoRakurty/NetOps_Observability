// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/ifbridge"
	"netops/backend/models"
	"netops/backend/nms"
)

// if_bridge_test.go — the bridge cycle (tracker 387 PR 13a).

func TestSamePortIsTheTopologyCanonicalKey(t *testing.T) {
	for _, c := range [][2]string{{"Gi3", "GigabitEthernet3"}, {"Te0/1/0", "TenGigabitEthernet0/1/0"}, {"ge0/3", "ge0/3"}} {
		if !samePort(c[0], c[1]) {
			t.Errorf("%q and %q are one port", c[0], c[1])
		}
	}
	for _, c := range [][2]string{{"Gi3", "Gi4"}, {"ge0/3", "ge0/4"}, {"Gi0/1", "Te0/1"}} {
		if samePort(c[0], c[1]) {
			t.Errorf("%q and %q are different ports", c[0], c[1])
		}
	}
}

func TestIfBridgeCycleProjectsStoresAndCounts(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	devs := []models.Device{
		{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Source: "snmp"},
		{ID: "cedge-40-b99e47eb", Name: "cEDGE-40", Source: "snmp"},
	}
	s := &server{ifBridge: ifbridge.NewStore(), ifBridgeMetrics: ifbridge.NewMetrics()}
	s.ingestNMSInterfaces("global", "nmsi-1", "vmanage", []nms.ControllerInterface{
		{DeviceID: "cedge-81-11060ae2", Resolve: "matched", IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}, Time: now},
		{DeviceID: "cedge-81-11060ae2", Resolve: "matched", IfName: "Loopback65528", VRF: "65528", Addrs: []string{"192.168.1.1"}, Time: now},
		{Resolve: "no_match", IfName: "Gi1", Addrs: []string{"10.9.9.9"}, Time: now},
	})

	// The stored state is unreadable on the first cycle: nothing is stored, so
	// rows the last api wrote are never overwritten before being read back.
	var published []ifbridge.State
	kv := fakeBridgeIO(map[string]map[string]string{"cedge-40-b99e47eb": {"192.168.200.25": "Gi3"}}, ifbridge.NewState(),
		func(st ifbridge.State) { published = append(published, st) })
	failing := kv
	failing.nmsRows = func(context.Context) (ifbridge.State, error) { return ifbridge.State{}, errors.New("valkey down") }
	loaded := false
	s.ifBridgeCycle(context.Background(), failing, devs, &loaded, now)
	if loaded || len(published) != 0 {
		t.Fatalf("stored before the previous rows were read: loaded=%v published=%d", loaded, len(published))
	}

	s.ifBridgeCycle(context.Background(), kv, devs, &loaded, now)
	if !loaded || len(published) != 1 || published[0].Devices["cedge-81-11060ae2"] == nil {
		t.Fatalf("not stored: loaded=%v %+v", loaded, published)
	}
	m := s.ifBridgeMetrics
	for _, c := range []struct {
		src, outcome string
		want         int
	}{
		{"nms", "bridged", 2}, // Gi3's address and its ifIndex
		{"snmp", "bridged", 1},
		{"nms", "internal_vpn", 1},
		{"nms", "device_unresolved", 1},
	} {
		if got := m.Rows(c.src, c.outcome); got != c.want {
			t.Errorf("%s/%s = %d, want %d", c.src, c.outcome, got, c.want)
		}
	}

	// A publish failure is counted and logged, never silent.
	broken := kv
	broken.publish = func(context.Context, ifbridge.State) error { return errors.New("write refused") }
	s.ifBridgeCycle(context.Background(), broken, devs, &loaded, now)
	// An SNMP read failure keeps the counts and is counted.
	unread := kv
	unread.snmpAges = func(context.Context) (collectors.SNMPIfRowAges, error) {
		return collectors.SNMPIfRowAges{}, errors.New("timeout")
	}
	s.ifBridgeCycle(context.Background(), unread, devs, &loaded, now)
	if m.Rows("nms", "bridged") != 2 {
		t.Fatal("an unread cycle reset the counts")
	}
	var b bytes.Buffer
	m.WriteMetrics(&b)
	for _, line := range []string{
		`netops_nms_iface_bridge_failures_total{stage="read"} 2`,
		`netops_nms_iface_bridge_failures_total{stage="publish"} 1`,
	} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}

	// The device leaves the inventory: its rows go on the next cycle.
	s.ifBridgeCycle(context.Background(), kv, devs[1:], &loaded, now)
	if last := published[len(published)-1]; len(last.Devices) != 0 {
		t.Fatalf("rows of a removed device stored: %+v", last.Devices)
	}
}

func TestIfBridgeFetchMergesAndFailsClosed(t *testing.T) {
	now := time.Now()
	stored := ifbridge.NewState()
	stored.Devices["cedge-81-11060ae2"] = &ifbridge.DeviceRows{Tenant: "global", At: now.Add(-time.Minute).UnixMilli(),
		Rows: []ifbridge.Row{{IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}}}}
	stored.Devices["future"] = &ifbridge.DeviceRows{Tenant: "global", At: now.Add(time.Hour).UnixMilli(),
		Rows: []ifbridge.Row{{IfName: "Gi1", Addrs: []string{"10.1.1.1"}}}}
	kv := fakeBridgeIO(nil, stored, nil)
	m, err := kv.fetch(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if m.Addr["cedge-81-11060ae2"]["192.168.200.33"] != "GigabitEthernet3" || m.Index["cedge-81-11060ae2"]["3"] != "GigabitEthernet3" {
		t.Fatalf("merged %v %v", m.Addr, m.Index)
	}
	if _, ok := m.Addr["future"]; ok {
		t.Fatal("a stored row from the future was believed")
	}
	for name, broken := range map[string]ifBridgeIO{
		"nms": func() ifBridgeIO {
			k := kv
			k.nmsRows = func(context.Context) (ifbridge.State, error) { return ifbridge.State{}, errors.New("x") }
			return k
		}(),
		"addr": func() ifBridgeIO {
			k := kv
			k.snmpAddr = func(context.Context) (map[string]map[string]string, error) { return nil, errors.New("x") }
			return k
		}(),
		"alias": func() ifBridgeIO {
			k := kv
			k.snmpAlias = func(context.Context) (map[string]map[string]string, error) { return nil, errors.New("x") }
			return k
		}(),
	} {
		if _, err := broken.fetch(context.Background(), now); err == nil {
			t.Errorf("%s unread, but the bridge was served", name)
		}
	}
}
