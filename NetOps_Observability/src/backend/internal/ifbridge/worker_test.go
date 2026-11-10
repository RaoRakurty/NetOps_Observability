// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeIO is an IO over a fixed SNMP half and stored state; publish records.
func fakeIO(snmp SNMP, stored State, published *[]State) IO {
	return IO{
		SNMP:    func(context.Context) (SNMP, error) { return snmp, nil },
		NMSRows: func(context.Context) (State, error) { return stored, nil },
		Publish: func(_ context.Context, st State) error {
			if published != nil {
				*published = append(*published, st)
			}
			return nil
		},
	}
}

func TestWorkerCycleProjectsStoresAndCounts(t *testing.T) {
	now := t0
	owners := map[string]string{"cedge-81-11060ae2": "", "cedge-40-b99e47eb": ""}
	store := NewStore()
	store.Ingest("global", "nmsi-1", "vmanage", []Record{
		{DeviceID: "cedge-81-11060ae2", Resolve: "matched", At: now, Row: Row{IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}}},
		{DeviceID: "cedge-81-11060ae2", Resolve: "matched", At: now, Row: Row{IfName: "Loopback65528", VRF: "65528", Addrs: []string{"192.168.1.1"}}},
		{Resolve: "no_match", At: now, Row: Row{IfName: "Gi1", Addrs: []string{"10.9.9.9"}}},
	}, now)
	var published []State
	io := fakeIO(SNMP{Addr: map[string]map[string]string{"cedge-40-b99e47eb": {"192.168.200.25": "Gi3"}}}, NewState(), &published)
	w := &Worker{Store: store, Metrics: NewMetrics(), IO: io}

	// The stored state is unreadable on the first cycle: nothing is stored, so
	// rows the last api wrote are never overwritten before being read back.
	failing := io
	failing.NMSRows = func(context.Context) (State, error) { return State{}, errors.New("valkey down") }
	w.IO = failing
	w.Cycle(context.Background(), owners, now)
	if w.Loaded() || len(published) != 0 {
		t.Fatalf("stored before the previous rows were read: loaded=%v published=%d", w.Loaded(), len(published))
	}

	w.IO = io
	w.Cycle(context.Background(), owners, now)
	if !w.Loaded() || len(published) != 1 || published[0].Devices["cedge-81-11060ae2"] == nil {
		t.Fatalf("not stored: loaded=%v %+v", w.Loaded(), published)
	}
	for _, c := range []struct {
		src, outcome string
		want         int
	}{
		{SourceNMS, MergeBridged, 2}, // Gi3's address and its ifIndex
		{SourceSNMP, MergeBridged, 1},
		{SourceNMS, OutcomeInternalVPN, 1},
		{SourceNMS, OutcomeDeviceUnresolved, 1},
	} {
		if got := w.Metrics.Rows(c.src, c.outcome); got != c.want {
			t.Errorf("%s/%s = %d, want %d", c.src, c.outcome, got, c.want)
		}
	}

	// A publish failure is counted and logged, never silent.
	broken := io
	broken.Publish = func(context.Context, State) error { return errors.New("write refused") }
	w.IO = broken
	w.Cycle(context.Background(), owners, now)
	// An SNMP read failure keeps the counts and is counted.
	unread := io
	unread.SNMP = func(context.Context) (SNMP, error) { return SNMP{}, errors.New("timeout") }
	w.IO = unread
	w.Cycle(context.Background(), owners, now)
	if w.Metrics.Rows(SourceNMS, MergeBridged) != 2 {
		t.Fatal("an unread cycle reset the counts")
	}
	var b bytes.Buffer
	w.Metrics.WriteMetrics(&b)
	for _, line := range []string{
		`netops_nms_iface_bridge_failures_total{stage="read"} 2`,
		`netops_nms_iface_bridge_failures_total{stage="publish"} 1`,
	} {
		if !strings.Contains(b.String(), line) {
			t.Errorf("missing %q in\n%s", line, b.String())
		}
	}

	// The device leaves the inventory: its rows go on the next cycle.
	w.IO = io
	w.Cycle(context.Background(), map[string]string{"cedge-40-b99e47eb": ""}, now)
	if last := published[len(published)-1]; len(last.Devices) != 0 {
		t.Fatalf("rows of a removed device stored: %+v", last.Devices)
	}
}

// A stored row whose tenant does not own the device (forged or stale) is
// dropped on load, never relabelled.
func TestWorkerDropsAStoredRowOfAnotherOwner(t *testing.T) {
	forged := NewState()
	forged.Devices["globex-edge"] = &DeviceRows{Tenant: "t_acme", At: t0.Add(-time.Minute).UnixMilli(),
		Rows: []Row{{IfName: "Gi9", Addrs: []string{"172.16.0.99"}}}}
	var published []State
	w := &Worker{Store: NewStore(), Metrics: NewMetrics(), IO: fakeIO(SNMP{}, forged, &published)}
	w.Cycle(context.Background(), map[string]string{"globex-edge": "t_globex"}, t0)
	if len(published) != 1 || len(published[0].Devices) != 0 {
		t.Fatalf("a stored row claiming t_acme was published for t_globex's device: %+v", published)
	}
}

func TestIOFetchMergesAndFailsClosed(t *testing.T) {
	now := t0
	stored := NewState()
	stored.Devices["cedge-81-11060ae2"] = &DeviceRows{Tenant: "global", At: now.Add(-time.Minute).UnixMilli(),
		Rows: []Row{{IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}}}}
	stored.Devices["future"] = &DeviceRows{Tenant: "global", At: now.Add(time.Hour).UnixMilli(),
		Rows: []Row{{IfName: "Gi1", Addrs: []string{"10.1.1.1"}}}}
	io := fakeIO(SNMP{}, stored, nil)
	m, err := io.Fetch(context.Background(), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Addr["cedge-81-11060ae2"]["192.168.200.33"] != "GigabitEthernet3" || m.Index["cedge-81-11060ae2"]["3"] != "GigabitEthernet3" {
		t.Fatalf("merged %v %v", m.Addr, m.Index)
	}
	if _, ok := m.Addr["future"]; ok {
		t.Fatal("a stored row from the future was believed")
	}
	nmsDown := io
	nmsDown.NMSRows = func(context.Context) (State, error) { return State{}, errors.New("x") }
	snmpDown := io
	snmpDown.SNMP = func(context.Context) (SNMP, error) { return SNMP{}, errors.New("x") }
	for name, broken := range map[string]IO{"nms": nmsDown, "snmp": snmpDown} {
		if _, err := broken.Fetch(context.Background(), now, nil); err == nil {
			t.Errorf("%s unread, but the bridge was served", name)
		}
	}
}
