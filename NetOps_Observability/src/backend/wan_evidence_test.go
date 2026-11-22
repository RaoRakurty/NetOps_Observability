// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/internal/ifbridge"
	"netops/backend/models"
	"netops/backend/wan"
)

// The device_if_* series carry the INVENTORY ID as `device` and the port as the
// device spells it ("Gi1"); rows know the device name and maybe the controller's
// spelling. Before 2026-11-22 rows looked series up by NAME, so on the lab
// (ids "cedge-40-fdf7b64f") utilisation, oper-state and the sparkline never joined.
func TestWanUtilisationJoinsOnTheInventoryID(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		v := "500000" // bits/s for the rate queries, Mbps for speed, 1 = up for oper
		switch q := r.URL.Query().Get("query"); q {
		case "device_if_speed":
			v = "1"
		case "device_if_oper_status":
			v = "1"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"device":"edge-1-ab12","ifName":"Gi1"},"value":[1,%q]}]}}`, v)
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)

	s := newWanTestServer(t, map[string]map[string]string{"edge-1-ab12": {"200.1.1.1": "GigabitEthernet1"}}, nil)
	s.discovery.Upsert(models.Device{ID: "edge-1-ab12", Name: "edge-1", TenantID: "acme"})
	s.vmRangeRaw = func(context.Context, string, int64, int64, int64) (map[string][]float64, error) {
		return map[string][]float64{wan.IfKey("edge-1-ab12", "Gi1"): {1, 2, 3}}, nil
	}
	rows, err := s.wanInterfaceRows(context.Background(), wanVis(s, "acme"), nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	r := rows[0]
	if !r.HasUtil || r.Util != 50 || !r.HasOper || !r.OperUp {
		t.Errorf("utilisation/oper did not join on the inventory id and canonical port: %+v", r)
	}
	if len(r.Spark) != 3 {
		t.Errorf("sparkline did not join: %v", r.Spark)
	}
	if r.WanConfidence != wan.Confirmed || r.WanReason == "" {
		t.Errorf("a table row says why it is WAN: %+v", r)
	}
}

func TestWanEvidenceCacheReusesAndNeverCachesAFailure(t *testing.T) {
	var c wanEvidenceCache
	calls := 0
	fail := false
	fetch := func(context.Context) (ifbridge.Merged, error) {
		calls++
		if fail {
			return ifbridge.Merged{}, errors.New("bridge unread")
		}
		return ifbridge.Merged{Addr: map[string]map[string]string{"d": {"10.0.0.1": "e1"}}}, nil
	}
	t0 := time.Unix(1_800_000_000, 0)
	ctx := context.Background()
	if _, err := c.get(ctx, t0, fetch); err != nil || calls != 1 {
		t.Fatalf("first read: calls %d err %v", calls, err)
	}
	if m, _ := c.get(ctx, t0.Add(10*time.Second), fetch); calls != 1 || m.Addr["d"]["10.0.0.1"] != "e1" {
		t.Fatalf("within the TTL the bundle is reused: calls %d", calls)
	}
	if _, _ = c.get(ctx, t0.Add(wanEvidenceTTL+time.Second), fetch); calls != 2 {
		t.Fatalf("after the TTL it is read again: calls %d", calls)
	}
	// A clock step backwards is not "fresh".
	if _, _ = c.get(ctx, t0, fetch); calls != 3 {
		t.Fatalf("a reading from the future is re-read: calls %d", calls)
	}
	fail = true
	later := t0.Add(5 * wanEvidenceTTL)
	if _, err := c.get(ctx, later, fetch); err == nil {
		t.Fatal("a failed read is reported")
	}
	fail = false
	if _, err := c.get(ctx, later.Add(time.Second), fetch); err != nil || calls != 5 {
		t.Fatalf("a failure is never cached: calls %d err %v", calls, err)
	}
}

// §3a: the evidence bundle holds every tenant's controller rows, but only the
// caller's visible devices are classified. Two tenants whose devices share port
// names and addresses: globex's transport evidence never confirms acme's port,
// and acme never sees globex's interface.
func TestWanEvidenceOfAnotherTenantNeverClassifiesACallersPort(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"acme-r1":   {"200.9.9.9": "GigabitEthernet1"},
		"globex-r1": {"200.9.9.9": "GigabitEthernet1"},
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.wanIfEvidence = func(context.Context) (ifbridge.Merged, error) {
		return ifbridge.Merged{Addr: ifaddr, NMS: map[string]ifbridge.DeviceRows{
			"globex-r1": {Tenant: "globex", Rows: []ifbridge.Row{
				{IfName: "GigabitEthernet1", VRF: "0", Role: ifbridge.RoleTransport, Addrs: []string{"200.9.9.9"}},
			}},
		}}, nil
	}
	s.discovery.Upsert(models.Device{ID: "acme-r1", Name: "acme-r1", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "globex-r1", Name: "globex-r1", TenantID: "globex"})

	acme, _ := s.wanProjectAll(context.Background(), wanVis(s, "acme"))
	for _, e := range append(append([]WanEndpoint{}, acme.Endpoints...), acme.Candidates...) {
		if e.Device != "acme-r1" {
			t.Fatalf("TENANT LEAK: acme saw %s/%s", e.Device, e.Interface)
		}
	}
	if len(acme.Endpoints) != 0 || len(acme.Circuits) != 0 {
		t.Fatalf("globex's transport evidence confirmed acme's port: %+v", acme.Endpoints)
	}
	globex, _ := s.wanProjectAll(context.Background(), wanVis(s, "globex"))
	if len(globex.Endpoints) != 1 || globex.Endpoints[0].Device != "globex-r1" || globex.Endpoints[0].WanBasis != wan.BasisSDWANTransport {
		t.Fatalf("globex's own evidence: %+v", globex.Endpoints)
	}
}

// The name pattern no longer gates the view: an SD-WAN edge whose name matches
// nothing still lists its transport ports (it returned nothing before), and a
// name-matched router with no evidence offers its ports instead of measuring
// every one of them.
func TestWanNamePatternIsAHintNotAGate(t *testing.T) {
	ifaddr := map[string]map[string]string{
		"site7-r1": {"200.7.7.7": "ge0/0", "192.168.7.1": "ge0/1"},
		"wan-core": {"10.0.0.1": "Ethernet1", "10.0.0.2": "Ethernet2"},
	}
	s := newWanTestServer(t, ifaddr, nil)
	s.wanIfEvidence = func(context.Context) (ifbridge.Merged, error) {
		return ifbridge.Merged{Addr: ifaddr, NMS: map[string]ifbridge.DeviceRows{
			"site7-r1": {Rows: []ifbridge.Row{
				{IfName: "ge0/0", VRF: "0", Role: ifbridge.RoleTransport, Addrs: []string{"200.7.7.7"}},
				{IfName: "ge0/1", VRF: "100", Role: ifbridge.RoleService, Addrs: []string{"192.168.7.1"}},
			}},
		}}, nil
	}
	s.discovery.Upsert(models.Device{ID: "site7-r1", Name: "site7-r1", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "wan-core", Name: "wan-core", TenantID: "acme"})

	p, _ := s.wanProjectAll(context.Background(), wanVis(s, "acme"))
	if len(p.Endpoints) != 1 || p.Endpoints[0].Device != "site7-r1" || p.Endpoints[0].Interface != "ge0/0" {
		t.Fatalf("confirmed = %+v, want only site7-r1/ge0/0", p.Endpoints)
	}
	offered := map[string]bool{}
	for _, c := range p.Candidates {
		offered[c.Device+"/"+c.Interface] = true
		if c.Target != "" {
			t.Errorf("a possible interface got a measurement target: %+v", c)
		}
	}
	if !offered["wan-core/Ethernet1"] || !offered["wan-core/Ethernet2"] || offered["site7-r1/ge0/1"] {
		t.Fatalf("possible = %v, want wan-core's two ports and never the service port", offered)
	}
	if len(p.Circuits) != 1 {
		t.Fatalf("only confirmed interfaces become circuits: %+v", p.Circuits)
	}
}
