// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devidentity

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func written(cs []Claim) map[string]string {
	out := map[string]string{}
	for _, c := range cs {
		out[c.Identity] = c.DeviceID
	}
	return out
}

func TestEveryOwnerGetsItsIDRowOnly(t *testing.T) {
	devs := []Device{
		{ID: "ctl-vmanage-aaa", Name: "edge-a", Address: "10.0.0.1", Owner: "t_acme"},
		{ID: "ctl-vmanage-bbb", Name: "edge-b", Address: "10.0.0.2", Owner: "t_globex"},
	}
	ifAddr := map[string]map[string]string{"ctl-vmanage-aaa": {"192.0.2.1": "Gi1"}}
	got, stats := Claims(nil, devs, ifAddr)
	want := map[string]string{"ctl-vmanage-aaa": "ctl-vmanage-aaa", "ctl-vmanage-bbb": "ctl-vmanage-bbb"}
	if !reflect.DeepEqual(written(got), want) {
		t.Fatalf("a tenant-owned controller device must get its id row and NOTHING derived from a name or address (tenant = channel):\n got %v\nwant %v", written(got), want)
	}
	if stats[StatKey{TierID, OutcomeWritten}] != 2 || stats[StatKey{TierPlatform, OutcomeWritten}] != 0 {
		t.Fatalf("stats: %v", stats)
	}
}

func TestAPlatformDeviceGetsNameAddressAndInterfaces(t *testing.T) {
	devs := []Device{{ID: "ctl-vmanage-p1", Name: "branch-7", Address: "192.168.50.7", Owner: "global"}}
	ifAddr := map[string]map[string]string{"ctl-vmanage-p1": {"192.168.222.107": "Lo200", "203.0.113.7": "Gi1"}}
	got, _ := Claims(nil, devs, ifAddr)
	want := map[string]string{
		"ctl-vmanage-p1": "ctl-vmanage-p1", "branch-7": "ctl-vmanage-p1", "192.168.50.7": "ctl-vmanage-p1",
		"192.168.222.107": "ctl-vmanage-p1", "203.0.113.7": "ctl-vmanage-p1",
	}
	if !reflect.DeepEqual(written(got), want) {
		t.Fatalf("got %v\nwant %v", written(got), want)
	}
	// The empty owner is the platform too.
	devs[0].Owner = ""
	if g, _ := Claims(nil, devs, ifAddr); len(g) != 5 {
		t.Fatalf("an empty owner is the platform: %v", written(g))
	}
}

func TestADirectDeviceAlwaysStands(t *testing.T) {
	devs := []Device{{ID: "ctl-vmanage-p1", Name: "branch-7", Address: "192.168.50.7", Owner: "global"}}
	ifAddr := map[string]map[string]string{"ctl-vmanage-p1": {"192.168.222.107": "Lo200"}}
	// A directly collected device presents the name and the interface address —
	// written or left out as ambiguous, the controller never claims it.
	direct := map[string]bool{"branch-7": true, "192.168.222.107": true}
	got, stats := Claims(direct, devs, ifAddr)
	want := map[string]string{"ctl-vmanage-p1": "ctl-vmanage-p1", "192.168.50.7": "ctl-vmanage-p1"}
	if !reflect.DeepEqual(written(got), want) {
		t.Fatalf("got %v\nwant %v", written(got), want)
	}
	if stats[StatKey{TierPlatform, OutcomeDirectStands}] != 2 {
		t.Fatalf("stats: %v", stats)
	}
}

func TestAnIdentityTwoDevicesHoldNamesNobody(t *testing.T) {
	devs := []Device{
		{ID: "ctl-vmanage-p1", Name: "branch-7", Address: "10.1.1.1", Owner: "global"},
		{ID: "ctl-meraki-p2", Name: "branch-7", Address: "10.1.1.2", Owner: "global"}, // second controller, same name
		{ID: "ctl-vmanage-t1", Name: "t-box", Address: "10.1.1.3", Owner: "t_acme"},   // tenant device, holds an address
	}
	ifAddr := map[string]map[string]string{
		"ctl-vmanage-p1": {"192.168.1.1": "Gi2", "10.1.1.3": "Gi3"}, // .1.1 also on an SNMP device; .1.3 is the tenant box's
		"snmp-dev-9":     {"192.168.1.1": "Vlan1"},
	}
	got, stats := Claims(nil, devs, ifAddr)
	w := written(got)
	for _, shared := range []string{"branch-7", "192.168.1.1", "10.1.1.3"} {
		if _, ok := w[shared]; ok {
			t.Fatalf("%q is held by two devices and must name nobody: %v", shared, w)
		}
	}
	for _, own := range []string{"10.1.1.1", "10.1.1.2", "ctl-vmanage-p1", "ctl-meraki-p2", "ctl-vmanage-t1"} {
		if _, ok := w[own]; !ok {
			t.Fatalf("%q is held by one device and should be written: %v", own, w)
		}
	}
	if stats[StatKey{TierPlatform, OutcomeShared}] != 4 { // branch-7 ×2, 192.168.1.1, 10.1.1.3
		t.Fatalf("stats: %v", stats)
	}
}

func TestMalformedIdentitiesAreRefused(t *testing.T) {
	devs := []Device{{ID: "ctl-x-1", Name: "evil\nname", Address: strings.Repeat("a", MaxIdentityLen+1), Owner: "global"}}
	got, stats := Claims(nil, devs, nil)
	if !reflect.DeepEqual(written(got), map[string]string{"ctl-x-1": "ctl-x-1"}) {
		t.Fatalf("got %v", written(got))
	}
	if stats[StatKey{TierPlatform, OutcomeInvalid}] != 2 {
		t.Fatalf("stats: %v", stats)
	}
}

func TestClaimsAreOrderIndependent(t *testing.T) {
	a := []Device{
		{ID: "ctl-a", Name: "n-a", Address: "10.0.0.1", Owner: "global"},
		{ID: "ctl-b", Name: "n-b", Address: "10.0.0.2", Owner: "global"},
		{ID: "ctl-c", Name: "n-a", Address: "10.0.0.3", Owner: "t_acme"},
	}
	b := []Device{a[2], a[0], a[1]}
	ifAddr := map[string]map[string]string{"ctl-a": {"192.0.2.1": "x", "192.0.2.2": "y"}}
	ga, sa := Claims(nil, a, ifAddr)
	gb, sb := Claims(nil, b, ifAddr)
	if !reflect.DeepEqual(ga, gb) || !reflect.DeepEqual(sa, sb) {
		t.Fatalf("order changed the result:\n%v\n%v", ga, gb)
	}
}

func TestMetricsExposition(t *testing.T) {
	m := NewMetrics()
	m.Set(map[StatKey]int{{TierID, OutcomeWritten}: 3, {TierPlatform, OutcomeShared}: 1})
	m.Held(HoldControllerNotReady)
	var buf bytes.Buffer
	m.WriteMetrics(&buf)
	out := buf.String()
	for _, want := range []string{
		`netops_tenant_registry_controller_rows{tier="controller_id",outcome="written"} 3`,
		`netops_tenant_registry_controller_rows{tier="controller_platform",outcome="shared"} 1`,
		`netops_tenant_registry_controller_rows{tier="controller_platform",outcome="invalid"} 0`,
		`netops_tenant_registry_held_total{reason="controller_not_ready"} 1`,
		`netops_tenant_registry_held_total{reason="snmp_not_ready"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	var nilM *Metrics
	nilM.Set(nil)
	nilM.Held(HoldSNMPNotReady)
	nilM.WriteMetrics(&buf) // no panic
}
