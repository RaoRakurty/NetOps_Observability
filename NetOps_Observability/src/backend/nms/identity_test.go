// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"strings"
	"testing"
	"time"
)

// mapResolver resolves tenant|key → id; anything else is "no match".
type mapResolver struct {
	m     map[string]string
	names map[string]string // tenant|lower(name) → id
	calls int
}

func (r *mapResolver) ResolveDevice(tenant string, _ KeyKind, key, name string) (string, bool) {
	r.calls++
	if id, ok := r.m[tenant+"|"+key]; ok {
		return id, true
	}
	if id, ok := r.names[tenant+"|"+strings.ToLower(name)]; ok && name != "" {
		return id, true
	}
	return "", false
}

func sampleBatch() Batch {
	return Batch{
		Events: []ControllerEvent{{TenantID: "t1", IntegrationID: "i1", EventID: "e1", DeviceID: "10.255.255.20",
			DeviceName: "vEdge-20", NormalizedEventType: "controller_bfd_down", EventTime: time.Unix(100, 0),
			CorrelationHints: map[string]string{"system_ip": "10.255.255.20"}}},
		States: []ControllerState{{TenantID: "t1", IntegrationID: "i1", EntityKey: "10.255.255.20|bgp|1.1.1.1",
			StateKind: "bgp", CurrentState: "up", DeviceID: "10.255.255.20", Data: map[string]any{"device_name": "vEdge-20"}}},
		Metrics: []ControllerMetric{{TenantID: "t1", Name: "controller_metric_device_cpu_pct", Value: 3,
			Tags: map[string]string{"device": "10.255.255.20", "peer": "10.255.255.40", "tenant_id": "t1"}}},
	}
}

func TestCanonicalizeRewritesEveryClassAndKeepsTheControllerKey(t *testing.T) {
	r := &mapResolver{m: map[string]string{"t1|10.255.255.20": "vedge-20-1e95f00f"}}
	in := sampleBatch()
	var names deviceNames
	out := canonicalize(r, KeySystemIP, &names, in)

	e := out.Events[0]
	if e.DeviceID != "vedge-20-1e95f00f" || e.CorrelationHints["controller_device_id"] != "10.255.255.20" || e.CorrelationHints["system_ip"] != "10.255.255.20" {
		t.Fatalf("event %+v", e)
	}
	s := out.States[0]
	if s.DeviceID != "vedge-20-1e95f00f" || s.EntityKey != "10.255.255.20|bgp|1.1.1.1" || s.Data["controller_device_id"] != "10.255.255.20" {
		t.Fatalf("state %+v — EntityKey must stay native so flap history survives", s)
	}
	m := out.Metrics[0]
	if m.Tags["device"] != "vedge-20-1e95f00f" || m.Tags["controller_device"] != "10.255.255.20" || m.Tags["peer"] != "10.255.255.40" {
		t.Fatalf("metric %v", m.Tags)
	}
	// The input batch is not mutated (maps are copied, never shared).
	if in.Events[0].DeviceID != "10.255.255.20" || in.Events[0].CorrelationHints["controller_device_id"] != "" ||
		in.States[0].Data["controller_device_id"] != nil || in.Metrics[0].Tags["device"] != "10.255.255.20" {
		t.Fatal("canonicalize mutated its input")
	}
}

func TestCanonicalizeUnmatchedKeepsNativeIdentity(t *testing.T) {
	r := &mapResolver{m: map[string]string{}}
	var names deviceNames
	out := canonicalize(r, KeySystemIP, &names, sampleBatch())
	if out.Events[0].DeviceID != "10.255.255.20" || out.Metrics[0].Tags["device"] != "10.255.255.20" || out.Metrics[0].Tags["controller_device"] != "" {
		t.Fatalf("%+v", out)
	}
	if _, ok := out.Events[0].CorrelationHints["controller_device_id"]; ok {
		t.Fatal("an unmatched device must not claim a join")
	}
}

func TestCanonicalizeOffForOpaqueKeysOrNoResolver(t *testing.T) {
	r := &mapResolver{m: map[string]string{"t1|10.255.255.20": "x"}}
	var names deviceNames
	if out := canonicalize(r, KeyNone, &names, sampleBatch()); out.Events[0].DeviceID != "10.255.255.20" || r.calls != 0 {
		t.Fatal("KeyNone must pass through without asking")
	}
	if out := canonicalize(nil, KeySystemIP, &names, sampleBatch()); out.Events[0].DeviceID != "10.255.255.20" {
		t.Fatal("nil resolver must pass through")
	}
}

// A metric carries only the key; the hostname a state or event reported for
// that key lets it match by name.
func TestCanonicalizeMetricMatchesByLearnedName(t *testing.T) {
	r := &mapResolver{m: map[string]string{}, names: map[string]string{"t1|cedge-40": "cedge-40-b99e47eb"}}
	p := NewPipeline(64)
	p.Resolver, p.KeyKind = r, KeySystemIP
	p.Route(Batch{States: []ControllerState{{TenantID: "t1", IntegrationID: "i1", EntityKey: "10.255.255.40", StateKind: "reachability",
		CurrentState: "reachable", DeviceID: "10.255.255.40", Data: map[string]any{"device_name": "cEDGE-40"}}}})
	routed := p.Route(Batch{Metrics: []ControllerMetric{{TenantID: "t1", Name: "controller_metric_device_cpu_pct", Value: 1,
		Tags: map[string]string{"device": "10.255.255.40"}}}})
	if len(routed.MetricLines) != 1 || !strings.Contains(routed.MetricLines[0], `device="cedge-40-b99e47eb"`) ||
		!strings.Contains(routed.MetricLines[0], `controller_device="10.255.255.40"`) {
		t.Fatalf("%v", routed.MetricLines)
	}
}

// The dedupe key is fixed from the native identity, so an event re-polled
// after its device became resolvable is still recognised as already sent.
func TestCanonicalizeMappingAppearingNeverReemits(t *testing.T) {
	r := &mapResolver{m: map[string]string{}}
	p := NewPipeline(64)
	p.Resolver, p.KeyKind = r, KeySystemIP
	ev := ControllerEvent{TenantID: "t1", IntegrationID: "i1", DeviceID: "10.255.255.20",
		NormalizedEventType: "controller_bfd_down", EventTime: time.Unix(100, 0), Message: "bfd down"} // no EventID: hashed key
	if got := p.Route(Batch{Events: []ControllerEvent{ev}}).Events; len(got) != 1 {
		t.Fatalf("first poll %d", len(got))
	}
	r.m["t1|10.255.255.20"] = "vedge-20-1e95f00f"
	if got := p.Route(Batch{Events: []ControllerEvent{ev}}).Events; len(got) != 0 {
		t.Fatalf("re-poll after the mapping appeared re-emitted %+v", got)
	}
}

func TestDeviceNamesMemoIsBounded(t *testing.T) {
	var d deviceNames
	for i := 0; i < deviceNameMemoCap+50; i++ {
		d.learn(strings.Repeat("k", 1)+string(rune('a'+i%26))+time.Duration(i).String(), "n")
	}
	if len(d.m) > deviceNameMemoCap {
		t.Fatalf("memo grew to %d", len(d.m))
	}
	d.learn("", "x")
	d.learn("k", "")
	if d.get("") != "" || d.get("k") != "" {
		t.Fatal("empty key or name must not be learned")
	}
}

// Every connector says what its DeviceID is — adding one forces the choice.
func TestEveryConnectorDeclaresItsDeviceKeyKind(t *testing.T) {
	want := map[string]KeyKind{
		"meraki": KeySerial, "catalyst_center": KeyNone, "catalyst_9800": KeyNone, "vmanage": KeySystemIP,
		"ndfc": KeySerial, "prime": KeyIP, "versa_director": KeyName, "versa_concerto": KeyName, "generic": KeyNone,
	}
	specs := Specs()
	if len(specs) != len(want) {
		t.Fatalf("%d connectors, %d decided — decide the new connector's DeviceKeyKind here", len(specs), len(want))
	}
	for v, s := range specs {
		k, ok := want[v]
		if !ok || s.DeviceKeyKind != k {
			t.Errorf("%s: DeviceKeyKind %q, want %q", v, s.DeviceKeyKind, k)
		}
	}
}
