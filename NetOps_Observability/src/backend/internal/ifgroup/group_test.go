// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifgroup

import (
	"math"
	"strings"
	"testing"
)

// group_test.go — the pure model. Every assertion here is about the ONE thing
// this module can get catastrophically wrong: presenting an absence as a fact.

func sample(value float64, kv ...string) Sample {
	labels := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		labels[kv[i]] = kv[i+1]
	}
	return Sample{Labels: labels, Value: value}
}

func TestIfStateNameDecodesTheMIBAndNeverGuesses(t *testing.T) {
	want := map[int]string{
		1: "up", 2: "down", 3: "testing", 4: "unknown",
		5: "dormant", 6: "not_present", 7: "lower_layer_down",
	}
	for v, name := range want {
		if got := ifStateName(v); got != name {
			t.Errorf("ifStateName(%d) = %q, want %q", v, got, name)
		}
	}
	for _, v := range []int{0, -1, 8, 99} {
		if got := ifStateName(v); got != "unknown" {
			t.Errorf("ifStateName(%d) = %q — an unrecognized state must decode to \"unknown\", never to up or down", v, got)
		}
	}
}

func TestSeriesKeyPrefersIfNameAndFallsBackToIndex(t *testing.T) {
	if got := seriesKey(map[string]string{"ifName": "Ethernet1", "index": "3"}); got != "Ethernet1" {
		t.Errorf("seriesKey = %q, want Ethernet1", got)
	}
	if got := seriesKey(map[string]string{"index": "3"}); got != "3" {
		t.Errorf("seriesKey fallback = %q, want the ifIndex 3", got)
	}
	if got := seriesKey(map[string]string{"device": "core-1"}); got != "" {
		t.Errorf("a sample identifying no interface must yield no key, got %q", got)
	}
}

// TestBuildInterfacesLeavesAbsentMeasurementsNull is the central honesty test:
// a counter that was never collected must be null, not zero.
func TestBuildInterfacesLeavesAbsentMeasurementsNull(t *testing.T) {
	ifaces, truncated := BuildInterfaces(Series{
		Oper: []Sample{sample(1, "ifName", "Ethernet1")},
	}, maxInterfaces)
	if truncated {
		t.Fatal("one interface must not truncate")
	}
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(ifaces))
	}
	i := ifaces[0]
	if i.Oper != "up" || i.OperValue == nil || *i.OperValue != 1 {
		t.Errorf("oper = %q/%v, want up/1", i.Oper, i.OperValue)
	}
	if i.AdminValue != nil {
		t.Error("admin state was never read; it must be null, not a value")
	}
	if i.Admin != "unknown" {
		t.Errorf("admin label = %q, want \"unknown\" — an unread admin state is not \"up\"", i.Admin)
	}
	for name, p := range map[string]*float64{
		"in_bps": i.InBps, "out_bps": i.OutBps, "speed_bps": i.SpeedBps,
		"in_util_pct": i.InUtilPct, "out_util_pct": i.OutUtilPct,
		"in_errors_per_s": i.InErrPerS, "out_errors_per_s": i.OutErrPerS,
	} {
		if p != nil {
			t.Errorf("%s = %v — an uncollected counter must be null; zero is a claim we cannot make", name, *p)
		}
	}
}

func TestBuildInterfacesFoldsEverySeriesAndComputesUtilisation(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{
		Oper:   []Sample{sample(1, "ifName", "Ethernet1", "ifAlias", "to-spine", "index", "1", "transport", "gnmi")},
		Admin:  []Sample{sample(2, "ifName", "Ethernet1")},
		InBps:  []Sample{sample(5e8, "ifName", "Ethernet1")},
		OutBps: []Sample{sample(1e8, "ifName", "Ethernet1")},
		Speed:  []Sample{sample(1000, "ifName", "Ethernet1")}, // Mbit/s → 1e9 bps
		InErr:  []Sample{sample(0.5, "ifName", "Ethernet1")},
		OutErr: []Sample{sample(0, "ifName", "Ethernet1")},
	}, maxInterfaces)
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(ifaces))
	}
	i := ifaces[0]
	if i.Alias != "to-spine" || i.Index != "1" || i.Transport != "gnmi" {
		t.Errorf("identity labels lost: %+v", i)
	}
	if i.Admin != "down" || i.AdminValue == nil || *i.AdminValue != 2 {
		t.Errorf("admin = %q/%v, want down/2", i.Admin, i.AdminValue)
	}
	if i.SpeedBps == nil || *i.SpeedBps != 1e9 {
		t.Fatalf("speed = %v, want 1e9 bps from 1000 Mbit/s", i.SpeedBps)
	}
	if i.InUtilPct == nil || math.Abs(*i.InUtilPct-50) > 1e-9 {
		t.Errorf("in util = %v, want 50%%", i.InUtilPct)
	}
	if i.OutUtilPct == nil || math.Abs(*i.OutUtilPct-10) > 1e-9 {
		t.Errorf("out util = %v, want 10%%", i.OutUtilPct)
	}
	// A measured ZERO is a fact and must survive as 0, not become null.
	if i.OutErrPerS == nil || *i.OutErrPerS != 0 {
		t.Errorf("a measured zero error rate must be reported as 0, got %v", i.OutErrPerS)
	}
}

// A counter with no state series is not an interface: we would have nothing
// true to say about it.
func TestBuildInterfacesRequiresAStateSeries(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{
		InBps: []Sample{sample(1e6, "ifName", "Ethernet9")},
		Speed: []Sample{sample(10, "ifName", "Ethernet9")},
	}, maxInterfaces)
	if len(ifaces) != 0 {
		t.Errorf("built %d interfaces from counters alone: %+v", len(ifaces), ifaces)
	}
}

func TestUtilPctIsNullWithoutACapacity(t *testing.T) {
	bps := 1e6
	if utilPct(&bps, nil) != nil {
		t.Error("no speed series means the percentage is UNKNOWN, not zero")
	}
	zero := 0.0
	if utilPct(&bps, &zero) != nil {
		t.Error("a zero capacity must not divide into an Inf percentage")
	}
	if utilPct(nil, &bps) != nil {
		t.Error("no throughput means no percentage")
	}
}

func TestFiniteRejectsNaNAndInf(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if finite(v) != nil {
			t.Errorf("finite(%v) must be nil — a non-finite sample is an absent measurement", v)
		}
	}
	if p := finite(0); p == nil || *p != 0 {
		t.Error("a finite zero is a value and must survive")
	}
}

func TestBuildInterfacesTruncatesAndSaysSo(t *testing.T) {
	var oper []Sample
	for i := 0; i < 10; i++ {
		oper = append(oper, sample(1, "ifName", string(rune('a'+i))))
	}
	ifaces, truncated := BuildInterfaces(Series{Oper: oper}, 4)
	if len(ifaces) != 4 || !truncated {
		t.Errorf("got %d rows truncated=%v, want 4/true", len(ifaces), truncated)
	}
}

func TestNaturalLessOrdersPortsTheWayOperatorsReadThem(t *testing.T) {
	cases := [][2]string{
		{"Ethernet2", "Ethernet10"},
		{"ge-0/0/2", "ge-0/0/10"},
		{"Ethernet1", "Ethernet1/1"},
		{"1/1/1", "1/1/10"},
		{"Ethernet1", "Loopback0"},
	}
	for _, c := range cases {
		if !naturalLess(c[0], c[1]) {
			t.Errorf("naturalLess(%q, %q) = false, want true", c[0], c[1])
		}
		if naturalLess(c[1], c[0]) {
			t.Errorf("naturalLess(%q, %q) = true — the order is not antisymmetric", c[1], c[0])
		}
	}
	if naturalLess("Ethernet1", "Ethernet1") {
		t.Error("a name is not less than itself")
	}
}

func TestBuildInterfacesSortsNaturally(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{
		sample(1, "ifName", "Ethernet10"),
		sample(1, "ifName", "Ethernet2"),
		sample(1, "ifName", "Ethernet1"),
	}}, maxInterfaces)
	got := []string{ifaces[0].Name, ifaces[1].Name, ifaces[2].Name}
	want := []string{"Ethernet1", "Ethernet2", "Ethernet10"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

// ── grouping ────────────────────────────────────────────────────────────────

// THE test for this feature. With no vrf label anywhere — today's reality on
// both transports — the answer must be ONE ungrouped bucket that says the
// membership is not collected. It must NOT be a group called "default".
func TestGroupByVRFNeverInventsADefaultInstance(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{
		sample(1, "ifName", "Ethernet1"),
		sample(2, "ifName", "Ethernet2"),
	}}, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, "VRF")
	if vrfLabels {
		t.Fatal("no series carried a vrf label; vrfLabels must be false")
	}
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want exactly one ungrouped bucket: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.VRF != "" {
		t.Errorf("the ungrouped bucket must have NO instance name, got %q", g.VRF)
	}
	if g.Membership != MembershipNotCollected {
		t.Errorf("membership = %q, want %q", g.Membership, MembershipNotCollected)
	}
	if strings.Contains(strings.ToLower(g.Label), "default") {
		t.Errorf("label %q claims a default instance — no collected series supports that", g.Label)
	}
	if g.Up != 1 || g.Down != 1 || g.Count != 2 {
		t.Errorf("counts = up %d down %d count %d, want 1/1/2", g.Up, g.Down, g.Count)
	}
}

func TestGroupByVRFUsesTheObservedLabelWhenItExists(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{
		sample(1, "ifName", "Ethernet1", "vrf", "CORP-WAN"),
		sample(1, "ifName", "Ethernet2", "vrf", "BLUE"),
		sample(2, "ifName", "Ethernet3", "vrf", "CORP-WAN"),
	}}, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, "VRF")
	if !vrfLabels {
		t.Fatal("vrf labels were present; vrfLabels must be true")
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
	}
	if groups[0].VRF != "BLUE" || groups[1].VRF != "CORP-WAN" {
		t.Errorf("groups are not name-ordered: %q, %q", groups[0].VRF, groups[1].VRF)
	}
	for _, g := range groups {
		if g.Membership != MembershipObserved {
			t.Errorf("group %q membership = %q, want %q", g.VRF, g.Membership, MembershipObserved)
		}
	}
	corp := groups[1]
	if corp.Count != 2 || corp.Up != 1 || corp.Down != 1 {
		t.Errorf("CORP-WAN counts = %d/%d/%d, want 2/1/1", corp.Count, corp.Up, corp.Down)
	}
}

// A partial roll-out (some series labelled, some not) is a THIRD fact and must
// not be collapsed into either of the other two.
func TestGroupByVRFKeepsAPartialLabellingHonest(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{
		sample(1, "ifName", "Ethernet1", "vrf", "CORP-WAN"),
		sample(1, "ifName", "Ethernet2"),
	}}, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, "routing-instance")
	if !vrfLabels || len(groups) != 2 {
		t.Fatalf("vrfLabels=%v groups=%d, want true/2", vrfLabels, len(groups))
	}
	last := groups[len(groups)-1]
	if last.Membership != MembershipNotCollected || last.VRF != "" {
		t.Fatalf("the trailing bucket must be the unlabelled one: %+v", last)
	}
	if !strings.Contains(last.Label, "routing-instance") {
		t.Errorf("the bucket label must use the device's dialect word, got %q", last.Label)
	}
}

func TestGroupByVRFOnNoInterfacesYieldsNoGroups(t *testing.T) {
	groups, vrfLabels := GroupByVRF(nil, "VRF")
	if len(groups) != 0 || vrfLabels {
		t.Errorf("no interfaces must yield no groups, got %d (vrfLabels=%v)", len(groups), vrfLabels)
	}
}

// ── coverage ────────────────────────────────────────────────────────────────

func TestTransportOfMarksTheSNMPLaneAsInferred(t *testing.T) {
	unstamped := []Interface{{Name: "Ethernet1"}, {Name: "Ethernet2"}}
	tr, inferred := TransportOf(unstamped)
	if tr != TransportSNMP || !inferred {
		t.Errorf("unstamped series = %q inferred=%v, want snmp/true — the SNMP lane stamps no transport label, so this is a convention, not a measurement", tr, inferred)
	}

	gnmi := []Interface{{Name: "e1", Transport: "gnmi"}}
	if tr, inferred = TransportOf(gnmi); tr != TransportGNMI || inferred {
		t.Errorf("stamped series = %q inferred=%v, want gnmi/false", tr, inferred)
	}

	mixed := []Interface{{Name: "e1", Transport: "gnmi"}, {Name: "e2"}}
	if tr, _ = TransportOf(mixed); tr != TransportMixed {
		t.Errorf("mixed lanes = %q, want %q", tr, TransportMixed)
	}

	if tr, inferred = TransportOf(nil); tr != TransportNone || inferred {
		t.Errorf("no interfaces = %q inferred=%v, want none/false", tr, inferred)
	}
}

func TestKnownRoutingInstancesDedupesAndOrders(t *testing.T) {
	got := KnownRoutingInstances([]Sample{
		sample(6, "vrf", "CORP-WAN", "peer", "10.0.0.1"),
		sample(6, "vrf", "CORP-WAN", "peer", "10.0.0.2"),
		sample(1, "vrf", "BLUE", "peer", "10.0.0.3"),
		sample(1, "peer", "10.0.0.4"), // no vrf label — contributes nothing
	}, maxInstances)
	if len(got) != 2 || got[0].Name != "BLUE" || got[1].Name != "CORP-WAN" {
		t.Fatalf("instances = %+v, want [BLUE CORP-WAN]", got)
	}
	for _, ri := range got {
		if ri.Source != "bgp_control_plane" {
			t.Errorf("instance %q source = %q — the response must name the lane it came from", ri.Name, ri.Source)
		}
	}
	if len(KnownRoutingInstances(nil, maxInstances)) != 0 {
		t.Error("no control-plane series means no known instances")
	}
}

func TestBuildCoverageExplainsEveryAbsence(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{sample(1, "ifName", "Ethernet1")}}, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, "VPRN")
	instances := KnownRoutingInstances([]Sample{sample(6, "vrf", "CORP-WAN")}, maxInstances)
	cov := BuildCoverage(ifaces, groups, vrfLabels, false, "VPRN", instances)

	if cov.VRFLabels {
		t.Error("coverage.vrf_labels must report the probe result, and no vrf label was present")
	}
	if cov.Interfaces != 1 || cov.InGroups != 0 || cov.Ungrouped != 1 {
		t.Errorf("counts = %d/%d/%d, want 1/0/1", cov.Interfaces, cov.InGroups, cov.Ungrouped)
	}
	if cov.Utilisation || cov.Errors {
		t.Error("neither speed nor error series were read; both coverage flags must be false")
	}
	joined := strings.Join(cov.Notes, " | ")
	for _, want := range []string{"VPRN", "not collected", "null", "routing_instances"} {
		if !strings.Contains(joined, want) {
			t.Errorf("coverage notes never mention %q: %s", want, joined)
		}
	}
	if strings.Contains(strings.ToLower(joined), "default vrf") {
		t.Errorf("the notes claim a default instance: %s", joined)
	}
}

func TestBuildCoverageOnNoSeriesSaysNothingIsCollected(t *testing.T) {
	cov := BuildCoverage(nil, nil, false, false, "VRF", nil)
	if cov.Transport != TransportNone || cov.Interfaces != 0 {
		t.Errorf("coverage = %+v, want no transport and zero interfaces", cov)
	}
	if len(cov.Notes) == 0 || !strings.Contains(cov.Notes[0], "No interface state series") {
		t.Errorf("an empty device must be explained, got %v", cov.Notes)
	}
}

func TestBuildCoverageFlagsTruncation(t *testing.T) {
	ifaces, _ := BuildInterfaces(Series{Oper: []Sample{sample(1, "ifName", "e1")}}, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, "VRF")
	cov := BuildCoverage(ifaces, groups, vrfLabels, true, "VRF", nil)
	if !cov.Truncated {
		t.Fatal("truncation must be reported")
	}
	if !strings.Contains(strings.Join(cov.Notes, " "), "truncated") {
		t.Errorf("truncation must also be explained in the notes: %v", cov.Notes)
	}
}

func TestInterfaceUpIsNeverTrueWithoutEvidence(t *testing.T) {
	if (Interface{}).Up() {
		t.Error("an interface with no state series must not report Up()")
	}
	down := 2
	if (Interface{OperValue: &down}).Up() {
		t.Error("oper 2 is down")
	}
	up := 1
	if !(Interface{OperValue: &up}).Up() {
		t.Error("oper 1 is up")
	}
}
