// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/lex"
)

// baselineSpy records every baseline call and answers for tenant t-a's
// devices only (another tenant's device is ErrNotFound, as the server does).
type baselineSpy struct {
	asked []BaselineRequest
	rep   BaselineReport
}

func (b *baselineSpy) fn(_ context.Context, p Principal, req BaselineRequest) (BaselineReport, error) {
	b.asked = append(b.asked, req)
	if p.Tenant != "t-a" || !strings.HasPrefix(req.DeviceID, "dev-") {
		return BaselineReport{}, ErrNotFound
	}
	r := b.rep
	r.DeviceID, r.Op = req.DeviceID, req.Op
	return r, nil
}

func baselineOrch(spy *baselineSpy) *Orchestrator {
	o := &Orchestrator{DS: newMockDS(), Flags: func(string) bool { return true }}
	o.Troubleshoot.ResolveDevice = func(_ context.Context, p Principal, ref string) (DeviceRef, error) {
		if p.Tenant == "t-a" && ref == "edge-1" {
			return DeviceRef{ID: "dev-edge-1", Name: "edge-1", Platform: "ios-xe"}, nil
		}
		return DeviceRef{}, ErrNotFound
	}
	if spy != nil {
		o.Troubleshoot.DeviceBaseline = spy.fn
	}
	return o
}

var labBaselineAt = time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC)

func TestClassifyBaseline(t *testing.T) {
	cases := map[string]string{
		"take a baseline of edge-1 before the change":               "baseline_take",
		"snapshot edge-1 so I can compare later":                    "baseline_take",
		"capture a pre-change snapshot of core-1":                   "baseline_take",
		"compare edge-1 with its baseline":                          "baseline_compare",
		"did everything come back after the change vs the snapshot": "baseline_compare",
		"what's missing on edge-1 compared to the baseline":         "baseline_compare",
		"post-change check against the baseline on edge-1":          "baseline_compare",
		// A metric baseline is the anomaly engine's, not a change baseline.
		"what is the cpu baseline on edge-1":      "",
		"is traffic above baseline at the dc":     "",
		"show the latency baseline for the probe": "",
		// No baseline word: not this route.
		"is edge-1 ready to upgrade": "",
		"bgp down on edge-1":         "",
	}
	for q, want := range cases {
		if got := classifyBaseline(lex.ClassifierText(q)); got != want {
			t.Errorf("classifyBaseline(%q) = %q, want %q", q, got, want)
		}
	}
}

func TestBaselineTakeAnswer(t *testing.T) {
	spy := &baselineSpy{rep: BaselineReport{DeviceName: "edge-1", BaselineID: "b-1", BaselineAt: labBaselineAt,
		Summary: "5 interfaces, 3 routing neighbours, 10 routes, version 17.03.02"}}
	o := baselineOrch(spy)
	ans, err := o.Ask(context.Background(), opsA(), "take a baseline of edge-1 before the change", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDeviceBaseline || len(spy.asked) != 1 || spy.asked[0].Op != BaselineTake || spy.asked[0].DeviceID != "dev-edge-1" {
		t.Fatalf("mode %s asked %+v", ans.Mode, spy.asked)
	}
	for _, want := range []string{"Baseline of edge-1 taken at 2026-11-18 09:30 UTC", "5 interfaces, 3 routing neighbours", "compare edge-1 with its baseline"} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("text missing %q:\n%s", want, ans.Text)
		}
	}
	if !hasCitation(ans.Citations, "baseline:b-1") || !strings.Contains(strings.Join(ans.Disclaimers, " "), noDeviceChangeNote) {
		t.Errorf("citations %+v disclaimers %v", ans.Citations, ans.Disclaimers)
	}
}

func TestBaselineCompareAnswerIsObservedOnly(t *testing.T) {
	spy := &baselineSpy{rep: BaselineReport{DeviceName: "edge-1", BaselineID: "b-1", BaselineAt: labBaselineAt,
		BaselineLabel: "CHG-1042", ReadAt: labBaselineAt.Add(2 * time.Hour), Changes: 2,
		Lines: []string{
			"Interface GigabitEthernet3 was up/up before the change and is up/down now.",
			"OSPF 10.0.0.3 on GigabitEthernet3 (FULL/BDR before the change) did not come back.",
			"Cannot compare isis (not read in the baseline).",
		},
		NotRead: []string{"isis: isis-neighbors output could not be parsed"}}}
	o := baselineOrch(spy)
	ans, err := o.Ask(context.Background(), opsA(), "did everything come back on edge-1 after the change compared to the baseline?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDeviceBaseline || spy.asked[0].Op != BaselineCompare {
		t.Fatalf("mode %s asked %+v", ans.Mode, spy.asked)
	}
	for _, want := range []string{"Compared edge-1 now with its baseline from 2026-11-18 09:30 UTC (CHG-1042)",
		"• Interface GigabitEthernet3 was up/up", "did not come back", "Cannot compare isis"} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("text missing %q:\n%s", want, ans.Text)
		}
	}
	for _, c := range ans.Citations {
		if c.Kind != "device" && c.Class != ClassObserved {
			t.Errorf("citation %+v is not OBSERVED", c)
		}
	}
	if !strings.Contains(strings.Join(ans.Disclaimers, " "), "Not read: isis") {
		t.Errorf("the unread section must be disclosed: %v", ans.Disclaimers)
	}
}

// §3a: another tenant's device is the same not-found as an unknown one, and
// the baseline seam never runs for it.
func TestBaselineAnswerCrossTenantDevice(t *testing.T) {
	spy := &baselineSpy{}
	o := baselineOrch(spy)
	ans, err := o.Ask(context.Background(), opsB(), "take a baseline of edge-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDeviceBaseline || !strings.Contains(ans.Text, "Which device") {
		t.Fatalf("tenant b: mode %s text %q", ans.Mode, ans.Text)
	}
	if len(spy.asked) != 0 {
		t.Fatalf("the seam ran for a device tenant b cannot see: %+v", spy.asked)
	}
	// A device handed in by the UI that tenant b cannot resolve is dropped by
	// the view binding: still no read.
	ans, err = o.Ask(context.Background(), opsB(), "take a baseline", map[string]string{"device_id": "dev-edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ans.Text, "Which device") || len(spy.asked) != 0 {
		t.Fatalf("tenant b via ui context: %q asked %+v", ans.Text, spy.asked)
	}
	// And if the seam itself refuses (another tenant's id reached it), the
	// answer is the not-in-scope one, never the device's existence.
	o.Troubleshoot.ResolveDevice = nil
	ans, _ = o.Ask(context.Background(), opsB(), "take a baseline", map[string]string{"device_id": "dev-edge-1"})
	if !strings.Contains(ans.Text, "isn't available in your scope") {
		t.Fatalf("seam refusal: %q", ans.Text)
	}
}

func TestBaselineAnswerNotWiredAndNoDevice(t *testing.T) {
	o := baselineOrch(nil)
	ans, err := o.Ask(context.Background(), opsA(), "take a baseline of edge-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("no seam: mode %s", ans.Mode)
	}
	spy := &baselineSpy{rep: BaselineReport{NotWired: "reading live device state needs infrastructure write access, which this account does not have — no command was run"}}
	o = baselineOrch(spy)
	ans, _ = o.Ask(context.Background(), opsA(), "compare edge-1 with its baseline", nil)
	if !strings.Contains(ans.Text, "needs infrastructure write access") || !strings.Contains(strings.Join(ans.Disclaimers, " "), noDeviceChangeNote) {
		t.Fatalf("not wired: %q %v", ans.Text, ans.Disclaimers)
	}
	ans, _ = o.Ask(context.Background(), opsA(), "compare with the baseline please", nil)
	if !strings.Contains(ans.Text, "Which device should I compare") {
		t.Fatalf("no device: %q", ans.Text)
	}
}

// Without the device-state module permission the answer is refused before
// any device is read.
func TestBaselineAnswerNeedsTheModule(t *testing.T) {
	spy := &baselineSpy{}
	o := baselineOrch(spy)
	ans, err := o.Ask(context.Background(), tenantA(), "take a baseline of edge-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable || len(spy.asked) != 0 {
		t.Fatalf("an unpermitted caller must be refused before a read: mode %s asked %v", ans.Mode, spy.asked)
	}
}

// End to end through the model-first planner: the two baseline routes reach
// this arm, and the upgrade route reaches the upgrade-readiness method.
func TestPlannerRoutesChangeAssistance(t *testing.T) {
	spy := &baselineSpy{rep: BaselineReport{DeviceName: "edge-1", BaselineID: "b-1", BaselineAt: labBaselineAt, Summary: "5 interfaces"}}
	for route, op := range map[string]string{PlanRouteBaseline: BaselineTake, PlanRouteCompare: BaselineCompare} {
		reply := "ROUTE: " + route
		o := plannerOrch(&plannerLLM{route: func(string) string { return reply }})
		o.Troubleshoot.DeviceBaseline = spy.fn
		o.Troubleshoot.ResolveDevice = baselineOrch(nil).Troubleshoot.ResolveDevice
		before := len(spy.asked)
		ans, err := o.Ask(context.Background(), opsA(), "edge-1, you know, the before/after thing", nil)
		if err != nil {
			t.Fatal(err)
		}
		if ans.Mode != ModeDeviceBaseline || len(spy.asked) != before+1 || spy.asked[before].Op != op {
			t.Errorf("route %s: mode %s asked %+v", route, ans.Mode, spy.asked)
		}
	}
	sk := loadTestSkills(t)
	o := plannerOrch(&plannerLLM{route: func(string) string { return "ROUTE: " + PlanRouteUpgrade }})
	o.Skills = sk
	var arm string
	o.Routed = func(d RouteDecision) { arm = d.Arm }
	ans, err := o.Ask(context.Background(), opsA(), "can edge-1 take the new code", nil)
	if err != nil {
		t.Fatal(err)
	}
	// This harness wires no gather tools, so the method gathers nothing and the
	// model answers; what is pinned here is that the skill arm took it first.
	if arm != ArmSkill || ans.Routing == nil || ans.Routing.Reason != RouteReasonPlanner {
		t.Fatalf("upgrade route: arm %s routing %+v", arm, ans.Routing)
	}
}
