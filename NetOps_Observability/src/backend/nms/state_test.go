// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"testing"
	"time"
)

func TestStateTrackerFlapAndTransitions(t *testing.T) {
	tr := NewStateTracker()
	t0 := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	mk := func(state string, at time.Time) ControllerState {
		return ControllerState{
			IntegrationID: "int1", EntityKey: "tunnel-42", StateKind: "tunnel",
			CurrentState: state, DeviceID: "r1", Time: at,
		}
	}

	// First sighting: not a flap, first_seen set, no change emitted.
	rec, chg := tr.Apply(mk("up", t0))
	if chg != nil || rec.FlapCount != 0 || !rec.FirstSeen.Equal(t0) {
		t.Fatalf("first sighting wrong: rec=%+v chg=%v", rec, chg)
	}

	// Steady state: no change, no flap, last_seen advances.
	rec, chg = tr.Apply(mk("up", t0.Add(1*time.Minute)))
	if chg != nil || rec.FlapCount != 0 || !rec.LastSeen.Equal(t0.Add(1*time.Minute)) {
		t.Fatalf("steady wrong: rec=%+v chg=%v", rec, chg)
	}

	// Transition up→down: change emitted, flap=1, previous recorded.
	rec, chg = tr.Apply(mk("down", t0.Add(2*time.Minute)))
	if chg == nil || chg.From != "up" || chg.To != "down" || rec.FlapCount != 1 || rec.PreviousState != "up" {
		t.Fatalf("transition wrong: rec=%+v chg=%+v", rec, chg)
	}

	// Flap back down→up: flap=2.
	_, chg = tr.Apply(mk("up", t0.Add(3*time.Minute)))
	if chg == nil || chg.To != "up" {
		t.Fatal("expected up transition")
	}
	got, _ := tr.Get(StateEntityKey(mk("up", t0)))
	if got.FlapCount != 2 {
		t.Fatalf("flap_count should be 2, got %d", got.FlapCount)
	}
	// first_seen preserved across flaps.
	if !got.FirstSeen.Equal(t0) {
		t.Fatalf("first_seen must persist: %v", got.FirstSeen)
	}
}

func TestMetricLineStableSortedLabels(t *testing.T) {
	m := ControllerMetric{
		Name: "controller_metric_tunnel_latency_ms", Value: 12.5,
		Time: time.UnixMilli(1700000000000),
		Tags: map[string]string{"site": "hq", "device": "r1", "tunnel": "t-1"},
	}
	got := MetricLine(m)
	want := `controller_metric_tunnel_latency_ms{device="r1",site="hq",tunnel="t-1"} 12.5 1700000000000`
	if got != want {
		t.Fatalf("metric line:\n got=%s\nwant=%s", got, want)
	}
	// Nameless → empty.
	if MetricLine(ControllerMetric{}) != "" {
		t.Fatal("nameless metric must render empty")
	}
	// Label value with a quote is escaped.
	q := MetricLine(ControllerMetric{Name: "x", Value: 1, Tags: map[string]string{"a": `he"llo`}})
	if q != `x{a="he\"llo"} 1` {
		t.Fatalf("escape wrong: %s", q)
	}
}
