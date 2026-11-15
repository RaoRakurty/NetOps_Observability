// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iristrigger

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

func incidentTrigger() Trigger {
	return Trigger{Name: "Critical BGP", Kind: KindIncident, Enabled: true,
		Filter: Filter{MinSeverity: "error", Signature: "bgp"}}
}

func TestValidateRefusesWhatWouldMisbehave(t *testing.T) {
	cases := map[string]Trigger{
		"no name":               {Kind: KindIncident, Filter: Filter{MinSeverity: "error"}},
		"empty filter":          {Name: "x", Kind: KindIncident},
		"unknown severity":      {Name: "x", Kind: KindIncident, Filter: Filter{MinSeverity: "urgent"}},
		"schedule too fast":     {Name: "x", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 5}},
		"schedule too slow":     {Name: "x", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 2000}},
		"unknown kind":          {Name: "x", Kind: "webhook"},
		"control char in name":  {Name: "a\x07b", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 30}},
		"invisible char":        {Name: "a" + string(rune(0x200b)) + "b", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 30}},
		"site with odd symbols": {Name: "x", Kind: KindIncident, Filter: Filter{Site: "dallas;drop"}},
		"long question":         {Name: "x", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 30}, Question: strings.Repeat("q", 301)},
	}
	for name, tr := range cases {
		tr := tr
		if err := Validate(&tr); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err=%v, want ErrInvalid", name, err)
		}
	}
	ok := Trigger{Name: "  Nightly   sweep ", Kind: KindSchedule, Schedule: Schedule{EveryMinutes: 15},
		Filter: Filter{MinSeverity: "critical"}}
	if err := Validate(&ok); err != nil {
		t.Fatal(err)
	}
	if ok.Name != "Nightly sweep" || ok.Filter != (Filter{}) {
		t.Fatalf("not normalised: %+v", ok)
	}
}

func TestMatchesEveryConditionMustHold(t *testing.T) {
	tr := incidentTrigger()
	tr.Filter.Site, tr.Filter.Role = "Dallas", "wan_edge"
	if err := Validate(&tr); err != nil {
		t.Fatal(err)
	}
	ev := IncidentEvent{Severity: "critical", Title: "BGP peer down", Site: "dallas", Role: "WAN_EDGE"}
	if !tr.Matches(ev) {
		t.Fatal("a matching incident did not match")
	}
	for name, mut := range map[string]func(*IncidentEvent){
		"low severity":   func(e *IncidentEvent) { e.Severity = "warning" },
		"other text":     func(e *IncidentEvent) { e.Title = "CPU high" },
		"other site":     func(e *IncidentEvent) { e.Site = "austin" },
		"other role":     func(e *IncidentEvent) { e.Role = "core" },
		"unknown device": func(e *IncidentEvent) { e.Site, e.Role = "", "" },
	} {
		e := ev
		mut(&e)
		if tr.Matches(e) {
			t.Errorf("%s: matched", name)
		}
	}
	rule := ev
	rule.Title, rule.Rule = "Peer flapping", "bgp_session_down"
	if !tr.Matches(rule) {
		t.Error("the signature should also match the rule name")
	}
	tr.Enabled = false
	if tr.Matches(ev) {
		t.Error("a disabled trigger matched")
	}
}

func TestDueWaitsOneIntervalThenRunsOncePerInterval(t *testing.T) {
	tr := Trigger{Kind: KindSchedule, Enabled: true, Schedule: Schedule{EveryMinutes: 30}, CreatedAt: t0}
	if tr.Due(t0) || tr.Due(t0.Add(29*time.Minute)) {
		t.Fatal("ran before its first interval")
	}
	if !tr.Due(t0.Add(30 * time.Minute)) {
		t.Fatal("not due after one interval")
	}
	last := t0.Add(31 * time.Minute)
	tr.LastRunAt = &last
	if tr.Due(t0.Add(40 * time.Minute)) {
		t.Fatal("due again inside the interval")
	}
	if tr.ScheduleSlot(t0.Add(31*time.Minute)) != tr.ScheduleSlot(t0.Add(59*time.Minute)) {
		t.Fatal("two ticks in one interval got different slots")
	}
	if tr.ScheduleSlot(t0.Add(31*time.Minute)) == tr.ScheduleSlot(t0.Add(61*time.Minute)) {
		t.Fatal("two intervals shared a slot")
	}
}

func TestDefaultQuestion(t *testing.T) {
	ev := &IncidentEvent{Title: "BGP peer down on edge-1"}
	if q := DefaultQuestion(incidentTrigger(), ev); !strings.Contains(q, "BGP peer down on edge-1") {
		t.Fatalf("question %q", q)
	}
	tr := incidentTrigger()
	tr.Question = "Why did the WAN fail?"
	if DefaultQuestion(tr, ev) != tr.Question {
		t.Fatal("the admin's question was not used")
	}
}

func newStoreWithTrigger(t *testing.T, tenant string) (*MemStore, Trigger) {
	t.Helper()
	st := NewMemStore()
	tr, err := st.Create(context.Background(), tenant, "u-admin", incidentTrigger(), t0)
	if err != nil {
		t.Fatal(err)
	}
	return st, tr
}

func TestAdmitDedupesAndHoldsTheDailyCap(t *testing.T) {
	ctx := context.Background()
	st, tr := newStoreWithTrigger(t, "acme")
	run := func(inc string) Run {
		return Run{TriggerID: tr.ID, TriggerName: tr.Name, IncidentID: inc, DedupeKey: IncidentKey(inc)}
	}
	r1, err := st.Admit(ctx, "acme", run("i1"), 2, t0)
	if err != nil || r1.Status != RunRunning {
		t.Fatalf("first: %+v %v", r1, err)
	}
	if _, err := st.Admit(ctx, "acme", run("i1"), 2, t0); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("the same incident ran twice: %v", err)
	}
	if r, err := st.Admit(ctx, "acme", run("i2"), 2, t0); err != nil || r.Status != RunRunning {
		t.Fatalf("second: %+v %v", r, err)
	}
	r3, err := st.Admit(ctx, "acme", run("i3"), 2, t0)
	if err != nil || r3.Status != RunSkipped || r3.Reason != SkipRunCap {
		t.Fatalf("the cap did not hold: %+v %v", r3, err)
	}
	// A skipped run does not count; tomorrow the cap resets.
	if r, err := st.Admit(ctx, "acme", run("i4"), 2, t0.Add(24*time.Hour)); err != nil || r.Status != RunRunning {
		t.Fatalf("next day: %+v %v", r, err)
	}
	got, _ := st.Get(ctx, "acme", tr.ID)
	if got.LastRunAt == nil || !got.LastRunAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("last run not moved: %v", got.LastRunAt)
	}
	if err := st.Finish(ctx, "acme", r1.ID, RunDone, "concluded", "inv-1", 1500, "summary", t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.TokensToday(ctx, "acme", t0); n != 1500 {
		t.Fatalf("tokens today %d", n)
	}
	runs, _ := st.Runs(ctx, "acme", 10)
	if len(runs) != 4 || runs[0].IncidentID != "i4" {
		t.Fatalf("runs newest first: %+v", runs)
	}
}

func TestStoreIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	st, tr := newStoreWithTrigger(t, "acme")
	if _, err := st.Get(ctx, "globex", tr.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant read the trigger: %v", err)
	}
	if _, err := st.SetEnabled(ctx, "globex", tr.ID, false, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant changed the trigger: %v", err)
	}
	if err := st.Delete(ctx, "globex", tr.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant deleted the trigger: %v", err)
	}
	if l, _ := st.List(ctx, "globex"); len(l) != 0 {
		t.Fatalf("another tenant listed %d triggers", len(l))
	}
	for _, bad := range []string{"", "*", "a*b"} {
		if _, err := st.List(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("tenant %q accepted", bad)
		}
	}
}

func TestDueSchedulesOnlyForSwitchedOnWorkspaces(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	sched := Trigger{Name: "Sweep", Kind: KindSchedule, Enabled: true, Schedule: Schedule{EveryMinutes: 15}}
	a, _ := st.Create(ctx, "acme", "u", sched, t0)
	_, _ = st.Create(ctx, "globex", "u", sched, t0)
	later := t0.Add(16 * time.Minute)
	if due, _ := st.DueSchedules(ctx, later); len(due) != 0 {
		t.Fatalf("due with every workspace switched off: %d", len(due))
	}
	on := DefaultSettings()
	on.Enabled = true
	if err := st.PutSettings(ctx, "acme", on); err != nil {
		t.Fatal(err)
	}
	due, _ := st.DueSchedules(ctx, later)
	if len(due) != 1 || due[0].ID != a.ID || due[0].TenantID != "acme" {
		t.Fatalf("due: %+v", due)
	}
}

func TestSettingsDefaultOffAndValidated(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	s, err := st.Settings(ctx, "acme")
	if err != nil || s.Enabled || s.MaxRunsPerDay != DefaultRunsPerDay {
		t.Fatalf("defaults: %+v %v", s, err)
	}
	if err := st.PutSettings(ctx, "acme", Settings{Enabled: true, MaxRunsPerDay: 0, MaxTokensPerDay: 5000}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero runs/day accepted: %v", err)
	}
}

func TestTriggerCapPerTenant(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	for i := 0; i < MaxTriggersPerTenant; i++ {
		if _, err := st.Create(ctx, "acme", "u", incidentTrigger(), t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Create(ctx, "acme", "u", incidentTrigger(), t0); !errors.Is(err, ErrTooMany) {
		t.Fatalf("21st trigger: %v", err)
	}
}
