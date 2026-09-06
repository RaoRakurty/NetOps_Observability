// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/configstore"
	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
)

// TestStateVocabularyMatchesConfigstore pins the two packages' vocabularies
// equal — the badge, the version row and the bus event must all say the same
// word for the same condition.
func TestStateVocabularyMatchesConfigstore(t *testing.T) {
	pairs := map[string]string{
		StateInSync:  configstore.DriftInSync,
		StateChanged: configstore.DriftChanged,
		StateDrifted: configstore.DriftDrifted,
		StateUnknown: configstore.DriftUnknown,
	}
	for mine, theirs := range pairs {
		if mine != theirs {
			t.Errorf("state vocabulary diverged: %q vs %q", mine, theirs)
		}
	}
	if len(States) != 4 {
		t.Fatalf("States = %v", States)
	}
	for _, s := range States {
		if !ValidState(s) {
			t.Errorf("ValidState(%q) = false", s)
		}
	}
	if ValidState("drifting") || ValidState("") {
		t.Error("ValidState accepted a value outside the closed vocabulary")
	}
}

// TestDriftStateMachine walks every transition the design specifies.
func TestDriftStateMachine(t *testing.T) {
	base := cfgText("edge-01")
	changed := cfgText("edge-02")

	cases := []struct {
		name    string
		ev      configstore.CaptureEvent
		want    string
		wantAdd bool
	}{
		{
			name: "first capture is a change, never a green badge on one data point",
			ev:   event("acme", "d1", base),
			want: StateChanged, wantAdd: true,
		},
		{
			name: "identical to previous, no golden set",
			ev:   withPrevious(event("acme", "d1", base), base),
			want: StateInSync,
		},
		{
			name: "identical to previous AND to golden",
			ev:   withGolden(withPrevious(event("acme", "d1", base), base), base),
			want: StateInSync,
		},
		{
			name: "differs from previous, no golden",
			ev:   withPrevious(event("acme", "d1", changed), base),
			want: StateChanged, wantAdd: true,
		},
		{
			name: "differs from golden outranks differs from previous",
			ev:   withGolden(withPrevious(event("acme", "d1", changed), base), base),
			want: StateDrifted, wantAdd: true,
		},
		{
			name: "unchanged since previous but still off the golden baseline",
			ev:   withGolden(withPrevious(event("acme", "d1", changed), changed), base),
			want: StateDrifted, wantAdd: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			got := f.eval.Observe(context.Background(), tc.ev)
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q", got.State, tc.want)
			}
			if tc.wantAdd && got.Added+got.Removed == 0 {
				t.Fatalf("a change must carry a diff summary: %+v", got)
			}
			if !tc.wantAdd && got.Added+got.Removed != 0 {
				t.Fatalf("in_sync must carry no diff summary: %+v", got)
			}
			st, ok, err := f.store.Get(context.Background(), "acme", false, "d1")
			if err != nil || !ok {
				t.Fatalf("state row missing: ok=%v err=%v", ok, err)
			}
			if st.State != tc.want || st.TenantID != "acme" {
				t.Fatalf("stored row = %+v", st)
			}
		})
	}
}

// TestInSyncEmitsNothing: the steady state must not flood the evidence lane.
func TestInSyncEmitsNothing(t *testing.T) {
	f := newFixture(t, nil)
	base := cfgText("edge-01")
	f.eval.Observe(context.Background(), withPrevious(event("acme", "d1", base), base))
	if n := len(f.bus.records()); n != 0 {
		t.Fatalf("in_sync published %d records, want 0", n)
	}
}

// TestBusEventShapeAndNoConfigText is the headline emission contract: the
// ConfigDrift event grounds as generic security evidence AND contains not one
// byte of configuration.
func TestBusEventShapeAndNoConfigText(t *testing.T) {
	f := newFixture(t, nil)
	ev := withGolden(withPrevious(event("acme", "d1", cfgText("edge-02")), cfgText("edge-01")), cfgText("edge-01"))
	verdict := f.eval.Observe(context.Background(), ev)
	if verdict.State != StateDrifted {
		t.Fatalf("state = %q", verdict.State)
	}

	recs := f.bus.records()
	if len(recs) != 1 {
		t.Fatalf("published %d records, want 1", len(recs))
	}
	if f.bus.topics[0] != secbus.TopicSecurityEvidence {
		t.Fatalf("topic = %q, want %q", f.bus.topics[0], secbus.TopicSecurityEvidence)
	}
	if recs[0].Key != "acme" {
		t.Errorf("partition key = %q, want the tenant id", recs[0].Key)
	}
	evt, ok := recs[0].Value.(secbus.EvidenceEvent)
	if !ok {
		t.Fatalf("record value is %T, want secbus.EvidenceEvent", recs[0].Value)
	}
	if evt.TenantID != "acme" || evt.EntityID != "d1" || evt.EntityType != secbus.EntityTypeDevice {
		t.Errorf("event grounding = %+v", evt)
	}
	if evt.Kind != secbus.KindPosture {
		t.Errorf("kind = %q, want %q", evt.Kind, secbus.KindPosture)
	}
	if evt.Severity != secfindings.SeverityHigh {
		t.Errorf("severity = %q, want high for drifted", evt.Severity)
	}
	if len(evt.EvidenceRefs) != 1 || evt.EvidenceRefs[0].Digest != ev.SHA {
		t.Errorf("evidence ref must point at the sealed version: %+v", evt.EvidenceRefs)
	}
	if evt.EvidenceRefs[0].RulesetVersion != RulesetVersion {
		t.Errorf("ruleset version = %q", evt.EvidenceRefs[0].RulesetVersion)
	}
	if evt.Attrs["control_id"] != ControlID || evt.Attrs["category"] != ControlCategory {
		t.Errorf("attrs = %v", evt.Attrs)
	}
	if !strings.Contains(evt.Attrs["control_title"].(string), "+") {
		t.Errorf("the diff summary must ride on the event: %v", evt.Attrs["control_title"])
	}

	// THE contract: serialize the whole event and hunt for configuration.
	raw, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(raw)
	for _, forbidden := range []string{canaryConfigLine, canarySecret, "hostname edge-", "interface Gi0/0", "enable secret"} {
		if strings.Contains(wire, forbidden) {
			t.Fatalf("CONFIG TEXT ON THE BUS: %q in\n%s", forbidden, wire)
		}
	}
}

// TestFindingIsDeterministic: the same verdict re-emitted dedups downstream.
func TestFindingIsDeterministic(t *testing.T) {
	ev := withPrevious(event("acme", "d1", cfgText("b")), cfgText("a"))
	at := time.Date(2026, 8, 25, 11, 0, 0, 0, time.UTC)
	a := Finding(ev, StateChanged, 2, 2, at)
	b := Finding(ev, StateChanged, 2, 2, at)
	if a.ID != b.ID {
		t.Fatalf("finding ids differ: %q vs %q", a.ID, b.ID)
	}
	ea, err := secbus.FromFinding(a)
	if err != nil {
		t.Fatal(err)
	}
	eb, _ := secbus.FromFinding(b)
	if ea.NativeID != eb.NativeID {
		t.Fatalf("native ids differ: %q vs %q", ea.NativeID, eb.NativeID)
	}
	// A DIFFERENT verdict must not collide with it.
	other, _ := secbus.FromFinding(Finding(ev, StateDrifted, 2, 2, at))
	if other.NativeID == ea.NativeID {
		t.Fatal("changed and drifted verdicts collide onto one native id")
	}
	if a.TenantID != "acme" {
		t.Errorf("tenant must be stamped from the device record: %q", a.TenantID)
	}
	// The finding model never serializes the tenant to a client.
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "acme") {
		t.Fatalf("tenant leaked into the finding JSON: %s", raw)
	}
}

// TestEmitFailureFallsToTheSpool then to `lost` — the 189 persist contract.
func TestEmitFailureFallsToTheSpool(t *testing.T) {
	f := newFixture(t, nil)
	f.bus.err = errors.New("bus down")
	ev := withPrevious(event("acme", "d1", cfgText("b")), cfgText("a"))
	f.eval.Observe(context.Background(), ev)

	f.mu.Lock()
	spooled := len(f.spooled)
	f.mu.Unlock()
	if spooled != 1 {
		t.Fatalf("spooled %d records, want 1", spooled)
	}
	snap := f.eval.Metrics().Snapshot()
	if snap["emit_failures_total"] != 1 || snap["spooled_total"] != 1 || snap["lost_total"] != 0 {
		t.Fatalf("metrics = %v", snap)
	}
	// Spool ALSO failing is the only condition that moves `lost`.
	f.spoolErr = errors.New("disk full")
	f.eval.Observe(context.Background(), withPrevious(event("acme", "d1", cfgText("c")), cfgText("a")))
	if got := f.eval.Metrics().Snapshot()["lost_total"]; got != 1 {
		t.Fatalf("lost_total = %d, want 1", got)
	}
}

// TestFailedCaptureFlipsTheBadgeToUnknown: an unreachable device never keeps a
// green badge.
func TestFailedCaptureFlipsTheBadgeToUnknown(t *testing.T) {
	f := newFixture(t, nil)
	base := cfgText("edge-01")
	f.eval.Observe(context.Background(), withPrevious(event("acme", "d1", base), base))
	if st, _, _ := f.store.Get(context.Background(), "acme", false, "d1"); st.State != StateInSync {
		t.Fatalf("precondition: state = %q", st.State)
	}
	f.eval.OnFailure(context.Background(), configstore.CaptureFailure{
		Device: configstore.Device{ID: "d1", TenantID: "acme"}, Tenant: "acme",
		At: f.now, Reason: "connect: connection refused",
	})
	st, ok, err := f.store.Get(context.Background(), "acme", false, "d1")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if st.State != StateUnknown {
		t.Fatalf("state = %q, want unknown", st.State)
	}
	if st.LastError == "" {
		t.Fatal("the failure reason must be carried on the badge")
	}
	// The last known sha survives, so the operator can still diff history.
	if st.LastSHA == "" {
		t.Error("the last known version id must not be cleared by a failed capture")
	}
	if got := f.eval.Metrics().Snapshot()["state_"+StateUnknown]; got != 1 {
		t.Errorf("gauge state_unknown = %d, want 1", got)
	}
	if got := f.eval.Metrics().Snapshot()["state_"+StateInSync]; got != 0 {
		t.Errorf("gauge state_in_sync = %d, want 0 after the transition", got)
	}
}

// TestNewFailsClosedOnIncompleteDeps.
func TestNewFailsClosedOnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("an empty Deps must be refused")
	} else if !strings.Contains(err.Error(), "missing required fields") {
		t.Fatalf("the refusal must name what is missing: %v", err)
	}
}

// TestEmissionIsOptional: with no bus wired the badge still works.
func TestEmissionIsOptional(t *testing.T) {
	f := newFixture(t, func(d *Deps) { d.Publish = nil })
	v := f.eval.Observe(context.Background(), withPrevious(event("acme", "d1", cfgText("b")), cfgText("a")))
	if v.State != StateChanged {
		t.Fatalf("state = %q", v.State)
	}
	if st, ok, _ := f.store.Get(context.Background(), "acme", false, "d1"); !ok || st.State != StateChanged {
		t.Fatal("the badge must still be written with no bus")
	}
}
