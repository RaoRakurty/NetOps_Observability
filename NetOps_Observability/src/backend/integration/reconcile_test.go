package integration

import (
	"testing"
	"time"
)

func stateEv(typ EventType, ext string, seq int64) IntegrationEvent {
	return IntegrationEvent{Type: typ, ExternalState: ext, ExternalSeq: seq, OccurredAt: time.Unix(seq, 0)}
}

func TestReconcile_AppliesMappedState(t *testing.T) {
	m := NewMappingEngine()
	d := m.Reconcile(stateEv(EventResolved, "resolved", 5), StateOpen, Watermark{})
	if !d.Apply || d.Target != StateResolved || d.Reason != "applied" {
		t.Fatalf("expected applied→resolved, got %+v", d)
	}
	if d.Watermark.Seq != 5 {
		t.Fatalf("watermark should advance to 5, got %+v", d.Watermark)
	}
}

func TestReconcile_StaleDropped(t *testing.T) {
	m := NewMappingEngine()
	d := m.Reconcile(stateEv(EventAcknowledged, "in progress", 2), StateOpen, Watermark{Seq: 5})
	if d.Apply || d.Reason != "stale" {
		t.Fatalf("seq<watermark must be dropped as stale, got %+v", d)
	}
}

func TestReconcile_TerminalNmsWins(t *testing.T) {
	m := NewMappingEngine()
	// Incident already resolved in NMS; a NEWER external "in progress" must NOT reopen.
	d := m.Reconcile(stateEv(EventAcknowledged, "in progress", 10), StateResolved, Watermark{Seq: 3})
	if d.Apply || d.Reason != "terminal-nms-wins" {
		t.Fatalf("terminal NMS state must win over non-terminal external, got %+v", d)
	}
	// But a terminal external update on a terminal incident is allowed (closed after resolved).
	d2 := m.Reconcile(stateEv(EventResolved, "closed", 11), StateResolved, Watermark{Seq: 3})
	if !d2.Apply || d2.Target != StateClosed {
		t.Fatalf("terminal→terminal should apply, got %+v", d2)
	}
}

func TestReconcile_AssignmentAndComment_ItsmOwned(t *testing.T) {
	m := NewMappingEngine()
	a := IntegrationEvent{Type: EventAssigned, Assignee: "jane", ExternalSeq: 6}
	d := m.Reconcile(a, StateOpen, Watermark{Seq: 1})
	if !d.Apply || d.Assignee != "jane" || d.Target != "" || d.Reason != "assignment-itsm-wins" {
		t.Fatalf("assignment should apply as ITSM-owned field, got %+v", d)
	}
	c := IntegrationEvent{Type: EventCommentAdded, Comment: "looking into it", ExternalSeq: 7}
	dc := m.Reconcile(c, StateResolved, Watermark{Seq: 1}) // comment on a resolved incident is fine
	if !dc.Apply || dc.Comment == "" || dc.Target != "" {
		t.Fatalf("comment should record without lifecycle change, got %+v", dc)
	}
}

func TestReconcile_Unmapped(t *testing.T) {
	m := NewMappingEngine()
	d := m.Reconcile(stateEv(EventUpdated, "frobnicated", 4), StateOpen, Watermark{})
	if d.Apply || d.Reason != "unmapped-state" {
		t.Fatalf("unknown state should be dropped for DLQ, got %+v", d)
	}
}

// TestReconcile_AdversarialStream is the headline: out-of-order webhooks +
// retries must NOT flap. We replay the canonical bad orderings against a threaded
// watermark and assert the final state is correct and intermediate stales are
// dropped.
func TestReconcile_AdversarialStream(t *testing.T) {
	m := NewMappingEngine()
	cur := StateOpen
	wm := Watermark{}
	apply := func(e IntegrationEvent) string {
		d := m.Reconcile(e, cur, wm)
		if d.Apply {
			if d.Target != "" {
				cur = d.Target
			}
			wm = d.Watermark
		}
		return d.Reason
	}

	// 1) ack(seq1) applied → Acknowledged
	if r := apply(stateEv(EventAcknowledged, "acknowledged", 1)); r != "applied" || cur != StateAcknowledged {
		t.Fatalf("ack should apply, reason=%s cur=%s", r, cur)
	}
	// 2) resolve(seq3) applied → Resolved
	if r := apply(stateEv(EventResolved, "resolved", 3)); r != "applied" || cur != StateResolved {
		t.Fatalf("resolve should apply, reason=%s cur=%s", r, cur)
	}
	// 3) LATE redelivery of ack(seq1) → stale, NO flap back to Acknowledged
	if r := apply(stateEv(EventAcknowledged, "acknowledged", 1)); r != "stale" || cur != StateResolved {
		t.Fatalf("late ack must be stale, reason=%s cur=%s", r, cur)
	}
	// 4) LATE out-of-order "in progress"(seq2) arriving after resolve → stale (seq<wm) AND terminal
	if r := apply(stateEv(EventAcknowledged, "in progress", 2)); cur != StateResolved {
		t.Fatalf("late intermediate must not reopen, reason=%s cur=%s", r, cur)
	}
	// 5) a genuinely newer reopen would be terminal-nms-wins (NMS owns terminal)
	if r := apply(stateEv(EventCreated, "reopened", 9)); r != "terminal-nms-wins" || cur != StateResolved {
		t.Fatalf("external reopen must not override NMS terminal, reason=%s cur=%s", r, cur)
	}
}

func TestMapState_DefaultAndOverride(t *testing.T) {
	m := NewMappingEngine()
	if s, _ := m.MapState("In Progress"); s != StateAcknowledged {
		t.Fatalf("default 'In Progress'→Acknowledged, got %s", s)
	}
	// Per-tenant override: this tenant treats "in progress" as Investigating.
	mo := m.WithStateMap(map[string]InternalState{"in progress": StateInvestigating})
	if s, _ := mo.MapState("in progress"); s != StateInvestigating {
		t.Fatalf("override not applied, got %s", s)
	}
	// Override is a copy — base engine unchanged.
	if s, _ := m.MapState("in progress"); s != StateAcknowledged {
		t.Fatalf("base engine mutated by override, got %s", s)
	}
}

func TestWins_ProviderPrecedence(t *testing.T) {
	m := NewMappingEngine()
	if !m.Wins("servicenow", "jira") {
		t.Fatal("servicenow should win over jira")
	}
	if m.Wins("slack", "servicenow") {
		t.Fatal("slack should not win over servicenow")
	}
	if !m.Wins("jira", "unknownprovider") {
		t.Fatal("known provider should win over unknown")
	}
}
