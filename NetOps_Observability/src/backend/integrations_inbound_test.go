package backend

// integrations_inbound_test.go — F-75.
//
// The inbound ITSM webhook answered `{"received": N}` with a hard-coded 200,
// where N was the number of events PARSED. Every one of them could fail to
// record and the response still said N — and the 200 told ServiceNow/Jira the
// delivery had been accepted, so it never redelivered. A transient database
// error became permanent loss of an inbound ticket-state transition, and the
// count in the response actively asserted otherwise.

import "testing"

func TestInboundReceivedCountsDurableEventsNotParsedOnes(t *testing.T) {
	// 5 parsed, 1 written, 1 already-stored duplicate, 3 failed.
	o := inboundOutcome{Parsed: 5, Recorded: 1, Duplicates: 1, Failed: 3}
	body := o.body()

	if got := body["received"]; got != 2 {
		t.Errorf("received = %v, want 2 (1 new + 1 duplicate); the old code said 5", got)
	}
	if got := body["parsed"]; got != 5 {
		t.Errorf("parsed = %v, want 5", got)
	}
	if got := body["failed"]; got != 3 {
		t.Errorf("failed = %v, want 3", got)
	}
	// The specific lie: received must never simply echo parsed.
	if body["received"] == body["parsed"] {
		t.Error("received must not echo the parsed count when events failed")
	}
}

// The headline defect: a failed write must not be reported as an accepted
// delivery, because the sender's retry is the only recovery mechanism.
func TestInboundFailureAsksTheSenderToRedeliver(t *testing.T) {
	if got := (inboundOutcome{Parsed: 1, Failed: 1}).status(); got != 500 {
		t.Fatalf("total failure = %d, want 500 so the sender retries", got)
	}
	// Partial success is still a failure — the events that landed are deduped
	// on replay, so redelivering all of them is safe and losing one is not.
	if got := (inboundOutcome{Parsed: 3, Recorded: 2, Failed: 1}).status(); got != 500 {
		t.Fatalf("partial failure = %d, want 500", got)
	}
}

func TestInboundSuccessIs200(t *testing.T) {
	o := inboundOutcome{Parsed: 2, Recorded: 2, Queued: 2}
	if got := o.status(); got != 200 {
		t.Fatalf("clean delivery = %d, want 200", got)
	}
	if got := o.body()["received"]; got != 2 {
		t.Errorf("received = %v, want 2", got)
	}
}

// A redelivery of events already stored is a success, not a failure — it is the
// sender doing exactly what the 500 above asked of it.
func TestInboundPureRedeliveryIsAccepted(t *testing.T) {
	o := inboundOutcome{Parsed: 3, Recorded: 0, Duplicates: 3}
	if got := o.status(); got != 200 {
		t.Fatalf("pure redelivery = %d, want 200 (else the sender retries forever)", got)
	}
	if got := o.body()["received"]; got != 3 {
		t.Errorf("received = %v, want 3 — the events are durable, just not new", got)
	}
}

// An empty delivery is vacuously fine and must not 500.
func TestInboundEmptyDeliveryIs200(t *testing.T) {
	if got := (inboundOutcome{}).status(); got != 200 {
		t.Fatalf("empty delivery = %d, want 200", got)
	}
}
