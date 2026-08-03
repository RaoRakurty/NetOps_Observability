package integration

import (
	"testing"
	"time"
)

func ev(seq int64, secs int, id string) IntegrationEvent {
	return IntegrationEvent{ExternalSeq: seq, OccurredAt: time.Unix(int64(secs), 0).UTC(), ProviderEvtID: id}
}

func TestIsStaleAndAdvance(t *testing.T) {
	wm := Watermark{}
	a := ev(5, 50, "a")
	if IsStale(a, wm) {
		t.Fatal("first event must not be stale against zero watermark")
	}
	wm = Advance(a, wm)
	if wm.Seq != 5 {
		t.Fatalf("watermark not advanced: %+v", wm)
	}
	// A re-delivered older event is stale and must not advance the watermark.
	old := ev(3, 30, "b")
	if !IsStale(old, wm) {
		t.Fatal("seq<watermark event should be stale")
	}
	if Advance(old, wm).Seq != 5 {
		t.Fatal("stale event must not move the watermark backwards")
	}
	// Equal key is stale (already applied) — stops exact re-application.
	if !IsStale(a, wm) {
		t.Fatal("equal-key event should be stale")
	}
}
