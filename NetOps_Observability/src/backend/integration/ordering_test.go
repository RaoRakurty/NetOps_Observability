package integration

import (
	"testing"
	"time"
)

func ev(seq int64, secs int, id string) IntegrationEvent {
	return IntegrationEvent{ExternalSeq: seq, OccurredAt: time.Unix(int64(secs), 0).UTC(), ProviderEvtID: id}
}

func TestOrder_BySeqThenTime(t *testing.T) {
	in := []IntegrationEvent{ev(3, 30, "c"), ev(1, 10, "a"), ev(2, 20, "b")}
	got := Order(in)
	want := []int64{1, 2, 3}
	for i, e := range got {
		if e.ExternalSeq != want[i] {
			t.Fatalf("position %d: seq=%d want %d (order=%v)", i, e.ExternalSeq, want[i], seqs(got))
		}
	}
	// Order must not mutate the input.
	if in[0].ExternalSeq != 3 {
		t.Fatalf("Order mutated its input")
	}
}

func TestOrder_ZeroSeqFallsBackToTime(t *testing.T) {
	in := []IntegrationEvent{ev(0, 30, "c"), ev(0, 10, "a"), ev(0, 20, "b")}
	got := Order(in)
	if got[0].OccurredAt.Unix() != 10 || got[2].OccurredAt.Unix() != 30 {
		t.Fatalf("zero-seq events should order by time: %v", times(got))
	}
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

func TestDedup_RawByProviderEvtID(t *testing.T) {
	seen := map[string]bool{}
	in := []IntegrationEvent{ev(1, 1, "x"), ev(2, 2, "y"), ev(1, 1, "x"), ev(3, 3, "")}
	got := Dedup(in, seen)
	if len(got) != 3 {
		t.Fatalf("expected 3 after dedup, got %d (%v)", len(got), ids(got))
	}
	// Empty-id events are passed through (cannot raw-dedup).
	if got[2].ProviderEvtID != "" {
		t.Fatalf("empty-id event should survive: %v", ids(got))
	}
	// A second pass with the same `seen` drops the already-seen ids.
	again := Dedup([]IntegrationEvent{ev(1, 1, "x"), ev(9, 9, "z")}, seen)
	if len(again) != 1 || again[0].ProviderEvtID != "z" {
		t.Fatalf("seen set not honored across calls: %v", ids(again))
	}
}

// helpers
func seqs(e []IntegrationEvent) []int64 {
	out := make([]int64, len(e))
	for i := range e {
		out[i] = e[i].ExternalSeq
	}
	return out
}
func times(e []IntegrationEvent) []int64 {
	out := make([]int64, len(e))
	for i := range e {
		out[i] = e[i].OccurredAt.Unix()
	}
	return out
}
func ids(e []IntegrationEvent) []string {
	out := make([]string, len(e))
	for i := range e {
		out[i] = e[i].ProviderEvtID
	}
	return out
}
