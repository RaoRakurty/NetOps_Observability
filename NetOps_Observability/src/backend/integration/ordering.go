package integration

import (
	"sort"
	"time"
)

// ordering.go — the Event Normalization + Ordering / Causality Layer (§4a).
//
// Webhooks (at-least-once, retried) + polling (catch-up) deliver events for one
// external incident OUT OF ORDER and DUPLICATED. Feeding those straight to the
// reconciler causes resolved-before-acknowledged, reopen/close flapping, and
// broken SLA timers. This layer turns a noisy multi-delivery stream into a
// causally-correct, deduped, monotonic one per (tenant, provider, external_id).
//
// All functions here are PURE (no IO, no clock) so they're exhaustively testable
// with adversarial orderings.

// Watermark is the high-water mark of what has already been applied for one
// external incident (one mapping row's applied_seq/applied_at). An event at or
// below the watermark is stale.
type Watermark struct {
	Seq int64     // last applied ExternalSeq (provider monotonic version)
	At  time.Time // last applied OccurredAt (tie-breaker when Seq is absent/equal)
}

// compareOrder returns -1, 0, or +1 comparing two events' order keys within a
// single (provider, external_id) stream. ExternalSeq is primary because it is
// provider-monotonic and immune to clock drift; OccurredAt breaks ties (and is
// the only signal when a provider supplies no sequence, ExternalSeq == 0).
func compareOrder(aSeq int64, aAt time.Time, bSeq int64, bAt time.Time) int {
	if aSeq != bSeq {
		if aSeq < bSeq {
			return -1
		}
		return 1
	}
	if aAt.Before(bAt) {
		return -1
	}
	if aAt.After(bAt) {
		return 1
	}
	return 0
}

// Order sorts a single external incident's events into causal apply-order
// (oldest first). Stable: equal-key events keep arrival order. Does not mutate
// the input slice.
func Order(events []IntegrationEvent) []IntegrationEvent {
	out := make([]IntegrationEvent, len(events))
	copy(out, events)
	sort.SliceStable(out, func(i, j int) bool {
		return compareOrder(out[i].ExternalSeq, out[i].OccurredAt, out[j].ExternalSeq, out[j].OccurredAt) < 0
	})
	return out
}

// IsStale reports whether an event is at or below the watermark — i.e. already
// applied or superseded by a newer event. Stale events must never be replayed as
// a transition (that is the flapping bug).
func IsStale(ev IntegrationEvent, wm Watermark) bool {
	return compareOrder(ev.ExternalSeq, ev.OccurredAt, wm.Seq, wm.At) <= 0
}

// Advance returns the watermark after applying ev — the max of the current
// watermark and the event's order key.
func Advance(ev IntegrationEvent, wm Watermark) Watermark {
	if compareOrder(ev.ExternalSeq, ev.OccurredAt, wm.Seq, wm.At) > 0 {
		return Watermark{Seq: ev.ExternalSeq, At: ev.OccurredAt}
	}
	return wm
}

// Dedup filters out level-1 raw duplicates (§4d) by ProviderEvtID, preserving
// order. `seen` is the set of already-processed ids (e.g. loaded from
// integration_events); it is updated in place. Events with an empty
// ProviderEvtID are passed through (cannot raw-dedup; logical/business dedup and
// the watermark still apply downstream).
func Dedup(events []IntegrationEvent, seen map[string]bool) []IntegrationEvent {
	out := events[:0:0] // new backing array, preserve nil-vs-empty semantics minimally
	for _, ev := range events {
		if ev.ProviderEvtID != "" {
			if seen[ev.ProviderEvtID] {
				continue
			}
			seen[ev.ProviderEvtID] = true
		}
		out = append(out, ev)
	}
	return out
}
