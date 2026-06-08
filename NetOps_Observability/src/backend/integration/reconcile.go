package integration

import "strings"

// reconcile.go — the State Reconciler (Layer 5, §4b/§4c). PURE: given an already
// ordered + deduped event, the current internal state, and the watermark, decide
// what (if anything) to apply. Decisions are table-driven and deterministic, so
// the priority ladder is exhaustively unit-testable with adversarial pairs.

// Decision is the reconciler's verdict for one event.
type Decision struct {
	Apply     bool          // whether to act on the incident at all
	Target    InternalState // lifecycle target ("" = no state change, e.g. assignment/comment)
	Assignee  string        // set when the event reassigns ownership
	Comment   string        // set when the event adds a comment
	Reason    string        // machine-readable why (audit/metrics): applied|stale|terminal-nms-wins|unmapped-state|assignment-itsm-wins|comment-recorded
	Watermark Watermark     // the watermark to persist when Apply is true (unchanged otherwise)
}

// MappingEngine reconciles external state into internal lifecycle, applying the
// per-tenant state map (§4b) and the conflict ladder (§4c). Zero value is unusable;
// use NewMappingEngine.
type MappingEngine struct {
	stateMap   map[string]InternalState // normalized external state -> internal
	precedence map[string]int           // provider -> rank (lower wins cross-provider ties)
}

// defaultStateMap is the shipped external→internal mapping. Providers normalize
// their native/raw state into these lowercase tokens in Normalize().
func defaultStateMap() map[string]InternalState {
	return map[string]InternalState{
		"new":           StateOpen,
		"open":          StateOpen,
		"triggered":     StateOpen,
		"reopened":      StateOpen,
		"acknowledged":  StateAcknowledged,
		"ack":           StateAcknowledged,
		"in progress":   StateAcknowledged,
		"in-progress":   StateAcknowledged,
		"investigating": StateInvestigating,
		"on hold":       StateInvestigating,
		"resolved":      StateResolved,
		"done":          StateResolved,
		"closed":        StateClosed,
		"cancelled":     StateClosed,
		// "escalated" intentionally maps to Open (severity bump is a separate concern).
		"escalated": StateOpen,
	}
}

// defaultPrecedence ranks providers for cross-provider tie-breaks (§4c rule 4).
func defaultPrecedence() map[string]int {
	return map[string]int{"servicenow": 0, "jira": 1, "pagerduty": 2, "slack": 3}
}

// NewMappingEngine returns an engine with the shipped defaults. Pass overrides to
// customize per tenant (a nil override keeps the default).
func NewMappingEngine() *MappingEngine {
	return &MappingEngine{stateMap: defaultStateMap(), precedence: defaultPrecedence()}
}

// WithStateMap returns a copy whose state map is overlaid with the given
// per-tenant overrides (keys normalized). Caller-supplied wins.
func (m *MappingEngine) WithStateMap(overrides map[string]InternalState) *MappingEngine {
	merged := make(map[string]InternalState, len(m.stateMap)+len(overrides))
	for k, v := range m.stateMap {
		merged[k] = v
	}
	for k, v := range overrides {
		merged[normState(k)] = v
	}
	return &MappingEngine{stateMap: merged, precedence: m.precedence}
}

func normState(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// MapState resolves a raw external state to an internal state.
func (m *MappingEngine) MapState(external string) (InternalState, bool) {
	s, ok := m.stateMap[normState(external)]
	return s, ok
}

// Wins reports whether provider a beats provider b in a cross-provider tie
// (lower rank wins; an unknown provider ranks last).
func (m *MappingEngine) Wins(a, b string) bool {
	ra, oka := m.precedence[a]
	rb, okb := m.precedence[b]
	if !oka {
		ra = 1 << 30
	}
	if !okb {
		rb = 1 << 30
	}
	return ra < rb
}

// Reconcile applies the conflict ladder (§4c) to a single ordered, deduped event.
//
//  0. stale (≤ watermark, §4a)            → drop, no replay  (stops flapping)
//  1. assignment / comment (ITSM-owned)   → apply field, no lifecycle change
//  2. terminal already (NMS owns terminal)→ a non-terminal external update never reopens
//  3. mapped state                        → apply the transition
//     unmapped                            → drop (caller DLQs for operator review)
func (m *MappingEngine) Reconcile(ev IntegrationEvent, current InternalState, wm Watermark) Decision {
	// §4a — never replay a stale/superseded event.
	if IsStale(ev, wm) {
		return Decision{Apply: false, Reason: "stale", Watermark: wm}
	}
	adv := Advance(ev, wm)

	switch ev.Type {
	case EventAssigned:
		// §4c rule 2 — ownership is authoritative from ITSM; no lifecycle change.
		return Decision{Apply: true, Assignee: ev.Assignee, Reason: "assignment-itsm-wins", Watermark: adv}
	case EventCommentAdded:
		return Decision{Apply: true, Comment: ev.Comment, Reason: "comment-recorded", Watermark: adv}
	}

	target, ok := m.MapState(ev.ExternalState)
	if !ok {
		if ts, okt := eventTypeToState(ev.Type); okt {
			target, ok = ts, true
		}
	}
	if !ok {
		return Decision{Apply: false, Reason: "unmapped-state", Watermark: wm}
	}

	// §4c rule 1 — terminal states are NMS-owned; a non-terminal external update
	// does not reopen an incident NMS has already resolved/closed.
	if current.IsTerminal() && !target.IsTerminal() {
		return Decision{Apply: false, Reason: "terminal-nms-wins", Watermark: wm}
	}

	return Decision{Apply: true, Target: target, Reason: "applied", Watermark: adv}
}

// eventTypeToState is the fallback mapping when an event carries no usable
// external state string but its type implies one.
func eventTypeToState(t EventType) (InternalState, bool) {
	switch t {
	case EventResolved:
		return StateResolved, true
	case EventAcknowledged:
		return StateAcknowledged, true
	case EventCreated:
		return StateOpen, true
	default:
		return "", false
	}
}
