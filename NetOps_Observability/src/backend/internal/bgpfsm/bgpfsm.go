// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package bgpfsm names what a BGP session transition MEANS — the one classifier
// every lane that reports a BGP state change shares (tracker 387).
//
// Owner rule (2026-11-10): only an ESTABLISHED session going down is a session
// failure. A move below established (idle <-> active, an OPEN that fails) is a
// neighbour that cannot connect: degraded, never a fault.
//
// Two lanes read it today: the SNMP trap receiver (collectors/trap_bgp.go) and
// the controller connectors (nms/vmanage_events.go). The correlation engine reads
// the same vocabulary (src/correlation/producers.py BGP_TRANSITION_CLASSES), and
// all three are pinned to collectors/testdata/bgp_transition_classes.json, so the
// table cannot drift between languages or lanes.
//
// Pure: no IO, no state.
package bgpfsm

import "strings"

// Transition classes — the closed set.
const (
	SessionLost      = "session_lost"      // established → anything lower: a fault
	SessionUp        = "session_up"        // anything → established
	NeverEstablished = "never_established" // moves below established that never reached it
	Progressing      = "progressing"       // a forward move into opensent/openconfirm
	Unknown          = "unknown"           // the prior state is not evidenced
)

// established is the rank of the one state a session failure starts from.
const established = 6

// Rank is the RFC 4271 §8.2.2 FSM order of a state label (idle 1 … established
// 6), case-insensitive. ok is false for anything else, including a vendor's
// extra words (VIPTELA's clearing/deleted).
func Rank(state string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "idle":
		return 1, true
	case "connect":
		return 2, true
	case "active":
		return 3, true
	case "opensent":
		return 4, true
	case "openconfirm":
		return 5, true
	case "established":
		return established, true
	}
	return 0, false
}

// Classify names a move between two state labels. prev "" means the prior state
// is not evidenced: only a move INTO established can be named then. "" when the
// new state is not an FSM state.
func Classify(prev, state string) string {
	to, okTo := Rank(state)
	if !okTo {
		return ""
	}
	from, okFrom := Rank(prev)
	switch {
	case to == established && from == established:
		return Unknown // not a transition; nothing to name
	case to == established:
		return SessionUp
	case !okFrom:
		return Unknown
	case from == established:
		return SessionLost // to < established here
	case to > from && to >= 4:
		return Progressing
	default:
		return NeverEstablished
	}
}

// NotASessionFailure reports the classes a BGP "down" may NOT be built from: the
// session was never established, so nothing was lost.
func NotASessionFailure(class string) bool {
	return class == NeverEstablished || class == Progressing
}
