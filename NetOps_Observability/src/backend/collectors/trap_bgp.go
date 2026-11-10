// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"strconv"
	"strings"
)

// trap_bgp.go — what a BGP session transition MEANS (tracker 387, trap semantics).
//
// Every vendor's BGP MIB reports the RFC 4271 §8.2.2 finite-state machine: idle,
// connect, active, opensent, openconfirm, established. A trap names the state the
// session moved to and, in most families, the one it left. Which family it is
// does not matter here: the packs map each vendor's objects onto bgp_state and
// bgp_prev_state, by OID, and this file reads only those.
//
// Owner rule (2026-11-10): only an established session going down is a fault. A
// session that oscillates below established (idle <-> active) never carried a
// route: it is a neighbour that cannot connect, or is not configured on the peer.
// That is a degraded condition, NOT a session failure, and nothing here may call
// it one. Event severity, operational state and impact are separate fields; the
// incident priority stays the correlation engine's (D3, "ingestion is not
// incident creation").

// The RFC 4271 states, in FSM order, by their MIB label (every vendor's enum uses
// these words; the numbers differ, e.g. VIPTELA-TRAPS counts from 0, so a state is
// always read by its label).
var bgpStateRank = map[string]int{
	"idle": 1, "connect": 2, "active": 3, "opensent": 4, "openconfirm": 5, "established": 6,
}

// bgpStateTitle is how an operator writes each state.
var bgpStateTitle = map[string]string{
	"idle": "Idle", "connect": "Connect", "active": "Active",
	"opensent": "OpenSent", "openconfirm": "OpenConfirm", "established": "Established",
}

// Transition classes, the closed set of TrapEvent.BGPTransition. The engine reads
// the same vocabulary (producers.BGP_TRANSITION_CLASSES), and both sides pin it to
// testdata/bgp_transition_classes.json.
const (
	bgpSessionLost       = "session_lost"      // established → anything lower: a fault
	bgpSessionUp         = "session_up"        // anything → established
	bgpNeverEstablished  = "never_established" // moves below established that never reached it
	bgpProgressing       = "progressing"       // a forward move into opensent/openconfirm
	bgpTransitionUnknown = "unknown"           // the prior state is not evidenced
)

// Bases for TrapEvent.BGPPrevStateBasis: where the prior state came from.
const (
	bgpPrevFromTrap        = "trap"             // the trap's own varbind
	bgpPrevFromTransition  = "transition_group" // another report of the same transition
	bgpPrevFromPeerHistory = "peer_history"     // the state this peer's last transition reached
)

// normalizeBGPState reads a state value (an enum label, or a bare RFC number when
// the agent's MIB is not indexed) into its label. "" for anything else, including
// a vendor's extra words (VIPTELA's clearing/deleted) and CISCO's none(0).
func normalizeBGPState(label, raw string) string {
	l := strings.ToLower(strings.TrimSpace(label))
	if _, ok := bgpStateRank[l]; ok {
		return l
	}
	if l != "" {
		return ""
	}
	// No label: only the RFC numbering (BGP4-MIB's enum, which every 1-based MIB
	// shares) can be read, never a vendor's own offset.
	r := strings.TrimSpace(raw)
	if i := strings.IndexByte(r, '('); i >= 0 && strings.HasSuffix(r, ")") {
		r = r[i+1 : len(r)-1]
	}
	for name, rank := range bgpStateRank {
		if r == strconv.Itoa(rank) {
			return name
		}
	}
	return ""
}

// classifyBGPTransition names a move between two states. prev "" means the prior
// state is not evidenced: only a move INTO established can be named then.
func classifyBGPTransition(prev, state string) string {
	to, okTo := bgpStateRank[state]
	if !okTo {
		return ""
	}
	from, okFrom := bgpStateRank[prev]
	switch {
	case to == 6 && from == 6:
		return bgpTransitionUnknown // not a transition; nothing to name
	case to == 6:
		return bgpSessionUp
	case !okFrom:
		return bgpTransitionUnknown
	case from == 6:
		return bgpSessionLost // to < 6 here
	case to > from && to >= 4:
		return bgpProgressing
	default:
		return bgpNeverEstablished
	}
}

// bgpTransitionMeaning is the separate event severity, operational state and
// impact of each class. Severity uses the syslog words the rest of the platform
// already shows. Impact is about THIS transition: a session that never came up
// withdrew no route, so it is degraded, not service-affecting.
type bgpMeaning struct {
	severity, opState, impact, text string
}

var bgpTransitionMeaning = map[string]bgpMeaning{
	bgpSessionLost:       {"err", "down", "service_affecting", "session lost"},
	bgpSessionUp:         {"info", "up", "none", "session up"},
	bgpNeverEstablished:  {"warning", "degraded", "degraded", "never established"},
	bgpProgressing:       {"notice", "transitional", "none", "progressing"},
	bgpTransitionUnknown: {"", "unknown", "unknown", ""},
}

// RFC 4271 §4.5 NOTIFICATION error codes and subcodes, with the RFCs that added
// to them (5492, 4486/8538/9384 Cease, 6608 FSM, 7313 ROUTE-REFRESH, 9234 Role).
// Standards tables, not a vendor's: every BGP speaker sends these numbers.
var bgpErrorCodes = map[int]string{
	1: "Message Header Error", 2: "OPEN Message Error", 3: "UPDATE Message Error",
	4: "Hold Timer Expired", 5: "Finite State Machine Error", 6: "Cease",
	7: "ROUTE-REFRESH Message Error",
}

var bgpErrorSubcodes = map[int]map[int]string{
	1: {1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"},
	2: {1: "Unsupported Version Number", 2: "Bad Peer AS", 3: "Bad BGP Identifier",
		4: "Unsupported Optional Parameter", 5: "Authentication Failure (deprecated)",
		6: "Unacceptable Hold Time", 7: "Unsupported Capability", 11: "Role Mismatch"},
	3: {1: "Malformed Attribute List", 2: "Unrecognized Well-known Attribute",
		3: "Missing Well-known Attribute", 4: "Attribute Flags Error", 5: "Attribute Length Error",
		6: "Invalid ORIGIN Attribute", 7: "AS Routing Loop (deprecated)", 8: "Invalid NEXT_HOP Attribute",
		9: "Optional Attribute Error", 10: "Invalid Network Field", 11: "Malformed AS_PATH"},
	5: {1: "Unexpected Message in OpenSent State", 2: "Unexpected Message in OpenConfirm State",
		3: "Unexpected Message in Established State"},
	6: {1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown", 3: "Peer De-configured",
		4: "Administrative Reset", 5: "Connection Rejected", 6: "Other Configuration Change",
		7: "Connection Collision Resolution", 8: "Out of Resources", 9: "Hard Reset", 10: "BFD Down"},
	7: {1: "Invalid Message Length"},
}

// parseBGPLastError reads a two-octet LastError (BGP4-MIB bgpPeerLastError and
// every copy of it: code then subcode) as the receiver renders it. ok=false for
// anything that is not exactly two octets. 0/0 means no error was ever sent.
func parseBGPLastError(raw string) (code, subcode int, ok bool) {
	r := strings.TrimSpace(raw)
	if !strings.HasPrefix(r, "0x") || len(r) != 6 {
		return 0, 0, false
	}
	v, err := strconv.ParseUint(r[2:], 16, 16)
	if err != nil {
		return 0, 0, false
	}
	return int(v >> 8), int(v & 0xff), true
}

// bgpErrorName renders a code/subcode as "Cease / Administrative Shutdown", or
// with the numbers when the table does not know them. "" for no error.
func bgpErrorName(code, subcode int) string {
	if code == 0 {
		return ""
	}
	name, ok := bgpErrorCodes[code]
	if !ok {
		name = "error code " + strconv.Itoa(code)
	}
	if subcode == 0 {
		return name
	}
	if s, ok := bgpErrorSubcodes[code][subcode]; ok {
		return name + " / " + s
	}
	return name + " / subcode " + strconv.Itoa(subcode)
}
