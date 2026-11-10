// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// trap_transitions.go — the receiver's per-entity memory (tracker 387, trap
// semantics): one BGP transition however many notifications report it, and an
// alarm's lifecycle across traps.
//
// TRANSITIONS. IOS-XE with every BGP family enabled sends SIX notifications for
// one transition (RFC 4273 bgpBackwardTransition, cbgp*, cbgpPeer2*; recorded on
// the lab: ~720/h for ~90 transitions/h), within about three seconds and with the
// same sysUpTime to the tick. Each is stored (D2/D5: never drop evidence). Every
// report of one transition carries the same transition_id, its position
// (transition_seq), the running occurrence_count and first/last seen, and the
// first is the representative. The final count is a read-time aggregate over
// transition_id, as D2 decided for repeats: nothing stored is rewritten.
//
// The memory also keeps what each peer's last transition reached. That is how a
// report that names no prior state (bgpBackwardTransition carries only the new
// one) is still classified: the prior state is the one the peer was last seen
// in, stated as bgp.prev_state_basis=peer_history, never presented as the trap's.
//
// LIFECYCLE. raise / escalate / downgrade / clear / repeat, against the previous
// trap with the same correlation key. A lower severity is a downgrade, never a
// recovery: recovery_verified is only set by a vendor clear (or a reported value
// back under the reported threshold).
//
// §3a: every key starts with the ATTRIBUTED device id (an inventory id, tenant-
// scoped). A trap no rung could attribute is never keyed, grouped or remembered:
// an address is not an identity, and two tenants can share one.
//
// Bounded (LRU) and process-local: after a restart the first report has no
// memory, which the basis fields say (prev_state stays unknown; lifecycle_basis
// "unknown").

const (
	transitionWindow     = 5 * time.Second // every family's report arrived within ~3 s
	transitionUptimeSkew = 300             // ticks (3 s): a different sysUpTime is a different event
	peerHistoryHorizon   = 10 * time.Minute
	transitionMaxPeers   = 16384
	lifecycleMaxKeys     = 16384
)

// Lifecycle states and bases, the closed sets of TrapEvent.LifecycleState/Basis.
const (
	lifecycleRaise     = "raise"
	lifecycleEscalate  = "escalate"
	lifecycleDowngrade = "downgrade"
	lifecycleClear     = "clear"
	lifecycleRepeat    = "repeat"

	lifecycleFromMemory = "receiver_memory"
	lifecycleUnknown    = "unknown"     // no earlier trap for this key in memory
	lifecycleLate       = "late_report" // older by device clock than the one remembered
)

// trapTransitions is the receiver's per-entity memory. Safe for concurrent use.
type trapTransitions struct {
	mu        sync.Mutex
	peers     *lruMap[*peerMemory]
	lifecycle *lruMap[lifecycleMemory]
}

type peerMemory struct {
	// The open group.
	id        string
	state     string
	prev      string
	prevBasis string
	first     time.Time
	last      time.Time
	count     int
	uptime    float64
	// What the peer's previous group reached, and when.
	lastState string
	lastSeen  time.Time
}

type lifecycleMemory struct {
	raised     bool
	sevRank    int
	deviceTime time.Time // zero when the device stated no time
}

func newTrapTransitions(maxPeers int) *trapTransitions {
	if maxPeers <= 0 {
		maxPeers = transitionMaxPeers
	}
	return &trapTransitions{peers: newLRUMap[*peerMemory](maxPeers), lifecycle: newLRUMap[lifecycleMemory](lifecycleMaxKeys)}
}

// correlationKey is `<family>:<device>:<entity>`, or "" when the trap cannot be
// keyed (no attributed device, or no family). The entity is the BGP session
// (`<vrf or ->/<afi>/<peer>`), the interface, or `device`.
func correlationKey(ev *TrapEvent) string {
	if ev.Device == "" || ev.Family == "" {
		return ""
	}
	entity := "device"
	switch {
	case ev.BGP != nil && ev.BGP.PeerAddress != "":
		vrf := ev.BGP.VRF
		if vrf == "" {
			vrf = "-"
		}
		entity = vrf + "/" + ev.BGP.PeerAFI + "/" + ev.BGP.PeerAddress
	case ev.BGP != nil:
		return "" // a BGP event whose peer did not decode names no session
	case ev.Interface != "":
		entity = "if/" + ev.Interface
	}
	return ev.Family + ":" + ev.Device + ":" + entity
}

// observeTransition groups one BGP report, fills a missing prior state from the
// group or the peer's history, and stamps the group fields. now = receive time.
func (t *trapTransitions) observeTransition(ev *TrapEvent, now time.Time) {
	b := ev.BGP
	if b == nil || b.State == "" || ev.CorrelationKey == "" {
		return
	}
	key := ev.CorrelationKey
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.peers.get(key)
	if !ok {
		m = &peerMemory{}
		t.peers.put(key, m)
	}
	if !m.sameTransition(ev, now) {
		if m.id != "" {
			m.lastState, m.lastSeen = m.state, m.last
		}
		m.id = transitionID(key, b.State, now)
		m.state, m.prev, m.prevBasis = b.State, "", ""
		m.first, m.count, m.uptime = now, 0, ev.UptimeSeconds
		// What the peer reached last time is the state this move left, if it
		// is recent and is not the state it moved to (that would be no move).
		if m.lastState != "" && m.lastState != b.State && now.Sub(m.lastSeen) <= peerHistoryHorizon {
			m.prev, m.prevBasis = m.lastState, bgpPrevFromPeerHistory
		}
	}
	m.count++
	m.last = now
	if b.PrevState != "" && b.PrevStateBasis == bgpPrevFromTrap {
		// The trap's own word beats an inference, and later reports inherit it.
		m.prev, m.prevBasis = b.PrevState, bgpPrevFromTransition
	} else if m.prev != "" {
		b.PrevState, b.PrevStateBasis = m.prev, m.prevBasis
	}
	ev.TransitionID = m.id
	ev.TransitionSeq = m.count
	ev.OccurrenceCount = m.count
	ev.TransitionRepresentative = m.count == 1
	ev.FirstSeen = m.first.UTC().Format(time.RFC3339Nano)
	ev.LastSeen = now.UTC().Format(time.RFC3339Nano)
}

// sameTransition: the open group is this report's transition.
func (m *peerMemory) sameTransition(ev *TrapEvent, now time.Time) bool {
	b := ev.BGP
	if m.id == "" || m.state != b.State || now.Sub(m.first) > transitionWindow || now.Before(m.first.Add(-transitionWindow)) {
		return false
	}
	if m.uptime > 0 && ev.UptimeSeconds > 0 {
		d := (m.uptime - ev.UptimeSeconds) * 100
		if d > transitionUptimeSkew || d < -transitionUptimeSkew {
			return false
		}
	}
	// A report whose own prior state contradicts the group's evidenced one is a
	// different move to the same state.
	if b.PrevStateBasis == bgpPrevFromTrap && m.prevBasis == bgpPrevFromTransition && m.prev != b.PrevState {
		return false
	}
	return true
}

// transitionID is stable for one group: the key, the state moved to and the
// first report's receive time.
func transitionID(key, state string, first time.Time) string {
	h := sha256.Sum256([]byte(key + "|" + state + "|" + first.UTC().Format(time.RFC3339Nano)))
	return "tr-" + hex.EncodeToString(h[:8])
}

// severityRank orders the normalized severities (higher = worse).
var severityRank = map[string]int{
	"debug": 0, "info": 1, "informational": 1, "notice": 2, "warning": 3, "warn": 3,
	"err": 4, "error": 4, "crit": 5, "critical": 5, "alert": 6, "emerg": 7,
}

// lifecycleInput is what a trap says about its alarm: raised or cleared, at
// which severity. ok=false: the trap states no lifecycle (a point event).
func lifecycleInput(ev *TrapEvent) (raised bool, sev int, ok bool) {
	if ev.BGP != nil {
		switch ev.BGP.TransitionClass {
		case bgpSessionLost, bgpNeverEstablished:
			return true, severityRank[ev.EventSeverity], true
		case bgpSessionUp:
			return false, severityRank[ev.EventSeverity], true
		}
		return false, 0, false
	}
	switch ev.EventState {
	case trapStateRaise:
		return true, severityRank[ev.Severity], true
	case trapStateClear:
		return false, severityRank[ev.Severity], true
	}
	return false, 0, false
}

// observeLifecycle names the trap's place in its alarm's lifecycle. A trap with
// no key (unattributed) still says raise or clear, with basis unknown.
func (t *trapTransitions) observeLifecycle(ev *TrapEvent) {
	raised, sev, ok := lifecycleInput(ev)
	if !ok {
		return
	}
	if !raised {
		ev.RecoveryVerified = true // a vendor clear, or a BGP session back up
	}
	var devTime time.Time
	if ev.DeviceEventTime != "" {
		if dt, err := time.Parse(time.RFC3339Nano, ev.DeviceEventTime); err == nil {
			devTime = dt
		}
	}
	ev.LifecycleState, ev.LifecycleBasis = lifecycleRaise, lifecycleUnknown
	if !raised {
		ev.LifecycleState = lifecycleClear
	}
	if ev.CorrelationKey == "" || t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, seen := t.lifecycle.get(ev.CorrelationKey)
	late := seen && !devTime.IsZero() && !prev.deviceTime.IsZero() && devTime.Before(prev.deviceTime)
	if seen {
		ev.LifecycleBasis = lifecycleFromMemory
		if late {
			ev.LifecycleBasis = lifecycleLate
		}
		switch {
		case !raised && !prev.raised:
			ev.LifecycleState = lifecycleRepeat
		case !raised:
			ev.LifecycleState = lifecycleClear
		case !prev.raised:
			ev.LifecycleState = lifecycleRaise
		case sev > prev.sevRank:
			ev.LifecycleState = lifecycleEscalate
		case sev < prev.sevRank:
			ev.LifecycleState = lifecycleDowngrade
		default:
			ev.LifecycleState = lifecycleRepeat
		}
	}
	if late {
		return // a late report never rewinds what the newer one established
	}
	t.lifecycle.put(ev.CorrelationKey, lifecycleMemory{raised: raised, sevRank: sev, deviceTime: devTime})
}

// Len is the number of peers remembered (tests, bounds).
func (t *trapTransitions) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peers.len()
}
