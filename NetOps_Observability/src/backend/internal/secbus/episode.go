// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secbus

// episode.go — the wire half of owner decision D2 (2026-11-11): the security
// lane tells the correlation engine about a standing finding only when it
// APPEARS, CHANGES or CLEARS, each stamped with the instant the current open
// episode was first seen. The per-scan history still reaches the findings store,
// on a topic the engine does not read.
//
// TWO TOPICS, TWO READERS
//
//	netops.security        the engine's evidence lane AND the router's findings
//	                       lane. Carries TRANSITIONS only (appear / change /
//	                       clear), plus whatever other producers (config drift)
//	                       already put there.
//	netops.security.audit  the router's findings lane ONLY. Carries the verdicts
//	                       that did not move this scan (`transition=unchanged`),
//	                       so every scan's verdicts are still indexed exactly as
//	                       before — the audit trail and the UI's security pages
//	                       read the index, never the bus.
//
// Before D2 every pass re-published every standing finding onto netops.security,
// and because the engine's signal_id is uuid5(source|native_id|ts) with ts the
// verdict instant, each pass minted a brand-new point signal for an unchanged
// finding: on the lab ~21,000 security signals a day across 16 devices, handing
// any device fault a "fresh" co-occurring security event inside the correlation
// window. The signal_id rule is unchanged: with no re-emission, the ts makes each
// real transition unique and a re-delivery of the same transition idempotent.
//
// The attrs below ride the engine's generic evidence pass-through
// (signals.evidence_signal_from_event copies wire attrs onto Signal.attrs), so
// `first_seen` reaches the engine with no engine-side change.

import (
	"strings"
	"time"
)

// TopicSecurityAudit is the router-only topic carrying the verdicts a scan
// re-confirmed without change. The correlation engine never subscribes to it
// (signals.EVIDENCE_CLASSES names netops.security only); the router indexes it
// into the same netops-secfindings-<seg>-* store as netops.security. kafka-init
// pre-creates it and the router holds Read on it (apply-acls.sh); producing
// rides the aggregator's prefixed netops.* bus-bridge grant.
const TopicSecurityAudit = "netops.security.audit"

// Transition values carried in attrs.transition.
const (
	TransitionAppear    = "appear"    // a new open episode
	TransitionChange    = "change"    // a material field moved inside an open episode
	TransitionClear     = "clear"     // an open finding is no longer reported
	TransitionUnchanged = "unchanged" // re-confirmed; audit topic only, never the engine
	// TransitionUnclassified marks a verdict stored while the lane's episode
	// state was unreadable: it went to the audit topic only, so it is NOT
	// evidence that the engine knows the finding (a later seed skips it).
	TransitionUnclassified = "unclassified"
)

// First-seen basis values carried in attrs.first_seen_basis.
const (
	// BasisObserved: this lane saw the episode open, so first_seen is the verdict
	// instant of the scan that opened it.
	BasisObserved = "observed"
	// BasisSeed: the episode was already open when change tracking started (an
	// upgrade, or lost state re-seeded from the findings index). first_seen is
	// the earliest RETAINED verdict for the identity, so it can predate the
	// current episode if the finding cleared and re-opened inside retention.
	BasisSeed = "seed"
)

// Attribute keys the episode stamp writes.
const (
	AttrTransition     = "transition"
	AttrFirstSeen      = "first_seen"
	AttrFirstSeenBasis = "first_seen_basis"
)

// ClearSuffix is the engine's recovery-kind convention (`<kind>_clear`, the
// controller and device lanes' recoveries). build_nodes skips every *_clear
// kind, so a clear closes and never becomes fault evidence.
const ClearSuffix = "_clear"

// ClearKind returns the recovery kind for a security lane kind.
//
// ENGINE REGISTRATION REQUIRED before these are emitted: the engine's evidence
// intake dispatches on signals.EVIDENCE_CLASS_BY_KIND, and the security class
// registers only the three onset kinds, so a `security_*_clear` record is
// dead-lettered (and moves corr_deadletters, which CorrDeadLettersRising alerts
// on). The lane therefore withholds clears unless the integrator turns them on.
func ClearKind(kind string) string { return kind + ClearSuffix }

// IsClearKind reports whether kind is a recovery kind.
func IsClearKind(kind string) bool { return strings.HasSuffix(kind, ClearSuffix) }

// StampEpisode writes the episode attrs onto an event. It never touches ts,
// native_id or the verdict fields: the event stays the same verdict it was, now
// annotated with where it sits in its episode.
func StampEpisode(ev *EvidenceEvent, transition string, firstSeen time.Time, basis string) {
	if ev.Attrs == nil {
		ev.Attrs = map[string]any{}
	}
	ev.Attrs[AttrTransition] = transition
	if !firstSeen.IsZero() {
		ev.Attrs[AttrFirstSeen] = firstSeen.UTC().Format(time.RFC3339Nano)
	}
	if basis != "" {
		ev.Attrs[AttrFirstSeenBasis] = basis
	}
}

// ClearSubject is what a clear event is built from: the identity and the
// classification of the finding that stopped being reported. The finding itself
// is absent from the clearing scan, so the lane keeps this snapshot per open
// episode.
type ClearSubject struct {
	TenantID       string
	Kind           string // the ONSET kind (security_posture|_exposure|_signal)
	NativeID       string
	EntityID       string
	EntityType     string
	EntityTokens   []string
	EvidenceClass  string
	ControlID      string
	RawRuleID      string
	ProviderSource string
	Category       string
	SeamID         string
	SeamType       string
}

// ClearEvent builds the recovery event for an episode that closed at `at`, in
// the scan `scanID`. The native_id is the finding's own, so the engine can pair
// the clear with its onset on the same identity and entity; severity is info,
// the convention every recovery uses. No verdict (status) is carried — the
// finding was not reported, so there is no verdict to state.
func ClearEvent(s ClearSubject, at time.Time, scanID string, firstSeen time.Time, basis string) EvidenceEvent {
	attrs := map[string]any{"evidence_class": s.EvidenceClass}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			attrs[k] = v
		}
	}
	put("provider_source", s.ProviderSource)
	put("control_id", s.ControlID)
	put("raw_rule_id", s.RawRuleID)
	put("category", s.Category)
	put("scan_id", scanID)
	put("seam_id", s.SeamID)
	put("seam_type", s.SeamType)
	entityType := s.EntityType
	if entityType == "" {
		entityType = EntityTypeDevice
	}
	ev := EvidenceEvent{
		SchemaVersion: SchemaVersion,
		TenantID:      s.TenantID,
		TS:            at.UTC().Format(time.RFC3339Nano),
		Kind:          ClearKind(s.Kind),
		EntityID:      s.EntityID,
		EntityType:    entityType,
		EntityTokens:  append([]string(nil), s.EntityTokens...),
		Severity:      "info",
		NativeID:      s.NativeID,
		SeamID:        s.SeamID,
		SeamType:      s.SeamType,
		Attrs:         attrs,
	}
	StampEpisode(&ev, TransitionClear, firstSeen, basis)
	return ev
}
