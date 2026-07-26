package nms

import "time"

// capability.go — the per-connector capability + fidelity declaration
// (tracker #128 Phase 2, design docs/Wireslessdesign.md §13).
//
// `Streams []string` says what a connector can POLL; it says nothing about
// what the vendor can actually REPORT, at what granularity, or how proven the
// mapping is. Without that declaration the platform cannot distinguish "this
// vendor cannot report X" from "X is healthy" — and the wireless spec forbids
// treating an unsupported capability as a healthy one. A capability at
// FidelityNone must render as an explicit "not observable here", never a
// green tile.
//
// Fidelity is the project's existing evidence ladder
// (docs/design/multi-vendor-wifi-expansion.md §0) made machine-readable:
//
//	none           the vendor cannot report it — an honest hole, not a gap
//	doc_claimed    authored from vendor docs (YANG/MIB/API refs cited in the
//	               connector); unproven against a live system
//	lab_validated  a captured/synthetic fixture replays through the
//	               transformer to the right canonical output
//	live_validated confirmed flowing end-to-end from a real system
//
// The ladder is EARNED upward, never assumed: a new connector ships
// doc_claimed at best, and nothing may claim live_validated without the
// system it names (report §26: "fidelity is answered by hardware, not by
// more design").

// Capability names one thing a connector might be able to observe or do.
// Wireless capabilities are namespaced "wireless."; other domains add their
// own namespace rather than growing a parallel type.
type Capability string

const (
	CapAPInventory        Capability = "wireless.ap_inventory"
	CapRadioState         Capability = "wireless.radio_state"
	CapRFMetrics          Capability = "wireless.rf_metrics"
	CapChannelUtil        Capability = "wireless.channel_utilization"
	CapClientSessions     Capability = "wireless.client_sessions"
	CapClientRFMetrics    Capability = "wireless.client_rf_metrics"
	CapRoamEvents         Capability = "wireless.roam_events"
	CapOnboardingFailures Capability = "wireless.onboarding_failures"
	CapAPUplinkMapping    Capability = "wireless.ap_uplink_mapping"
	CapMLOLinks           Capability = "wireless.mlo_links"
	// Remediation capabilities (Phase 8; declaring one does NOT enable it —
	// FEATURE_WIRELESS_ACTIONS gates execution, default off).
	CapRRMActions       Capability = "wireless.rrm_actions"
	CapClientDisconnect Capability = "wireless.client_disconnect"
)

// Fidelity is how proven a capability's mapping is (the evidence ladder).
type Fidelity string

const (
	FidelityNone          Fidelity = "none"
	FidelityDocClaimed    Fidelity = "doc_claimed"
	FidelityLabValidated  Fidelity = "lab_validated"
	FidelityLiveValidated Fidelity = "live_validated"
)

// CapabilityDecl declares one capability with its fidelity and the vendor's
// REAL reporting granularity (not our polling ask — if the vendor computes a
// value once a minute, polling every 10s reports the same number six times).
type CapabilityDecl struct {
	Capability   Capability
	Fidelity     Fidelity
	PollInterval time.Duration // vendor's real granularity; 0 = on-change/unknown
	Notes        string        // the citation (YANG model / MIB / API doc) or the hole
}

// CapabilityOf returns the declaration for a capability, if the spec makes
// one. Absent = the connector has not assessed it — callers must treat that
// as FidelityNone (fail closed), never as supported.
func (s ConnectorSpec) CapabilityOf(c Capability) (CapabilityDecl, bool) {
	for _, d := range s.Capabilities {
		if d.Capability == c {
			return d, true
		}
	}
	return CapabilityDecl{}, false
}
