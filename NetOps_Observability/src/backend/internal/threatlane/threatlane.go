// Package threatlane is Correlix's THREAT-DETECTION lane (T6 of
// SECURITY_BUILD_PLAN_2026-08-25 / SECURITY_OBSERVABILITY_HLD §5b): the third
// security evidence class, "signal" — an active security signal derived from
// telemetry the platform already ingests (device syslog + IPFIX/NetFlow flows).
//
// It is a SELF-CONTAINED PRODUCER of secfindings.Finding objects with
// EvidenceClass "signal". Per the removable-module ARCHITECTURE CONSTRAINT it
// hard-depends on nothing security-specific in the core — only on
// internal/secfindings (the shared, owned finding model) and the standard
// library. The correlation engine consumes what this package emits (via
// internal/secbus) with zero threat-specific code; deleting internal/threatlane
// removes the feature and touches nothing else. It is a LEAF: no core or
// non-security package imports it (verified by grep + a simulated-removal build).
//
// It MIRRORS the sibling posture producer internal/hardening: a rules-as-code
// CATALOG (independently worded, MITRE ATT&CK-tagged, version-pinned), an
// Engine.Detect that runs the catalog over input, and all input behind NARROW
// interfaces (LogSource / FlowSource) with in-memory stubs so the lane is fully
// decoupled from the running stack. Real wiring to the live syslog/flow pipeline
// is a later step (see the TODO(deploy) markers on the source interfaces).
//
// Two detection families:
//
//   - DEVICE-LOG detections over normalized syslog (hand-authored, low false
//     positive): logging disabled/tampered, log buffer cleared, off-hours
//     configuration change, new local user, privilege escalation, GRE/tunnel
//     interface creation, AAA/authentication tampering. Each rule is a single
//     match over one normalized LogEvent → a Fail finding.
//
//   - FLOW-BEHAVIORAL detections over normalized flow records: periodic
//     low-variance BEACONING, volumetric EGRESS exfiltration to a rare external
//     peer, and horizontal/vertical SCAN fan-out. Behavioral rules reason over a
//     grouped SERIES of flows and emit a lower-confidence Warning finding (a
//     triage signal, not a hard verdict).
//
// FAIL-CLOSED (§9/§10, no false "all clear"): a detection lane emits ONLY when a
// rule genuinely fires — the absence of a finding is never a green claim. If a
// source is UNAVAILABLE (transport/store error) Detect propagates the error so
// the caller surfaces "unassessed"; it never swallows the failure into an empty
// (falsely clean) result. An empty-but-healthy source yields no findings, which
// is the honest "evaluated, nothing tripped" outcome for a signal lane.
//
// §3a tenant isolation: every finding's TenantID is stamped from the SOURCE
// RECORD's tenant (the syslog/flow row is itself principal-scoped upstream),
// NEVER from a request body — this package has no request surface at all. It is
// a pure producer: no store, no HTTP handler, no list/get, so it ships no
// org_isolation_test.go (there is no data-returning surface to leak). See the
// commit message for that note.
package threatlane

import "netops/backend/internal/secfindings"

// RulesetVersion is the pinned version stamp for the hand-authored catalog in
// this package (§5c version-pinning). It is stamped onto every emitted finding's
// EvidenceRef so a verdict is replayable against the exact ruleset it was scored
// under. Bump it whenever a rule's detection, technique mapping, or severity
// changes.
const RulesetVersion = "correlix-threatlane-2026-08-27"

// SourceThreatLane is the provider id stamped on Finding.Source. It is a
// package-local constant (NOT a new secfindings.Source* constant) so the shared
// model gains no threat-specific vocabulary — secfindings.Finding.Source is a
// free string and this provider owns its value, exactly as internal/advisory
// owns its offline-feed source value.
const SourceThreatLane = "correlix-threatlane"

// Detection family categories — the plane a rule reasons over. They populate
// Finding.Category for operator-facing grouping.
const (
	CategoryDeviceLog = "device-log" // hand-authored syslog detections
	CategoryFlow      = "flow"       // flow-behavioral detections
)

// Standard MITRE ATT&CK framework tag prefix used in Finding.Standards, so a
// consumer can filter security findings by ATT&CK coverage. The technique id
// itself is also carried in Finding.ControlID (the canonical rule mapping) and
// named in Detail, mirroring how internal/advisory threads its CVE taxonomy.
const attackTagPrefix = "MITRE ATT&CK "

// attackStandard renders a technique id into the Standards tag form.
func attackStandard(technique string) string { return attackTagPrefix + technique }

// severityOK reports whether s is one of the canonical secfindings severities.
// Used only by the catalog self-consistency test so a hand-authored rule can
// never ship an unknown severity token.
func severityOK(s string) bool {
	switch s {
	case secfindings.SeverityCritical, secfindings.SeverityHigh,
		secfindings.SeverityMedium, secfindings.SeverityLow, secfindings.SeverityInfo:
		return true
	default:
		return false
	}
}
