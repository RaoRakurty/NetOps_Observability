// Package configdrift is the CONSUMER half of the config keystone (P3-CFG,
// design docs/design/CONFIG_BACKUP_AND_DRIFT_DESIGN_2026-08-25.md §4): it turns
// each capture internal/configstore takes into a per-device SYNC VERDICT (the
// inventory badge), a bus SIGNAL (the ConfigDrift event) and a hardening
// ConfigSource (so the §5e rules stop reporting Unknown once a backup exists).
//
// ── WHY IT IS ITS OWN PACKAGE ───────────────────────────────────────────────
// The design's module boundary: config backup is FOUNDATIONAL, and security /
// compliance / RCA are CONSUMERS of it. Keeping the consumer wiring here means
// internal/configstore imports nothing security-specific and stays a pure NMS
// module. Deleting THIS package removes the security/RCA consumption and leaves
// backup, versioning, diff and retention fully working.
//
// ── THE BUS EVENT (and why netops.security, not netops.controller_events) ───
// The drift signal is emitted as a secfindings.Finding produced through the
// EXISTING internal/secbus producer onto netops.security. Three reasons, all
// from the design:
//
//  1. §4 of the design names the consumers of a ConfigDrift event: the security
//     lane, compliance and RCA. All three already read the ONE normalized
//     evidence shape (secfindings.Finding → secbus.EvidenceEvent);
//     netops.controller_events is stack control-plane telemetry with no
//     grounding path into any of them, so publishing there would produce a
//     signal with no consumer.
//  2. secbus.FromFinding is what lets the correlation engine ground this as a
//     fourth evidence class with ZERO drift-specific code (T2b) — exactly the
//     "one capture, four beneficiaries" property. A bespoke event shape would
//     require an engine change per producer.
//  3. The router already persists netops.security into netops-secfindings-<seg>-*
//     (SECURITY_FINDINGS_STORE_DECISION 2026-08-28), so the same emission ALSO
//     lands the drift verdict in the findings index the Security surface reads.
//
// The event carries a diff SUMMARY (counts, in the control title) and a
// BY-REFERENCE pointer to the sealed version. It NEVER carries configuration
// text — not a line of it, redacted or otherwise (§5c evidence by reference,
// LLM06/§8 no payloads on the bus). The bus-event test asserts exactly that.
//
// ── ISOLATION ───────────────────────────────────────────────────────────────
// §3a throughout: the drift state row is stamped with the DEVICE's tenant, the
// state store filters by the caller's principal (PG tenant_iso FORCE-RLS via
// WithTenant; file backend by a tenant-keyed map), the bulk list is own-only,
// a cross-tenant device id answers 404, and the bus record's partition key is
// the tenant id — the same keying every other lane uses.
package configdrift

import (
	"strings"
	"time"
)

// The drift-state vocabulary. It is the SAME closed set internal/configstore
// exports (in_sync | changed | drifted | unknown) — duplicated as constants here
// rather than imported so the two packages' API surfaces stay independent, and
// pinned equal by a test.
const (
	StateInSync  = "in_sync"
	StateChanged = "changed"
	StateDrifted = "drifted"
	StateUnknown = "unknown"
)

// States is the closed vocabulary in render order (metrics + filter validation).
var States = []string{StateInSync, StateChanged, StateDrifted, StateUnknown}

// ValidState reports whether s is in the closed vocabulary. Every state that
// arrives from a query string goes through this before it reaches a store.
func ValidState(s string) bool {
	for _, v := range States {
		if v == s {
			return true
		}
	}
	return false
}

// RulesetVersion pins the drift ruleset stamped on every emitted finding's
// evidence reference, so a past verdict stays replayable (§5c version pinning).
const RulesetVersion = "configdrift-1.0.0"

// ControlID / ControlCategory are the owned control-layer identity of the drift
// verdict. They are Correlix's own control ids, not a copied framework's text.
const (
	ControlID       = "CFG-DRIFT-001"
	ControlCategory = "drift"
	// SourceConfigDrift names the provider that produced the finding (§5h). It
	// is a plain string on the model, so this module declares its own identity
	// without editing the shared finding package.
	SourceConfigDrift = "correlix-configdrift"
)

// State is one device's stored sync status — the row behind the inventory badge.
//
// It is a STORE ROW, not a response body: the JSON tags are the file backend's
// on-disk format and no handler marshals this type. Responses are projected
// explicitly (toStatus → configstore.DriftStatus, and driftItem for the list),
// which is what keeps the owner stamp off the wire while still round-tripping
// through the state file.
type State struct {
	// TenantID is stamped from the DEVICE record (§3a rule 2).
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	State    string `json:"state"`

	LastSHA   string `json:"last_sha,omitempty"`
	GoldenSHA string `json:"golden_sha,omitempty"`

	Added   int `json:"lines_added,omitempty"`
	Removed int `json:"lines_removed,omitempty"`

	// LastError is the scrubbed reason the last capture failed. Present only in
	// the unknown state; an empty string means "never captured".
	LastError string `json:"last_error,omitempty"`

	LastCapture time.Time `json:"last_capture_at,omitempty"`
	ChangedAt   time.Time `json:"changed_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// NormTenant is the canonical tenant spelling for store keys and the RLS GUC.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// visible reports whether a caller scoped to `tenant` (or cross-tenant) may see
// rows owned by `owner`.
func visible(tenant string, cross bool, owner string) bool {
	return cross || owner == NormTenant(tenant)
}
