// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package secbus is the COMMON BUS SEAM the security evidence providers emit
// through (T2, SECURITY_OBSERVABILITY_HLD §5b). It turns Correlix's owned,
// normalized secfindings.Finding into a GENERIC evidence event on the bus, so
// the correlation engine can ground security as a fourth evidence class with
// ZERO security-specific code — the event carries only the fields any lane's
// raw event carries (entity, kind, ts, severity, tokens, attrs, evidence-refs).
//
// ARCHITECTURE CONSTRAINT (removable module): this package is a LEAF producer.
// It imports only secfindings and the standard library, and NOTHING in the core
// (package backend or any non-security package) imports it — deleting
// internal/secbus, internal/hardening and internal/advisory leaves the build
// green. The bus transport is injected as a Publisher interface (§5 "interfaces
// for external deps"); the concrete transport (the Vector bus-bridge produceJSON
// in package backend) is bound at the wiring layer, never depended on here.
//
// The wire shape is DELIBERATELY generic. If a security consumer would be the
// only thing able to interpret a field, that field does not belong on the wire —
// the specific security classification (control id, standards, verdict) rides in
// attrs, which every lane already carries and the engine treats as opaque.
package secbus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/secfindings"
)

// SchemaVersion pins the wire contract T2b (the Python consume-and-ground step)
// relies on. Bump ONLY on a breaking change to EvidenceEvent's shape; additive
// optional fields do not require a bump. Kept as a constant (no mutable global).
const SchemaVersion = "1"

// Kind* are the engine-facing signal kinds this lane emits — one per evidence
// class (§5b). They are the lane discriminator a generic consumer switches on
// (the security analogue of the cloud lane's CLOUD_KINDS), NOT a per-rule kind:
// the specific control/rule identity rides in Attrs, so the engine's kind space
// stays a small stable vocabulary. Each maps directly onto a Python Signal.kind.
const (
	KindPosture  = "security_posture"  // from EvidenceClass "posture"
	KindExposure = "security_exposure" // from EvidenceClass "exposure"
	KindSignal   = "security_signal"   // from EvidenceClass "signal"
)

// EntityTypeDevice is the engine EntityType a security subject grounds as. Host,
// network-device and container findings all ground onto the DEVICE node so they
// co-locate with the network telemetry already on that entity; the finer
// resource kind is preserved in Attrs["resource_kind"], never lost.
const EntityTypeDevice = "device"

// EvidenceRef is the wire form of a by-reference, version-pinned pointer to the
// raw artifact a verdict was derived from. It is a POINTER only — a locator, a
// kind, a pinned ruleset version and an optional content digest — and NEVER a
// copy of the underlying evidence (§5c, and the §3a/LLM06 rule that no payload
// or secret is inlined onto the bus). It mirrors secfindings.EvidenceRef but is
// its own type so the wire schema is pinned independently of the internal model.
type EvidenceRef struct {
	Locator        string `json:"locator"`
	Kind           string `json:"kind,omitempty"`
	RulesetVersion string `json:"ruleset_version,omitempty"`
	Digest         string `json:"digest,omitempty"`
}

// EvidenceEvent is the GENERIC security-evidence event on netops.security. Every
// field maps onto a Python correlation Signal field (src/correlation/signals.py
// class Signal, ~line 577) so a future trivial adapter — the same shape as
// cloud_signal_from_event — grounds it with no security-specific logic:
//
//	SchemaVersion  → (wire hygiene; not a Signal field)
//	TenantID       → Signal.tenant_id      (§3a, stamped from the finding)
//	TS             → Signal.ts             (RFC3339 UTC event time)
//	Kind           → Signal.kind           (security_posture|_exposure|_signal)
//	EntityID       → Signal.entity_id      (MANDATORY; the device subject)
//	EntityType     → Signal.entity_type    ("device")
//	EntityTokens   → Signal.entity_tokens  (co-location grounding keys)
//	Severity       → Signal.severity        (raw token; the engine's existing
//	                                         severity aliases already map
//	                                         critical/high/medium/low/info)
//	NativeID       → Signal.native_id       (deterministic → stable signal_id)
//	FindingID      → (storage identity; not a Signal field — see findingDocIDOf)
//	SeamID/Type/…  → Signal.attrs           (seam attribution, opaque to engine)
//	EvidenceRefs   → Signal.attrs           (by-reference pointers only)
//	Attrs          → Signal.attrs           (control id, standards, verdict,
//	                                         status_detail — the verdict REASON, …)
type EvidenceEvent struct {
	SchemaVersion  string         `json:"schema_version"`
	TenantID       string         `json:"tenant_id"`
	TS             string         `json:"ts"`
	Kind           string         `json:"kind"`
	EntityID       string         `json:"entity_id"`
	EntityType     string         `json:"entity_type"`
	EntityTokens   []string       `json:"entity_tokens,omitempty"`
	Severity       string         `json:"severity"`
	NativeID       string         `json:"native_id"`
	FindingID      string         `json:"cx_finding_id,omitempty"`
	SeamID         string         `json:"seam_id,omitempty"`
	SeamType       string         `json:"seam_type,omitempty"`
	InternetFacing bool           `json:"internet_facing,omitempty"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs,omitempty"`
	Attrs          map[string]any `json:"attrs,omitempty"`
}

// kindForClass maps a finding's EvidenceClass onto the engine-facing lane kind.
// An unknown/empty class is an error, never a guessed lane — provenance is never
// invented (§10 no silent failures).
func kindForClass(evidenceClass string) (string, error) {
	switch evidenceClass {
	case secfindings.EvidencePosture:
		return KindPosture, nil
	case secfindings.EvidenceExposure:
		return KindExposure, nil
	case secfindings.EvidenceSignal:
		return KindSignal, nil
	default:
		return "", fmt.Errorf("secbus: finding has no/unknown evidence_class %q", evidenceClass)
	}
}

// entityIDOf derives the engine's mandatory entity_id from the finding subject,
// following the engine's convention (a bare identifier, most-stable first): the
// device uid, else the hostname, else the device name, else the address. An
// empty result is an error — Signal.entity_id is MANDATORY and the engine
// dead-letters an empty one, so we refuse to emit rather than ship a signal the
// engine will reject.
func entityIDOf(r secfindings.Resource) (string, error) {
	for _, cand := range []string{r.DeviceID, r.Hostname, r.DeviceName, r.Address} {
		if s := strings.TrimSpace(cand); s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("secbus: finding resource carries no device id/hostname/name/address to ground on")
}

// entityTokensOf builds the engine's CO-LOCATION grounding keys for the subject.
// The bare entity_id joins to any signal on the same node; the prefixed keys
// (device:/host:/seam:) join to the specific device, host and seam. All prefixes
// used here are ENTITY-scoped — none is in the engine's forbidden tenant/org/
// global/all/ssid/wlan set — so a security signal can never merge unrelated
// entities (the #99 grounding-token guard). Deduped and order-stable.
func entityTokensOf(entityID string, r secfindings.Resource, seam *secfindings.SeamContext) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	add(entityID)
	if s := strings.TrimSpace(r.DeviceID); s != "" {
		add("device:" + s)
	}
	if s := strings.TrimSpace(r.Hostname); s != "" {
		add("host:" + s)
	}
	if seam != nil {
		if s := strings.TrimSpace(seam.SeamID); s != "" {
			add("seam:" + s)
		}
	}
	return out
}

// nativeIDOf builds the deterministic native id: the identity of the THING
// ASSESSED — tenant, evidence class, control, subject device and the producing
// rule — NOT of the assessment run that produced this verdict.
//
// TWO IDENTITIES, ONE PER QUESTION (L-01, 2026-09-03 — read before editing):
//
//	native_id — "which finding is this?"  STABLE across scans. It is the
//	            collapse key behind `current=true` and behind the compliance
//	            scorecards' current-state fold, so two scans of the same rule on
//	            the same device MUST produce the same value or the newer verdict
//	            can never supersede the older one.
//	_id       — "which verdict is this?"  sha2(native_id | attrs.scan_id),
//	            computed by the router. The scan id is STILL the second half, so
//	            every scan keeps its own retained document and the history the
//	            trend/drift views read is untouched. Only the VIEW collapses.
//
// f.ScanID was folded into native_id until 2026-09-03. That made every scan its
// own collapse group: `current=true` returned every verdict ever recorded, the
// Findings page showed 444 stale Unknowns from rules that no longer exist, and
// the compliance scorecard read AC-17 as Fail/168 while the current scan said
// NotApplicable. The scan run is carried in attrs.scan_id (and in the `_id`),
// which is where a per-run identity belongs.
//
// TenantID leads the discriminators so the identity is tenant-scoped: device
// ids are unique within a tenant, not across the platform, and the cross-tenant
// platform view collapses on this field without a tenant filter under it —
// without the tenant segment two tenants' "spine1" would fold into one row.
//
// f.ID is the per-finding discriminator. Without it, a rule that legitimately
// fires more than once for one device in one scan (e.g. threatlane's
// per-conversation and per-source detections) would collide onto ONE native_id
// and every finding after the first would be indistinguishable — the router
// would hash them to ONE _id and one would overwrite the other. A producer that
// emits at most one finding per (rule, device, scan) may leave ID empty: the
// segment is then empty and identity degrades to the assessment scope.
//
// Engine-side, signal_id is uuid5(source|native_id|ts_ms) — the verdict INSTANT
// is already part of it — so a stable native_id does not make a later scan
// dedup away as a redelivery; only a genuine re-delivery of the SAME verdict
// (same native_id AND same ts) collapses, which is the §9 idempotency intent.
//
// Kept < the engine's 256-char id cap by hashing when the joined form would
// overflow (deterministic, collision-resistant), so a long control id or rule
// id can never silently truncate to a colliding id at the model boundary.
func nativeIDOf(f secfindings.Finding, entityID, kind string) string {
	raw := strings.Join([]string{
		"security", kind, f.EvidenceClass, f.TenantID, f.ControlID, entityID, f.ID,
	}, "|")
	if len(raw) <= 256 {
		return raw
	}
	sum := sha256.Sum256([]byte(raw))
	return "security|" + kind + "|" + hex.EncodeToString(sum[:])
}

// findingDocIDOf computes the STORAGE identity of a verdict:
// sha256(native_id | attrs.scan_id), lowercase hex.
//
// WHO REALLY ASSIGNS THE _id (D-09, 2026-09-03 — read this before changing it).
// Go does NOT assign the OpenSearch document id. The router does: the
// vector-router's `security_identity` transform computes
// `sha2(native_id + "|" + attrs.scan_id, variant: "SHA-256")` into
// `.cx_finding_id`, and the secfindings sink is configured `id_key:
// cx_finding_id`, which lifts that key into the bulk action's `_id` AND removes
// it from the document body (which is why no indexed `_source` carries the
// field, and why a `term` on it matched nothing).
//
// This function therefore does not MINT a second identity — it recomputes the
// SAME one, byte-for-byte, from the SAME two inputs, so the field exists on the
// bus for every consumer that is not the router (the Python grounding step, a
// future direct-Finding writer, an operator replaying the topic). The router
// still overwrites it unconditionally on its good path and deletes it on the
// quarantine path, so a bus producer cannot forge a document id with it.
//
// The scan id is read back OUT of the assembled attrs rather than off the
// finding, so it is exactly the string the router will hash — attrsOf omits a
// blank scan_id, and a value that differed by so much as trimmed whitespace
// would produce a second, silently-wrong id. Identity requires BOTH halves:
// with either missing the router quarantines the record instead of indexing it,
// so we return "" (the field is omitempty) rather than hash an empty half.
func findingDocIDOf(nativeID string, attrs map[string]any) string {
	scanID, _ := attrs["scan_id"].(string)
	if nativeID == "" || scanID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nativeID + "|" + scanID))
	return hex.EncodeToString(sum[:])
}

// StatusDetailMax bounds the verdict REASON carried in attrs.status_detail. The
// reason is producer-authored prose, so it is bounded like every other external
// string that reaches the bus (§9 bounded IO); a longer one is truncated with an
// ellipsis rather than dropped, because a clipped reason still explains more
// than no reason at all.
const StatusDetailMax = 512

// attrsOf assembles Signal.attrs: the security CLASSIFICATION, the verdict
// REASON, and evidence POINTERS only. It deliberately inlines NO raw evidence,
// config snippet or secret (§5c by-reference, §3a/LLM06 no payloads on the bus)
// — the raw artifact stays behind EvidenceRefs, and Finding.Observed (which IS
// the offending config excerpt) is deliberately NOT carried here. Empty values
// are omitted to keep the wire lean and the consumer's honest defaults intact.
//
// status_detail is the ONE narrative field that does ride the wire, and it does
// so because §5g's "never a false clear" is only half a rule without it: an
// Unknown/NotApplicable verdict whose REASON does not survive the bus reaches
// the operator as a bare grey chip, and "we could not read the running-config",
// "this control does not exist on this platform" and "we could not even tell
// what platform this is" are three different facts with three different fixes.
// It is a classification of the verdict, not evidence about the device.
func attrsOf(f secfindings.Finding, seam *secfindings.SeamContext) map[string]any {
	attrs := map[string]any{
		"evidence_class": f.EvidenceClass,
	}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			attrs[k] = v
		}
	}
	put("provider_source", f.Source)
	put("control_id", f.ControlID)
	put("control_title", f.ControlTitle)
	put("category", f.Category)
	put("raw_rule_id", f.RawRuleID)
	put("scan_id", f.ScanID)
	put("status_detail", clampDetail(f.Detail))
	if f.Status != "" {
		attrs["status"] = f.Status
	}
	if f.StatusID != 0 {
		attrs["status_id"] = int(f.StatusID)
	}
	if len(f.Standards) > 0 {
		std := append([]string(nil), f.Standards...)
		sort.Strings(std)
		attrs["standards"] = std
	}
	if seam != nil {
		put("seam_id", seam.SeamID)
		put("seam_type", seam.SeamType)
		if seam.InternetFacing {
			attrs["internet_facing"] = true
		}
	}
	return attrs
}

// clampDetail trims and bounds the verdict reason. The budget is counted in
// RUNES and the cut lands on a rune boundary, so a truncated multi-byte reason
// can never be written as invalid UTF-8 (the em-dashes in these strings are
// three bytes each, so a byte-wise cut would be a live hazard, not a theoretical
// one).
func clampDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	runes := []rune(detail)
	if len(runes) <= StatusDetailMax {
		return detail
	}
	return string(runes[:StatusDetailMax]) + "…"
}

// FromFinding converts one owned, normalized secfindings.Finding into the
// generic bus evidence event. It is PURE (no IO, no wall-clock read) and
// deterministic given the finding, so the same finding always yields the same
// event (idempotent producer input). It returns an error — never a partial or
// guessed event — when the finding cannot ground (no evidence class, or no
// subject to ground on), so a malformed finding is refused at the seam rather
// than dead-lettered downstream.
//
// §3a: TenantID is carried STRAIGHT from the finding (stamped upstream from the
// authenticated principal); there is no tenant parameter to override it with.
func FromFinding(f secfindings.Finding) (EvidenceEvent, error) {
	kind, err := kindForClass(f.EvidenceClass)
	if err != nil {
		return EvidenceEvent{}, err
	}
	entityID, err := entityIDOf(f.Resource)
	if err != nil {
		return EvidenceEvent{}, err
	}
	ts := f.Time
	if ts.IsZero() {
		return EvidenceEvent{}, fmt.Errorf("secbus: finding has zero verdict time (event-time discipline)")
	}

	refs := make([]EvidenceRef, 0, 1)
	if f.EvidenceRef != nil {
		refs = append(refs, EvidenceRef{
			Locator:        f.EvidenceRef.Locator,
			Kind:           f.EvidenceRef.Kind,
			RulesetVersion: f.EvidenceRef.RulesetVersion,
			Digest:         f.EvidenceRef.Digest,
		})
	}

	nativeID := nativeIDOf(f, entityID, kind)
	attrs := attrsOf(f, f.SeamContext)

	ev := EvidenceEvent{
		SchemaVersion: SchemaVersion,
		TenantID:      f.TenantID,
		TS:            ts.UTC().Format(time.RFC3339Nano),
		Kind:          kind,
		EntityID:      entityID,
		EntityType:    EntityTypeDevice,
		EntityTokens:  entityTokensOf(entityID, f.Resource, f.SeamContext),
		Severity:      f.Severity,
		NativeID:      nativeID,
		FindingID:     findingDocIDOf(nativeID, attrs),
		EvidenceRefs:  refs,
		Attrs:         attrs,
	}
	if f.SeamContext != nil {
		ev.SeamID = f.SeamContext.SeamID
		ev.SeamType = f.SeamContext.SeamType
		ev.InternetFacing = f.SeamContext.InternetFacing
	}
	return ev, nil
}
