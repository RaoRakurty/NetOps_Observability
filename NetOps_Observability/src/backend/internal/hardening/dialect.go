// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package hardening

// dialect.go — THE DIALECT SEAM.
//
// A hardening rule is a vendor-neutral CONCEPT (rule.go) with a per-vendor
// realization: how the insecure state is written in that platform's
// configuration grammar, and how it is fixed. The concept catalogue, the engine
// and the benchmark provenance are core; the DIALECTS beyond the core one are
// the `security_dialects` entitlement, and their implementations live outside
// this package under src/backend/enterprise/dialects.
//
// This file is what makes that possible without core ever naming the commercial
// package: a DialectPack is a plain data contribution — rule id → binding —
// that DefaultCatalog merges in, plus the small set of exported detection
// builders and config accessors an out-of-package dialect needs to express one.
//
// DIRECTION. Core defines this seam; the commercial package satisfies it; the
// assembly layer (package main) is the only place that names both and passes
// the packs in. A missing pack is not an error and never a false clear: a rule
// with no binding for the device's vendor is reported NotApplicable — the
// honest non-verdict the engine already emits for an unbound vendor — and the
// licence gate (WithDialectGate) reports RuleDialectNotLicensed instead of
// silently assessing nothing.

// DialectPack is one dialect's contribution to the catalogue: the per-rule
// detection + remediation bindings for a single Vendor, keyed by the rule ID
// they bind to.
//
// It is DATA, not code injection: a pack cannot add, remove or re-word a rule,
// change its severity or its control mapping, or touch another vendor's
// binding. It can only answer "how does THIS platform express THIS rule's
// insecure state, and how is it fixed". A binding for an id the catalogue does
// not carry is ignored (a pack authored against a newer catalogue must not
// break an older engine); the pack's own tests assert that every id it names
// resolves, so an ignored binding is caught where the data lives, never in
// production.
type DialectPack struct {
	// Vendor is the dialect these bindings realize.
	Vendor Vendor
	// Bindings maps a Rule.ID to that rule's realization in this dialect.
	Bindings map[string]VendorBinding
}

// applyDialects returns rules with the packs' bindings merged in. Inputs are
// copied: neither the caller's rules nor the packs are mutated, and the
// resulting catalogue stays immutable (§5 no global mutable state).
func applyDialects(rules []Rule, packs []DialectPack) []Rule {
	if len(packs) == 0 {
		return rules
	}
	// rule id -> vendor -> binding, so a rule is visited once.
	byRule := map[string]map[Vendor]VendorBinding{}
	for _, p := range packs {
		if p.Vendor == VendorUnknown || len(p.Bindings) == 0 {
			continue
		}
		for id, b := range p.Bindings {
			if b.Detect == nil {
				continue // a binding with no detection cannot assess anything
			}
			if _, ok := byRule[id]; !ok {
				byRule[id] = map[Vendor]VendorBinding{}
			}
			byRule[id][p.Vendor] = b
		}
	}
	out := make([]Rule, len(rules))
	copy(out, rules)
	for i := range out {
		add, ok := byRule[out[i].ID]
		if !ok {
			continue
		}
		merged := make(map[Vendor]VendorBinding, len(out[i].bindings)+len(add))
		for v, b := range out[i].bindings {
			merged[v] = b
		}
		for v, b := range add {
			merged[v] = b
		}
		out[i].bindings = merged
	}
	return out
}

// DialectRuleIDs returns every rule id in the shipped catalogue, so a dialect
// pack's tests can assert that each id it binds actually exists. Fresh map per
// call.
func DialectRuleIDs() map[string]bool {
	ids := map[string]bool{}
	for _, r := range DefaultCatalog().Rules() {
		ids[r.ID] = true
	}
	return ids
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection builders, exported for out-of-package dialects
//
// These are the same builders the core bindings use. They are exported so a
// dialect pack expresses a detection declaratively — "this line being present is
// the insecure state" — instead of hand-rolling a closure over Config, which is
// where subtle false clears come from.
// ─────────────────────────────────────────────────────────────────────────────

// DetectPresent trips when a line matching pattern is PRESENT. absentNote is
// the observation recorded when it is not (the assessed-and-clean evidence).
func DetectPresent(pattern, absentNote string) func(*Config) DetectResult {
	return present(pattern, absentNote)
}

// DetectAbsent trips when NO line matches pattern — the "required hardening
// line is missing" shape. missingNote is the evidence for the tripped case,
// presentNote for the clean one.
func DetectAbsent(pattern, missingNote, presentNote string) func(*Config) DetectResult {
	return absent(pattern, missingNote, presentNote)
}

// DetectBothPresentAbsent trips when needle is present AND guard is absent —
// "the feature is on but its safeguard is not configured".
func DetectBothPresentAbsent(needle, guard, note string) func(*Config) DetectResult {
	return bothPresentAbsent(needle, guard, note)
}

// DetectNotApplicable reports the control as structurally inapplicable on this
// platform, carrying the REASON (see DetectResult.NotApplicable). Use it ONLY
// where the operating system cannot express the insecure state at all — never
// as a placeholder for unwritten detection, which is an UNBOUND vendor.
func DetectNotApplicable(reason string) func(*Config) DetectResult {
	return func(*Config) DetectResult {
		return DetectResult{NotApplicable: true, Evidence: reason}
	}
}

// DetectIOSSNMPNoACL is the core IOS-XE "SNMP community with no source ACL"
// detection, exported because a dialect that shares the IOS SNMP configuration
// grammar (Arista EOS) must reuse it rather than re-implement it — two copies of
// one regex family is exactly how the two dialects drift apart.
func DetectIOSSNMPNoACL(c *Config) DetectResult { return iosSNMPNoACL(c) }
