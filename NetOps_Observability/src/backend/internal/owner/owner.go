// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package owner is the ONE spelling of a data owner (tracker 356).
//
// The platform realm has had two spellings: "" (untagged devices, "discovered
// infrastructure is platform-scoped until assigned") and "global" (what a
// Global-view principal stamps; correlation's canon_tenant, ClickHouse row
// policies, ticketing). Every store and comparison that decides "whose is
// this?" canonicalizes through Of, so the two can never split one owner in two
// — and real tenant ids are never collapsed into each other or into the
// platform.
//
// A leaf package on purpose: no imports beyond the standard library, so any
// package (nms, ticketing, internal/tenant, the api root) can depend on it
// without a cycle.
package owner

import "strings"

// Platform is the canonical owner of platform-realm rows. internal/tenant's
// Global and nms.PlatformOwner are pinned to it by test.
const Platform = "global"

// Of is the canonical owner for t: trimmed, lower-cased, and "" → Platform.
// Tenant ids are compared case-insensitively everywhere in the app layer.
func Of(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return Platform
	}
	return t
}

// IsPlatform reports whether t names the platform realm in either spelling.
func IsPlatform(t string) bool { return Of(t) == Platform }

// Same reports whether a and b are the same owner.
func Same(a, b string) bool { return Of(a) == Of(b) }

// ScopeReads is the DIRECTIONAL access rule for an already-scoped (non-cross)
// principal: may a caller scoped to `scope` read a row owned by `row`?
//
// An exact owner match always may (case/space-insensitive). Beyond that, ONLY
// the explicit Provider scope ("global") also reads the platform's untagged
// ("") rows (tracker 365). The reverse is deliberately NOT granted: a
// principal whose scope is "" is an unbound / unresolved caller, and widening
// it to the Provider's "global" rows would turn a missing tenant into access.
// This is the app-layer mirror of Postgres migration 0062 (platform_alias:
// app.tenant_id = 'global' AND tenant_id = '').
func ScopeReads(scope, row string) bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	r := strings.ToLower(strings.TrimSpace(row))
	if s == r {
		return true
	}
	return s == Platform && r == ""
}
