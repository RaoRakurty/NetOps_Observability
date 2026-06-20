package main

// scopes.go — the scope identity model for PBAC (docs/design/saas-identity-pbac.md
// §1.2, §7.4). A scope is a node in the resource hierarchy a binding can point at:
//
//	platform  >  org:<slug>  >  tenant:<slug>  >  resource:<kind>:<id>
//
// Canonical ids are `type:slug` (human-readable for incidents/audits/logs). The
// containment hierarchy is a STRICT single-parent tree; cross-cutting access
// (MSP / shared / break-glass) is never re-parenting — it is a binding whose
// scope_id points across the tree. Authorization's only traversal is
// ancestor-or-self, which walks parents (depth ≤ 4).
//
// Phase A keeps the tree DERIVED from the org + tenant stores (no redundant
// persisted scope table): org:<id> parents come from orgStore, tenant:<id>
// parents from the tenant's org. Resource scopes are lazy (minted on first use)
// and parent onto their tenant. A scope id, once minted, is STABLE — never
// re-mapped.

import "strings"

// Scope types (the fixed lattice, highest → lowest).
const (
	ScopePlatform = "platform"
	scopeTypeOrg      = "org"
	scopeTypeTenant   = "tenant"
	scopeTypeResource = "resource"
)

// scopeOrg / scopeTenant / scopeResource mint canonical scope ids.
func scopeOrg(id string) string    { return scopeTypeOrg + ":" + strings.ToLower(strings.TrimSpace(id)) }
func scopeTenant(id string) string { return scopeTypeTenant + ":" + strings.ToLower(strings.TrimSpace(id)) }
//nolint:unused // part of the scope-mint API (lazy resource scopes); used as resource-level ACLs land (Phase D+)
func scopeResource(kind, id string) string {
	return scopeTypeResource + ":" + strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.ToLower(strings.TrimSpace(id))
}

// parseScope splits a scope id into its type and the remainder (slug / kind:id).
// platform has no slug. Unknown/blank → ("", "").
func parseScope(id string) (scopeType, rest string) {
	id = strings.TrimSpace(id)
	if id == ScopePlatform {
		return ScopePlatform, ""
	}
	i := strings.IndexByte(id, ':')
	if i < 0 {
		return "", ""
	}
	return id[:i], id[i+1:]
}

// scopeParent returns the parent scope id, or "" for the platform root (and for
// malformed ids). tenant:X → org:<orgOf(X)>; org:Y → platform; resource:* → its
// tenant (encoded as resource:<kind>:<id>@<tenant> is NOT used — resource parent
// is resolved by the caller that knows the owning tenant). Derived from the live
// org/tenant stores so the tree always matches reality.
func (s *server) scopeParent(scopeID string) string {
	t, rest := parseScope(scopeID)
	switch t {
	case ScopePlatform:
		return ""
	case scopeTypeOrg:
		return ScopePlatform
	case scopeTypeTenant:
		// A tenant's parent is its org. Fall back to the Global org if unknown.
		org := OrgGlobal
		if s.tenants != nil {
			if tn, ok := s.tenants.Get(rest); ok {
				org = orgOf(tn)
			}
		}
		return scopeOrg(org)
	default:
		// resource scopes parent onto their tenant; callers that mint them pass the
		// tenant explicitly, so a bare resource id has no derivable parent here.
		return ""
	}
}

// canonicalScopeID resolves the tenant/org identifier inside a scope id to its
// opaque canonical id (org_…/t_…). This is the "resolve before authorize"
// compatibility bridge: a legacy slug-based scope (tenant:acme-prod) and the
// opaque-id form (tenant:t_ab…) both canonicalize to the SAME string, so the
// reach comparison unifies them. It NEVER authorizes on a slug — it only
// normalizes both sides to the opaque id before the string compare. platform and
// unresolvable scopes pass through unchanged (fail-closed: an unknown ref stays
// itself and simply won't match a real canonical scope).
//
// Cost: a tenant/org Resolve is an O(1) id-map hit for the opaque-id common case;
// only a legacy slug falls back to an O(n) scan. (Phase 2: add a slug→id index.)
func (s *server) canonicalScopeID(scopeID string) string {
	typ, rest := parseScope(scopeID)
	switch typ {
	case scopeTypeTenant:
		if s.tenants != nil {
			if t, ok := s.tenants.Resolve(rest); ok {
				return scopeTenant(t.ID)
			}
		}
	case scopeTypeOrg:
		if s.orgs != nil {
			if o, ok := s.orgs.Resolve(rest); ok {
				return scopeOrg(o.ID)
			}
		}
	}
	return scopeID
}

// scopeAncestorOrSelf reports whether `ancestor` is the same as, or an ancestor
// of, `descendant` in the containment tree. This is the ONLY traversal the
// authorization path performs (bounded by tree depth ≤ 4 + a hard cap). Both
// endpoints (and every walked parent) are canonicalized to opaque ids first, so a
// slug-based scope and its opaque-id equivalent compare equal (legacy compat).
func (s *server) scopeAncestorOrSelf(ancestor, descendant string) bool {
	ancestor = s.canonicalScopeID(strings.TrimSpace(ancestor))
	cur := s.canonicalScopeID(strings.TrimSpace(descendant))
	for i := 0; cur != "" && i < 8; i++ { // i<8 is a cycle backstop; real depth ≤ 4
		if strings.EqualFold(cur, ancestor) {
			return true
		}
		cur = s.canonicalScopeID(s.scopeParent(cur))
	}
	return false
}
