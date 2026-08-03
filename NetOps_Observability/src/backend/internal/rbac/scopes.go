package rbac

// scopes.go — the scope identity VOCABULARY for PBAC
// (docs/design/saas-identity-pbac.md §1.2, §7.4). A scope is a node in the
// resource hierarchy a binding can point at:
//
//	platform  >  org:<slug>  >  tenant:<slug>  >  resource:<kind>:<id>
//
// Canonical ids are `type:slug` (human-readable for incidents/audits/logs). A
// scope id, once minted, is STABLE — never re-mapped. The containment TREE
// (parent/canonicalize/ancestor-or-self) is derived from the live org + tenant
// stores and lives with the server (main's scopes.go); this file owns only the
// id forms.

import "strings"

// Scope types (the fixed lattice, highest → lowest).
const (
	ScopePlatform     = "platform"
	ScopeTypeOrg      = "org"
	ScopeTypeTenant   = "tenant"
	ScopeTypeResource = "resource"
)

// ScopeOrg / ScopeTenant mint canonical scope ids.
func ScopeOrg(id string) string { return ScopeTypeOrg + ":" + strings.ToLower(strings.TrimSpace(id)) }
func ScopeTenant(id string) string {
	return ScopeTypeTenant + ":" + strings.ToLower(strings.TrimSpace(id))
}

// ParseScope splits a scope id into its type and the remainder (slug / kind:id).
// platform has no slug. Unknown/blank → ("", "").
func ParseScope(id string) (scopeType, rest string) {
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
