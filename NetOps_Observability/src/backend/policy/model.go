// Package policy is the security-policy engine for the platform. It models
// authentication, password, session and account-lifecycle controls as typed
// SECURITY POLICIES (not free-form user preferences) and resolves them through
// a deterministic hierarchy: System → Tenant → Role → User.
//
// Design tenets (CLAUDE.md guardrails):
//   - Interfaces first, pure core, no hidden coupling. This package holds ONLY
//     the domain model + the resolution/validation logic. It never touches the
//     store, HTTP, or tenancy plumbing — the server injects a Source.
//   - Deterministic: the same catalog + the same scope documents always resolve
//     to the same effective value and the same inheritance trail.
//   - Zero-trust: every override is validated against its setting's constraints
//     before it can be stored; resolution re-checks lock/harden invariants.
//
// NIST alignment: the catalog (catalog.go) tags each setting with the relevant
// SP 800-63B / 800-53 / 800-128 reference so the configured controls map back
// to a recognised baseline rather than to ad-hoc opinions.
package policy

import "slices"

// Scope is a level in the policy hierarchy. Lower scopes (further down this
// list) are MORE specific and, subject to lock/harden rules, win over higher
// ones. The integer ordering is load-bearing for the resolution walk.
type Scope string

const (
	ScopeSystem Scope = "system" // platform-wide baseline (platform owner only)
	ScopeTenant Scope = "tenant" // per-tenant policy
	ScopeRole   Scope = "role"   // per-role within a tenant
	ScopeUser   Scope = "user"   // per-user override (the most specific)
)

// scopeOrder is the fixed top→down precedence the engine walks. Declared once
// so the order can never drift between resolution, tracing and validation.
var scopeOrder = []Scope{ScopeSystem, ScopeTenant, ScopeRole, ScopeUser}

// Rank returns the position of a scope in the hierarchy (0 = System, most
// general). Used to reason about "higher" vs "lower" scopes deterministically.
func (s Scope) Rank() int { return slices.Index(scopeOrder, s) }

// Domain groups settings into the four security control families. The UI
// renders one card group per domain; flat key/value soup is explicitly avoided.
type Domain string

const (
	DomainAuthentication Domain = "authentication"
	DomainPassword       Domain = "password"
	DomainSession        Domain = "session"
	DomainLifecycle      Domain = "account_lifecycle"
)

// Kind is the value type of a setting. Exactly one field of Value is meaningful
// per Kind; Kind tells every reader which one.
type Kind string

const (
	KindBool     Kind = "bool"
	KindInt      Kind = "int"      // a bare count (length, attempts, history depth)
	KindDuration Kind = "duration" // a span expressed in whole seconds (Value.Num)
	KindEnum     Kind = "enum"     // one of Constraint.Enum (Value.Str)
	KindList     Kind = "list"     // an ordered set of strings (Value.List)
)

// Tier drives progressive disclosure in the UI: TierBasic settings show in the
// default admin view; TierAdvanced only in advanced mode.
type Tier string

const (
	TierBasic    Tier = "basic"
	TierAdvanced Tier = "advanced"
)

// Harden expresses a monotonic constraint: a more specific scope may only make
// a setting STRICTER, never weaker. This is what makes the hierarchy a security
// control rather than a preference cascade — a tenant can tighten the system
// floor but never loosen it. HardenNone leaves a setting freely overridable
// (within its Constraint). Hardening applies to Bool/Int/Duration; Enum/List
// are always HardenNone (set-restriction semantics are a future refinement).
type Harden string

const (
	HardenNone   Harden = ""       // any in-range override is accepted
	HardenHigher Harden = "higher" // stricter = larger (e.g. min password length)
	HardenLower  Harden = "lower"  // stricter = smaller (e.g. idle session timeout)
)

// Value is a typed, JSON-stable, comparable policy value. Exactly one field is
// populated, selected by Kind. Keeping it a flat struct (rather than `any`)
// satisfies the "explicit types" rule and makes equality + ordering trivial.
type Value struct {
	Kind Kind     `json:"kind"`
	Bool bool     `json:"bool,omitempty"`
	Num  int64    `json:"num,omitempty"`  // KindInt count OR KindDuration seconds
	Str  string   `json:"str,omitempty"`  // KindEnum selection
	List []string `json:"list,omitempty"` // KindList members
}

// Equal reports whether two values are identical for the same Kind.
func (v Value) Equal(o Value) bool {
	if v.Kind != o.Kind {
		return false
	}
	switch v.Kind {
	case KindBool:
		return v.Bool == o.Bool
	case KindInt, KindDuration:
		return v.Num == o.Num
	case KindEnum:
		return v.Str == o.Str
	case KindList:
		return slices.Equal(v.List, o.List)
	}
	return false
}

// Constraint bounds a setting's value. Min/Max apply to Int/Duration (inclusive,
// in the setting's Unit). Enum lists the allowed members for Enum/List kinds.
type Constraint struct {
	Min  *int64   `json:"min,omitempty"`
	Max  *int64   `json:"max,omitempty"`
	Unit string   `json:"unit,omitempty"` // "characters","attempts","seconds","days"
	Enum []string `json:"enum,omitempty"` // allowed members (Enum + List kinds)
}

// Setting is the immutable catalog definition of one policy control. It carries
// everything the UI needs to render a self-describing card (label, rationale,
// NIST refs, tier) and everything the engine needs to validate + resolve.
type Setting struct {
	Key         string     `json:"key"` // stable id, e.g. "password.min_length"
	Domain      Domain     `json:"domain"`
	Label       string     `json:"label"`
	Description string     `json:"description"`
	Kind        Kind       `json:"kind"`
	Default     Value      `json:"default"` // catalog baseline when no scope overrides
	Constraint  Constraint `json:"constraint"`
	Tier        Tier       `json:"tier"`
	NIST        []string   `json:"nist"`     // e.g. ["SP 800-63B §5.1.1.2"]
	Lockable    bool       `json:"lockable"` // may a scope lock it against lower overrides
	Harden      Harden     `json:"harden"`   // monotonic stricter-only direction
	Rationale   string     `json:"rationale"`
}

// Override is a value set for one setting at one scope. Locked, when the setting
// is Lockable, forbids any more-specific scope from changing it.
type Override struct {
	Value  Value `json:"value"`
	Locked bool  `json:"locked,omitempty"`
}

// Document is the set of overrides authored at one scope instance: the system
// baseline, a single tenant, a (tenant,role) pair, or a single user. Tenant is
// the owning tenant used for multi-tenant isolation at the storage layer
// (empty for the System scope, which is global / platform-owned).
type Document struct {
	Scope     Scope               `json:"scope"`
	Selector  string              `json:"selector"`         // tenant id / role id / username ("" for system)
	Tenant    string              `json:"tenant,omitempty"` // owning tenant for RLS (tenant/role/user scopes)
	Overrides map[string]Override `json:"overrides"`
	UpdatedAt string              `json:"updated_at,omitempty"` // RFC3339, stamped by the store
	UpdatedBy string              `json:"updated_by,omitempty"`
}

// Subject identifies whose effective policy is being resolved. Role/User may be
// empty to resolve a coarser effective policy (e.g. tenant-only).
type Subject struct {
	Tenant string `json:"tenant"`
	Role   string `json:"role,omitempty"`
	User   string `json:"user,omitempty"`
}
