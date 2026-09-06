// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package policy

// resolve.go is the deterministic resolution engine. Given the catalog, the set
// of override Documents in play, and the Subject (tenant/role/user) being
// resolved, it walks the hierarchy System → Tenant → Role → User and produces,
// for every setting, the effective value plus a full inheritance trail. The walk
// re-applies the lock and harden invariants at read time, so the result is
// correct even if a parent scope was tightened after a child override was
// authored. The same catalog + same documents + same subject always yield the
// identical Resolution — there is no map iteration or wall-clock dependence.

// TrailStep records what one scope contributed during resolution. Applied is
// true when this scope's value became (or remained) the effective value; false
// when the override was ignored (locked above), clamped (would weaken), or
// invalid. Note explains a non-applied step in human-readable terms.
type TrailStep struct {
	Scope    Scope  `json:"scope"`
	Selector string `json:"selector,omitempty"`
	Value    Value  `json:"value"`
	Locked   bool   `json:"locked,omitempty"`
	Applied  bool   `json:"applied"`
	Note     string `json:"note,omitempty"`
}

// Resolved is the effective outcome for one setting. Source is the scope that
// supplied the effective value (empty when it falls back to the catalog default,
// in which case FromDefault is true). Locked/LockedAt report whether a scope has
// frozen the setting against more-specific overrides. Trail is the ordered list
// of every scope that authored an override for this key.
type Resolved struct {
	Key         string      `json:"key"`
	Domain      Domain      `json:"domain"`
	Value       Value       `json:"value"`
	Source      Scope       `json:"source,omitempty"`
	FromDefault bool        `json:"from_default"`
	Locked      bool        `json:"locked,omitempty"`
	LockedAt    Scope       `json:"locked_at,omitempty"`
	Trail       []TrailStep `json:"trail,omitempty"`
}

// selectorFor returns the document selector a subject uses at a given scope.
// System is global (""); the others key off the subject's tenant/role/user.
func selectorFor(sub Subject, scope Scope) string {
	switch scope {
	case ScopeSystem:
		return ""
	case ScopeTenant:
		return sub.Tenant
	case ScopeRole:
		return sub.Role
	case ScopeUser:
		return sub.User
	}
	return ""
}

// findDoc returns the document authored at (scope, selector), or nil. The store
// is responsible for handing in only documents the caller is allowed to see
// (tenant isolation); the engine simply matches.
func findDoc(docs []Document, scope Scope, selector string) *Document {
	for i := range docs {
		if docs[i].Scope == scope && docs[i].Selector == selector {
			return &docs[i]
		}
	}
	return nil
}

// resolveKey resolves a single setting against the documents for a subject.
func resolveKey(s Setting, docs []Document, sub Subject) Resolved {
	r := Resolved{
		Key:         s.Key,
		Domain:      s.Domain,
		Value:       s.Default,
		FromDefault: true,
	}
	var locked bool
	var lockedAt Scope

	for _, scope := range scopeOrder {
		sel := selectorFor(sub, scope)
		if scope != ScopeSystem && sel == "" {
			continue // the subject has no instance at this level
		}
		doc := findDoc(docs, scope, sel)
		if doc == nil {
			continue
		}
		ov, has := doc.Overrides[s.Key]
		if !has {
			continue
		}
		step := TrailStep{Scope: scope, Selector: sel, Value: ov.Value, Locked: ov.Locked}

		switch {
		case locked:
			step.Applied = false
			step.Note = "ignored — locked at " + string(lockedAt)
		case ValidateValue(s, ov.Value) != nil:
			step.Applied = false
			step.Note = "ignored — value outside constraint"
		case scope != ScopeSystem && !atLeastAsStrict(s.Harden, ov.Value, r.Value):
			// The override would weaken the inherited policy; the stricter
			// inherited value is retained and this step is reported as clamped.
			step.Applied = false
			step.Note = "clamped — would weaken inherited policy"
		default:
			r.Value = ov.Value
			r.Source = scope
			r.FromDefault = false
			step.Applied = true
		}

		// A lockable, locked override freezes the setting from here down even if
		// its own value was clamped to the stricter inherited value.
		if ov.Locked && s.Lockable && step.Note != "ignored — value outside constraint" && !locked {
			locked = true
			lockedAt = scope
		}
		r.Trail = append(r.Trail, step)
	}

	r.Locked = locked
	r.LockedAt = lockedAt
	return r
}

// Resolve resolves every catalog setting for a subject, returning results in
// stable catalog order (grouped by domain). This is the single entry point used
// by the API for the effective-policy view and the Policy Simulator.
func Resolve(cat *Catalog, docs []Document, sub Subject) []Resolved {
	all := cat.All()
	out := make([]Resolved, len(all))
	for i, s := range all {
		out[i] = resolveKey(s, docs, sub)
	}
	return out
}

// ResolveSetting resolves a single setting by key. Ok is false if the key is not
// in the catalog.
func ResolveSetting(cat *Catalog, key string, docs []Document, sub Subject) (Resolved, bool) {
	s, ok := cat.Setting(key)
	if !ok {
		return Resolved{}, false
	}
	return resolveKey(s, docs, sub), true
}

// InheritedValue computes the effective value a setting would have for a subject
// considering only scopes strictly *higher* (more general) than `at`. It is the
// baseline the write path validates a new override against (see ValidateOverride)
// and reports whether a higher scope has locked the setting.
func InheritedValue(cat *Catalog, key string, docs []Document, sub Subject, at Scope) (value Value, locked bool, ok bool) {
	s, found := cat.Setting(key)
	if !found {
		return Value{}, false, false
	}
	// Build a subject that only carries the levels above `at` so resolveKey
	// naturally ignores `at` and everything below it.
	higher := Subject{}
	for _, scope := range scopeOrder {
		if scope.Rank() >= at.Rank() {
			break
		}
		switch scope {
		case ScopeTenant:
			higher.Tenant = sub.Tenant
		case ScopeRole:
			higher.Role = sub.Role
		case ScopeUser:
			higher.User = sub.User
		}
	}
	r := resolveKey(s, docs, higher)
	return r.Value, r.Locked, true
}
