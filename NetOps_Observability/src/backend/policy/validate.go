package policy

// validate.go enforces the zero-trust write path: no override may be stored
// until it satisfies (a) its setting's Kind, (b) its Constraint bounds, and
// (c) the monotonic Harden rule against the value inherited from higher scopes.
// Resolution (resolve.go) re-applies the same Harden/lock invariants at read
// time, so a later tightening of a parent scope can never be defeated by an
// override authored while the parent was weaker.

import (
	"fmt"
	"slices"
)

// ValidationError describes why an override was rejected, carrying the offending
// key so the API/UI can attach the message to the right card.
type ValidationError struct {
	Key    string
	Reason string
}

func (e *ValidationError) Error() string { return e.Key + ": " + e.Reason }

func verr(key, format string, a ...any) *ValidationError {
	return &ValidationError{Key: key, Reason: fmt.Sprintf(format, a...)}
}

// ValidateValue checks a value against a setting's Kind and Constraint, ignoring
// hierarchy. It is the per-field gate used by both the write path and resolution.
func ValidateValue(s Setting, v Value) error {
	if v.Kind != s.Kind {
		return verr(s.Key, "value kind %q does not match setting kind %q", v.Kind, s.Kind)
	}
	switch s.Kind {
	case KindBool:
		return nil
	case KindInt, KindDuration:
		if s.Constraint.Min != nil && v.Num < *s.Constraint.Min {
			return verr(s.Key, "value %d below minimum %d", v.Num, *s.Constraint.Min)
		}
		if s.Constraint.Max != nil && v.Num > *s.Constraint.Max {
			return verr(s.Key, "value %d above maximum %d", v.Num, *s.Constraint.Max)
		}
		return nil
	case KindEnum:
		if !slices.Contains(s.Constraint.Enum, v.Str) {
			return verr(s.Key, "value %q is not one of the allowed options", v.Str)
		}
		return nil
	case KindList:
		seen := make(map[string]struct{}, len(v.List))
		for _, item := range v.List {
			if len(s.Constraint.Enum) > 0 && !slices.Contains(s.Constraint.Enum, item) {
				return verr(s.Key, "list member %q is not an allowed option", item)
			}
			if _, dup := seen[item]; dup {
				return verr(s.Key, "list member %q is duplicated", item)
			}
			seen[item] = struct{}{}
		}
		return nil
	}
	return verr(s.Key, "unknown setting kind %q", s.Kind)
}

// ValidateOverride checks a proposed override at scope `at` against the setting
// and the value inherited from higher (more general) scopes. `inherited` is the
// effective value that would apply if this override were absent — i.e. the
// resolution of all strictly-higher scopes. `inheritedLocked` reports whether a
// higher scope locked the setting, in which case no override at a lower scope is
// permitted at all.
func ValidateOverride(s Setting, at Scope, ov Override, inherited Value, inheritedLocked bool) error {
	if inheritedLocked {
		return verr(s.Key, "locked by a higher scope and cannot be overridden")
	}
	if ov.Locked && !s.Lockable {
		return verr(s.Key, "setting is not lockable")
	}
	if err := ValidateValue(s, ov.Value); err != nil {
		return err
	}
	// Monotonicity: a more specific scope may only make the control stricter.
	// The System scope establishes the baseline and is not bound by it.
	if at != ScopeSystem {
		if !atLeastAsStrict(s.Harden, ov.Value, inherited) {
			return verr(s.Key, "override would weaken the inherited policy (%s); a more specific scope may only tighten it",
				describeHarden(s.Harden))
		}
	}
	return nil
}

// atLeastAsStrict reports whether `candidate` is at least as strict as `base`
// under the setting's harden direction. HardenNone always permits.
func atLeastAsStrict(h Harden, candidate, base Value) bool {
	switch h {
	case HardenNone:
		return true
	case HardenHigher:
		// stricter = larger (Int/Duration) or true (Bool)
		switch candidate.Kind {
		case KindBool:
			return boolRank(candidate.Bool) >= boolRank(base.Bool)
		case KindInt, KindDuration:
			return candidate.Num >= base.Num
		}
	case HardenLower:
		// stricter = smaller (Int/Duration) or false (Bool)
		switch candidate.Kind {
		case KindBool:
			return boolRank(candidate.Bool) <= boolRank(base.Bool)
		case KindInt, KindDuration:
			return candidate.Num <= base.Num
		}
	}
	// Enum/List have no monotonic order — harden does not apply.
	return true
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func describeHarden(h Harden) string {
	switch h {
	case HardenHigher:
		return "may only be raised"
	case HardenLower:
		return "may only be lowered"
	default:
		return "is freely settable"
	}
}
