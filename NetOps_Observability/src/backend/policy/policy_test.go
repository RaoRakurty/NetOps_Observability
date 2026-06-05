package policy

import (
	"reflect"
	"testing"
)

// doc is a tiny constructor for a scope document in tests.
func doc(scope Scope, selector string, ov map[string]Override) Document {
	return Document{Scope: scope, Selector: selector, Overrides: ov}
}

func find(rs []Resolved, key string) Resolved {
	for _, r := range rs {
		if r.Key == key {
			return r
		}
	}
	return Resolved{}
}

// Every catalog default must satisfy its own constraint — a baseline that
// violates its bounds would be unresolvable.
func TestCatalogDefaultsAreValid(t *testing.T) {
	cat := BuiltinCatalog()
	for _, s := range cat.All() {
		if err := ValidateValue(s, s.Default); err != nil {
			t.Errorf("%s: default fails its own constraint: %v", s.Key, err)
		}
		if s.Default.Kind != s.Kind {
			t.Errorf("%s: default kind %q != setting kind %q", s.Key, s.Default.Kind, s.Kind)
		}
	}
}

func TestScopeRankOrder(t *testing.T) {
	if ScopeSystem.Rank() != 0 || ScopeUser.Rank() != 3 {
		t.Fatalf("scope ranks drifted: system=%d user=%d", ScopeSystem.Rank(), ScopeUser.Rank())
	}
	if !(ScopeSystem.Rank() < ScopeTenant.Rank() &&
		ScopeTenant.Rank() < ScopeRole.Rank() &&
		ScopeRole.Rank() < ScopeUser.Rank()) {
		t.Fatal("scope order is not strictly increasing")
	}
}

// Precedence: with no overrides we get the default; each more-specific scope
// that tightens wins over the one above it.
func TestResolvePrecedence(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme", Role: "ops", User: "alice"}

	// No documents → default (12).
	r := find(Resolve(cat, nil, sub), "password.min_length")
	if r.Value.Num != 12 || !r.FromDefault || r.Source != "" {
		t.Fatalf("default: got value=%d source=%q fromDefault=%v", r.Value.Num, r.Source, r.FromDefault)
	}

	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"password.min_length": {Value: intV(14)}}),
		doc(ScopeTenant, "acme", map[string]Override{"password.min_length": {Value: intV(16)}}),
		doc(ScopeRole, "ops", map[string]Override{"password.min_length": {Value: intV(20)}}),
		doc(ScopeUser, "alice", map[string]Override{"password.min_length": {Value: intV(24)}}),
	}
	r = find(Resolve(cat, docs, sub), "password.min_length")
	if r.Value.Num != 24 || r.Source != ScopeUser || r.FromDefault {
		t.Fatalf("user precedence: got value=%d source=%q", r.Value.Num, r.Source)
	}
	// Trail records all four scopes, all applied (each tightens).
	if len(r.Trail) != 4 {
		t.Fatalf("expected 4 trail steps, got %d", len(r.Trail))
	}
	for _, step := range r.Trail {
		if !step.Applied {
			t.Errorf("step %s should be applied: %s", step.Scope, step.Note)
		}
	}
}

// HardenHigher (min length): a lower scope may raise the floor but a weaker
// override is clamped to the inherited stricter value.
func TestHardenHigherClampsWeakening(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme"}
	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"password.min_length": {Value: intV(12)}}),
		doc(ScopeTenant, "acme", map[string]Override{"password.min_length": {Value: intV(8)}}),
	}
	r := find(Resolve(cat, docs, sub), "password.min_length")
	if r.Value.Num != 12 {
		t.Fatalf("weakening should clamp to 12, got %d", r.Value.Num)
	}
	if r.Source != ScopeSystem {
		t.Fatalf("effective source should remain system, got %q", r.Source)
	}
	tenantStep := r.Trail[len(r.Trail)-1]
	if tenantStep.Applied || tenantStep.Note == "" {
		t.Fatalf("tenant step should be clamped with a note, got applied=%v note=%q", tenantStep.Applied, tenantStep.Note)
	}
}

// HardenLower (idle timeout): a lower scope may shorten but not lengthen.
func TestHardenLowerClampsLengthening(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme"}
	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"session.idle_timeout": {Value: durV(mins(30))}}),
		doc(ScopeTenant, "acme", map[string]Override{"session.idle_timeout": {Value: durV(mins(60))}}),
	}
	r := find(Resolve(cat, docs, sub), "session.idle_timeout")
	if r.Value.Num != mins(30) {
		t.Fatalf("lengthening should clamp to 30m (%d s), got %d", mins(30), r.Value.Num)
	}

	// Shortening is allowed.
	docs[1] = doc(ScopeTenant, "acme", map[string]Override{"session.idle_timeout": {Value: durV(mins(10))}})
	r = find(Resolve(cat, docs, sub), "session.idle_timeout")
	if r.Value.Num != mins(10) || r.Source != ScopeTenant {
		t.Fatalf("shortening should apply 10m, got %d source=%q", r.Value.Num, r.Source)
	}
}

// Bool HardenHigher (mfa_required): false→true tightens; true→false is clamped.
func TestHardenBool(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme"}

	// system false, tenant true → true.
	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"authentication.mfa_required": {Value: boolV(false)}}),
		doc(ScopeTenant, "acme", map[string]Override{"authentication.mfa_required": {Value: boolV(true)}}),
	}
	if r := find(Resolve(cat, docs, sub), "authentication.mfa_required"); !r.Value.Bool || r.Source != ScopeTenant {
		t.Fatalf("tenant should enable MFA, got %v source=%q", r.Value.Bool, r.Source)
	}

	// system true, tenant false → stays true (clamped).
	docs = []Document{
		doc(ScopeSystem, "", map[string]Override{"authentication.mfa_required": {Value: boolV(true)}}),
		doc(ScopeTenant, "acme", map[string]Override{"authentication.mfa_required": {Value: boolV(false)}}),
	}
	if r := find(Resolve(cat, docs, sub), "authentication.mfa_required"); !r.Value.Bool {
		t.Fatal("tenant must not be able to disable system-required MFA")
	}
}

// A lockable, locked override at a higher scope freezes lower overrides.
func TestLockFreezesLowerScopes(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme", Role: "ops"}
	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"password.min_length": {Value: intV(16), Locked: true}}),
		doc(ScopeTenant, "acme", map[string]Override{"password.min_length": {Value: intV(20)}}),
	}
	r := find(Resolve(cat, docs, sub), "password.min_length")
	if r.Value.Num != 16 {
		t.Fatalf("lock should pin value to 16, got %d", r.Value.Num)
	}
	if !r.Locked || r.LockedAt != ScopeSystem {
		t.Fatalf("expected locked at system, got locked=%v at=%q", r.Locked, r.LockedAt)
	}
	last := r.Trail[len(r.Trail)-1]
	if last.Scope != ScopeTenant || last.Applied {
		t.Fatalf("tenant override should be ignored under lock, got %+v", last)
	}
}

// ValidateOverride is the write-path gate.
func TestValidateOverride(t *testing.T) {
	cat := BuiltinCatalog()
	s, _ := cat.Setting("password.min_length")

	// Weakening below the inherited value is rejected at a non-system scope.
	if err := ValidateOverride(s, ScopeTenant, Override{Value: intV(8)}, intV(12), false); err == nil {
		t.Error("expected weakening (8 < 12) to be rejected")
	}
	// Tightening is accepted.
	if err := ValidateOverride(s, ScopeTenant, Override{Value: intV(16)}, intV(12), false); err != nil {
		t.Errorf("tightening (16 >= 12) should be accepted, got %v", err)
	}
	// Out-of-constraint is rejected regardless of hierarchy.
	if err := ValidateOverride(s, ScopeSystem, Override{Value: intV(200)}, Value{}, false); err == nil {
		t.Error("expected value above max (200 > 128) to be rejected")
	}
	// A lock above forbids any override.
	if err := ValidateOverride(s, ScopeTenant, Override{Value: intV(20)}, intV(16), true); err == nil {
		t.Error("expected override under a higher lock to be rejected")
	}
	// System scope establishes the baseline and is not bound by harden.
	if err := ValidateOverride(s, ScopeSystem, Override{Value: intV(8)}, intV(12), false); err != nil {
		t.Errorf("system baseline should not be harden-bound, got %v", err)
	}

	// Non-lockable setting cannot be locked.
	ns, _ := cat.Setting("password.history_depth")
	if err := ValidateOverride(ns, ScopeTenant, Override{Value: intV(6), Locked: true}, intV(5), false); err == nil {
		t.Error("expected locking a non-lockable setting to be rejected")
	}
}

func TestValidateValueEnumAndList(t *testing.T) {
	cat := BuiltinCatalog()
	s, _ := cat.Setting("authentication.allowed_methods")

	if err := ValidateValue(s, listV("password", "oidc")); err != nil {
		t.Errorf("valid list rejected: %v", err)
	}
	if err := ValidateValue(s, listV("password", "carrierpigeon")); err == nil {
		t.Error("expected unknown list member to be rejected")
	}
	if err := ValidateValue(s, listV("password", "password")); err == nil {
		t.Error("expected duplicate list member to be rejected")
	}
}

// InheritedValue must reflect only scopes above the target.
func TestInheritedValue(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme", Role: "ops", User: "alice"}
	docs := []Document{
		doc(ScopeSystem, "", map[string]Override{"password.min_length": {Value: intV(12)}}),
		doc(ScopeTenant, "acme", map[string]Override{"password.min_length": {Value: intV(16)}}),
		doc(ScopeRole, "ops", map[string]Override{"password.min_length": {Value: intV(20)}}),
	}
	// Inherited at the role scope should see system+tenant only (16), not role.
	v, locked, ok := InheritedValue(cat, "password.min_length", docs, sub, ScopeRole)
	if !ok || v.Num != 16 || locked {
		t.Fatalf("inherited at role: got value=%d locked=%v ok=%v", v.Num, locked, ok)
	}
	// Inherited at the user scope should see through role (20).
	v, _, _ = InheritedValue(cat, "password.min_length", docs, sub, ScopeUser)
	if v.Num != 20 {
		t.Fatalf("inherited at user: expected 20, got %d", v.Num)
	}
}

// Resolution must be deterministic and order-stable.
func TestResolveDeterministic(t *testing.T) {
	cat := BuiltinCatalog()
	sub := Subject{Tenant: "acme", Role: "ops", User: "alice"}
	docs := []Document{
		doc(ScopeUser, "alice", map[string]Override{"session.idle_timeout": {Value: durV(mins(5))}}),
		doc(ScopeSystem, "", map[string]Override{"password.min_length": {Value: intV(14)}}),
		doc(ScopeTenant, "acme", map[string]Override{"authentication.mfa_required": {Value: boolV(true)}}),
	}
	a := Resolve(cat, docs, sub)
	b := Resolve(cat, docs, sub)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("resolution is not deterministic")
	}
	// Stable catalog order: index 0 is the first catalog setting both times.
	if a[0].Key != cat.All()[0].Key {
		t.Fatal("resolution order does not match catalog order")
	}
}
