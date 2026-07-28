package main

import (
	"path/filepath"
	"testing"

	"netops/backend/policy"
)

// policy_store_test.go — Phase 2 store: persistence, tenant isolation, and the
// zero-trust write gate (delegating value/harden/lock checks to the engine,
// which is covered by policy/policy_test.go). These tests assert the store's
// own responsibilities: reference validation, the document chain it feeds the
// resolver, durable round-tripping, and override clear/prune.

const keyMinLen = "password.min_length" // KindInt, default 12, [8,128], Lockable, HardenHigher

func intOv(n int64, locked bool) policy.Override {
	return policy.Override{Value: policy.Value{Kind: policy.KindInt, Num: n}, Locked: locked}
}

func newTestPolicyStore(t *testing.T) *policy.SecurityStore {
	t.Helper()
	return policy.NewSecurityStore(filepath.Join(t.TempDir(), "security_policies.json"), platformKV{}, logError)
}

func resolvedFor(t *testing.T, s *policy.SecurityStore, sub policy.Subject, key string) policy.Resolved {
	t.Helper()
	r, ok := s.ResolveSetting(sub, key)
	if !ok {
		t.Fatalf("setting %q not in catalog", key)
	}
	return r
}

// An empty store resolves to the catalog default from the catalog source.
func TestPolicyStore_EmptyResolvesToDefault(t *testing.T) {
	s := newTestPolicyStore(t)
	r := resolvedFor(t, s, policy.Subject{Tenant: "acme", User: "alice"}, keyMinLen)
	if !r.FromDefault || r.Value.Num != 12 {
		t.Fatalf("want catalog default 12 from_default, got value=%d from_default=%v source=%s", r.Value.Num, r.FromDefault, r.Source)
	}
}

// A system override is the baseline every subject inherits.
func TestPolicyStore_SystemBaselineInherited(t *testing.T) {
	s := newTestPolicyStore(t)
	if _, err := s.SetOverride(policy.ScopeSystem, "", "", keyMinLen, intOv(14, false), "root"); err != nil {
		t.Fatalf("system set: %v", err)
	}
	r := resolvedFor(t, s, policy.Subject{Tenant: "acme", User: "alice"}, keyMinLen)
	if r.Value.Num != 14 || r.Source != policy.ScopeSystem || r.FromDefault {
		t.Fatalf("want 14 from system, got value=%d source=%s from_default=%v", r.Value.Num, r.Source, r.FromDefault)
	}
}

// A tenant may tighten above the system floor (HardenHigher), and that value
// wins for that tenant's subjects.
func TestPolicyStore_TenantTightensAndWins(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))
	mustSet(t, s, policy.ScopeTenant, "acme", "", keyMinLen, intOv(16, false))

	r := resolvedFor(t, s, policy.Subject{Tenant: "acme", User: "alice"}, keyMinLen)
	if r.Value.Num != 16 || r.Source != policy.ScopeTenant {
		t.Fatalf("want 16 from tenant, got value=%d source=%s", r.Value.Num, r.Source)
	}
}

// A tenant may NOT weaken below the inherited system floor — the engine's
// monotonic harden rule is enforced on the write path.
func TestPolicyStore_TenantCannotWeaken(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))
	if _, err := s.SetOverride(policy.ScopeTenant, "acme", "", keyMinLen, intOv(10, false), "tadmin"); err == nil {
		t.Fatal("expected rejection of a weakening tenant override, got nil")
	}
}

// A locked system setting cannot be overridden by a lower scope at all.
func TestPolicyStore_LockFreezesLowerScopes(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, true)) // locked
	if _, err := s.SetOverride(policy.ScopeTenant, "acme", "", keyMinLen, intOv(16, false), "tadmin"); err == nil {
		t.Fatal("expected rejection under a higher-scope lock, got nil")
	}
	// And resolution reports the lock.
	r := resolvedFor(t, s, policy.Subject{Tenant: "acme"}, keyMinLen)
	if !r.Locked || r.LockedAt != policy.ScopeSystem {
		t.Fatalf("want locked at system, got locked=%v at=%s", r.Locked, r.LockedAt)
	}
}

// One tenant's policy is invisible to another tenant's subjects.
func TestPolicyStore_TenantIsolation(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))
	mustSet(t, s, policy.ScopeTenant, "acme", "", keyMinLen, intOv(20, false))

	other := resolvedFor(t, s, policy.Subject{Tenant: "globex", User: "bob"}, keyMinLen)
	if other.Value.Num != 14 || other.Source != policy.ScopeSystem {
		t.Fatalf("tenant globex leaked acme policy: value=%d source=%s", other.Value.Num, other.Source)
	}
	// Documents listing is likewise tenant-scoped: globex sees system only.
	if docs := s.Documents("globex"); len(docs) != 1 || docs[0].Scope != policy.ScopeSystem {
		t.Fatalf("globex should see only the system document, got %d docs", len(docs))
	}
	if docs := s.Documents("acme"); len(docs) != 2 {
		t.Fatalf("acme should see system + its own document, got %d docs", len(docs))
	}
}

// Reference validation rejects structurally inconsistent scope references.
func TestPolicyStore_ReferenceValidation(t *testing.T) {
	s := newTestPolicyStore(t)
	cases := []struct {
		name             string
		scope            policy.Scope
		selector, tenant string
	}{
		{"system with selector", policy.ScopeSystem, "acme", ""},
		{"tenant without selector", policy.ScopeTenant, "", ""},
		{"role without tenant", policy.ScopeRole, "admin", ""},
		{"user without tenant", policy.ScopeUser, "alice", ""},
	}
	for _, c := range cases {
		if _, err := s.SetOverride(c.scope, c.selector, c.tenant, keyMinLen, intOv(16, false), "x"); err == nil {
			t.Errorf("%s: expected reference-validation error, got nil", c.name)
		}
	}
}

// Unknown catalog keys are rejected on the write path.
func TestPolicyStore_UnknownKeyRejected(t *testing.T) {
	s := newTestPolicyStore(t)
	if _, err := s.SetOverride(policy.ScopeSystem, "", "", "password.does_not_exist", intOv(1, false), "root"); err == nil {
		t.Fatal("expected unknown-key rejection, got nil")
	}
}

// Overrides survive a store restart (durable round-trip through the kv blob).
func TestPolicyStore_PersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security_policies.json")
	s1 := policy.NewSecurityStore(path, platformKV{}, logError)
	mustSet(t, s1, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))
	mustSet(t, s1, policy.ScopeTenant, "acme", "", keyMinLen, intOv(18, false))

	s2 := policy.NewSecurityStore(path, platformKV{}, logError)
	r := resolvedFor(t, s2, policy.Subject{Tenant: "acme"}, keyMinLen)
	if r.Value.Num != 18 || r.Source != policy.ScopeTenant {
		t.Fatalf("reloaded store lost tenant override: value=%d source=%s", r.Value.Num, r.Source)
	}
}

// Clearing an override reverts the setting to its inherited value; pruneEmpty
// removes the now-empty document entirely.
func TestPolicyStore_ClearOverride(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))
	mustSet(t, s, policy.ScopeTenant, "acme", "", keyMinLen, intOv(18, false))

	if err := s.ClearOverride(policy.ScopeTenant, "acme", "", keyMinLen, "tadmin", true); err != nil {
		t.Fatalf("clear: %v", err)
	}
	r := resolvedFor(t, s, policy.Subject{Tenant: "acme"}, keyMinLen)
	if r.Value.Num != 14 || r.Source != policy.ScopeSystem {
		t.Fatalf("after clear want inherited 14 from system, got value=%d source=%s", r.Value.Num, r.Source)
	}
	if docs := s.Documents("acme"); len(docs) != 1 { // only the system doc remains
		t.Fatalf("pruneEmpty should have removed the empty tenant doc, got %d docs", len(docs))
	}
}

// A returned Document is a copy: mutating it must not affect stored state.
func TestPolicyStore_DocumentReturnsCopy(t *testing.T) {
	s := newTestPolicyStore(t)
	mustSet(t, s, policy.ScopeSystem, "", "", keyMinLen, intOv(14, false))

	d, found, err := s.Document(policy.ScopeSystem, "", "")
	if err != nil || !found {
		t.Fatalf("document: found=%v err=%v", found, err)
	}
	d.Overrides[keyMinLen] = intOv(99, false) // tamper with the returned copy
	r := resolvedFor(t, s, policy.Subject{}, keyMinLen)
	if r.Value.Num != 14 {
		t.Fatalf("store mutated through returned copy: got %d", r.Value.Num)
	}
}

func mustSet(t *testing.T, s *policy.SecurityStore, scope policy.Scope, selector, tenant, key string, ov policy.Override) {
	t.Helper()
	if _, err := s.SetOverride(scope, selector, tenant, key, ov, "tester"); err != nil {
		t.Fatalf("set %s@%s/%s: %v", key, scope, selector, err)
	}
}
