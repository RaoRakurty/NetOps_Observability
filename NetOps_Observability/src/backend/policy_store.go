package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/policy"
)

// policy_store.go — Phase 2 of the Security Policy Configuration System.
//
// Phase 1 (the `policy` package) is the pure, I/O-free engine: the catalog, the
// typed value/constraint model, the zero-trust write validator and the
// deterministic resolver. It deliberately never touches storage — "the server
// injects a Source". This file is that Source: the persistence + tenancy layer
// that owns the per-scope override Documents, enforces tenant isolation on every
// read and write, runs each proposed override through the engine's validator
// before it is stored, and feeds the resolver the exact document chain a subject
// is entitled to see.
//
// Design (CLAUDE.md guardrails):
//   - Modular & injectable: the engine stays pure; this store is the only thing
//     that knows about kv persistence and tenancy. No hidden coupling.
//   - Zero-trust at the boundary: a write is rejected unless its (scope,
//     selector, tenant) reference is internally consistent AND the override
//     passes policy.ValidateOverride against the value inherited from higher
//     scopes. Unknown catalog keys are rejected.
//   - Tenant isolation: a subject only ever resolves against the global System
//     document plus documents tagged with its own tenant. A tenant can never
//     read or write another tenant's policy through this store.
//   - Persistence parity: like every other identity store, the whole collection
//     is marshalled to a single JSON blob through the kvBackend seam, so the
//     file→Postgres swap (STORE_BACKEND=postgres) needs no change here.
//
// No HTTP wiring lives here — the admin API + Policy Simulator endpoints are
// Phase 3; the React UI is Phase 4. This file is unreferenced by the server
// until then, exactly as Phase 1 was.

// securityPolicyStore persists the security-policy override Documents and is the
// engine's Source. It is safe for concurrent use.
type securityPolicyStore struct {
	mu      sync.RWMutex
	catalog *policy.Catalog
	docs    map[string]policy.Document // keyed by docKey(scope, tenant, selector)
	path    string
	now     func() time.Time // injectable clock; defaults to time.Now (UTC stamped at use)
}

// newSecurityPolicyStore builds the store over the built-in catalog and loads
// any persisted documents from path.
func newSecurityPolicyStore(path string) *securityPolicyStore {
	s := &securityPolicyStore{
		catalog: policy.BuiltinCatalog(),
		docs:    make(map[string]policy.Document),
		path:    path,
		now:     time.Now,
	}
	s.load()
	return s
}

// docKey is the in-memory index key. Selector alone is ambiguous across tenants
// (two tenants may each have a role "admin" or a user "alice"), so the owning
// tenant is part of the key. System documents are global: tenant and selector
// are both empty.
func docKey(scope policy.Scope, tenant, selector string) string {
	return string(scope) + "\x1f" + tenant + "\x1f" + selector
}

// load reads the persisted document collection. A missing key is an empty store,
// not an error (mirrors the other kv-backed stores).
func (s *securityPolicyStore) load() {
	b, err := kvLoad(s.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logError("policy.store", "load", errf(err))
		}
		return
	}
	if len(b) == 0 {
		return
	}
	var docs []policy.Document
	if err := json.Unmarshal(b, &docs); err != nil {
		logError("policy.store", "unmarshal", errf(err))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range docs {
		if d.Overrides == nil {
			d.Overrides = map[string]policy.Override{}
		}
		s.docs[docKey(d.Scope, d.Tenant, d.Selector)] = d
	}
}

// snapshotLocked returns the documents as a deterministically ordered slice
// (scope rank, then tenant, then selector) so the persisted blob is stable
// across writes and diffs cleanly. Caller holds the lock.
func (s *securityPolicyStore) snapshotLocked() []policy.Document {
	out := make([]policy.Document, 0, len(s.docs))
	for _, d := range s.docs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].Scope.Rank(), out[j].Scope.Rank(); a != b {
			return a < b
		}
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Selector < out[j].Selector
	})
	return out
}

// flushLocked persists the current collection. Caller holds the lock.
func (s *securityPolicyStore) flushLocked() error {
	b, err := json.MarshalIndent(s.snapshotLocked(), "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// ---------------------------------------------------------------------------
// Reference normalisation + subject derivation
// ---------------------------------------------------------------------------

// normalizeRef validates and canonicalises a (scope, selector, tenant) document
// reference. It enforces the structural tenancy invariants that hold regardless
// of who is calling — authorization (who may write which scope) is the HTTP
// layer's job in Phase 3; this is the structural floor below it.
//
//   - System: global; selector and tenant must be empty.
//   - Tenant: selector is the tenant id; the owning tenant is set equal to it.
//   - Role:   selector is the role; an owning tenant is required.
//   - User:   selector is the username; an owning tenant is required.
func normalizeRef(scope policy.Scope, selector, tenant string) (sel, ten string, err error) {
	selector = strings.TrimSpace(selector)
	tenant = strings.TrimSpace(tenant)
	switch scope {
	case policy.ScopeSystem:
		if selector != "" || tenant != "" {
			return "", "", errors.New("policy: system scope is global and takes no selector/tenant")
		}
		return "", "", nil
	case policy.ScopeTenant:
		if selector == "" {
			return "", "", errors.New("policy: tenant scope requires a tenant selector")
		}
		// The tenant document's owning tenant is the tenant itself.
		return selector, selector, nil
	case policy.ScopeRole:
		if selector == "" || tenant == "" {
			return "", "", errors.New("policy: role scope requires a role selector and an owning tenant")
		}
		return selector, tenant, nil
	case policy.ScopeUser:
		if selector == "" || tenant == "" {
			return "", "", errors.New("policy: user scope requires a user selector and an owning tenant")
		}
		return selector, tenant, nil
	default:
		return "", "", fmt.Errorf("policy: unknown scope %q", scope)
	}
}

// subjectForRef builds the resolution Subject a given document reference belongs
// to. A user-scope reference carries no role (a user's role is contextual and
// not part of the document key); the inherited baseline a user override is
// validated against therefore considers System + Tenant only. This is safe: the
// resolver re-applies the harden/lock invariants at read time against the live
// subject's real role, so a user override that slips past the System+Tenant gate
// but is weaker than the user's role policy is simply clamped when resolved.
func subjectForRef(scope policy.Scope, selector, tenant string) policy.Subject {
	switch scope {
	case policy.ScopeTenant:
		return policy.Subject{Tenant: selector}
	case policy.ScopeRole:
		return policy.Subject{Tenant: tenant, Role: selector}
	case policy.ScopeUser:
		return policy.Subject{Tenant: tenant, User: selector}
	default: // System
		return policy.Subject{}
	}
}

// chainForLocked returns the tenant-isolated document chain a subject resolves
// against: the global System document plus the subject's own tenant/role/user
// documents. Documents tagged with any other tenant are never returned, which is
// the read-side isolation guarantee. Caller holds (at least) the read lock.
func (s *securityPolicyStore) chainForLocked(sub policy.Subject) []policy.Document {
	var chain []policy.Document
	add := func(scope policy.Scope, tenant, selector string) {
		if d, ok := s.docs[docKey(scope, tenant, selector)]; ok {
			chain = append(chain, d)
		}
	}
	add(policy.ScopeSystem, "", "")
	if sub.Tenant != "" {
		add(policy.ScopeTenant, sub.Tenant, sub.Tenant)
		if sub.Role != "" {
			add(policy.ScopeRole, sub.Tenant, sub.Role)
		}
		if sub.User != "" {
			add(policy.ScopeUser, sub.Tenant, sub.User)
		}
	}
	return chain
}

// ---------------------------------------------------------------------------
// Read API (consumed by the Phase 3 effective-policy view + Policy Simulator)
// ---------------------------------------------------------------------------

// Catalog exposes the immutable built-in catalog so the API can render the
// self-describing setting cards.
func (s *securityPolicyStore) Catalog() *policy.Catalog { return s.catalog }

// Resolve returns the effective policy for a subject: every catalog setting with
// its effective value, source scope and full inheritance trail. Deterministic.
func (s *securityPolicyStore) Resolve(sub policy.Subject) []policy.Resolved {
	s.mu.RLock()
	chain := s.chainForLocked(sub)
	s.mu.RUnlock()
	return policy.Resolve(s.catalog, chain, sub)
}

// ResolveSetting resolves a single setting for a subject. ok is false when key
// is not in the catalog.
func (s *securityPolicyStore) ResolveSetting(sub policy.Subject, key string) (policy.Resolved, bool) {
	s.mu.RLock()
	chain := s.chainForLocked(sub)
	s.mu.RUnlock()
	return policy.ResolveSetting(s.catalog, key, chain, sub)
}

// Document returns the raw overrides authored at one scope (for the editing UI).
// found is false when no document exists there yet; the returned zero Document
// then carries an initialised (empty) Overrides map so callers can render an
// empty editor without a nil check.
func (s *securityPolicyStore) Document(scope policy.Scope, selector, tenant string) (policy.Document, bool, error) {
	sel, ten, err := normalizeRef(scope, selector, tenant)
	if err != nil {
		return policy.Document{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.docs[docKey(scope, ten, sel)]
	if !ok {
		return policy.Document{Scope: scope, Selector: sel, Tenant: ten, Overrides: map[string]policy.Override{}}, false, nil
	}
	return cloneDocument(d), true, nil
}

// Documents lists the documents a tenant is entitled to see: the global System
// document plus every document owned by that tenant (tenant/role/user scopes).
// An empty tenant returns only the System document. The result is in stable
// snapshot order. This is the tenant-scoped admin listing used by Phase 3.
func (s *securityPolicyStore) Documents(tenant string) []policy.Document {
	tenant = strings.TrimSpace(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []policy.Document
	for _, d := range s.snapshotLocked() {
		if d.Scope == policy.ScopeSystem || d.Tenant == tenant {
			out = append(out, cloneDocument(d))
		}
	}
	return out
}

// AllDocuments returns every stored document (deep-copied, stable order). This
// is the cross-tenant listing reserved for the platform owner; tenant-scoped
// callers must use Documents(tenant), which never crosses the tenant boundary.
func (s *securityPolicyStore) AllDocuments() []policy.Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := s.snapshotLocked()
	out := make([]policy.Document, len(snap))
	for i, d := range snap {
		out[i] = cloneDocument(d)
	}
	return out
}

// ---------------------------------------------------------------------------
// Write API (zero-trust: validate against inherited policy, then persist)
// ---------------------------------------------------------------------------

// Validate runs the full write gate for a proposed override WITHOUT persisting:
// reference consistency, catalog membership, kind/constraint bounds, and the
// monotonic harden rule against the value inherited from higher scopes. It backs
// both SetOverride and the UI's pre-flight ("would this be accepted?").
func (s *securityPolicyStore) Validate(scope policy.Scope, selector, tenant, key string, ov policy.Override) error {
	sel, ten, err := normalizeRef(scope, selector, tenant)
	if err != nil {
		return err
	}
	setting, ok := s.catalog.Setting(key)
	if !ok {
		return fmt.Errorf("policy: unknown setting %q", key)
	}
	sub := subjectForRef(scope, sel, ten)
	s.mu.RLock()
	chain := s.chainForLocked(sub)
	s.mu.RUnlock()
	inherited, inheritedLocked, ok := policy.InheritedValue(s.catalog, key, chain, sub, scope)
	if !ok {
		return fmt.Errorf("policy: unknown setting %q", key)
	}
	return policy.ValidateOverride(setting, scope, ov, inherited, inheritedLocked)
}

// SetOverride validates and persists a single override at one scope, stamping
// the document's audit fields, and returns the setting's newly resolved value at
// that scope. actor is recorded as the author.
func (s *securityPolicyStore) SetOverride(scope policy.Scope, selector, tenant, key string, ov policy.Override, actor string) (policy.Resolved, error) {
	sel, ten, err := normalizeRef(scope, selector, tenant)
	if err != nil {
		return policy.Resolved{}, err
	}
	setting, ok := s.catalog.Setting(key)
	if !ok {
		return policy.Resolved{}, fmt.Errorf("policy: unknown setting %q", key)
	}
	sub := subjectForRef(scope, sel, ten)

	s.mu.Lock()
	defer s.mu.Unlock()

	chain := s.chainForLocked(sub)
	inherited, inheritedLocked, ok := policy.InheritedValue(s.catalog, key, chain, sub, scope)
	if !ok {
		return policy.Resolved{}, fmt.Errorf("policy: unknown setting %q", key)
	}
	if err := policy.ValidateOverride(setting, scope, ov, inherited, inheritedLocked); err != nil {
		return policy.Resolved{}, err
	}

	k := docKey(scope, ten, sel)
	prev, existed := s.docs[k]
	// Mutate a clone so stored maps are never aliased and a flush failure can be
	// rolled back to the exact prior state.
	next := cloneDocument(prev)
	next.Scope, next.Selector, next.Tenant = scope, sel, ten
	next.Overrides[key] = ov
	next.UpdatedAt = s.now().UTC().Format(time.RFC3339)
	next.UpdatedBy = strings.TrimSpace(actor)
	s.docs[k] = next

	if err := s.flushLocked(); err != nil {
		if existed {
			s.docs[k] = prev
		} else {
			delete(s.docs, k)
		}
		return policy.Resolved{}, err
	}

	r, _ := policy.ResolveSetting(s.catalog, key, s.chainForLocked(sub), sub)
	return r, nil
}

// ClearOverride removes a single override at one scope, reverting that setting to
// its inherited value. Removing the last override leaves an empty document on
// record (still tenant-tagged) so its audit trail is preserved; pass pruneEmpty
// to delete the document entirely when it becomes empty.
func (s *securityPolicyStore) ClearOverride(scope policy.Scope, selector, tenant, key, actor string, pruneEmpty bool) error {
	sel, ten, err := normalizeRef(scope, selector, tenant)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := docKey(scope, ten, sel)
	prev, ok := s.docs[k]
	if !ok {
		return nil // nothing to clear is not an error
	}
	if _, present := prev.Overrides[key]; !present {
		return nil
	}
	// Mutate a clone so a flush failure rolls back cleanly.
	next := cloneDocument(prev)
	delete(next.Overrides, key)
	if pruneEmpty && len(next.Overrides) == 0 {
		delete(s.docs, k)
	} else {
		next.UpdatedAt = s.now().UTC().Format(time.RFC3339)
		next.UpdatedBy = strings.TrimSpace(actor)
		s.docs[k] = next
	}
	if err := s.flushLocked(); err != nil {
		s.docs[k] = prev
		return err
	}
	return nil
}

// cloneDocument returns a deep copy so callers cannot mutate stored state through
// the returned map (the maps are otherwise shared by reference).
func cloneDocument(d policy.Document) policy.Document {
	ov := make(map[string]policy.Override, len(d.Overrides))
	for k, v := range d.Overrides {
		ov[k] = v
	}
	d.Overrides = ov
	return d
}
