package bgpwatch

// state.go — the per-tenant ALERT POLICY: which origins a tenant expects to
// announce its prefixes, which upstreams it buys transit from, and the two
// thresholds. It is the small, MUTABLE control-plane half of this feature (the
// evaluated verdicts themselves are derived, never stored), so it follows the
// bgp_ops.go watchlist pattern exactly: two backends behind ONE interface —
// pgStore on Postgres (migration 0041, tenant_iso FORCE-RLS through the
// injected WithTenant seam) and FileStore everywhere else.
//
// Isolation lives IN the store (§3a rule 4): Postgres by the RLS policy, the
// file backend by a tenant-keyed map. Neither has an unscoped "list all" — not
// even an internal one — and every method refuses "" and "*" outright, so a
// mis-scoped caller reads and writes NOTHING rather than everything.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// Store bounds (§9 — operator input is still bounded input).
const (
	// MaxPolicyPrefixes caps how many per-prefix overrides one tenant may hold.
	MaxPolicyPrefixes = 200
	// MaxPolicyBytes caps one tenant's serialized policy.
	MaxPolicyBytes = 64 << 10
)

// TenantPolicy is one tenant's declared intent.
type TenantPolicy struct {
	// Default applies to every watched prefix with no per-prefix override.
	Default PolicyConfig `json:"default"`
	// Prefixes are per-prefix overrides, keyed by the canonical prefix.
	Prefixes map[string]PolicyConfig `json:"prefixes,omitempty"`

	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// For returns the effective config for one prefix: the override when present,
// otherwise the tenant default, always with the shipped thresholds filled in.
func (p TenantPolicy) For(prefix string) PolicyConfig {
	if c, ok := p.Prefixes[prefix]; ok {
		// A per-prefix override that leaves a threshold unset inherits the
		// tenant default's — an override is a NARROWING, never a reset.
		if c.MinVisibility <= 0 {
			c.MinVisibility = p.Default.MinVisibility
		}
		if c.MinVantages <= 0 {
			c.MinVantages = p.Default.MinVantages
		}
		return c.withDefaults()
	}
	return p.Default.withDefaults()
}

// Normalize validates and bounds an operator-supplied policy. It is the ONE
// place caller input becomes a stored policy, and it is fail-closed: an
// unparsable ASN or an unparsable prefix is an ERROR, never a dropped field
// that would silently widen or narrow what gets alerted on.
func (p TenantPolicy) Normalize() (TenantPolicy, error) {
	out := TenantPolicy{Prefixes: map[string]PolicyConfig{}}
	def, err := normalizeConfig(p.Default)
	if err != nil {
		return TenantPolicy{}, fmt.Errorf("default policy: %w", err)
	}
	out.Default = def
	if len(p.Prefixes) > MaxPolicyPrefixes {
		return TenantPolicy{}, fmt.Errorf("at most %d per-prefix policies are allowed (%d supplied)", MaxPolicyPrefixes, len(p.Prefixes))
	}
	keys := make([]string, 0, len(p.Prefixes))
	for k := range p.Prefixes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pref, perr := parsePrefix(k)
		if perr != nil {
			return TenantPolicy{}, fmt.Errorf("policy key %q is not a prefix", clip(k, 64))
		}
		c, cerr := normalizeConfig(p.Prefixes[k])
		if cerr != nil {
			return TenantPolicy{}, fmt.Errorf("policy for %s: %w", pref.String(), cerr)
		}
		out.Prefixes[pref.String()] = c
	}
	return out, nil
}

func normalizeConfig(c PolicyConfig) (PolicyConfig, error) {
	out := PolicyConfig{MinVisibility: c.MinVisibility, MinVantages: c.MinVantages}
	if len(c.ExpectedOrigins) > MaxDeclaredASNs || len(c.Upstreams) > MaxDeclaredASNs {
		return PolicyConfig{}, fmt.Errorf("at most %d ASNs per set", MaxDeclaredASNs)
	}
	dedupe := func(in []uint32) []uint32 {
		seen := map[uint32]bool{}
		var o []uint32
		for _, a := range in {
			if a == 0 {
				continue // AS0 is reserved (RFC 7607)
			}
			if seen[a] {
				continue
			}
			seen[a] = true
			o = append(o, a)
		}
		sort.Slice(o, func(i, j int) bool { return o[i] < o[j] })
		return o
	}
	out.ExpectedOrigins = dedupe(c.ExpectedOrigins)
	out.Upstreams = dedupe(c.Upstreams)
	if out.MinVisibility < 0 || out.MinVisibility > 1 {
		return PolicyConfig{}, errors.New("min_visibility must be between 0 and 1")
	}
	if out.MinVantages < 0 || out.MinVantages > 64 {
		return PolicyConfig{}, errors.New("min_vantages must be between 0 and 64")
	}
	return out, nil
}

// PolicyStore is the per-tenant policy register. Every method takes a CONCRETE
// tenant: there is no cross-tenant read of another tenant's alert policy,
// because a policy is the tenant's own operational intent, not reference data.
type PolicyStore interface {
	Policy(ctx context.Context, tenant string) (TenantPolicy, error)
	SetPolicy(ctx context.Context, tenant, owner string, p TenantPolicy) error
}

// ── file backend ────────────────────────────────────────────────────────────

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory
// (tests, and a dev build with no persistence configured).
type FileStore struct {
	mu      sync.RWMutex
	path    string
	rows    map[string]TenantPolicy
	loadErr error
}

// NewFileStore loads persisted state. A missing file starts empty; a CORRUPT
// file starts empty AND records the error, which the integrator logs — a policy
// that failed to load must never look like a policy the tenant never set (§10).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]TenantPolicy{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	if err != nil {
		return s // absent store → empty, not an error
	}
	var rows map[string]TenantPolicy
	if err := json.Unmarshal(b, &rows); err != nil {
		s.loadErr = err
		return s
	}
	for k, v := range rows {
		s.rows[normTenant(k)] = v
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileStore) LoadErr() error { return s.loadErr }

// Policy returns ONE tenant's policy (the zero policy when unset).
func (s *FileStore) Policy(_ context.Context, tenant string) (TenantPolicy, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return TenantPolicy{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.rows[t]
	if !ok {
		return TenantPolicy{Prefixes: map[string]PolicyConfig{}}, nil
	}
	return clonePolicy(p), nil
}

// SetPolicy replaces ONE tenant's policy.
func (s *FileStore) SetPolicy(_ context.Context, tenant, owner string, p TenantPolicy) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	p.UpdatedBy = clip(owner, 128)
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.rows[t]
	// Store a DEEP copy: the caller keeps no live reference into the store.
	stored := clonePolicy(p)
	stored.UpdatedBy, stored.UpdatedAt = p.UpdatedBy, p.UpdatedAt
	s.rows[t] = stored
	if err := s.flushLocked(); err != nil {
		if had {
			s.rows[t] = prev
		} else {
			delete(s.rows, t)
		}
		return err
	}
	return nil
}

func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.Marshal(s.rows)
	if err != nil {
		return err
	}
	if len(b) > MaxPolicyBytes*MaxPolicyPrefixes {
		return errors.New("bgpwatch: policy store exceeds its size bound")
	}
	return platformdb.Save(s.path, b)
}

// clonePolicy DEEP-copies a policy, slices included. A shallow copy would hand
// a caller a live reference into the store's own state, and a caller that then
// sorted or appended to it would silently mutate what the evaluator alerts on.
func clonePolicy(p TenantPolicy) TenantPolicy {
	out := TenantPolicy{Default: cloneConfig(p.Default), UpdatedBy: p.UpdatedBy, UpdatedAt: p.UpdatedAt,
		Prefixes: make(map[string]PolicyConfig, len(p.Prefixes))}
	for k, v := range p.Prefixes {
		out.Prefixes[k] = cloneConfig(v)
	}
	return out
}

func cloneConfig(c PolicyConfig) PolicyConfig {
	return PolicyConfig{
		ExpectedOrigins: append([]uint32(nil), c.ExpectedOrigins...),
		Upstreams:       append([]uint32(nil), c.Upstreams...),
		MinVisibility:   c.MinVisibility,
		MinVantages:     c.MinVantages,
	}
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0041) ──

// DB is the injected relational seam: run fn inside a transaction whose
// row-level security GUC is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres backend.
func NewPGStore(db DB) PolicyStore { return &pgStore{db: db} }

// Policy reads ONE tenant's row. cross is ALWAYS false: the GUC is the concrete
// tenant, never the '*' wildcard, so even a platform-owner session reading
// through here sees exactly one tenant's policy.
func (s *pgStore) Policy(ctx context.Context, tenant string) (TenantPolicy, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return TenantPolicy{}, err
	}
	out := TenantPolicy{Prefixes: map[string]PolicyConfig{}}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var raw []byte
		var by string
		var at time.Time
		row := tx.QueryRow(ctx,
			`SELECT policy, updated_by, updated_at FROM bgp_alert_policy WHERE tenant_id = $1`, t)
		if err := row.Scan(&raw, &by, &at); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &out); err != nil {
				return fmt.Errorf("stored bgp alert policy is unreadable: %w", err)
			}
		}
		if out.Prefixes == nil {
			out.Prefixes = map[string]PolicyConfig{}
		}
		out.UpdatedBy, out.UpdatedAt = by, at
		return nil
	})
	return out, err
}

// SetPolicy upserts ONE tenant's row. tenant_id is stamped from the caller's
// resolved tenant as a bound parameter — defence in depth alongside the
// FORCE-RLS WITH CHECK, and structurally unable to stamp '*'.
func (s *pgStore) SetPolicy(ctx context.Context, tenant, owner string, p TenantPolicy) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	body, err := json.Marshal(TenantPolicy{Default: p.Default, Prefixes: p.Prefixes})
	if err != nil {
		return err
	}
	if len(body) > MaxPolicyBytes {
		return fmt.Errorf("policy exceeds the %d-byte bound", MaxPolicyBytes)
	}
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO bgp_alert_policy (tenant_id, policy, updated_by, updated_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (tenant_id)
			 DO UPDATE SET policy = EXCLUDED.policy, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			t, body, clip(strings.TrimSpace(owner), 128))
		return err
	})
}
