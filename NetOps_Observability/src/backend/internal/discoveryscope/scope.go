// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package discoveryscope holds the TENANT-OWNED SNMP discovery scopes
// (2026-11-10): a scan the platform owner points at a customer's network, on
// that customer's behalf, with that customer's own SNMP profiles. Every device
// it finds belongs to the customer — the scope is the channel (the tenant comes
// from this server-side configuration, never from what a device answers).
//
// The scanner itself is internal/discovery (ScanScope); this package is the
// stored configuration, its tenant-isolated stores (Postgres FORCE-RLS
// migration 0067, or one file record per scope), the in-memory snapshot the
// scanner reads, and the /api/discovery/scopes surface.
//
// WHO MAY WRITE (owner decision D1, 2026-11-10). A scope is per-tenant data,
// but it aims the PLATFORM's prober at a network: on a shared appliance every
// tenant shares the host's reach, so a tenant-written range would be a probe of
// someone else's address space. Create / update / delete is therefore the
// platform owner's, choosing the customer explicitly; a customer reads its own
// scopes. Tenant self-service arrives when the customer's own collector runs
// the sweep (collector tier C3/C4).
package discoveryscope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"netops/backend/internal/discovery"
	"netops/backend/internal/owner"
)

// Scope is one tenant-owned discovery scope as stored.
type Scope struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// Ranges are validated, normalized IPv4 CIDRs (discovery.ValidateScanRanges).
	Ranges          []string `json:"ranges"`
	AllowNonPrivate bool     `json:"allow_non_private"`
	// CredentialRefs are SNMP profile ids, all owned by TenantID (owner decision
	// D2). Empty means "every profile the customer owns", in name order.
	CredentialRefs []string  `json:"credential_refs"`
	Enabled        bool      `json:"enabled"`
	CreatedBy      string    `json:"created_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Bounds (§9: everything bounded).
const (
	MaxPerTenant      = 16
	MaxTotal          = 256
	MaxCredentialRefs = 16
	maxNameLen        = 80
	maxRefLen         = 128
	maxActorLen       = 256
	maxTenantLen      = 256
)

// idPattern is the server-generated id shape: never chosen by a client.
var idPattern = regexp.MustCompile(`^ds-[0-9a-f]{16}$`)

// ValidID reports whether id has the server-generated shape.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// ErrInvalid marks a scope that fails validation (a 400 at the API, corruption
// at load).
var ErrInvalid = errors.New("invalid discovery scope")

// NormTenant is the canonical owner spelling: trimmed and lower-cased.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Validate checks and normalizes s in place. It is applied on the way IN (the
// API, both stores' writes) and on the way OUT (both stores' loads): stored
// data is never trusted without validation (§3).
func Validate(s *Scope) error {
	s.TenantID = NormTenant(s.TenantID)
	s.Name = strings.TrimSpace(s.Name)
	switch {
	case !ValidID(s.ID):
		return fmt.Errorf("%w: id %q", ErrInvalid, s.ID)
	case s.TenantID == "" || owner.IsPlatform(s.TenantID):
		// The platform's own scan is /api/discovery/config; a scope always
		// belongs to a customer.
		return fmt.Errorf("%w: a scope must belong to a customer, not the platform", ErrInvalid)
	case len(s.TenantID) > maxTenantLen:
		return fmt.Errorf("%w: tenant id too long", ErrInvalid)
	case s.Name == "" || len(s.Name) > maxNameLen || strings.IndexFunc(s.Name, unicode.IsControl) >= 0:
		return fmt.Errorf("%w: a name of 1 to %d printable characters is required", ErrInvalid, maxNameLen)
	case len(s.CreatedBy) > maxActorLen:
		return fmt.Errorf("%w: created_by too long", ErrInvalid)
	case len(s.CredentialRefs) > MaxCredentialRefs:
		return fmt.Errorf("%w: at most %d SNMP profiles per scan", ErrInvalid, MaxCredentialRefs)
	}
	clean, _, err := discovery.ValidateScanRanges(s.Ranges, s.AllowNonPrivate)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(clean) == 0 {
		return fmt.Errorf("%w: at least one address range is required", ErrInvalid)
	}
	s.Ranges = clean
	refs := make([]string, 0, len(s.CredentialRefs))
	seen := map[string]bool{}
	for _, r := range s.CredentialRefs {
		r = strings.TrimSpace(r)
		if r == "" || len(r) > maxRefLen || strings.IndexFunc(r, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: SNMP profile reference %q", ErrInvalid, r)
		}
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	s.CredentialRefs = refs
	return nil
}

// Hosts is the number of addresses the scope's ranges expand to (0 when they
// do not validate).
func Hosts(s Scope) int {
	_, n, err := discovery.ValidateScanRanges(s.Ranges, s.AllowNonPrivate)
	if err != nil {
		return 0
	}
	return n
}

// EnabledHosts is what the turned-on scopes charge against the shared sweep
// budget, leaving out the scope with id exclude ("" excludes none).
func EnabledHosts(scopes []Scope, exclude string) int {
	n := 0
	for _, o := range scopes {
		if o.Enabled && o.ID != exclude {
			n += Hosts(o)
		}
	}
	return n
}

// BudgetError is THE refusal for a write that would take the scans past the
// appliance's one sweep budget — the same words on the customer-scan API and
// on the platform scan's own config, so an operator reads one rule.
func BudgetError(used int) error {
	return fmt.Errorf("the scans together would probe %d addresses per sweep; the appliance's budget is %d, shared by every scan — narrow the ranges", used, discovery.MaxScanHosts)
}

// Store is the persistence seam. Every read is scoped by the caller's
// (tenant, cross); a write is filed under the scope's OWN tenant and nothing
// else.
type Store interface {
	// List returns the scopes visible to (tenant, cross): one tenant's, or
	// every one when cross. A read failure is an error, never an empty list.
	List(ctx context.Context, tenant string, cross bool) ([]Scope, error)
	// Get returns one scope visible to (tenant, cross).
	Get(ctx context.Context, tenant string, cross bool, id string) (Scope, bool, error)
	// Put upserts s under s.TenantID. It never moves a scope between tenants:
	// an existing id under another tenant is refused.
	Put(ctx context.Context, s Scope) error
	// Delete removes tenant's scope id; false when it was not there.
	Delete(ctx context.Context, tenant, id string) (bool, error)
}

// NewID returns a fresh server-generated scope id (ds- + 16 hex from
// crypto/rand). A client never chooses an id.
func NewID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("scope id: %w", err)
	}
	return "ds-" + hex.EncodeToString(b[:]), nil
}

// unavailableStore answers every call with the reason scopes cannot be stored
// on this backend — never an empty list, which would read as "no scopes".
type unavailableStore struct{ err error }

// Unavailable is the Store for a backend that cannot hold scopes.
func Unavailable(reason error) Store { return unavailableStore{err: reason} }

func (u unavailableStore) List(context.Context, string, bool) ([]Scope, error) { return nil, u.err }
func (u unavailableStore) Get(context.Context, string, bool, string) (Scope, bool, error) {
	return Scope{}, false, u.err
}
func (u unavailableStore) Put(context.Context, Scope) error                     { return u.err }
func (u unavailableStore) Delete(context.Context, string, string) (bool, error) { return false, u.err }
