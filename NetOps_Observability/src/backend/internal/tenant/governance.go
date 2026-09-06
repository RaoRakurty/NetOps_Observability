// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenant

// governance.go — the per-tenant governance store (Phase-2 W3.2, extracted
// from package main's tenant_governance.go): required tags, the RCA window,
// attribution precedence and the seam-owner registry, with the three-state
// load / rollback-on-failed-persist discipline and closed-vocabulary
// normalizers. Handlers and the env path stay in main.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"netops/backend/appid"
	cloudpkg "netops/backend/cloud"
	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// defaultRcaWindowHours / maxRcaWindowHours mirror the cloud signal window
// bounds (cloud.SignalWindowHours / SignalWindowMaxHours) — imported values,
// aliased locally so the vocabulary reads at home here.
const (
	defaultRcaWindowHours = cloudpkg.SignalWindowHours
	maxRcaWindowHours     = cloudpkg.SignalWindowMaxHours
)

// normTenant mirrors main's tenant normalization (duplicated at the boundary).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

const (
	requiredTagsMax   = 32 // bounded list — a governance list, not a dumping ground
	requiredTagMaxLen = 64
)

// GovernanceConfig is one tenant's governance record. Zero values mean
// "unset → platform default" (the exact behavior that predates the editors).
type GovernanceConfig struct {
	TenantID     string   `json:"tenant_id"`
	RequiredTags []string `json:"required_tags,omitempty"`
	// RcaWindowHours: default read window for the tenant-scoped cloud signal /
	// RCA surfaces when a request names none. 0 = unset → platform default.
	RcaWindowHours int `json:"rca_window_hours,omitempty"`
	// AttributionPrecedence: tenant ordering of the appid precedence classes
	// (a validated permutation of appid.PrecedenceClasses). nil = unset →
	// the intrinsic default ladder.
	AttributionPrecedence []string `json:"attribution_precedence,omitempty"`
	// SeamOwners: owner-class → the tenant's ACTUAL responsible party (#113
	// slice 2). Keys are the closed signature-catalog owner vocabulary
	// (SeamOwnerClasses); values name the real provider/team so RCA ownership
	// reads "Lumen (DIA circuit #12345)" instead of the generic class label.
	// nil = unset → class labels only.
	SeamOwners map[string]SeamOwnerEntry `json:"seam_owners,omitempty"`
}

// SeamOwnerEntry is one registry row: who the class resolves to for this
// tenant, plus an optional escalation contact. Non-secret display data.
type SeamOwnerEntry struct {
	Name    string `json:"name"`              // e.g. "Lumen (DIA circuit #12345)"
	Contact string `json:"contact,omitempty"` // email / phone / portal — free text, bounded
}

// SeamOwnerClasses is the CLOSED owner-class vocabulary — exactly the
// signature catalog's owner Literal (catalog.py) that corr objects carry in
// corr_current.owner. A registry key outside this list is refused.
var SeamOwnerClasses = []string{
	"netops", "carrier", "cloud_provider", "app_team", "colo_provider", "isp", "sdwan_vendor",
}

func IsSeamOwnerClass(c string) bool {
	for _, k := range SeamOwnerClasses {
		if k == c {
			return true
		}
	}
	return false
}

// GovernanceStore is a file-backed per-tenant map, keyed by tenant in the
// store itself (§3a). Mirrors tenantDisplayStore — nothing here is a secret.
type GovernanceStore struct {
	mu   sync.RWMutex
	cfgs map[string]GovernanceConfig
	path string
	// loadErr: the stored file could not be READ — not "no tenant set a
	// governance policy". Conflating them reverted every tenant to the default
	// ladder/required-tag set and let the next write erase the others (§10).
	loadErr error
}

func NewGovernanceStore(path string) *GovernanceStore {
	s := &GovernanceStore{cfgs: map[string]GovernanceConfig{}, path: path}
	if err := s.load(); err != nil {
		s.loadErr = err
		applog.Error("tenant.governance", "stored governance config unreadable — every tenant reads as default and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	return s
}

// tenantGovernancePath resolves the store's kv key (env-overridable like every
// other file-backed store; blank env keeps the default).
// SeedForTest stores one tenant's config and persists — tests only (the
// error-vs-empty persistence matrix seeds stores this way).
func (s *GovernanceStore) SeedForTest(tenantID string, cfg GovernanceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfgs[normTenant(tenantID)] = cfg
	return s.saveLocked()
}

func (s *GovernanceStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no governance policy set yet
	}
	if err != nil {
		return fmt.Errorf("read tenant governance config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = none set yet
	}
	var m map[string]GovernanceConfig
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode tenant governance config: %w", err)
	}
	for id, c := range m {
		c.TenantID = id
		m[id] = c
	}
	s.cfgs = m
	return nil
}

// saveLocked persists the map. Caller holds s.mu. Blank path = in-memory only.
//
// F-62/F-63: this used to swallow the kvSave error into a logWarn and return
// nothing, which made every handler above it STRUCTURALLY unable to report a
// failed write — the seed defect ("PUT returns 200, reload shows the old
// value"). The mutators below now roll back and propagate, and the handlers
// answer 500. A write path that cannot fail is a write path that is not
// writing.
func (s *GovernanceStore) saveLocked() error {
	// The in-memory map is not the stored state when the load failed: flushing it
	// would erase every other tenant's stored rows. Fail closed (F-62 shape).
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the stored governance config: its stored contents were never read: %w", s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.cfgs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode tenant governance: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("settings", "persist tenant governance failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist tenant governance: %w", err)
	}
	return nil
}

// restoreLocked rolls the in-memory map back after a failed persist so RAM and
// disk cannot disagree. Caller holds s.mu.
func (s *GovernanceStore) restoreLocked(tenant string, prev GovernanceConfig, had bool) {
	if had {
		s.cfgs[tenant] = prev
		return
	}
	delete(s.cfgs, tenant)
}

// requiredTags returns the tenant's EFFECTIVE required-tag list and whether it
// is a custom (tenant-set) list. Unconfigured tenants — and a server built
// without the store — get the platform default (nil-safe).
func (s *GovernanceStore) RequiredTags(tenant string) ([]string, bool) {
	if s == nil {
		return cloudpkg.DefaultRequiredTags(), false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && len(c.RequiredTags) > 0 {
		return append([]string(nil), c.RequiredTags...), true
	}
	return cloudpkg.DefaultRequiredTags(), false
}

// setRequiredTags stamps the tenant FROM THE PRINCIPAL (callers pass the
// principalTenant result, never body input) and persists. tags==nil resets the
// tenant to the platform default.
func (s *GovernanceStore) SetRequiredTags(tenant string, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.RequiredTags = tags
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return err
	}
	return nil
}

// rcaWindowHours returns the tenant's EFFECTIVE default read window (hours)
// for the cloud signal surfaces and whether it is a custom override. The
// platform default is defaultRcaWindowHours — exactly the pre-editor
// behavior. Values are clamped defensively on read too (safety on a hand-
// edited store file). Nil-safe.
func (s *GovernanceStore) RcaWindowHours(tenant string) (int, bool) {
	if s == nil {
		return defaultRcaWindowHours, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && c.RcaWindowHours > 0 {
		if c.RcaWindowHours > maxRcaWindowHours {
			return maxRcaWindowHours, true
		}
		return c.RcaWindowHours, true
	}
	return defaultRcaWindowHours, false
}

// setRcaWindowHours stamps the tenant FROM THE PRINCIPAL and persists.
// hours==0 resets the tenant to the platform default.
func (s *GovernanceStore) SetRcaWindowHours(tenant string, hours int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.RcaWindowHours = hours
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return err
	}
	return nil
}

// NormalizeRcaWindowHours validates a caller's window: a whole number of hours
// within the same safe bounds the signal surfaces clamp to (1..168). Off-bounds
// fails the request — the editor never silently stores a window the read path
// would refuse to honor.
func NormalizeRcaWindowHours(n int) (int, error) {
	if n < 1 || n > maxRcaWindowHours {
		return 0, fmt.Errorf("rca_window_hours must be 1..%d", maxRcaWindowHours)
	}
	return n, nil
}

// handleRcaWindowSettings serves GET/PUT /api/settings/rca-window.
func (s *GovernanceStore) AttributionPrecedence(tenant string) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.cfgs[tenant]; ok && len(c.AttributionPrecedence) > 0 {
		if order, err := appid.NormalizePrecedence(c.AttributionPrecedence); err == nil {
			return order, true
		}
	}
	return nil, false
}

// setAttributionPrecedence stamps the tenant FROM THE PRINCIPAL and persists.
// order==nil resets the tenant to the default ladder.
func (s *GovernanceStore) SetAttributionPrecedence(tenant string, order []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.AttributionPrecedence = order
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return err
	}
	return nil
}

// handleAttributionPrecedenceSettings serves GET/PUT /api/settings/attribution-precedence.
func (s *GovernanceStore) SeamOwners(tenant string) (map[string]SeamOwnerEntry, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cfgs[tenant]
	if !ok || len(c.SeamOwners) == 0 {
		return nil, false
	}
	out := make(map[string]SeamOwnerEntry, len(c.SeamOwners))
	for k, v := range c.SeamOwners {
		if IsSeamOwnerClass(k) && strings.TrimSpace(v.Name) != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// setSeamOwners stamps the tenant FROM THE PRINCIPAL and persists. owners==nil
// resets the tenant to class-label-only display.
func (s *GovernanceStore) SetSeamOwners(tenant string, owners map[string]SeamOwnerEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.cfgs[tenant]
	c := prev
	c.TenantID = tenant
	c.SeamOwners = owners
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		s.restoreLocked(tenant, prev, had)
		return err
	}
	return nil
}

const (
	seamOwnerNameMaxLen    = 120
	seamOwnerContactMaxLen = 200
)

// NormalizeSeamOwners validates a caller's registry: closed class vocabulary,
// bounded non-empty names, bounded contacts, empty-name rows dropped. Anything
// off-spec fails the request.
func NormalizeSeamOwners(raw map[string]SeamOwnerEntry) (map[string]SeamOwnerEntry, error) {
	if len(raw) == 0 {
		return nil, errors.New("seam_owners must map at least one owner class")
	}
	out := make(map[string]SeamOwnerEntry, len(raw))
	for k, v := range raw {
		class := strings.ToLower(strings.TrimSpace(k))
		if !IsSeamOwnerClass(class) {
			return nil, fmt.Errorf("seam_owners: unknown owner class %q (valid: %s)", k, strings.Join(SeamOwnerClasses, ", "))
		}
		name := strings.TrimSpace(v.Name)
		contact := strings.TrimSpace(v.Contact)
		if name == "" {
			continue // an empty row means "no override for this class"
		}
		if len(name) > seamOwnerNameMaxLen {
			return nil, fmt.Errorf("seam_owners.%s: name must be at most %d characters", class, seamOwnerNameMaxLen)
		}
		if len(contact) > seamOwnerContactMaxLen {
			return nil, fmt.Errorf("seam_owners.%s: contact must be at most %d characters", class, seamOwnerContactMaxLen)
		}
		out[class] = SeamOwnerEntry{Name: name, Contact: contact}
	}
	if len(out) == 0 {
		return nil, errors.New("seam_owners: every row was empty")
	}
	return out, nil
}

// handleSeamOwnersSettings serves GET/PUT /api/settings/seam-owners (#113
// slice 2): the per-tenant registry that turns an RCA owner CLASS (isp /
// carrier / cloud_provider / …) into the tenant's actual responsible party.
func IsGovernanceAuditAction(action any) bool {
	switch action {
	case "set_required_tags", "set_rca_window", "set_attribution_precedence", "set_time_display", "set_seam_owners":
		return true
	}
	return false
}

func NormalizeRequiredTags(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("required_tags must list at least one tag")
	}
	if len(raw) > requiredTagsMax {
		return nil, fmt.Errorf("required_tags: at most %d tags", requiredTagsMax)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		tag := strings.ToLower(strings.TrimSpace(t))
		if tag == "" || len(tag) > requiredTagMaxLen {
			return nil, fmt.Errorf("required_tags: each tag must be 1..%d characters", requiredTagMaxLen)
		}
		for _, c := range tag {
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
				c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
			if !ok {
				return nil, fmt.Errorf("required_tags: invalid tag key %q (letters, digits, . _ : / - only)", tag)
			}
		}
		if seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out, nil
}

// handleRequiredTagsSettings serves GET/PUT /api/settings/required-tags.
