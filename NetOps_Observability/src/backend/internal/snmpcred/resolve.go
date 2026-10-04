// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package snmpcred

// resolve.go — the ONE answer to "which SNMP credential does this device use?"
//
// Every consumer that turns a device into an SNMP conversation (the collector
// target builder, the verification runner, the credential sentinel) asks here,
// so they cannot drift apart. They did: the target builder applied the
// sentinel's learned override only for devices that ALSO had a credential_ref,
// so a scan-discovered device (no ref) whose profile the sentinel had adopted
// kept polling with the SNMP_COMMUNITY/"public" fallback — the sentinel logged
// "credential override adopted" while every poll failed (2026-10-04, four
// Cisco vEdges, collector_target_up=0).
//
// Tenant isolation (§3a) lives here too: a profile is usable for a device only
// when it is platform-owned ("" tenant) or owned by the device's own tenant. A
// credential_ref (or a learned override) that names another tenant's profile
// resolves to nothing — another tenant's secret is never sent to a device.

import (
	"sort"
	"strings"

	"netops/backend/internal/tenant"
	"netops/backend/models"
)

// PlatformOwned reports whether a tenant id denotes the platform itself — the
// untagged "" or the global tenant (rbac.SameTenantStrict compares the same
// way: trimmed, case-insensitive).
func PlatformOwned(tenantID string) bool {
	t := strings.TrimSpace(tenantID)
	return t == "" || strings.EqualFold(t, tenant.Global)
}

// UsableFor reports whether credential c may be used to talk to a device owned
// by tenantID: platform-owned profiles serve every device, a tenant's profile
// serves only that tenant's devices — never another tenant's, and never a
// platform-owned (e.g. scan-discovered) device.
func UsableFor(c Credential, tenantID string) bool {
	if PlatformOwned(c.TenantID) {
		return true
	}
	if PlatformOwned(tenantID) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(c.TenantID), strings.TrimSpace(tenantID))
}

// ResolveFor resolves a credential_ref for a device of tenantID: id first, then
// a case-insensitive name match, considering ONLY profiles usable for that
// tenant. A name shared by several usable profiles resolves deterministically:
// the tenant's own profile before a platform one, then the lowest id.
func (s *Store) ResolveFor(ref, tenantID string) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Credential{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.creds[ref]; ok && UsableFor(c, tenantID) {
		return c, true
	}
	var best Credential
	found := false
	for _, c := range s.creds {
		if !strings.EqualFold(c.Name, ref) || !UsableFor(c, tenantID) {
			continue
		}
		if !found || betterNameMatch(c, best, tenantID) {
			best, found = c, true
		}
	}
	return best, found
}

func betterNameMatch(c, cur Credential, tenantID string) bool {
	cOwn, curOwn := !PlatformOwned(c.TenantID), !PlatformOwned(cur.TenantID)
	if cOwn != curOwn {
		return cOwn
	}
	return c.ID < cur.ID
}

// ScanCandidates returns the profiles the platform subnet sweep may try, in the
// order it tries them: platform-owned only (scan-discovered devices are
// platform-owned until an operator assigns them, so a tenant's secret must
// never be sprayed at platform-scanned addresses), sorted by name
// (case-insensitive) then id — the order the SNMP Profiles list shows, so the
// operator can see exactly what the sweep will do.
func (s *Store) ScanCandidates() []Credential {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Credential, 0, len(s.creds))
	for _, c := range s.creds {
		if PlatformOwned(c.TenantID) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ResolveForDevice returns the credential the pollers must use for dev: the
// sentinel's learned override while it stands (it exists only because the
// bound profile — or the default community, for an unbound device — stopped
// answering), else the bound credential_ref. Both are tenant-checked. ok=false
// means "no profile": the poller's SNMP_COMMUNITY/"public" fallback applies.
// Nil stores are tolerated (early boot, tests).
func ResolveForDevice(creds *Store, overrides *OverrideStore, dev models.Device) (Credential, bool) {
	if creds == nil {
		return Credential{}, false
	}
	if overrides != nil {
		if ov, ok := overrides.Get(dev.ID); ok {
			if c, ok := creds.ResolveFor(ov.ProfileID, dev.TenantID); ok {
				return c, true
			}
		}
	}
	return creds.ResolveFor(dev.CredentialRef, dev.TenantID)
}
