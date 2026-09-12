// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"errors"
	"fmt"

	"netops/backend/internal/vendorprofile"
)

// profile.go — the VENDOR PROFILE adapter (T9). Provider selection by
// (vendor, platform) is DECLARATIVE: each vendor profile names the
// VendorAdvisoryProvider that assesses its platform and the CPE product ids an
// advisory query carries. This package therefore holds NO vendor table and no
// per-vendor branch — it reads the binding through the registry, exactly as the
// design's `cve.psirt_connector` field prescribes.
//
// HONESTY (§5g). A platform no profile claims is UNASSESSED: every helper here
// returns an error (never a silently substituted "default" provider), so the
// caller surfaces the device as not-assessed rather than as clear.

// ErrNoProvider — a profile exists but names no provider, or the named provider
// was not supplied to SelectProvider. Either way the device is UNASSESSED.
var ErrNoProvider = errors.New("advisory: no provider bound for this vendor/platform")

// ProviderNameFor returns the provider identity (a Source* value) the vendor
// profile binds to (vendor, platform).
func ProviderNameFor(reg *vendorprofile.Registry, vendor, platform string) (string, error) {
	if reg == nil {
		return "", fmt.Errorf("%w: nil registry", ErrNoProvider)
	}
	b, err := reg.AdvisoryFor(vendor, platform)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoProvider, err)
	}
	return b.Provider, nil
}

// ProductIDsFor returns the CPE product ids the profile declares for
// (vendor, platform) — the tokens an advisory feed is matched under.
func ProductIDsFor(reg *vendorprofile.Registry, vendor, platform string) ([]string, error) {
	if reg == nil {
		return nil, fmt.Errorf("%w: nil registry", ErrNoProvider)
	}
	b, err := reg.AdvisoryFor(vendor, platform)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoProvider, err)
	}
	return append([]string(nil), b.ProductIDs...), nil
}

// SelectProvider picks, from the providers the caller has wired, the one the
// vendor profile binds to q's (Vendor, Platform). Providers are matched on
// Name(); a nil entry is ignored. It NEVER falls back to "the first provider" —
// an unbound or unsupplied provider is an error so the caller reports the device
// unassessed.
func SelectProvider(reg *vendorprofile.Registry, providers []VendorAdvisoryProvider, q Query) (VendorAdvisoryProvider, error) {
	name, err := ProviderNameFor(reg, q.Vendor, q.Platform)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		if p != nil && p.Name() == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("%w: profile binds %q for %s/%s but no such provider is wired",
		ErrNoProvider, name, q.Vendor, q.Platform)
}
