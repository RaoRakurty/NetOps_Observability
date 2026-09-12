// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// registry.go — the ONE provider registry (Wave 5 #17: extensibility).
//
// Everything the platform needs to know ABOUT a provider — display identity,
// offered auth methods, valid scope shapes, org-onboarding shape, capability
// flags, adapter constructors — lives on a single ProviderDescriptor that each
// provider file registers at init. Provider-neutral code consults the registry
// instead of switching on Provider constants, so adding Oracle/Alibaba/vSphere
// is one new adapter file + one RegisterProvider call — no surgery on the
// framework, the broker, the catalog handler, or the UI.
//
// The registry follows the capability-pack pattern (capability.go): populated
// once at init, never mutated afterwards — immutable-after-release, not shared
// mutable state.

import (
	"sort"
	"strings"
)

// ProviderDescriptor declares one cloud provider to the platform. All fields
// are non-secret. Constructor funcs are the adapter seam: AdapterFor and
// friends resolve through them, so the descriptor OWNS how its adapter is
// built (with the live exchanger+probe, an injected exchanger, or a platform
// assertion source).
type ProviderDescriptor struct {
	ID          Provider // canonical lowercase token ("aws")
	DisplayName string   // customer-facing full name ("Amazon Web Services")
	ShortLabel  string   // compact label for dense UI cells ("AWS")

	// AuthMethods is the preference-ordered offer (index 0 = recommended).
	// AuthMethodProhibited is never listed.
	AuthMethods []AuthMethod

	// ScopeTypes are the collection-scope kinds the provider supports,
	// broad → narrow (the order the UI presents).
	ScopeTypes []ScopeType

	// OrgScopeTypes are the scope kinds an ORG-level (multi-account) connector
	// may anchor on (e.g. AWS: org/OU; Azure: org/management group; GCP:
	// org/folder). Always a subset of ScopeTypes.
	OrgScopeTypes []ScopeType

	// MemberScopeType is what enumerating an org anchor yields (AWS: account,
	// Azure: subscription, GCP: project).
	MemberScopeType ScopeType

	// SetupDocKey names the provider's setup documentation article — a stable
	// key, never a URL (the docs host is deployment config).
	SetupDocKey string

	// Capability-class flags — what the provider's telemetry integration
	// actually offers today. HONEST values only: a lane nobody built is false.
	HasFlowLogs   bool // VPC/VNet flow-log lane exists
	HasHealthLane bool // provider incident/maintenance (health) lane exists

	// IdentityRef returns the provider-native identity reference (role ARN /
	// client id / SA email) used in non-secret cache keys and audit detail.
	// Never used as an identity key on its own.
	IdentityRef func(IdentityConfig) string

	// NewAdapter builds the adapter wired to LIVE production seams (real
	// endpoints, env-backed platform identity). Required.
	NewAdapter func() CloudIdentityProvider

	// NewAdapterWithExchanger builds the adapter with an injected
	// TokenExchanger and NO probe client (tests / alternative deployments).
	// Optional; nil → NewAdapterWithExchanger returns nil for this provider.
	NewAdapterWithExchanger func(TokenExchanger) CloudIdentityProvider

	// NewAdapterWithAssertions builds the LIVE adapter with every exchanger's
	// assertion source replaced (platform workload issuer wiring). Optional;
	// nil → AdapterForWithAssertions falls back to NewAdapter.
	NewAdapterWithAssertions func(WorkloadAssertionSource) CloudIdentityProvider
}

// providerRegistry is populated at init by each provider file and read-only
// afterwards (same lifecycle as the capability-pack registry).
var providerRegistry = map[Provider]ProviderDescriptor{}

// RegisterProvider adds a provider descriptor to the registry. It is called
// from init() (or from a test); a structurally invalid or duplicate
// registration is a programmer error and fails fast with a panic — a provider
// half-registered at boot must never limp into production.
func RegisterProvider(d ProviderDescriptor) {
	if strings.TrimSpace(string(d.ID)) == "" {
		panic("cloudconn: RegisterProvider: empty provider id")
	}
	if d.ID != Provider(strings.ToLower(strings.TrimSpace(string(d.ID)))) {
		panic("cloudconn: RegisterProvider: provider id must be canonical lowercase: " + string(d.ID))
	}
	if _, dup := providerRegistry[d.ID]; dup {
		panic("cloudconn: RegisterProvider: duplicate provider " + string(d.ID))
	}
	if strings.TrimSpace(d.DisplayName) == "" || strings.TrimSpace(d.ShortLabel) == "" {
		panic("cloudconn: RegisterProvider(" + string(d.ID) + "): display name and short label are required")
	}
	if len(d.AuthMethods) == 0 {
		panic("cloudconn: RegisterProvider(" + string(d.ID) + "): at least one auth method is required")
	}
	for _, m := range d.AuthMethods {
		if !m.Valid() || m.IsProhibited() {
			panic("cloudconn: RegisterProvider(" + string(d.ID) + "): auth method " + string(m) + " is invalid or prohibited")
		}
	}
	if len(d.ScopeTypes) == 0 {
		panic("cloudconn: RegisterProvider(" + string(d.ID) + "): at least one scope type is required")
	}
	scopeSet := make(map[ScopeType]bool, len(d.ScopeTypes))
	for _, st := range d.ScopeTypes {
		scopeSet[st] = true
	}
	for _, st := range d.OrgScopeTypes {
		if !scopeSet[st] {
			panic("cloudconn: RegisterProvider(" + string(d.ID) + "): org scope type " + string(st) + " is not in ScopeTypes")
		}
	}
	if d.NewAdapter == nil {
		panic("cloudconn: RegisterProvider(" + string(d.ID) + "): NewAdapter constructor is required")
	}
	providerRegistry[d.ID] = d
}

// Descriptor returns the registered descriptor for p. ok=false if unknown.
func Descriptor(p Provider) (ProviderDescriptor, bool) {
	d, ok := providerRegistry[p]
	return d, ok
}

// Descriptors returns every registered descriptor, deterministically ordered
// by provider id (the catalog/UI order).
func Descriptors() []ProviderDescriptor {
	out := make([]ProviderDescriptor, 0, len(providerRegistry))
	for _, d := range providerRegistry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RegisteredProviders returns every registered provider id, sorted.
func RegisteredProviders() []Provider {
	out := make([]Provider, 0, len(providerRegistry))
	for p := range providerRegistry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IdentityRefFor resolves the provider-native identity reference for a config
// through the registry. Unknown provider or absent hook → "".
func IdentityRefFor(p Provider, cfg IdentityConfig) string {
	d, ok := providerRegistry[p]
	if !ok || d.IdentityRef == nil {
		return ""
	}
	return d.IdentityRef(cfg)
}
