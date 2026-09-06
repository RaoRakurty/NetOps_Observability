// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

import (
	"context"
	"time"
)

// Severity ranks a validation finding.
type Severity string

const (
	SeverityError   Severity = "error"   // blocks activation
	SeverityWarning Severity = "warning" // allowed but surfaced (e.g. legacy method, scope mismatch)
	SeverityInfo    Severity = "info"
)

// Finding is one structured validation result item. Code is stable + machine
// readable; Remediation is exact operator guidance. Never carries a secret.
type Finding struct {
	Severity    Severity `json:"severity"`
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
}

// ValidationResult is the outcome of a pure configuration validation (no network).
type ValidationResult struct {
	OK       bool      `json:"ok"` // false if any error-severity finding
	Findings []Finding `json:"findings"`
}

// Add appends a finding and keeps OK consistent.
func (r *ValidationResult) Add(sev Severity, code, msg, remediation string) {
	r.Findings = append(r.Findings, Finding{Severity: sev, Code: code, Message: msg, Remediation: remediation})
	if sev == SeverityError {
		r.OK = false
	}
}

// ExchangeRequest asks a provider adapter to mint a short-lived provider token
// for a single tenant+connector+identity, bounded to a capability set + scope.
type ExchangeRequest struct {
	Identity        IdentityConfig
	CapabilitySetID string        // pack FullID the token is bounded to
	Scope           Scope         // the provider account/sub/project the token targets
	Audience        string        // token audience (federation)
	Region          string        // optional regional binding (AWS regional STS endpoint)
	MaxLifetime     time.Duration // upper bound the broker enforces
	// LegacySecret is populated by the broker ONLY for legacy static-credential
	// methods, decrypted from the Vault at call time. Empty for federated methods.
	LegacySecret string
}

// ScopedToken is a short-lived provider token. It is NEVER persisted and NEVER
// logged; the broker caches it in memory until Expiry with a strict expiry margin.
type ScopedToken struct {
	Provider  Provider  `json:"provider"`
	Value     string    `json:"-"` // opaque provider token — never serialized
	Expiry    time.Time `json:"expiry"`
	TokenType string    `json:"token_type,omitempty"`
	// AWS carries the STS session-credential TRIPLET (AWS consumers need all
	// three to sign requests). Populated only for ProviderAWS; never serialized,
	// and AWSCredentials self-redacts under fmt verbs.
	AWS *AWSCredentials `json:"-"`
}

// DiscoverRequest asks a provider adapter to enumerate reachable scopes. Token
// is the broker-minted scoped credential the probe authenticates with — the
// adapter itself holds no credentials (zero trust).
type DiscoverRequest struct {
	Identity IdentityConfig
	Root     Scope // optional starting scope (org/mgmt-group/folder)
	Token    ScopedToken
}

// CapabilityCheckRequest asks a provider adapter to verify the granted permissions
// against a capability pack. Token is the broker-minted scoped credential the
// probe authenticates with.
type CapabilityCheckRequest struct {
	Identity IdentityConfig
	Pack     CapabilityPack
	Scope    Scope
	Token    ScopedToken
}

// PermissionStatus is the granted/denied status of one required permission.
type PermissionStatus struct {
	Permission string `json:"permission"`
	Granted    bool   `json:"granted"`
	Detail     string `json:"detail,omitempty"`
}

// CapabilityReport is the outcome of a live permission validation.
type CapabilityReport struct {
	Pack        string             `json:"pack"` // FullID
	AllGranted  bool               `json:"all_granted"`
	Permissions []PermissionStatus `json:"permissions"`
	Findings    []Finding          `json:"findings"`
}

// RevokeRequest asks a provider adapter to tear down / disable a trust.
type RevokeRequest struct {
	Identity IdentityConfig
}

// SetupArtifact is one deploy artifact the operator applies on their side.
type SetupArtifact struct {
	Kind    string `json:"kind"` // "cloudformation" | "terraform" | "manual" | "gcloud" | "azure_cli" | "federated_credential"
	Title   string `json:"title"`
	Format  string `json:"format"` // "yaml" | "hcl" | "json" | "text"
	Content string `json:"content"`
}

// SetupBundle is the full set of deploy artifacts + human steps for establishing
// trust for a connector. Pure output — never contains a secret.
type SetupBundle struct {
	Provider  Provider        `json:"provider"`
	Method    AuthMethod      `json:"method"`
	Summary   string          `json:"summary"`
	Steps     []string        `json:"steps"`
	Artifacts []SetupArtifact `json:"artifacts"`
}

// CloudIdentityProvider is the provider-neutral adapter contract. Adapters are
// stateless and hold no credentials of their own.
//
// Implemented purely (no network): Provider, ValidateConfiguration,
// SetupInstructions. ExchangeCredential is LIVE (delegated to the provider's
// TokenExchanger — AWS STS AssumeRole/GetSessionToken, Azure Entra client
// credentials/WIF assertion, GCP assertion grant/STS exchange+impersonation).
// DiscoverScopes and ValidateCapabilities are LIVE (delegated to the provider's
// probe client — AWS GetCallerIdentity + IAM policy simulation, Azure
// subscriptions + RBAC permissions, GCP projects + testIamPermissions) and
// authenticate with a broker-minted ScopedToken carried on the request; an
// adapter without a probe client (or a request without a token) returns
// ErrProviderExchangeDeferred. Revoke still returns ErrProviderExchangeDeferred
// (documented follow-up).
type CloudIdentityProvider interface {
	Provider() Provider

	// ValidateConfiguration checks an identity config for structural + security
	// correctness WITHOUT any network call (no root/admin, no wildcard principal,
	// federated preferred, required fields present).
	ValidateConfiguration(cfg IdentityConfig) ValidationResult

	// SetupInstructions renders the provider-native deploy artifacts (templates,
	// CLI, manual steps) that establish least-privilege trust for a pack. Pure.
	SetupInstructions(cfg IdentityConfig, pack CapabilityPack) (SetupBundle, error)

	// ExchangeCredential mints a short-lived scoped provider token. Live-network.
	ExchangeCredential(ctx context.Context, req ExchangeRequest) (ScopedToken, error)

	// DiscoverScopes enumerates reachable scopes. Live-network.
	DiscoverScopes(ctx context.Context, req DiscoverRequest) ([]Scope, error)

	// ValidateCapabilities checks granted permissions against a pack. Live-network.
	ValidateCapabilities(ctx context.Context, req CapabilityCheckRequest) (CapabilityReport, error)

	// Revoke tears down / disables the trust. Live-network.
	Revoke(ctx context.Context, req RevokeRequest) error
}

// AdapterFor returns the provider adapter for p wired to its LIVE production
// token exchanger AND probe client (real endpoints, env-backed platform
// identity), or nil if unknown. Resolution goes through the provider registry
// (registry.go) — AdapterFor stays the adapter seam; the descriptor owns how
// its adapter is constructed.
func AdapterFor(p Provider) CloudIdentityProvider {
	d, ok := providerRegistry[p]
	if !ok {
		return nil
	}
	return d.NewAdapter()
}

// NewAdapterWithExchanger returns the provider adapter wired to an injected
// TokenExchanger — the DI seam tests and alternative deployments use (e.g. an
// httptest server standing in for STS/Entra/Google endpoints). No probe client
// is wired: DiscoverScopes/ValidateCapabilities defer. Unknown provider (or a
// descriptor without the injection hook) → nil.
func NewAdapterWithExchanger(p Provider, x TokenExchanger) CloudIdentityProvider {
	d, ok := providerRegistry[p]
	if !ok || d.NewAdapterWithExchanger == nil {
		return nil
	}
	return d.NewAdapterWithExchanger(x)
}

// NewAWSAdapter returns the AWS adapter with fully injected seams (tests /
// alternative deployments). Either seam may be nil → that surface defers.
func NewAWSAdapter(x TokenExchanger, probe *AWSProbeClient) CloudIdentityProvider {
	return awsAdapter{exchange: x, probe: probe}
}

// NewAzureAdapter returns the Azure adapter with fully injected seams.
func NewAzureAdapter(x TokenExchanger, probe *AzureARMProbeClient) CloudIdentityProvider {
	return azureAdapter{exchange: x, probe: probe}
}

// NewGCPAdapter returns the GCP adapter with fully injected seams.
func NewGCPAdapter(x TokenExchanger, probe *GCPProbeClient) CloudIdentityProvider {
	return gcpAdapter{exchange: x, probe: probe}
}
