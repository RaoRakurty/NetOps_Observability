// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

import "strings"

// Provider is the cloud provider a connection targets. Provider-neutral code
// branches on this; the UI/API never leaks the underlying backend vendor beyond
// these three canonical tokens.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

// Valid reports whether p is a registered provider (registry.go).
func (p Provider) Valid() bool {
	_, ok := providerRegistry[p]
	return ok
}

// ParseProvider normalizes a free-form provider token.
func ParseProvider(s string) (Provider, bool) {
	p := Provider(strings.ToLower(strings.TrimSpace(s)))
	return p, p.Valid()
}

// AuthMethod is HOW Correlix authenticates to the provider. The ordering here is
// the security preference order (lower rank = more preferred). Federated methods
// are secretless; legacy methods hold a reusable secret and are de-emphasized.
type AuthMethod string

const (
	// AuthMethodWorkloadFederation — OIDC workload-identity federation. Correlix
	// presents a signed OIDC assertion (its own workload identity) and receives a
	// short-lived provider token. No stored provider secret. PREFERRED.
	//   Azure: Entra Workload Identity Federation (federated credential).
	//   GCP:   Workload Identity Federation pool + provider (+ optional SA impersonation).
	//   AWS:   IAM OIDC identity provider → AssumeRoleWithWebIdentity.
	AuthMethodWorkloadFederation AuthMethod = "workload_identity_federation"

	// AuthMethodCloudRole — cloud-native cross-account role / managed identity with
	// no stored secret; trust is anchored on a principal + external id.
	//   AWS: cross-account IAM role, sts:AssumeRole with a per-connector ExternalId.
	//   Azure: managed identity (future).
	AuthMethodCloudRole AuthMethod = "cloud_role"

	// AuthMethodCertificate — customer certificate credential (Azure app cert).
	// Correlix stores the certificate + private key PEM bundle Vault-encrypted
	// (like a legacy secret) and signs a per-exchange client-assertion JWT with
	// it; the assertion is short-lived even though the key material is stored.
	AuthMethodCertificate AuthMethod = "certificate"

	// AuthMethodClientSecret — rotatable client secret (Azure app secret). LEGACY.
	AuthMethodClientSecret AuthMethod = "client_secret"

	// AuthMethodStaticKey — long-lived static access key / service-account key.
	// LEGACY fallback only: labeled, root/admin rejected, encrypted, never re-shown.
	AuthMethodStaticKey AuthMethod = "static_key"

	// AuthMethodProhibited — cloud admin username/password. NEVER a connector
	// credential; present only so validation can reject it explicitly.
	AuthMethodProhibited AuthMethod = "admin_password"
)

// authMethodRank orders methods by the security preference order (§ doc.go).
var authMethodRank = map[AuthMethod]int{
	AuthMethodWorkloadFederation: 1,
	AuthMethodCloudRole:          2,
	AuthMethodCertificate:        3,
	AuthMethodClientSecret:       4,
	AuthMethodStaticKey:          5,
	AuthMethodProhibited:         6,
}

// Rank returns the preference rank (1 = most preferred). Unknown → 0.
func (m AuthMethod) Rank() int { return authMethodRank[m] }

// Valid reports whether m is a recognized method (prohibited counts as known).
func (m AuthMethod) Valid() bool { _, ok := authMethodRank[m]; return ok }

// IsFederated reports whether the method is secretless workload federation.
func (m AuthMethod) IsFederated() bool { return m == AuthMethodWorkloadFederation }

// IsLegacy reports whether the method holds a long-lived reusable secret and
// should be visually de-emphasized + policy-disableable.
func (m AuthMethod) IsLegacy() bool {
	return m == AuthMethodClientSecret || m == AuthMethodStaticKey
}

// IsProhibited reports whether the method must be rejected outright.
func (m AuthMethod) IsProhibited() bool { return m == AuthMethodProhibited }

// HoldsStoredSecret reports whether choosing the method means Correlix must store
// reusable provider credential material (→ Vault-encrypted, audited, rotatable).
// Federated and cloud-role do not. Certificate does: minting the client-assertion
// JWT requires the certificate's private key (uploaded as a PEM bundle, encrypted
// at rest, decrypted only by the broker at exchange time).
func (m AuthMethod) HoldsStoredSecret() bool {
	return m == AuthMethodClientSecret || m == AuthMethodStaticKey || m == AuthMethodCertificate
}

// ParseAuthMethod normalizes a free-form method token.
func ParseAuthMethod(s string) (AuthMethod, bool) {
	m := AuthMethod(strings.ToLower(strings.TrimSpace(s)))
	return m, m.Valid()
}

// ProviderMethods returns the auth methods a provider supports, preference-ordered
// (index 0 = most preferred). AuthMethodProhibited is never offered. The offer
// comes from the provider's registered descriptor (registry.go); a copy is
// returned so callers can never mutate the registry.
func ProviderMethods(p Provider) []AuthMethod {
	d, ok := providerRegistry[p]
	if !ok {
		return nil
	}
	return append([]AuthMethod(nil), d.AuthMethods...)
}

// MethodAllowed reports whether p offers method m at all.
func MethodAllowed(p Provider, m AuthMethod) bool {
	for _, x := range ProviderMethods(p) {
		if x == m {
			return true
		}
	}
	return false
}
