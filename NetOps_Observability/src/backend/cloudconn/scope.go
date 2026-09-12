// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

import "strings"

// ScopeType is a canonical, provider-neutral collection-scope kind. The COLLECTION
// scope (what an operator asks Correlix to observe) is deliberately distinct from
// the PERMISSION scope (what the granted trust actually reaches); a mismatch is
// surfaced as a warning, never silently widened.
type ScopeType string

const (
	ScopeOrg          ScopeType = "org"            // AWS Organizations root / Azure tenant root / GCP org
	ScopeMgmtGroup    ScopeType = "mgmt_group"     // Azure management group
	ScopeOU           ScopeType = "ou"             // AWS Organizational Unit
	ScopeFolder       ScopeType = "folder"         // GCP folder
	ScopeAccount      ScopeType = "account"        // AWS account
	ScopeSubscription ScopeType = "subscription"   // Azure subscription
	ScopeProject      ScopeType = "project"        // GCP project
	ScopeRegion       ScopeType = "region"         // a region within an account/sub/project
	ScopeResourceGrp  ScopeType = "resource_group" // Azure resource group
	ScopeVPC          ScopeType = "vpc"            // AWS/GCP VPC
	ScopeVNet         ScopeType = "vnet"           // Azure VNet
	ScopeExplicit     ScopeType = "explicit"       // an explicit list of resource ids
)

// ValidForProvider reports whether a scope type is meaningful for a provider.
// The valid set is declared on the provider's registered descriptor (registry.go).
func (st ScopeType) ValidForProvider(p Provider) bool {
	d, ok := providerRegistry[p]
	if !ok {
		return false
	}
	for _, s := range d.ScopeTypes {
		if s == st {
			return true
		}
	}
	return false
}

// ScopeTypesForProvider lists the scope types a provider supports in the
// descriptor's declared broad → narrow order (a copy — never the registry slice).
func ScopeTypesForProvider(p Provider) []ScopeType {
	d, ok := providerRegistry[p]
	if !ok {
		return nil
	}
	return append([]ScopeType(nil), d.ScopeTypes...)
}

// Scope is one collection-scope binding: a scope type plus the provider-native id
// it points at (account id, subscription id, project id, region, ...). Never used
// as a uniqueness key on its own — provider ids are not globally unique across
// Correlix tenants.
type Scope struct {
	Type       ScopeType `json:"type"`
	Ref        string    `json:"ref"`                  // provider-native id (account/sub/project/region/...)
	Display    string    `json:"display,omitempty"`    // human label; NEVER an identity/uniqueness key
	Regions    []string  `json:"regions,omitempty"`    // optional region narrowing
	Discovered bool      `json:"discovered,omitempty"` // came from DiscoverScopes (vs operator-entered)
}

// ParseScopeType normalizes a free-form scope token.
func ParseScopeType(s string) (ScopeType, bool) {
	st := ScopeType(strings.ToLower(strings.TrimSpace(s)))
	for p := range providerRegistry {
		if st.ValidForProvider(p) {
			return st, true
		}
	}
	return st, false
}

// ValidateScopes checks a scope set for a provider: non-empty, each type valid for
// the provider, each with a ref. Returns the first problem found, or nil.
func ValidateScopes(p Provider, scopes []Scope) error {
	if len(scopes) == 0 {
		return &ContractError{Code: "scope_empty", Msg: "at least one collection scope is required"}
	}
	for _, sc := range scopes {
		if !sc.Type.ValidForProvider(p) {
			return &ContractError{Code: "scope_type_invalid", Msg: "scope type " + string(sc.Type) + " is not valid for provider " + string(p)}
		}
		if strings.TrimSpace(sc.Ref) == "" {
			return &ContractError{Code: "scope_ref_missing", Msg: "scope of type " + string(sc.Type) + " needs a provider ref"}
		}
	}
	return nil
}
