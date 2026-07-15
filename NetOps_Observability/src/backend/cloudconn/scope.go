package cloudconn

import "strings"

// ScopeType is a canonical, provider-neutral collection-scope kind. The COLLECTION
// scope (what an operator asks Correlix to observe) is deliberately distinct from
// the PERMISSION scope (what the granted trust actually reaches); a mismatch is
// surfaced as a warning, never silently widened.
type ScopeType string

const (
	ScopeOrg          ScopeType = "org"           // AWS Organizations root / Azure tenant root / GCP org
	ScopeMgmtGroup    ScopeType = "mgmt_group"    // Azure management group
	ScopeOU           ScopeType = "ou"            // AWS Organizational Unit
	ScopeFolder       ScopeType = "folder"        // GCP folder
	ScopeAccount      ScopeType = "account"       // AWS account
	ScopeSubscription ScopeType = "subscription"  // Azure subscription
	ScopeProject      ScopeType = "project"       // GCP project
	ScopeRegion       ScopeType = "region"        // a region within an account/sub/project
	ScopeResourceGrp  ScopeType = "resource_group" // Azure resource group
	ScopeVPC          ScopeType = "vpc"           // AWS/GCP VPC
	ScopeVNet         ScopeType = "vnet"          // Azure VNet
	ScopeExplicit     ScopeType = "explicit"      // an explicit list of resource ids
)

var scopeByProvider = map[Provider]map[ScopeType]bool{
	ProviderAWS: {
		ScopeOrg: true, ScopeOU: true, ScopeAccount: true, ScopeRegion: true,
		ScopeVPC: true, ScopeExplicit: true,
	},
	ProviderAzure: {
		ScopeOrg: true, ScopeMgmtGroup: true, ScopeSubscription: true, ScopeRegion: true,
		ScopeResourceGrp: true, ScopeVNet: true, ScopeExplicit: true,
	},
	ProviderGCP: {
		ScopeOrg: true, ScopeFolder: true, ScopeProject: true, ScopeRegion: true,
		ScopeVPC: true, ScopeExplicit: true,
	},
}

// ValidForProvider reports whether a scope type is meaningful for a provider.
func (st ScopeType) ValidForProvider(p Provider) bool {
	return scopeByProvider[p][st]
}

// ScopeTypesForProvider lists the scope types a provider supports (unordered set
// materialized in a stable order for the UI).
func ScopeTypesForProvider(p Provider) []ScopeType {
	// deterministic order: broad → narrow
	order := []ScopeType{
		ScopeOrg, ScopeMgmtGroup, ScopeOU, ScopeFolder, ScopeAccount, ScopeSubscription,
		ScopeProject, ScopeResourceGrp, ScopeVPC, ScopeVNet, ScopeRegion, ScopeExplicit,
	}
	out := make([]ScopeType, 0, len(order))
	for _, st := range order {
		if st.ValidForProvider(p) {
			out = append(out, st)
		}
	}
	return out
}

// Scope is one collection-scope binding: a scope type plus the provider-native id
// it points at (account id, subscription id, project id, region, ...). Never used
// as a uniqueness key on its own — provider ids are not globally unique across
// Correlix tenants.
type Scope struct {
	Type      ScopeType `json:"type"`
	Ref       string    `json:"ref"`             // provider-native id (account/sub/project/region/...)
	Display   string    `json:"display,omitempty"` // human label; NEVER an identity/uniqueness key
	Regions   []string  `json:"regions,omitempty"` // optional region narrowing
	Discovered bool     `json:"discovered,omitempty"` // came from DiscoverScopes (vs operator-entered)
}

// ParseScopeType normalizes a free-form scope token.
func ParseScopeType(s string) (ScopeType, bool) {
	st := ScopeType(strings.ToLower(strings.TrimSpace(s)))
	for p := range scopeByProvider {
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
