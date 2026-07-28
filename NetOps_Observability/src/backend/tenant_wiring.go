package main

// tenant_wiring.go — composition root + source-compat shims for internal/tenant.
//
// The tenant model/store owns the isolation boundary's data; what it must NOT
// own are its cross-domain inputs — persistence, the org-layer default,
// identity-id minting/slug rules and region validation — so those are injected
// here (§2: main is wiring). The aliases keep the ~75 in-package consumers of
// the Tenant type and its sentinels source-compatible.

import "netops/backend/internal/tenant"

// Type + constant shims (the jwtClaims-alias technique).
type (
	Tenant        = tenant.Tenant
	IsolationMode = tenant.IsolationMode
	tenantRepo    = tenant.Repo
)

const (
	TenantGlobal          = tenant.Global
	TenantStatusActive    = tenant.StatusActive
	TenantStatusSuspended = tenant.StatusSuspended

	IsolationShared           = tenant.IsolationShared
	IsolationDedicatedSchema  = tenant.IsolationDedicatedSchema
	IsolationDedicatedDB      = tenant.IsolationDedicatedDB
	IsolationDedicatedCluster = tenant.IsolationDedicatedCluster
)

// tenantDeps supplies the store's injected cross-domain dependencies.
func tenantDeps() tenant.Deps {
	return tenant.Deps{
		KV:           platformKV{},
		DefaultOrg:   OrgGlobal,
		MintID:       mintTenantID,
		SlugFromName: slugFromName,
		ValidateSlug: validateSlug,
		ValidateRegion: func(r string) error {
			_, err := normalizeRegion(r)
			return err
		},
	}
}

// newTenantStore keeps the historical constructor shape for the many call sites
// (prod + tests) that only ever vary the path.
func newTenantStore(path string) (*tenant.Store, error) {
	return tenant.NewStore(path, tenantDeps())
}
