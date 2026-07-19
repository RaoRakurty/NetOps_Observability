package cloudconn

// org.go — org-level (multi-account) onboarding contract (Wave 5 #17 slice 2).
//
// An ORG connector anchors its trust on a provider organization container —
// AWS Organizations root/OU, Azure tenant root/management group, GCP
// organization/folder — instead of a single account. The anchor drives:
//
//   - SetupInstructions: org-level trust artifacts (StackSet / management-group
//     role assignment / folder IAM binding) rendered next to the single-account
//     ones, so the operator deploys the observer trust ONCE for every member.
//   - DiscoverScopes: an org connector is ENUMERABLE — with live credentials
//     the provider probe lists the member accounts/subscriptions/projects under
//     the anchor. Without live credentials the honest deferral sentinel
//     (ErrProviderExchangeDeferred) is returned, never a fabricated list.
//
// §3a: the org connector stays TENANT-OWNED; every member scope discovered or
// selected under it inherits the connector's tenant (the connector row is the
// single stamping source — see cloud_ingest_service.go). Discovery NEVER
// silently widens collection: the operator still selects what to observe.

import "strings"

// OrgScopeAnchor is the org-level enrollment anchor on a connector's identity
// configuration. All fields are non-secret deployment metadata.
type OrgScopeAnchor struct {
	// Type is the org container kind — must be one of the provider
	// descriptor's OrgScopeTypes (aws: org|ou, azure: org|mgmt_group,
	// gcp: org|folder).
	Type ScopeType `json:"type"`
	// Ref is the provider-native container id (o-…, ou-…, management-group
	// id, tenant root group, organization id, folder id).
	Ref string `json:"ref"`
	// RoleTemplate names the role/permission template stamped into every
	// member account by the org-level deployment (the StackSet stack /
	// inherited role assignment / folder binding). Empty → the default
	// observer role name.
	RoleTemplate string `json:"role_template,omitempty"`
}

// DefaultOrgRoleTemplate is the member-account role name the org-level
// artifacts deploy when the operator does not override it.
const DefaultOrgRoleTemplate = "correlix-observer"

// RoleTemplateOrDefault returns the effective member-role template name.
func (a OrgScopeAnchor) RoleTemplateOrDefault() string {
	if t := strings.TrimSpace(a.RoleTemplate); t != "" {
		return t
	}
	return DefaultOrgRoleTemplate
}

// OrgScopeTypesForProvider lists the org-anchor kinds a provider supports
// (registry-driven; a copy).
func OrgScopeTypesForProvider(p Provider) []ScopeType {
	d, ok := providerRegistry[p]
	if !ok {
		return nil
	}
	return append([]ScopeType(nil), d.OrgScopeTypes...)
}

// MemberScopeTypeForProvider is what enumerating an org anchor yields
// (account / subscription / project). "" for an unknown provider.
func MemberScopeTypeForProvider(p Provider) ScopeType {
	d, ok := providerRegistry[p]
	if !ok {
		return ""
	}
	return d.MemberScopeType
}

// IsOrgScopeType reports whether st is an org-anchor kind for provider p.
func IsOrgScopeType(p Provider, st ScopeType) bool {
	for _, t := range OrgScopeTypesForProvider(p) {
		if t == st {
			return true
		}
	}
	return false
}

// ValidateOrgAnchor checks an org anchor for a provider: known org container
// kind, non-empty ref, and a role template that is a plain resource name (no
// path/wildcard tricks — it is spliced into deploy artifacts).
func ValidateOrgAnchor(p Provider, a OrgScopeAnchor) error {
	if !IsOrgScopeType(p, a.Type) {
		return &ContractError{Code: "org_scope_type_invalid",
			Msg: "scope type " + string(a.Type) + " is not an org-level anchor for provider " + string(p)}
	}
	if strings.TrimSpace(a.Ref) == "" {
		return &ContractError{Code: "org_ref_missing", Msg: "the org/management-group/folder id is required"}
	}
	if t := strings.TrimSpace(a.RoleTemplate); t != "" && !validRoleTemplateName(t) {
		return &ContractError{Code: "org_role_template_invalid",
			Msg: "the role template must be a plain name (letters, digits, . _ + = , @ -), max 64 chars"}
	}
	return nil
}

// orgAnchorFor resolves the effective org anchor of a discover request: the
// request Root when it names an org-level scope, else the identity's stored
// anchor. nil = single-account discovery.
func orgAnchorFor(req DiscoverRequest, p Provider) *OrgScopeAnchor {
	if IsOrgScopeType(p, req.Root.Type) && strings.TrimSpace(req.Root.Ref) != "" {
		return &OrgScopeAnchor{Type: req.Root.Type, Ref: strings.TrimSpace(req.Root.Ref)}
	}
	if req.Identity.Org != nil && IsOrgScopeType(p, req.Identity.Org.Type) && strings.TrimSpace(req.Identity.Org.Ref) != "" {
		return req.Identity.Org
	}
	return nil
}

// validRoleTemplateName bounds the member-role name to the common IAM-safe
// character set — it is embedded verbatim in rendered artifacts.
func validRoleTemplateName(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '+' || r == '=' || r == ',' || r == '@' || r == '-':
		default:
			return false
		}
	}
	return true
}
