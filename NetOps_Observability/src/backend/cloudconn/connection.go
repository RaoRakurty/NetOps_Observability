package cloudconn

import "strings"

// LifecycleState is the connector lifecycle state machine. A connector cannot
// collect telemetry until StateActive, and can only reach StateActive through
// successful validation. Identity health (can we authenticate?) is tracked
// SEPARATELY from telemetry health (is data flowing?) — see Health.
type LifecycleState string

const (
	StateDraft                   LifecycleState = "DRAFT"                    // created, auth not yet chosen/deployed
	StateDeploying               LifecycleState = "DEPLOYING"                // operator deploying trust (templates) on their side
	StateValidating              LifecycleState = "VALIDATING"               // running trust/permission validation
	StateActive                  LifecycleState = "ACTIVE"                   // validated; collecting
	StateDegraded                LifecycleState = "DEGRADED"                 // collecting but partial (some sources/perms failing)
	StateRotationRequired        LifecycleState = "ROTATION_REQUIRED"        // a stored secret is aging/expiring
	StateReauthorizationRequired LifecycleState = "REAUTHORIZATION_REQUIRED" // trust broke; needs re-consent/re-deploy
	StateDisabled                LifecycleState = "DISABLED"                 // operator-paused; no collection, trust intact
	StateRevoked                 LifecycleState = "REVOKED"                  // trust torn down; cannot exchange tokens
	StateDeleting                LifecycleState = "DELETING"                 // teardown in progress
	StateDeleted                 LifecycleState = "DELETED"                  // terminal
)

// validTransitions is the allowed state-machine edge set. Anything not listed is
// rejected — no silent illegal jumps.
var validTransitions = map[LifecycleState]map[LifecycleState]bool{
	StateDraft:                   set(StateDeploying, StateValidating, StateDisabled, StateDeleting),
	StateDeploying:               set(StateValidating, StateDraft, StateDisabled, StateDeleting),
	StateValidating:              set(StateActive, StateDegraded, StateReauthorizationRequired, StateDraft, StateDisabled, StateDeleting),
	StateActive:                  set(StateDegraded, StateRotationRequired, StateReauthorizationRequired, StateValidating, StateDisabled, StateRevoked, StateDeleting),
	StateDegraded:                set(StateActive, StateRotationRequired, StateReauthorizationRequired, StateValidating, StateDisabled, StateRevoked, StateDeleting),
	StateRotationRequired:        set(StateValidating, StateActive, StateDegraded, StateDisabled, StateRevoked, StateDeleting),
	StateReauthorizationRequired: set(StateValidating, StateDeploying, StateDisabled, StateRevoked, StateDeleting),
	StateDisabled:                set(StateValidating, StateDraft, StateRevoked, StateDeleting),
	StateRevoked:                 set(StateDeleting),
	StateDeleting:                set(StateDeleted),
	StateDeleted:                 set(),
}

func set(states ...LifecycleState) map[LifecycleState]bool {
	m := make(map[LifecycleState]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return m
}

// CanTransition reports whether from→to is a legal lifecycle edge.
func CanTransition(from, to LifecycleState) bool {
	return validTransitions[from][to]
}

// Collecting reports whether telemetry collection is permitted in this state.
// Only ACTIVE and DEGRADED collect; everything else is fail-closed.
func (s LifecycleState) Collecting() bool {
	return s == StateActive || s == StateDegraded
}

// CanExchangeToken reports whether the Identity Broker may mint a provider token
// for a connector in this state. Disabled/revoked/deleted fail closed.
func (s LifecycleState) CanExchangeToken() bool {
	switch s {
	case StateValidating, StateActive, StateDegraded, StateRotationRequired:
		return true
	default:
		return false
	}
}

// Terminal reports whether no further transitions are possible.
func (s LifecycleState) Terminal() bool { return s == StateDeleted }

// IdentityConfig is CONCERN 1 (Identity): who Correlix authenticates AS to the
// provider. It holds ONLY trust metadata — never a plaintext secret. A stored
// legacy secret lives in the Vault and is referenced by LegacySecretRef.
//
// A connection is NEVER keyed off DisplayName / account / subscription / project
// name / client id alone; the opaque connector id is the identity key.
type IdentityConfig struct {
	Provider    Provider   `json:"provider"`
	Method      AuthMethod `json:"method"`
	TenantID    string     `json:"tenant_id"`    // Correlix owning tenant (from token, never body)
	ConnectorID string     `json:"connector_id"` // opaque ccn_ id

	// AWS
	RoleARN    string `json:"role_arn,omitempty"`
	ExternalID string `json:"external_id,omitempty"` // per-tenant+connector, confused-deputy protection

	// Azure (workload federation / certificate / client secret)
	AzureTenantID    string `json:"azure_tenant_id,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Audience         string `json:"audience,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	FederatedSubject string `json:"federated_subject,omitempty"`
	CertThumbprint   string `json:"cert_thumbprint,omitempty"`

	// GCP (workload federation)
	ProjectNumber    string `json:"project_number,omitempty"`
	WorkloadPool     string `json:"workload_pool,omitempty"`
	WorkloadProvider string `json:"workload_provider,omitempty"`
	ServiceAccount   string `json:"service_account,omitempty"` // SA email for impersonation

	// Legacy static-credential path (references only — NEVER the secret itself).
	LegacySecretRef string `json:"legacy_secret_ref,omitempty"` // csr_ handle into the Vault
	LegacyKeyID     string `json:"legacy_key_id,omitempty"`     // AWS AccessKeyId / GCP SA key id — non-secret, for age tracking

	// Org is the OPTIONAL org-level (multi-account) enrollment anchor (org.go).
	// Non-secret deployment metadata, persisted with the identity config: it
	// shapes the rendered trust artifacts (StackSet / management-group role /
	// folder binding) and makes DiscoverScopes enumerate member accounts. nil =
	// single-account connector.
	Org *OrgScopeAnchor `json:"org,omitempty"`

	// Anchor is Correlix's own side of the trust (its AWS principal / OIDC issuer
	// + subject the customer's trust policy must reference). It is populated by the
	// framework from PLATFORM config when rendering setup templates — NEVER from a
	// request body — and is not a per-tenant secret.
	Anchor TrustAnchor `json:"anchor,omitempty"`
}

// TrustAnchor is Correlix's identity as seen by the customer's cloud when
// establishing trust. All fields are non-secret and platform-global.
type TrustAnchor struct {
	AWSPrincipalARN string `json:"aws_principal_arn,omitempty"` // the Correlix principal the customer role trusts
	OIDCIssuer      string `json:"oidc_issuer,omitempty"`       // Correlix workload OIDC issuer URL
	OIDCSubject     string `json:"oidc_subject,omitempty"`      // subject Correlix presents in its assertion
	OIDCAudience    string `json:"oidc_audience,omitempty"`     // audience the provider expects
}

// ParseLifecycleState normalizes a free-form state token.
func ParseLifecycleState(s string) (LifecycleState, bool) {
	st := LifecycleState(strings.ToUpper(strings.TrimSpace(s)))
	if _, ok := validTransitions[st]; ok {
		return st, true
	}
	return st, false
}
