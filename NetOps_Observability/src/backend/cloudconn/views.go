// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// views.go — the API/UI projections of a connector (Phase-2 W3.10, extracted
// from package main's cloud_connectors_handlers.go): the redacted connector
// view (never secret material), the identity/trust view, and the root-key
// hint heuristic the onboarding flow warns on. Handlers stay in main.

import (
	"strings"
	"time"
)

type ConnectorView struct {
	ID              string           `json:"id"`
	Provider        Provider         `json:"provider"`
	DisplayName     string           `json:"display_name"`
	AuthMethod      AuthMethod       `json:"auth_method"`
	AuthFederated   bool             `json:"auth_federated"`
	AuthLegacy      bool             `json:"auth_legacy"`
	PackFullID      string           `json:"capability_pack"`
	State           LifecycleState   `json:"state"`
	Collecting      bool             `json:"collecting"`
	Identity        IdentityView     `json:"identity"`
	Scopes          []Scope          `json:"scopes"`
	IdentityHealth  HealthStatus     `json:"identity_health"`
	TelemetryHealth HealthStatus     `json:"telemetry_health"`
	LastValidation  ValidationResult `json:"last_validation"`
	Version         int64            `json:"version"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// IdentityView exposes only NON-secret trust metadata.
type IdentityView struct {
	RoleARN          string `json:"role_arn,omitempty"`
	ExternalID       string `json:"external_id,omitempty"`
	AzureTenantID    string `json:"azure_tenant_id,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Audience         string `json:"audience,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	FederatedSubject string `json:"federated_subject,omitempty"`
	CertThumbprint   string `json:"cert_thumbprint,omitempty"`
	ProjectNumber    string `json:"project_number,omitempty"`
	WorkloadPool     string `json:"workload_pool,omitempty"`
	WorkloadProvider string `json:"workload_provider,omitempty"`
	ServiceAccount   string `json:"service_account,omitempty"`
	HasLegacySecret  bool   `json:"has_legacy_secret"` // a secret is stored (never the value)
	LegacyKeyHint    string `json:"legacy_key_hint,omitempty"`
	// Org is the org-level (multi-account) enrollment anchor — non-secret
	// deployment metadata (Wave 5 #17 slice 2). nil = single-account connector.
	Org *OrgScopeAnchor `json:"org,omitempty"`
}

func ToConnectorView(c Connector) ConnectorView {
	return ConnectorView{
		ID: c.ConnectorID, Provider: c.Provider, DisplayName: c.DisplayName,
		AuthMethod: c.AuthMethod, AuthFederated: c.AuthMethod.IsFederated(), AuthLegacy: c.AuthMethod.IsLegacy(),
		PackFullID: c.PackFullID, State: c.State, Collecting: c.State.Collecting(),
		Identity: IdentityView{
			RoleARN: c.Identity.RoleARN, ExternalID: c.Identity.ExternalID,
			AzureTenantID: c.Identity.AzureTenantID, ClientID: c.Identity.ClientID,
			Audience: c.Identity.Audience, Issuer: c.Identity.Issuer,
			FederatedSubject: c.Identity.FederatedSubject, CertThumbprint: c.Identity.CertThumbprint,
			ProjectNumber: c.Identity.ProjectNumber, WorkloadPool: c.Identity.WorkloadPool,
			WorkloadProvider: c.Identity.WorkloadProvider, ServiceAccount: c.Identity.ServiceAccount,
			HasLegacySecret: c.Identity.LegacySecretRef != "", LegacyKeyHint: c.Identity.LegacyKeyID,
			Org: c.Identity.Org,
		},
		Scopes: c.Scopes, IdentityHealth: c.IdentityHealth, TelemetryHealth: c.TelemetryHealth,
		LastValidation: c.LastValidation, Version: c.Version, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
}

// cloudTrustAnchor builds Correlix's own trust anchor from PLATFORM env (never a
// request body): the AWS principal customer roles trust, and the OIDC issuer for
// Azure/GCP workload federation.
func IsRootKeyHint(hint string) bool {
	h := strings.ToLower(strings.TrimSpace(hint))
	return h == "root" || strings.HasPrefix(h, "root:") || strings.Contains(h, "administratoraccess")
}
