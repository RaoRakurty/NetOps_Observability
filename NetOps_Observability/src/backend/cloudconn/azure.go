package cloudconn

import (
	"context"
	"fmt"
	"strings"
)

// azureAdapter implements CloudIdentityProvider for Azure. The preferred method is
// Entra Workload Identity Federation: Correlix presents its own OIDC workload
// assertion and receives a short-lived Azure token — no stored client secret. A
// certificate credential is the non-federated fallback; a client secret is a
// labeled legacy option. Runtime uses the app/workload identity, NEVER delegated
// user tokens (admin-consent OAuth is a SETUP step that grants app roles).
// Live token acquisition is delegated to the injected TokenExchanger
// (AzureEntraExchanger in production).
type azureAdapter struct {
	exchange TokenExchanger
	probe    *AzureARMProbeClient
}

// init registers Azure in the ONE provider registry (registry.go).
func init() {
	RegisterProvider(ProviderDescriptor{
		ID:          ProviderAzure,
		DisplayName: "Microsoft Azure",
		ShortLabel:  "Azure",
		AuthMethods: []AuthMethod{AuthMethodWorkloadFederation, AuthMethodCertificate, AuthMethodClientSecret},
		ScopeTypes: []ScopeType{
			ScopeOrg, ScopeMgmtGroup, ScopeSubscription, ScopeResourceGrp, ScopeVNet, ScopeRegion, ScopeExplicit,
		},
		OrgScopeTypes:   []ScopeType{ScopeOrg, ScopeMgmtGroup},
		MemberScopeType: ScopeSubscription,
		SetupDocKey:     "cloud-connector-azure",
		HasFlowLogs:     false, // honest: no VNet flow-log capability in azure-observer-v1
		HasHealthLane:   false, // honest: no Azure Service Health lane built yet
		IdentityRef:     func(cfg IdentityConfig) string { return cfg.ClientID },
		NewAdapter: func() CloudIdentityProvider {
			return azureAdapter{exchange: NewAzureEntraExchanger(), probe: NewAzureARMProbeClient()}
		},
		NewAdapterWithExchanger: func(x TokenExchanger) CloudIdentityProvider {
			return azureAdapter{exchange: x}
		},
		NewAdapterWithAssertions: func(src WorkloadAssertionSource) CloudIdentityProvider {
			x := NewAzureEntraExchanger()
			x.Assertions = src
			return azureAdapter{exchange: x, probe: NewAzureARMProbeClient()}
		},
	})
}

func (azureAdapter) Provider() Provider { return ProviderAzure }

func (a azureAdapter) ValidateConfiguration(cfg IdentityConfig) ValidationResult {
	r := ValidationResult{OK: true}
	if cfg.Provider != ProviderAzure {
		r.Add(SeverityError, "provider_mismatch", "identity provider is not azure", "Recreate the connector with provider=azure.")
		return r
	}
	if cfg.Method.IsProhibited() {
		r.Add(SeverityError, "method_prohibited", "an Azure admin username/password is never a connector credential", "Use Workload Identity Federation (recommended), a certificate, or a legacy client secret.")
		return r
	}
	if !MethodAllowed(ProviderAzure, cfg.Method) {
		r.Add(SeverityError, "method_unsupported", "auth method "+string(cfg.Method)+" is not supported for Azure", "Use Workload Identity Federation (recommended), a certificate, or a client secret.")
		return r
	}
	// Common identifiers required for every Azure method.
	if strings.TrimSpace(cfg.AzureTenantID) == "" {
		r.Add(SeverityError, "azure_tenant_missing", "the Entra (Azure AD) tenant id is required", "Copy the Directory (tenant) ID from the app registration.")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		r.Add(SeverityError, "client_id_missing", "the application (client) id is required", "Copy the Application (client) ID from the app registration.")
	}

	switch cfg.Method {
	case AuthMethodWorkloadFederation:
		if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.FederatedSubject) == "" {
			r.Add(SeverityError, "federation_incomplete", "workload federation needs the issuer + subject of the Correlix workload identity", "Deploy the federated credential from the setup step; the framework supplies issuer/subject.")
		}
		if strings.TrimSpace(cfg.Audience) == "" {
			r.Add(SeverityWarning, "audience_default", "no audience set; the Entra default api://AzureADTokenExchange will be used", "")
		}
	case AuthMethodCertificate:
		if strings.TrimSpace(cfg.CertThumbprint) == "" {
			r.Add(SeverityError, "cert_thumbprint_missing", "the certificate thumbprint is required", "Upload the certificate to the app registration and paste its thumbprint.")
		}
		if cfg.LegacySecretRef == "" {
			r.Add(SeverityError, "cert_material_missing", "the certificate + private key bundle has not been uploaded", "Upload the certificate PEM bundle (certificate + private key); it is encrypted immediately and never re-displayed.")
		}
	case AuthMethodClientSecret:
		r.Add(SeverityWarning, "legacy_method", "a client secret is a legacy credential — not recommended", "Prefer Workload Identity Federation: no stored secret, short-lived tokens.")
		if cfg.LegacySecretRef == "" {
			r.Add(SeverityError, "secret_ref_missing", "the encrypted client-secret reference is required", "Submit the client secret; it is encrypted immediately and never re-displayed.")
		}
	}
	return r
}

func (a azureAdapter) SetupInstructions(cfg IdentityConfig, pack CapabilityPack) (SetupBundle, error) {
	if pack.Provider != ProviderAzure {
		return SetupBundle{}, &ContractError{Code: "pack_provider_mismatch", Msg: "capability pack is not an Azure pack"}
	}
	issuer := orPlaceholder(cfg.Anchor.OIDCIssuer, "https://<correlix-issuer>")
	subject := orPlaceholder(cfg.Anchor.OIDCSubject, "correlix:connector:<connector-id>")
	audience := orPlaceholder(cfg.Audience, "api://AzureADTokenExchange")
	sub := "<SUBSCRIPTION_ID>"

	bundle := SetupBundle{
		Provider: ProviderAzure,
		Method:   cfg.Method,
		Summary:  fmt.Sprintf("Register a Correlix app in Entra, grant it read-only roles (%s), and federate it to the Correlix workload identity — no stored secret.", pack.FullID()),
		Steps: []string{
			"Option A (recommended): click Connect with Microsoft to run admin-consent OAuth — it registers the app and grants the read-only roles below in one flow. Consent grants APP roles; Correlix's runtime uses the app/workload identity, never your user token.",
			"Option B (manual): create an app registration, then add the federated credential JSON below (Workload Identity Federation).",
			"Assign the built-in Reader + Monitoring Reader roles at the subscription scope.",
			"Paste the tenant id + client id back into Correlix and run Validate Trust.",
		},
		Artifacts: []SetupArtifact{
			{Kind: "federated_credential", Title: "Entra federated credential (Workload Identity Federation)", Format: "json", Content: azureFederatedCredential(issuer, subject, audience)},
			{Kind: "azure_cli", Title: "Azure CLI — app + least-privilege role assignment", Format: "text", Content: azureCLI(sub, pack)},
			{Kind: "manual", Title: "Admin-consent OAuth (Connect with Microsoft)", Format: "text", Content: azureAdminConsent(pack)},
		},
	}
	return bundle, nil
}

func azureFederatedCredential(issuer, subject, audience string) string {
	return `{
  "name": "correlix-workload-federation",
  "issuer": "` + issuer + `",
  "subject": "` + subject + `",
  "description": "Correlix workload identity — short-lived federated tokens, no client secret",
  "audiences": ["` + audience + `"]
}
`
}

func azureCLI(sub string, pack CapabilityPack) string {
	var b strings.Builder
	b.WriteString("# Register the Correlix observer app and grant read-only roles (" + pack.FullID() + ")\n")
	b.WriteString("APP_ID=$(az ad app create --display-name correlix-observer --query appId -o tsv)\n")
	b.WriteString("az ad sp create --id \"$APP_ID\"\n")
	b.WriteString("SUB=" + sub + "\n")
	b.WriteString("az role assignment create --assignee \"$APP_ID\" --role \"Reader\" --scope \"/subscriptions/$SUB\"\n")
	b.WriteString("az role assignment create --assignee \"$APP_ID\" --role \"Monitoring Reader\" --scope \"/subscriptions/$SUB\"\n")
	b.WriteString("# Then add the federated credential (see the federated_credential artifact):\n")
	b.WriteString("az ad app federated-credential create --id \"$APP_ID\" --parameters correlix-fic.json\n")
	b.WriteString("# Reader + Monitoring Reader are read-only. Never grant Owner/Contributor.\n")
	return b.String()
}

func azureAdminConsent(pack CapabilityPack) string {
	return "Connect with Microsoft (admin-consent OAuth):\n\n" +
		"1. A Global Administrator opens the Correlix consent link and approves the read-only role grant.\n" +
		"2. Consent registers the multi-tenant Correlix app in your Entra tenant and grants the built-in\n" +
		"   Reader + Monitoring Reader roles for " + pack.FullID() + " (read-only).\n" +
		"3. IMPORTANT: consent grants APPLICATION roles. Correlix's runtime authenticates as the\n" +
		"   app / workload identity via Workload Identity Federation — it never uses a signed-in\n" +
		"   user's delegated token, and no user session is stored.\n" +
		"4. Return to Correlix and run Validate Trust.\n"
}

// ExchangeCredential acquires a short-lived Entra access token: the Correlix
// workload OIDC assertion (client_assertion, federated credential) for WIF, or
// the Vault-decrypted client secret for the legacy method. The configuration is
// re-validated first — an invalid config never reaches the wire (zero trust).
func (a azureAdapter) ExchangeCredential(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	if a.exchange == nil {
		return ScopedToken{}, ErrProviderExchangeDeferred
	}
	if res := a.ValidateConfiguration(req.Identity); !res.OK {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "identity configuration has blocking findings"}
	}
	return a.exchange.Exchange(ctx, req)
}

// DiscoverScopes lists the subscriptions the exchanged token can reach — the
// cheapest authenticated ARM read, doubling as the live identity proof.
func (a azureAdapter) DiscoverScopes(ctx context.Context, req DiscoverRequest) ([]Scope, error) {
	if a.probe == nil || strings.TrimSpace(req.Token.Value) == "" {
		return nil, ErrProviderExchangeDeferred
	}
	subs, err := a.probe.Subscriptions(ctx, req.Token.Value)
	if err != nil {
		return nil, err
	}
	scopes := make([]Scope, 0, len(subs))
	for _, sub := range subs {
		scopes = append(scopes, Scope{
			Type: ScopeSubscription, Ref: sub.SubscriptionID, Display: sub.DisplayName, Discovered: true,
		})
	}
	return scopes, nil
}

// ValidateCapabilities reads the principal's granted RBAC permission sets at
// the subscription scope and grades every pack permission against them with
// Azure wildcard semantics. Read-only; no target API is invoked.
func (a azureAdapter) ValidateCapabilities(ctx context.Context, req CapabilityCheckRequest) (CapabilityReport, error) {
	if a.probe == nil || strings.TrimSpace(req.Token.Value) == "" {
		return CapabilityReport{}, ErrProviderExchangeDeferred
	}
	sub := strings.TrimSpace(req.Scope.Ref)
	if sub == "" {
		return CapabilityReport{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "a subscription scope is required for the permission check"}
	}
	perms, err := a.probe.Permissions(ctx, req.Token.Value, sub)
	if err != nil {
		return CapabilityReport{}, err
	}
	report := CapabilityReport{Pack: req.Pack.FullID(), AllGranted: true}
	for _, required := range req.Pack.AllPermissions() {
		granted := AzureActionGranted(perms, required)
		detail := ""
		if !granted {
			report.AllGranted = false
			detail = "not covered by the granted RBAC actions at subscription " + sub
		}
		report.Permissions = append(report.Permissions, PermissionStatus{Permission: required, Granted: granted, Detail: detail})
	}
	if !report.AllGranted {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityWarning, Code: "permissions_missing",
			Message:     "some declared pack permissions are not granted at the subscription scope",
			Remediation: "Assign the built-in Reader + Monitoring Reader roles at the subscription scope, then re-run the permission check.",
		})
	}
	return report, nil
}

func (a azureAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}

func orPlaceholder(v, placeholder string) string {
	if strings.TrimSpace(v) == "" {
		return placeholder
	}
	return v
}
