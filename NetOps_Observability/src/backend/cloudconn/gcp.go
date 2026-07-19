package cloudconn

import (
	"context"
	"fmt"
	"strings"
)

// gcpAdapter implements CloudIdentityProvider for GCP. The preferred method is
// Workload Identity Federation: Correlix presents its OIDC assertion to a workload
// identity pool provider and receives a short-lived federated token (optionally
// impersonating a least-privilege service account) — no stored SA key. An SA JSON
// key is a labeled legacy fallback. Live credential exchange is delegated to
// the injected TokenExchanger (GCPSTSExchanger in production).
type gcpAdapter struct {
	exchange TokenExchanger
	probe    *GCPProbeClient
}

// init registers GCP in the ONE provider registry (registry.go).
func init() {
	RegisterProvider(ProviderDescriptor{
		ID:          ProviderGCP,
		DisplayName: "Google Cloud",
		ShortLabel:  "GCP",
		AuthMethods: []AuthMethod{AuthMethodWorkloadFederation, AuthMethodStaticKey},
		ScopeTypes: []ScopeType{
			ScopeOrg, ScopeFolder, ScopeProject, ScopeVPC, ScopeRegion, ScopeExplicit,
		},
		OrgScopeTypes:   []ScopeType{ScopeOrg, ScopeFolder},
		MemberScopeType: ScopeProject,
		SetupDocKey:     "cloud-connector-gcp",
		HasFlowLogs:     true,  // VPC flow-log lane (gcp-observer pack flow_logs capability)
		HasHealthLane:   false, // honest: no GCP incident lane built yet
		IdentityRef: func(cfg IdentityConfig) string {
			if cfg.ServiceAccount != "" {
				return cfg.ServiceAccount
			}
			return cfg.WorkloadProvider
		},
		NewAdapter: func() CloudIdentityProvider {
			return gcpAdapter{exchange: NewGCPSTSExchanger(), probe: NewGCPProbeClient()}
		},
		NewAdapterWithExchanger: func(x TokenExchanger) CloudIdentityProvider {
			return gcpAdapter{exchange: x}
		},
		NewAdapterWithAssertions: func(src WorkloadAssertionSource) CloudIdentityProvider {
			x := NewGCPSTSExchanger()
			x.Assertions = src
			return gcpAdapter{exchange: x, probe: NewGCPProbeClient()}
		},
	})
}

func (gcpAdapter) Provider() Provider { return ProviderGCP }

func (a gcpAdapter) ValidateConfiguration(cfg IdentityConfig) ValidationResult {
	r := ValidationResult{OK: true}
	if cfg.Provider != ProviderGCP {
		r.Add(SeverityError, "provider_mismatch", "identity provider is not gcp", "Recreate the connector with provider=gcp.")
		return r
	}
	if cfg.Method.IsProhibited() {
		r.Add(SeverityError, "method_prohibited", "a GCP admin username/password is never a connector credential", "Use Workload Identity Federation (recommended) or a legacy service-account key.")
		return r
	}
	if !MethodAllowed(ProviderGCP, cfg.Method) {
		r.Add(SeverityError, "method_unsupported", "auth method "+string(cfg.Method)+" is not supported for GCP", "Use Workload Identity Federation (recommended) or a service-account key.")
		return r
	}
	if strings.TrimSpace(cfg.ProjectNumber) == "" {
		r.Add(SeverityError, "project_number_missing", "the project number is required", "Copy the numeric project number (not the project id) from the GCP console.")
	}

	switch cfg.Method {
	case AuthMethodWorkloadFederation:
		if strings.TrimSpace(cfg.WorkloadPool) == "" || strings.TrimSpace(cfg.WorkloadProvider) == "" {
			r.Add(SeverityError, "federation_incomplete", "workload federation needs the pool + provider ids", "Deploy the setup below; it creates the workload identity pool + provider.")
		}
		if sa := strings.TrimSpace(cfg.ServiceAccount); sa != "" && !strings.Contains(sa, ".iam.gserviceaccount.com") {
			r.Add(SeverityError, "sa_email_malformed", "the impersonated service-account email is malformed", "Expected <name>@<project>.iam.gserviceaccount.com.")
		}
	case AuthMethodStaticKey:
		r.Add(SeverityWarning, "legacy_method", "a service-account JSON key is a legacy credential — not recommended", "Prefer Workload Identity Federation: no stored key, short-lived tokens.")
		if cfg.LegacySecretRef == "" {
			r.Add(SeverityError, "secret_ref_missing", "the encrypted SA-key reference is required", "Submit the SA JSON key; it is encrypted immediately and never re-displayed.")
		}
		sa := strings.TrimSpace(cfg.ServiceAccount)
		if sa == "" {
			r.Add(SeverityError, "sa_email_missing", "the service-account email is required", "Provide the SA email the key belongs to.")
		} else if isGCPOwnerSA(sa) {
			r.Add(SeverityError, "owner_sa_rejected", "an owner/editor or default compute service account is rejected", "Create a dedicated least-privilege observer service account.")
		}
	}
	return r
}

// isGCPOwnerSA flags service accounts that are clearly over-privileged defaults.
func isGCPOwnerSA(sa string) bool {
	s := strings.ToLower(strings.TrimSpace(sa))
	return strings.HasPrefix(s, "owner@") ||
		strings.Contains(s, "-compute@developer.gserviceaccount.com") || // default compute SA (Editor)
		strings.HasPrefix(s, "editor@")
}

func (a gcpAdapter) SetupInstructions(cfg IdentityConfig, pack CapabilityPack) (SetupBundle, error) {
	if pack.Provider != ProviderGCP {
		return SetupBundle{}, &ContractError{Code: "pack_provider_mismatch", Msg: "capability pack is not a GCP pack"}
	}
	projectNum := orPlaceholder(cfg.ProjectNumber, "<PROJECT_NUMBER>")
	issuer := orPlaceholder(cfg.Anchor.OIDCIssuer, "https://<correlix-issuer>")
	subject := orPlaceholder(cfg.Anchor.OIDCSubject, "correlix:connector:<connector-id>")
	project := "<PROJECT_ID>"

	bundle := SetupBundle{
		Provider: ProviderGCP,
		Method:   AuthMethodWorkloadFederation,
		Summary:  fmt.Sprintf("Create a workload identity pool federated to the Correlix OIDC issuer and a least-privilege observer service account (%s) — no stored SA key.", pack.FullID()),
		Steps: []string{
			"Run the gcloud commands below (Cloud Shell works) to create the workload identity pool + OIDC provider and a read-only observer service account.",
			"Grant the observer SA the viewer roles and let the Correlix workload identity impersonate it.",
			"Paste the project number + pool/provider ids back into Correlix and run Validate Trust.",
		},
		Artifacts: []SetupArtifact{
			{Kind: "gcloud", Title: "gcloud / Cloud Shell — workload identity federation", Format: "text", Content: gcpGcloud(projectNum, project, issuer, subject, pack)},
			{Kind: "terraform", Title: "Terraform — workload identity pool + observer SA", Format: "hcl", Content: gcpTerraform(project, issuer, pack)},
		},
	}
	appendGCPOrgArtifacts(&bundle, cfg, pack)
	return bundle, nil
}

// appendGCPOrgArtifacts adds the ORG-LEVEL (folder/organization) trust
// artifact when the connector carries an org anchor: the viewer roles bound
// ONCE at the folder/org node, inherited by every member project. Pure — no
// secrets, no network.
func appendGCPOrgArtifacts(bundle *SetupBundle, cfg IdentityConfig, pack CapabilityPack) {
	if cfg.Org == nil {
		return
	}
	node := orPlaceholder(cfg.Org.Ref, "<FOLDER_OR_ORG_ID>")
	kind := "folders"
	if cfg.Org.Type == ScopeOrg {
		kind = "organizations"
	}
	bundle.Summary += " ORG MODE: the folder/org-level bindings below cover every member project under " + kind + "/" + node + "."
	bundle.Steps = append(bundle.Steps,
		"Organization (multi-account): bind the observer SA's viewer roles ONCE at the "+kind+" node below — GCP IAM inheritance grants them in every current and future member project.",
		"Correlix enumerates member projects on Discover Scopes (a read-only parent-filtered projects listing); you still select which projects to observe.",
	)
	bundle.Artifacts = append(bundle.Artifacts, SetupArtifact{
		Kind: "gcloud", Format: "text",
		Title:   "gcloud — " + strings.TrimSuffix(kind, "s") + "-level IAM bindings (inherited by all projects)",
		Content: gcpOrgGcloud(kind, node, pack),
	})
}

func gcpOrgGcloud(kind, node string, pack CapabilityPack) string {
	var b strings.Builder
	b.WriteString("# Org-level enrollment (" + pack.FullID() + ", read-only): bindings at the\n")
	b.WriteString("# " + strings.TrimSuffix(kind, "s") + " node inherit to every member project.\n")
	b.WriteString("NODE=" + node + "\n")
	b.WriteString("SA=correlix-observer@$PROJECT.iam.gserviceaccount.com\n")
	for _, role := range gcpRoles(pack) {
		b.WriteString("gcloud resource-manager " + kind + " add-iam-policy-binding $NODE \\\n")
		b.WriteString("  --member=\"serviceAccount:$SA\" --role=\"" + role + "\"\n")
	}
	b.WriteString("# Enumeration (Discover Scopes) additionally lists projects under the node:\n")
	b.WriteString("gcloud resource-manager " + kind + " add-iam-policy-binding $NODE \\\n")
	b.WriteString("  --member=\"serviceAccount:$SA\" --role=\"roles/browser\"\n")
	b.WriteString("# viewer/browser roles are read-only. Never grant roles/owner or roles/editor.\n")
	return b.String()
}

func gcpRoles(pack CapabilityPack) []string {
	// Map the pack to least-privilege predefined viewer roles.
	roles := []string{"roles/compute.viewer", "roles/monitoring.viewer"}
	for _, c := range pack.Capabilities {
		if c.Key == "flow_logs" {
			roles = append(roles, "roles/logging.viewer")
		}
	}
	return roles
}

func gcpGcloud(projectNum, project, issuer, subject string, pack CapabilityPack) string {
	var b strings.Builder
	b.WriteString("# Workload Identity Federation for Correlix (" + pack.FullID() + ", read-only)\n")
	b.WriteString("PROJECT=" + project + "\n")
	b.WriteString("PROJECT_NUMBER=" + projectNum + "\n")
	b.WriteString("gcloud iam workload-identity-pools create correlix-pool --project=$PROJECT --location=global --display-name=Correlix\n")
	b.WriteString("gcloud iam workload-identity-pools providers create-oidc correlix-provider \\\n")
	b.WriteString("  --project=$PROJECT --location=global --workload-identity-pool=correlix-pool \\\n")
	b.WriteString("  --issuer-uri=\"" + issuer + "\" --attribute-mapping=\"google.subject=assertion.sub\"\n")
	b.WriteString("gcloud iam service-accounts create correlix-observer --project=$PROJECT --display-name=\"Correlix Observer\"\n")
	b.WriteString("SA=correlix-observer@$PROJECT.iam.gserviceaccount.com\n")
	for _, role := range gcpRoles(pack) {
		b.WriteString("gcloud projects add-iam-policy-binding $PROJECT --member=\"serviceAccount:$SA\" --role=\"" + role + "\"\n")
	}
	b.WriteString("# Let the Correlix workload identity impersonate the observer SA:\n")
	b.WriteString("gcloud iam service-accounts add-iam-policy-binding $SA \\\n")
	b.WriteString("  --role=roles/iam.workloadIdentityUser \\\n")
	b.WriteString("  --member=\"principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/correlix-pool/subject/" + subject + "\"\n")
	b.WriteString("# viewer roles are read-only. Never grant roles/owner or roles/editor.\n")
	return b.String()
}

func gcpTerraform(project string, issuer string, pack CapabilityPack) string {
	var roleBlocks strings.Builder
	for i, role := range gcpRoles(pack) {
		fmt.Fprintf(&roleBlocks, `resource "google_project_iam_member" "correlix_observer_%d" {
  project = "%s"
  role    = "%s"
  member  = "serviceAccount:${google_service_account.correlix_observer.email}"
}
`, i, project, role)
	}
	return `# Correlix Workload Identity Federation (` + pack.FullID() + `, read-only)
resource "google_iam_workload_identity_pool" "correlix" {
  workload_identity_pool_id = "correlix-pool"
  display_name              = "Correlix"
}

resource "google_iam_workload_identity_pool_provider" "correlix" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.correlix.workload_identity_pool_id
  workload_identity_pool_provider_id = "correlix-provider"
  attribute_mapping                  = { "google.subject" = "assertion.sub" }
  oidc { issuer_uri = "` + issuer + `" }
}

resource "google_service_account" "correlix_observer" {
  account_id   = "correlix-observer"
  display_name = "Correlix Observer"
}

` + roleBlocks.String()
}

// ExchangeCredential mints a short-lived GCP access token: STS token exchange
// (Correlix OIDC assertion → federated token → optional generateAccessToken SA
// impersonation) for WIF, or a self-signed RS256 assertion grant for the legacy
// SA key. The configuration is re-validated first (zero trust).
func (a gcpAdapter) ExchangeCredential(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	if a.exchange == nil {
		return ScopedToken{}, ErrProviderExchangeDeferred
	}
	if res := a.ValidateConfiguration(req.Identity); !res.OK {
		return ScopedToken{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "identity configuration has blocking findings"}
	}
	return a.exchange.Exchange(ctx, req)
}

// DiscoverScopes lists the ACTIVE projects the exchanged token can reach —
// also the live identity proof for the token.
//
// ORG connectors are ENUMERABLE (Wave 5 #17): rooted on a folder/organization
// anchor, the probe lists the projects under that node (parent-filtered,
// read-only). Discovery never widens collection by itself.
func (a gcpAdapter) DiscoverScopes(ctx context.Context, req DiscoverRequest) ([]Scope, error) {
	if a.probe == nil || strings.TrimSpace(req.Token.Value) == "" {
		return nil, ErrProviderExchangeDeferred
	}
	var projects []GCPProject
	var err error
	if org := orgAnchorFor(req, ProviderGCP); org != nil {
		parentType := "folder"
		if org.Type == ScopeOrg {
			parentType = "organization"
		}
		projects, err = a.probe.ProjectsUnder(ctx, req.Token.Value, parentType, org.Ref)
	} else {
		projects, err = a.probe.Projects(ctx, req.Token.Value)
	}
	if err != nil {
		return nil, err
	}
	scopes := make([]Scope, 0, len(projects))
	for _, p := range projects {
		scopes = append(scopes, Scope{
			Type: ScopeProject, Ref: p.ProjectID, Display: p.Name, Discovered: true,
		})
	}
	return scopes, nil
}

// ValidateCapabilities runs projects.testIamPermissions — GCP's canonical dry
// permission check — grading every pack permission at the project scope.
func (a gcpAdapter) ValidateCapabilities(ctx context.Context, req CapabilityCheckRequest) (CapabilityReport, error) {
	if a.probe == nil || strings.TrimSpace(req.Token.Value) == "" {
		return CapabilityReport{}, ErrProviderExchangeDeferred
	}
	project := strings.TrimSpace(req.Scope.Ref)
	if project == "" {
		return CapabilityReport{}, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "a project scope is required for the permission check"}
	}
	perms := req.Pack.AllPermissions()
	granted, err := a.probe.TestPermissions(ctx, req.Token.Value, project, perms)
	if err != nil {
		return CapabilityReport{}, err
	}
	report := CapabilityReport{Pack: req.Pack.FullID(), AllGranted: true}
	for _, perm := range perms {
		ok := granted[perm]
		detail := ""
		if !ok {
			report.AllGranted = false
			detail = "not granted at project " + project
		}
		report.Permissions = append(report.Permissions, PermissionStatus{Permission: perm, Granted: ok, Detail: detail})
	}
	if !report.AllGranted {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityWarning, Code: "permissions_missing",
			Message:     "some declared pack permissions are not granted at the project scope",
			Remediation: "Grant the read-only viewer roles from the setup template, then re-run the permission check.",
		})
	}
	return report, nil
}

func (a gcpAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}
