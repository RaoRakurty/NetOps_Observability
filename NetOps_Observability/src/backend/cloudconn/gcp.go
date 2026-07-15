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
	return bundle, nil
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

func (a gcpAdapter) DiscoverScopes(_ context.Context, _ DiscoverRequest) ([]Scope, error) {
	return nil, ErrProviderExchangeDeferred
}

func (a gcpAdapter) ValidateCapabilities(_ context.Context, _ CapabilityCheckRequest) (CapabilityReport, error) {
	return CapabilityReport{}, ErrProviderExchangeDeferred
}

func (a gcpAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}
