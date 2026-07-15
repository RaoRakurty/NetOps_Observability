package cloudconn

import (
	"context"
	"fmt"
	"strings"
)

// awsAdapter implements CloudIdentityProvider for AWS. The preferred method is a
// cross-account IAM role assumed via sts:AssumeRole with a per-tenant+connector
// ExternalId (confused-deputy protection). Static access keys are a labeled
// legacy fallback (root rejected). Live credential exchange is delegated to the
// injected TokenExchanger (AWSSTSExchanger in production).
type awsAdapter struct {
	exchange TokenExchanger
}

func (awsAdapter) Provider() Provider { return ProviderAWS }

// ValidateConfiguration enforces the AWS trust security rules with NO network:
//   - method must be offered by AWS and not prohibited/legacy-warned
//   - cross-account role: RoleARN well-formed, not root, ExternalId minted+unique
//   - static key: not a root key, warn (legacy), require a secret ref
func (a awsAdapter) ValidateConfiguration(cfg IdentityConfig) ValidationResult {
	r := ValidationResult{OK: true}
	if cfg.Provider != ProviderAWS {
		r.Add(SeverityError, "provider_mismatch", "identity provider is not aws", "Recreate the connector with provider=aws.")
		return r
	}
	if cfg.Method.IsProhibited() {
		r.Add(SeverityError, "method_prohibited", "cloud admin username/password is never a connector credential", "Choose cross-account role (recommended) or, if unavoidable, a scoped legacy access key.")
		return r
	}
	if !MethodAllowed(ProviderAWS, cfg.Method) {
		r.Add(SeverityError, "method_unsupported", "auth method "+string(cfg.Method)+" is not supported for AWS", "Use cross-account role (recommended) or a legacy access key.")
		return r
	}

	switch cfg.Method {
	case AuthMethodCloudRole, AuthMethodWorkloadFederation:
		validateAWSRole(&r, cfg)
	case AuthMethodStaticKey:
		validateAWSStaticKey(&r, cfg)
	}
	return r
}

func validateAWSRole(r *ValidationResult, cfg IdentityConfig) {
	arn := strings.TrimSpace(cfg.RoleARN)
	if arn == "" {
		r.Add(SeverityError, "role_arn_missing", "role ARN is required for cross-account role", "Deploy the provided CloudFormation/Terraform, then paste the created role ARN.")
		return
	}
	if !strings.HasPrefix(arn, "arn:aws:iam::") || !strings.Contains(arn, ":role/") {
		r.Add(SeverityError, "role_arn_malformed", "role ARN is not a valid iam role ARN", "Expected arn:aws:iam::<account-id>:role/<name>.")
	}
	if isAWSRootPrincipal(arn) {
		r.Add(SeverityError, "root_principal_rejected", "the account root is never an acceptable connector principal", "Create a dedicated, least-privilege observer role instead of using the account root.")
	}
	if strings.Contains(arn, "*") {
		r.Add(SeverityError, "wildcard_principal_rejected", "a wildcard principal is not allowed", "The role ARN must name one exact role, no wildcards.")
	}
	if strings.EqualFold(cfg.RoleARN, cfg.Anchor.AWSPrincipalARN) {
		r.Add(SeverityError, "principal_confusion", "the customer role must not be the Correlix principal itself", "Use the role created in the customer account.")
	}
	// ExternalId: mandatory + must look minted (unpredictable). A missing/derived
	// value defeats confused-deputy protection.
	if strings.TrimSpace(cfg.ExternalID) == "" {
		r.Add(SeverityError, "external_id_missing", "a per-connector ExternalId is required (confused-deputy protection)", "Regenerate trust; the framework mints the ExternalId — do not set it by hand.")
	} else if !ValidExternalID(cfg.ExternalID) {
		r.Add(SeverityError, "external_id_weak", "the ExternalId is not a framework-minted random value", "Never derive the ExternalId from tenant/account/email; let the framework mint it.")
	}
}

func validateAWSStaticKey(r *ValidationResult, cfg IdentityConfig) {
	r.Add(SeverityWarning, "legacy_method", "static access keys are a legacy fallback — not recommended", "Prefer a cross-account role: no stored secret, short-lived tokens, rotatable trust.")
	if cfg.LegacySecretRef == "" {
		r.Add(SeverityError, "secret_ref_missing", "the encrypted access key/secret reference is required", "Submit the access key + secret; it is encrypted immediately and never re-displayed.")
	}
	keyID := strings.TrimSpace(cfg.LegacyKeyID)
	if keyID == "" {
		r.Add(SeverityError, "key_id_missing", "the AccessKeyId (non-secret) is required for age tracking", "Provide the AccessKeyId; the secret is stored separately in the Vault.")
	}
	// Reject the account root's access key (AKIA keys under the root user). We can
	// only reject on clear signals without a network call; the live validator adds
	// an iam:GetUser check. AdministratorAccess is warned at permission-validation.
	if isAWSRootKeyID(keyID) {
		r.Add(SeverityError, "root_key_rejected", "root-account access keys are rejected", "Create a dedicated least-privilege IAM user or, better, switch to a cross-account role.")
	}
}

// isAWSRootPrincipal reports whether an ARN denotes the account root.
func isAWSRootPrincipal(arn string) bool {
	a := strings.ToLower(strings.TrimSpace(arn))
	return strings.HasSuffix(a, ":root") || strings.HasSuffix(a, ":user/root")
}

// isAWSRootKeyID flags access-key ids that are clearly the account root's. Root
// keys are conventionally created only by the root user; we reject the sentinel
// "root" marker some onboarding flows pass through the key-id field.
func isAWSRootKeyID(keyID string) bool {
	k := strings.ToLower(strings.TrimSpace(keyID))
	return k == "root" || strings.HasPrefix(k, "root:")
}

// SetupInstructions renders CloudFormation, Terraform and manual-IAM artifacts for
// the least-privilege observer role, wiring the exact ExternalId + the pack's
// permissions. Pure — no secret content.
func (a awsAdapter) SetupInstructions(cfg IdentityConfig, pack CapabilityPack) (SetupBundle, error) {
	if pack.Provider != ProviderAWS {
		return SetupBundle{}, &ContractError{Code: "pack_provider_mismatch", Msg: "capability pack is not an AWS pack"}
	}
	trusted := cfg.Anchor.AWSPrincipalARN
	if strings.TrimSpace(trusted) == "" {
		trusted = "arn:aws:iam::<CORRELIX_ACCOUNT_ID>:role/correlix-connector"
	}
	extID := cfg.ExternalID
	if strings.TrimSpace(extID) == "" {
		extID = "<EXTERNAL_ID_FROM_CORRELIX>"
	}
	perms := pack.AllPermissions()

	bundle := SetupBundle{
		Provider: ProviderAWS,
		Method:   AuthMethodCloudRole,
		Summary:  fmt.Sprintf("Create a read-only cross-account role Correlix assumes via STS, trusting %s with ExternalId %s and granting the %s permissions.", trusted, extID, pack.FullID()),
		Steps: []string{
			"Deploy ONE of the templates below in the AWS account you want observed (CloudFormation or Terraform), or follow the manual IAM steps.",
			"The template creates a role trusting only the Correlix principal, gated by the exact ExternalId — no wildcard principals, no root.",
			"Copy the created role ARN back into Correlix and run Validate Trust.",
		},
		Artifacts: []SetupArtifact{
			{Kind: "cloudformation", Title: "CloudFormation — Correlix observer role", Format: "yaml", Content: awsCloudFormation(trusted, extID, pack, perms)},
			{Kind: "terraform", Title: "Terraform — Correlix observer role", Format: "hcl", Content: awsTerraform(trusted, extID, pack, perms)},
			{Kind: "manual", Title: "Manual IAM setup", Format: "text", Content: awsManual(trusted, extID, pack, perms)},
		},
	}
	return bundle, nil
}

func awsPolicyStatements(perms []string) string {
	// One read-only statement over the least-privilege permission set. Resource:"*"
	// is required for Describe/List APIs that are not resource-scoped; the pack is
	// read-only so this stays least-privilege by ACTION.
	var b strings.Builder
	b.WriteString("[\n")
	for i, p := range perms {
		comma := ","
		if i == len(perms)-1 {
			comma = ""
		}
		b.WriteString("            \"" + p + "\"" + comma + "\n")
	}
	b.WriteString("          ]")
	return b.String()
}

func awsCloudFormation(trusted, extID string, pack CapabilityPack, perms []string) string {
	return `AWSTemplateFormatVersion: '2010-09-09'
Description: Correlix read-only observer role (` + pack.FullID() + `). Least-privilege, cross-account AssumeRole with ExternalId.
Resources:
  CorrelixObserverRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: correlix-observer
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: '` + trusted + `'
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: '` + extID + `'
      Policies:
        - PolicyName: correlix-observer-readonly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: ` + awsPolicyStatements(perms) + `
                Resource: '*'
Outputs:
  RoleArn:
    Description: Paste this back into Correlix
    Value: !GetAtt CorrelixObserverRole.Arn
`
}

func awsTerraform(trusted, extID string, pack CapabilityPack, perms []string) string {
	var permList strings.Builder
	for i, p := range perms {
		comma := ","
		if i == len(perms)-1 {
			comma = ""
		}
		permList.WriteString("      \"" + p + "\"" + comma + "\n")
	}
	return `# Correlix read-only observer role (` + pack.FullID() + `)
resource "aws_iam_role" "correlix_observer" {
  name                 = "correlix-observer"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "` + trusted + `" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = "` + extID + `" } }
    }]
  })
}

resource "aws_iam_role_policy" "correlix_observer_readonly" {
  name = "correlix-observer-readonly"
  role = aws_iam_role.correlix_observer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
` + permList.String() + `      ]
      Resource = "*"
    }]
  })
}

output "role_arn" {
  value = aws_iam_role.correlix_observer.arn
}
`
}

func awsManual(trusted, extID string, pack CapabilityPack, perms []string) string {
	var b strings.Builder
	b.WriteString("Manual IAM setup for " + pack.FullID() + " (read-only):\n\n")
	b.WriteString("1. IAM → Roles → Create role → Custom trust policy:\n")
	b.WriteString("   {\n     \"Version\":\"2012-10-17\",\n     \"Statement\":[{\n")
	b.WriteString("       \"Effect\":\"Allow\",\n")
	b.WriteString("       \"Principal\":{\"AWS\":\"" + trusted + "\"},\n")
	b.WriteString("       \"Action\":\"sts:AssumeRole\",\n")
	b.WriteString("       \"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"" + extID + "\"}}\n")
	b.WriteString("     }]\n   }\n\n")
	b.WriteString("2. Attach an inline least-privilege policy allowing ONLY these actions on Resource \"*\":\n")
	for _, p := range perms {
		b.WriteString("     - " + p + "\n")
	}
	b.WriteString("\n3. Set Maximum session duration = 1 hour. Name the role 'correlix-observer'.\n")
	b.WriteString("4. Copy the role ARN back into Correlix and click Validate Trust.\n")
	b.WriteString("\nNever attach AdministratorAccess. Never use the account root. The ExternalId above is unique to this connector.\n")
	return b.String()
}

// ── live-network methods ──────────────────────────────────────────────────────

// ExchangeCredential mints short-lived STS session credentials: sts:AssumeRole
// (RoleArn + ExternalId, DurationSeconds ≤ MaxLifetime) for role identities,
// sts:GetSessionToken for legacy static keys. The configuration is re-validated
// first — an invalid trust config never reaches the wire (zero trust).
func (a awsAdapter) ExchangeCredential(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	if a.exchange == nil {
		return ScopedToken{}, ErrProviderExchangeDeferred
	}
	if res := a.ValidateConfiguration(req.Identity); !res.OK {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "identity configuration has blocking findings"}
	}
	return a.exchange.Exchange(ctx, req)
}

func (a awsAdapter) DiscoverScopes(_ context.Context, _ DiscoverRequest) ([]Scope, error) {
	return nil, ErrProviderExchangeDeferred
}

func (a awsAdapter) ValidateCapabilities(_ context.Context, _ CapabilityCheckRequest) (CapabilityReport, error) {
	return CapabilityReport{}, ErrProviderExchangeDeferred
}

func (a awsAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}
