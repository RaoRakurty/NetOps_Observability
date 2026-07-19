package cloudconn

import (
	"context"
	"errors"
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
	probe    *AWSProbeClient
}

// init registers AWS in the ONE provider registry (registry.go). Everything
// provider-neutral code knows about AWS — offer, scopes, org shape, flags,
// adapter construction — is declared here and nowhere else.
func init() {
	RegisterProvider(ProviderDescriptor{
		ID:          ProviderAWS,
		DisplayName: "Amazon Web Services",
		ShortLabel:  "AWS",
		AuthMethods: []AuthMethod{AuthMethodWorkloadFederation, AuthMethodCloudRole, AuthMethodStaticKey},
		ScopeTypes: []ScopeType{
			ScopeOrg, ScopeOU, ScopeAccount, ScopeVPC, ScopeRegion, ScopeExplicit,
		},
		OrgScopeTypes:   []ScopeType{ScopeOrg, ScopeOU},
		MemberScopeType: ScopeAccount,
		SetupDocKey:     "cloud-connector-aws",
		HasFlowLogs:     true, // VPC flow-log lane (aws-observer pack flow_logs capability)
		HasHealthLane:   true, // AWS Health incident/maintenance lane
		IdentityRef:     func(cfg IdentityConfig) string { return cfg.RoleARN },
		NewAdapter: func() CloudIdentityProvider {
			return awsAdapter{exchange: NewAWSSTSExchanger(), probe: NewAWSProbeClient()}
		},
		NewAdapterWithExchanger: func(x TokenExchanger) CloudIdentityProvider {
			return awsAdapter{exchange: x}
		},
		NewAdapterWithAssertions: func(src WorkloadAssertionSource) CloudIdentityProvider {
			x := NewAWSSTSExchanger()
			x.Assertions = src
			return awsAdapter{exchange: x, probe: NewAWSProbeClient()}
		},
	})
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
	case AuthMethodCloudRole:
		validateAWSRole(&r, cfg)
	case AuthMethodWorkloadFederation:
		validateAWSWebIdentity(&r, cfg)
	case AuthMethodStaticKey:
		validateAWSStaticKey(&r, cfg)
	}
	return r
}

// validateAWSWebIdentity checks the KEYLESS AssumeRoleWithWebIdentity trust:
// same role-ARN hygiene as the cross-account role, but NO ExternalId — that
// parameter does not exist on AssumeRoleWithWebIdentity; the confused-deputy
// protection is the role trust policy's aud/sub conditions on the OIDC
// provider (rendered by the setup template).
func validateAWSWebIdentity(r *ValidationResult, cfg IdentityConfig) {
	validateAWSRoleARN(r, cfg)
	if strings.TrimSpace(cfg.Audience) == "" {
		r.Add(SeverityWarning, "audience_default", "no audience set; the STS default sts.amazonaws.com will be expected by the role trust condition", "")
	}
}

func validateAWSRole(r *ValidationResult, cfg IdentityConfig) {
	if !validateAWSRoleARN(r, cfg) {
		return
	}
	// ExternalId: mandatory + must look minted (unpredictable). A missing/derived
	// value defeats confused-deputy protection.
	if strings.TrimSpace(cfg.ExternalID) == "" {
		r.Add(SeverityError, "external_id_missing", "a per-connector ExternalId is required (confused-deputy protection)", "Regenerate trust; the framework mints the ExternalId — do not set it by hand.")
	} else if !ValidExternalID(cfg.ExternalID) {
		r.Add(SeverityError, "external_id_weak", "the ExternalId is not a framework-minted random value", "Never derive the ExternalId from tenant/account/email; let the framework mint it.")
	}
}

// validateAWSRoleARN applies the shared role-ARN hygiene (well-formed, no root,
// no wildcard, not the Correlix principal). Returns false when the ARN is
// absent (nothing further can be checked).
func validateAWSRoleARN(r *ValidationResult, cfg IdentityConfig) bool {
	arn := strings.TrimSpace(cfg.RoleARN)
	if arn == "" {
		r.Add(SeverityError, "role_arn_missing", "role ARN is required for cross-account role", "Deploy the provided CloudFormation/Terraform, then paste the created role ARN.")
		return false
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
	return true
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
	if cfg.Method == AuthMethodWorkloadFederation {
		bundle := awsWebIdentitySetup(cfg, pack)
		appendAWSOrgArtifacts(&bundle, cfg, pack)
		return bundle, nil
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
	appendAWSOrgArtifacts(&bundle, cfg, pack)
	return bundle, nil
}

// appendAWSOrgArtifacts adds the ORG-LEVEL (multi-account) trust artifacts when
// the connector carries an org anchor: a service-managed CloudFormation
// StackSet that deploys the SAME observer role (and, for workload federation,
// the OIDC provider) into every member account of the organization/OU, plus
// the management-account enumeration permission note. Pure — no secrets, no
// network. The member-role trust mirrors the connector's auth method exactly.
func appendAWSOrgArtifacts(bundle *SetupBundle, cfg IdentityConfig, pack CapabilityPack) {
	if cfg.Org == nil {
		return
	}
	target := strings.TrimSpace(cfg.Org.Ref)
	if target == "" {
		target = "<ORG_ROOT_OR_OU_ID>"
	}
	role := cfg.Org.RoleTemplateOrDefault()
	bundle.Summary += " ORG MODE: the StackSet below deploys the same role (" + role + ") into every member account under " + target + "."
	bundle.Steps = append(bundle.Steps,
		"Organization (multi-account): deploy the StackSet from the MANAGEMENT account with service-managed permissions targeting "+target+" — every current and future member account gets the observer role automatically.",
		"Grant the management-account observer role organizations:ListAccounts + organizations:ListAccountsForParent (read-only) so Correlix can enumerate member accounts on Discover Scopes.",
	)
	bundle.Artifacts = append(bundle.Artifacts,
		SetupArtifact{
			Kind: "cloudformation", Format: "yaml",
			Title:   "CloudFormation StackSet — observer role in every member account",
			Content: awsOrgStackSet(target, role, cfg, pack),
		},
		SetupArtifact{
			Kind: "manual", Format: "text",
			Title:   "Management-account enumeration permission",
			Content: awsOrgEnumerationNote(target),
		},
	)
}

// awsOrgStackSet renders the StackSet template. The per-member trust follows
// the connector's auth method: cross-account role (AWS principal + ExternalId)
// or web identity (per-account OIDC provider + aud/sub-pinned trust).
func awsOrgStackSet(target, role string, cfg IdentityConfig, pack CapabilityPack) string {
	perms := pack.AllPermissions()
	var resources string
	if cfg.Method == AuthMethodWorkloadFederation {
		issuer := orPlaceholder(cfg.Anchor.OIDCIssuer, "https://<correlix-issuer>")
		subject := orPlaceholder(cfg.Anchor.OIDCSubject, "correlix:connector:<connector-id>")
		audience := orPlaceholder(cfg.Audience, orPlaceholder(cfg.Anchor.OIDCAudience, "sts.amazonaws.com"))
		issuerHost := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
		resources = `  CorrelixOIDCProvider:
    Type: AWS::IAM::OIDCProvider
    Properties:
      Url: '` + issuer + `'
      ClientIdList: ['` + audience + `']
  CorrelixObserverRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ` + role + `
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Ref CorrelixOIDCProvider
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                '` + issuerHost + `:aud': '` + audience + `'
                '` + issuerHost + `:sub': '` + subject + `'`
	} else {
		trusted := orPlaceholder(cfg.Anchor.AWSPrincipalARN, "arn:aws:iam::<CORRELIX_ACCOUNT_ID>:role/correlix-connector")
		extID := orPlaceholder(cfg.ExternalID, "<EXTERNAL_ID_FROM_CORRELIX>")
		resources = `  CorrelixObserverRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ` + role + `
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
                sts:ExternalId: '` + extID + `'`
	}
	return `# Deploy from the MANAGEMENT account (CloudFormation → StackSets →
# service-managed permissions). Target: ` + target + `
# Creates the '` + role + `' observer role in EVERY member account; accounts that
# join the organization later receive it automatically (auto-deployment).
#
#   aws cloudformation create-stack-set \
#     --stack-set-name correlix-observer \
#     --permission-model SERVICE_MANAGED \
#     --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
#     --template-body file://correlix-observer.yaml
#   aws cloudformation create-stack-instances \
#     --stack-set-name correlix-observer \
#     --deployment-targets OrganizationalUnitIds=` + target + ` \
#     --regions us-east-1
#
AWSTemplateFormatVersion: '2010-09-09'
Description: Correlix read-only observer role (` + pack.FullID() + `), org-wide via StackSet. Identical least-privilege trust in every member account.
Resources:
` + resources + `
      Policies:
        - PolicyName: correlix-observer-readonly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: ` + awsPolicyStatements(perms) + `
                Resource: '*'
`
}

func awsOrgEnumerationNote(target string) string {
	return "Member-account enumeration (Discover Scopes) is read-only and needs ONE extra\n" +
		"permission on the role Correlix assumes in the MANAGEMENT account:\n\n" +
		"  { \"Effect\": \"Allow\", \"Action\": [\"organizations:ListAccounts\",\n" +
		"    \"organizations:ListAccountsForParent\"], \"Resource\": \"*\" }\n\n" +
		"Correlix lists the accounts under " + target + " and shows them for selection —\n" +
		"discovery never widens the collection scope by itself; you choose what to observe.\n" +
		"Without this permission, Discover Scopes reports the honest deferred/denied state.\n"
}

// awsWebIdentitySetup renders the KEYLESS trust artifacts: an IAM OIDC identity
// provider for the Correlix workload issuer plus an observer role whose trust
// policy allows sts:AssumeRoleWithWebIdentity gated on the exact aud + sub —
// the web-identity equivalent of the ExternalId condition. Pure; no secrets.
func awsWebIdentitySetup(cfg IdentityConfig, pack CapabilityPack) SetupBundle {
	issuer := orPlaceholder(cfg.Anchor.OIDCIssuer, "https://<correlix-issuer>")
	subject := orPlaceholder(cfg.Anchor.OIDCSubject, "correlix:connector:<connector-id>")
	audience := orPlaceholder(cfg.Audience, orPlaceholder(cfg.Anchor.OIDCAudience, "sts.amazonaws.com"))
	issuerHost := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	perms := pack.AllPermissions()

	trust := `{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<YOUR_ACCOUNT_ID>:oidc-provider/` + issuerHost + `" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "` + issuerHost + `:aud": "` + audience + `",
        "` + issuerHost + `:sub": "` + subject + `"
      }
    }
  }]
}`
	var manual strings.Builder
	manual.WriteString("Keyless setup (AssumeRoleWithWebIdentity) for " + pack.FullID() + ":\n\n")
	manual.WriteString("1. IAM → Identity providers → Add provider → OpenID Connect:\n")
	manual.WriteString("   Provider URL: " + issuer + "\n")
	manual.WriteString("   Audience:     " + audience + "\n\n")
	manual.WriteString("2. IAM → Roles → Create role → Web identity, using the trust policy artifact\n")
	manual.WriteString("   (aud AND sub are pinned to this exact connector — the confused-deputy\n")
	manual.WriteString("   protection on the web-identity path).\n\n")
	manual.WriteString("3. Attach an inline least-privilege policy allowing ONLY these actions on Resource \"*\":\n")
	for _, p := range perms {
		manual.WriteString("     - " + p + "\n")
	}
	manual.WriteString("\n4. Set Maximum session duration = 1 hour. Copy the role ARN back into Correlix.\n")
	manual.WriteString("\nNo AWS access key is created, stored, or used anywhere in this mode.\n")

	return SetupBundle{
		Provider: ProviderAWS,
		Method:   AuthMethodWorkloadFederation,
		Summary:  fmt.Sprintf("Create an IAM OIDC provider for the Correlix issuer and a read-only observer role assumed KEYLESSLY via sts:AssumeRoleWithWebIdentity, granting the %s permissions.", pack.FullID()),
		Steps: []string{
			"Register the Correlix workload issuer as an IAM OIDC identity provider.",
			"Create the observer role with the web-identity trust policy below (aud + sub pinned to this connector).",
			"Attach the least-privilege read-only permissions and paste the role ARN back into Correlix, then run Validate Trust.",
		},
		Artifacts: []SetupArtifact{
			{Kind: "manual", Title: "IAM OIDC provider + web-identity role trust policy", Format: "json", Content: trust},
			{Kind: "manual", Title: "Manual setup steps (keyless)", Format: "text", Content: manual.String()},
		},
	}
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

// ExchangeCredential mints short-lived STS session credentials:
// sts:AssumeRoleWithWebIdentity (keyless, workload OIDC assertion) for
// federated identities, sts:AssumeRole (RoleArn + ExternalId) for cross-account
// roles, sts:GetSessionToken for legacy static keys. The configuration is
// re-validated first — an invalid trust config never reaches the wire.
func (a awsAdapter) ExchangeCredential(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	if a.exchange == nil {
		return ScopedToken{}, ErrProviderExchangeDeferred
	}
	if res := a.ValidateConfiguration(req.Identity); !res.OK {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "identity configuration has blocking findings"}
	}
	return a.exchange.Exchange(ctx, req)
}

// DiscoverScopes proves the exchanged credential live (sts:GetCallerIdentity)
// and returns the account it reaches as a discovered scope. LIVE-network,
// read-only, authenticated with the broker-minted token on the request.
//
// ORG connectors are ENUMERABLE (Wave 5 #17): when the request is rooted on an
// org anchor (org/OU), the probe additionally lists the member accounts via
// AWS Organizations (management-account credentials required). Discovery never
// widens collection by itself — the operator still selects what to observe.
// Without live credentials the honest deferral sentinel is returned.
func (a awsAdapter) DiscoverScopes(ctx context.Context, req DiscoverRequest) ([]Scope, error) {
	if a.probe == nil || req.Token.AWS == nil {
		return nil, ErrProviderExchangeDeferred
	}
	ident, err := a.probe.CallerIdentity(ctx, *req.Token.AWS, "")
	if err != nil {
		return nil, err
	}
	scopes := []Scope{{
		Type: ScopeAccount, Ref: ident.Account, Display: ident.ARN, Discovered: true,
	}}
	if org := orgAnchorFor(req, ProviderAWS); org != nil {
		accounts, err := a.probe.OrganizationAccounts(ctx, *req.Token.AWS, org.Ref)
		if err != nil {
			return nil, err
		}
		for _, acct := range accounts {
			if acct.ID == ident.Account {
				continue // already listed as the proven caller account
			}
			scopes = append(scopes, Scope{Type: ScopeAccount, Ref: acct.ID, Display: acct.Name, Discovered: true})
		}
	}
	return scopes, nil
}

// ValidateCapabilities runs the LIVE per-permission dry check: GetCallerIdentity
// establishes the principal, then ONE iam:SimulatePrincipalPolicy evaluation
// grades every pack permission (via its concrete probe action). No target API
// is ever invoked. When the simulator itself is denied to the principal, every
// permission is honestly reported UNVERIFIED (never guessed granted/denied).
func (a awsAdapter) ValidateCapabilities(ctx context.Context, req CapabilityCheckRequest) (CapabilityReport, error) {
	if a.probe == nil || req.Token.AWS == nil {
		return CapabilityReport{}, ErrProviderExchangeDeferred
	}
	report := CapabilityReport{Pack: req.Pack.FullID()}
	ident, err := a.probe.CallerIdentity(ctx, *req.Token.AWS, "")
	if err != nil {
		return CapabilityReport{}, err
	}
	report.Findings = append(report.Findings, Finding{
		Severity: SeverityInfo, Code: "caller_identity",
		Message: "authenticated to account " + ident.Account + " as " + ident.ARN,
	})

	perms := req.Pack.AllPermissions()
	actions := make([]string, 0, len(perms))
	actionFor := make(map[string]string, len(perms))
	for _, perm := range perms {
		if act := AWSProbeActionFor(perm); act != "" {
			actions = append(actions, act)
			actionFor[perm] = act
		}
	}
	principal := IAMPrincipalFromCallerARN(ident.ARN)
	decisions, simErr := a.probe.SimulatePermissions(ctx, *req.Token.AWS, principal, actions)
	var xe *ExchangeError
	if simErr != nil && errors.As(simErr, &xe) && xe.Denied() {
		// The observer role lacks iam:SimulatePrincipalPolicy — an expected,
		// least-privilege condition. Report every permission unverified.
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityWarning, Code: "simulation_denied",
			Message:     "the principal may not run iam:SimulatePrincipalPolicy — per-permission results are unverifiable",
			Remediation: "Optionally grant iam:SimulatePrincipalPolicy (read-only, self-scoped) to enable live permission validation.",
		})
		for _, perm := range perms {
			report.Permissions = append(report.Permissions, PermissionStatus{
				Permission: perm, Granted: false, Detail: "unverified: policy simulation denied",
			})
		}
		return report, nil
	}
	if simErr != nil {
		return CapabilityReport{}, simErr
	}
	report.AllGranted = true
	for _, perm := range perms {
		act, ok := actionFor[perm]
		if !ok {
			report.AllGranted = false
			report.Permissions = append(report.Permissions, PermissionStatus{
				Permission: perm, Granted: false, Detail: "unverified: no concrete probe action mapped for this wildcard",
			})
			continue
		}
		granted := decisions[act]
		detail := ""
		if act != perm {
			detail = "probed as " + act
		}
		if !granted {
			report.AllGranted = false
			if detail != "" {
				detail += "; "
			}
			detail += "denied by IAM policy simulation"
		}
		report.Permissions = append(report.Permissions, PermissionStatus{Permission: perm, Granted: granted, Detail: detail})
	}
	if !report.AllGranted {
		report.Findings = append(report.Findings, Finding{
			Severity: SeverityWarning, Code: "permissions_missing",
			Message:     "some declared pack permissions are not granted to the connector principal",
			Remediation: "Re-apply the setup template's least-privilege policy, then re-run the permission check.",
		})
	}
	return report, nil
}

func (a awsAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}
