package cloudconn

// org_test.go — Wave 5 #17 slice 2: org-level (multi-account) onboarding.
// Covers: anchor validation per provider; org trust artifacts rendered by
// SetupInstructions (StackSet / management-group role / folder binding);
// member-account enumeration through DiscoverScopes against httptest provider
// fixtures; and the honest deferral sentinel when no live probe is wired.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── anchor validation ─────────────────────────────────────────────────────────

func TestValidateOrgAnchor(t *testing.T) {
	ok := []struct {
		p Provider
		a OrgScopeAnchor
	}{
		{ProviderAWS, OrgScopeAnchor{Type: ScopeOrg, Ref: "o-a1b2c3"}},
		{ProviderAWS, OrgScopeAnchor{Type: ScopeOU, Ref: "ou-a1b2-c3d4", RoleTemplate: "my-observer_v2"}},
		{ProviderAzure, OrgScopeAnchor{Type: ScopeMgmtGroup, Ref: "mg-prod"}},
		{ProviderAzure, OrgScopeAnchor{Type: ScopeOrg, Ref: "root-group-id"}},
		{ProviderGCP, OrgScopeAnchor{Type: ScopeFolder, Ref: "123456789"}},
		{ProviderGCP, OrgScopeAnchor{Type: ScopeOrg, Ref: "987654321"}},
	}
	for _, c := range ok {
		if err := ValidateOrgAnchor(c.p, c.a); err != nil {
			t.Errorf("%s %s: unexpected error %v", c.p, c.a.Type, err)
		}
	}
	bad := []struct {
		name string
		p    Provider
		a    OrgScopeAnchor
	}{
		{"member type is not an anchor", ProviderAWS, OrgScopeAnchor{Type: ScopeAccount, Ref: "123456789012"}},
		{"cross-provider anchor", ProviderAWS, OrgScopeAnchor{Type: ScopeMgmtGroup, Ref: "mg"}},
		{"folder is not azure", ProviderAzure, OrgScopeAnchor{Type: ScopeFolder, Ref: "123"}},
		{"ref required", ProviderGCP, OrgScopeAnchor{Type: ScopeFolder, Ref: "  "}},
		{"unknown provider", Provider("nope"), OrgScopeAnchor{Type: ScopeOrg, Ref: "x"}},
		{"role template injection", ProviderAWS, OrgScopeAnchor{Type: ScopeOrg, Ref: "o-x", RoleTemplate: "role'; rm -rf /"}},
		{"role template too long", ProviderAWS, OrgScopeAnchor{Type: ScopeOrg, Ref: "o-x", RoleTemplate: strings.Repeat("a", 65)}},
	}
	for _, c := range bad {
		if err := ValidateOrgAnchor(c.p, c.a); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	if got := (OrgScopeAnchor{}).RoleTemplateOrDefault(); got != DefaultOrgRoleTemplate {
		t.Fatalf("default role template = %q", got)
	}
}

// ── org setup artifacts ───────────────────────────────────────────────────────

func awsObserverPack(t *testing.T) CapabilityPack {
	t.Helper()
	pack, ok := Pack("aws-observer-v1")
	if !ok {
		t.Fatal("aws-observer-v1 not registered")
	}
	return pack
}

func TestAWSOrgSetupArtifacts(t *testing.T) {
	pack := awsObserverPack(t)
	cfg := IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::111122223333:role/correlix-observer", ExternalID: NewExternalID(),
		Anchor: TrustAnchor{AWSPrincipalARN: "arn:aws:iam::999900001111:role/correlix-connector"},
		Org:    &OrgScopeAnchor{Type: ScopeOU, Ref: "ou-a1b2-c3d4e5", RoleTemplate: "acme-observer"},
	}
	bundle, err := AdapterFor(ProviderAWS).SetupInstructions(cfg, pack)
	if err != nil {
		t.Fatalf("SetupInstructions: %v", err)
	}
	stack := findArtifact(t, bundle, "CloudFormation StackSet")
	for _, want := range []string{"ou-a1b2-c3d4e5", "RoleName: acme-observer", "sts:ExternalId: '" + cfg.ExternalID + "'", "SERVICE_MANAGED"} {
		if !strings.Contains(stack.Content, want) {
			t.Errorf("StackSet artifact missing %q", want)
		}
	}
	enum := findArtifact(t, bundle, "enumeration permission")
	if !strings.Contains(enum.Content, "organizations:ListAccounts") {
		t.Error("enumeration note missing organizations:ListAccounts")
	}
	if !strings.Contains(bundle.Summary, "ORG MODE") {
		t.Error("summary must flag org mode")
	}

	// Workload federation org mode: the StackSet carries the per-account OIDC
	// provider + web-identity trust instead of the ExternalId trust.
	cfgWIF := IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodWorkloadFederation,
		RoleARN: cfg.RoleARN,
		Anchor: TrustAnchor{OIDCIssuer: "https://token.correlix.example/oidc", OIDCSubject: "correlix:connector:ccn_1"},
		Org:    &OrgScopeAnchor{Type: ScopeOrg, Ref: "o-abc123"},
	}
	bundleWIF, err := AdapterFor(ProviderAWS).SetupInstructions(cfgWIF, pack)
	if err != nil {
		t.Fatalf("SetupInstructions (WIF): %v", err)
	}
	stackWIF := findArtifact(t, bundleWIF, "CloudFormation StackSet")
	for _, want := range []string{"AWS::IAM::OIDCProvider", "sts:AssumeRoleWithWebIdentity", "correlix:connector:ccn_1", "o-abc123"} {
		if !strings.Contains(stackWIF.Content, want) {
			t.Errorf("WIF StackSet missing %q", want)
		}
	}
	if strings.Contains(stackWIF.Content, "sts:ExternalId") {
		t.Error("WIF StackSet must not carry an ExternalId condition (no such parameter on the web-identity path)")
	}

	// No anchor → no org artifacts (single-account bundles stay unchanged).
	cfgSingle := cfg
	cfgSingle.Org = nil
	single, err := AdapterFor(ProviderAWS).SetupInstructions(cfgSingle, pack)
	if err != nil {
		t.Fatalf("SetupInstructions (single): %v", err)
	}
	for _, a := range single.Artifacts {
		if strings.Contains(a.Title, "StackSet") {
			t.Error("single-account bundle must not carry the StackSet artifact")
		}
	}
}

func TestAzureAndGCPOrgSetupArtifacts(t *testing.T) {
	azPack, _ := Pack("azure-observer-v1")
	azCfg := IdentityConfig{
		Provider: ProviderAzure, Method: AuthMethodWorkloadFederation,
		AzureTenantID: "tid", ClientID: "cid",
		Org: &OrgScopeAnchor{Type: ScopeMgmtGroup, Ref: "mg-production"},
	}
	azBundle, err := AdapterFor(ProviderAzure).SetupInstructions(azCfg, azPack)
	if err != nil {
		t.Fatalf("azure SetupInstructions: %v", err)
	}
	az := findArtifact(t, azBundle, "management-group role assignment")
	for _, want := range []string{"managementGroups/$MG", "MG=mg-production", "Management Group Reader"} {
		if !strings.Contains(az.Content, want) {
			t.Errorf("azure org artifact missing %q", want)
		}
	}

	gcpPack, _ := Pack("gcp-observer-v1")
	gcpCfg := IdentityConfig{
		Provider: ProviderGCP, Method: AuthMethodWorkloadFederation,
		ProjectNumber: "123", WorkloadPool: "p", WorkloadProvider: "pr",
		Org: &OrgScopeAnchor{Type: ScopeFolder, Ref: "555666777"},
	}
	gcpBundle, err := AdapterFor(ProviderGCP).SetupInstructions(gcpCfg, gcpPack)
	if err != nil {
		t.Fatalf("gcp SetupInstructions: %v", err)
	}
	gc := findArtifact(t, gcpBundle, "IAM bindings")
	for _, want := range []string{"resource-manager folders add-iam-policy-binding", "NODE=555666777", "roles/browser"} {
		if !strings.Contains(gc.Content, want) {
			t.Errorf("gcp org artifact missing %q", want)
		}
	}
	// Org node kind flips the gcloud group.
	gcpCfg.Org = &OrgScopeAnchor{Type: ScopeOrg, Ref: "888"}
	gcpBundle2, err := AdapterFor(ProviderGCP).SetupInstructions(gcpCfg, gcpPack)
	if err != nil {
		t.Fatalf("gcp SetupInstructions (org): %v", err)
	}
	gc2 := findArtifact(t, gcpBundle2, "IAM bindings")
	if !strings.Contains(gc2.Content, "resource-manager organizations add-iam-policy-binding") {
		t.Error("gcp org-node artifact must use the organizations command group")
	}
}

func findArtifact(t *testing.T, b SetupBundle, titleFragment string) SetupArtifact {
	t.Helper()
	for _, a := range b.Artifacts {
		if strings.Contains(a.Title, titleFragment) {
			return a
		}
	}
	t.Fatalf("no artifact titled ~%q in %v", titleFragment, artifactTitles(b))
	return SetupArtifact{}
}

func artifactTitles(b SetupBundle) []string {
	out := make([]string, 0, len(b.Artifacts))
	for _, a := range b.Artifacts {
		out = append(out, a.Title)
	}
	return out
}

// ── enumeration: AWS Organizations ────────────────────────────────────────────

const orgTestCallerXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/correlix-observer/probe</Arn>
    <UserId>AROAEXAMPLE:probe</UserId>
    <Account>111122223333</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

func TestAWSDiscoverScopesEnumeratesOrgMembers(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if _, err := w.Write([]byte(orgTestCallerXML)); err != nil {
			t.Errorf("write sts response: %v", err)
		}
	}))
	defer sts.Close()

	var gotTarget, gotBody string
	orgs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTarget = r.Header.Get("X-Amz-Target")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		resp := map[string]any{"Accounts": []map[string]string{
			{"Id": "111122223333", "Name": "management", "Status": "ACTIVE"},
			{"Id": "444455556666", "Name": "member-prod", "Status": "ACTIVE"},
			{"Id": "999988887777", "Name": "leaving", "Status": "SUSPENDED"},
		}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode orgs response: %v", err)
		}
	}))
	defer orgs.Close()

	probe := &AWSProbeClient{Client: sts.Client(), STSEndpoint: sts.URL, OrgsEndpoint: orgs.URL}
	adapter := NewAWSAdapter(nil, probe)
	creds := AWSCredentials{AccessKeyID: "ASIATEST", SecretAccessKey: "secret", SessionToken: "tok"}

	scopes, err := adapter.DiscoverScopes(context.Background(), DiscoverRequest{
		Root:  Scope{Type: ScopeOU, Ref: "ou-a1b2-c3d4e5"},
		Token: ScopedToken{Provider: ProviderAWS, AWS: &creds},
	})
	if err != nil {
		t.Fatalf("DiscoverScopes: %v", err)
	}
	if gotTarget != "AWSOrganizationsV20161128.ListAccountsForParent" {
		t.Fatalf("target = %q — an OU anchor must use ListAccountsForParent", gotTarget)
	}
	if !strings.Contains(gotBody, `"ParentId":"ou-a1b2-c3d4e5"`) {
		t.Fatalf("request body missing ParentId: %s", gotBody)
	}
	// Caller account + the one OTHER active member; suspended filtered; no dupes.
	if len(scopes) != 2 {
		t.Fatalf("scopes = %+v", scopes)
	}
	if scopes[0].Ref != "111122223333" || scopes[1].Ref != "444455556666" {
		t.Fatalf("unexpected member refs: %+v", scopes)
	}
	for _, sc := range scopes {
		if sc.Type != ScopeAccount || !sc.Discovered {
			t.Fatalf("member scope must be a discovered account: %+v", sc)
		}
	}

	// Org-root anchor uses plain ListAccounts.
	if _, err := adapter.DiscoverScopes(context.Background(), DiscoverRequest{
		Root:  Scope{Type: ScopeOrg, Ref: "o-abc123"},
		Token: ScopedToken{Provider: ProviderAWS, AWS: &creds},
	}); err != nil {
		t.Fatalf("DiscoverScopes(org): %v", err)
	}
	if gotTarget != "AWSOrganizationsV20161128.ListAccounts" {
		t.Fatalf("target = %q — an org anchor must use ListAccounts", gotTarget)
	}
}

// ── enumeration: Azure management group ──────────────────────────────────────

func TestAzureDiscoverScopesEnumeratesMgmtGroup(t *testing.T) {
	arm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/providers/Microsoft.Management/managementGroups/mg-prod/descendants") {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"value": []map[string]any{
			{"name": "child-group", "type": "Microsoft.Management/managementGroups", "properties": map[string]string{"displayName": "Child"}},
			{"name": "00000000-0000-0000-0000-000000000001", "type": "Microsoft.Management/managementGroups/subscriptions", "properties": map[string]string{"displayName": "Prod Sub"}},
			{"name": "00000000-0000-0000-0000-000000000002", "type": "Microsoft.Management/managementGroups/subscriptions", "properties": map[string]string{"displayName": "Dev Sub"}},
		}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer arm.Close()

	adapter := NewAzureAdapter(nil, &AzureARMProbeClient{Client: arm.Client(), BaseURL: arm.URL})
	scopes, err := adapter.DiscoverScopes(context.Background(), DiscoverRequest{
		Root:  Scope{Type: ScopeMgmtGroup, Ref: "mg-prod"},
		Token: ScopedToken{Provider: ProviderAzure, Value: "bearer-token"},
	})
	if err != nil {
		t.Fatalf("DiscoverScopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("want the 2 subscriptions only (child group filtered), got %+v", scopes)
	}
	if scopes[0].Type != ScopeSubscription || scopes[0].Display != "Prod Sub" {
		t.Fatalf("scope[0] = %+v", scopes[0])
	}
}

// ── enumeration: GCP folder / organization ───────────────────────────────────

func TestGCPDiscoverScopesEnumeratesFolder(t *testing.T) {
	var gotFilter string
	crm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"projects": []map[string]string{
			{"projectId": "prod-app", "name": "Prod App"},
			{"projectId": "prod-data", "name": "Prod Data"},
		}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer crm.Close()

	adapter := NewGCPAdapter(nil, &GCPProbeClient{Client: crm.Client(), CRMBase: crm.URL})
	scopes, err := adapter.DiscoverScopes(context.Background(), DiscoverRequest{
		Root:  Scope{Type: ScopeFolder, Ref: "555666777"},
		Token: ScopedToken{Provider: ProviderGCP, Value: "bearer"},
	})
	if err != nil {
		t.Fatalf("DiscoverScopes: %v", err)
	}
	if !strings.Contains(gotFilter, "parent.type:folder") || !strings.Contains(gotFilter, "parent.id:555666777") {
		t.Fatalf("filter = %q", gotFilter)
	}
	if len(scopes) != 2 || scopes[0].Type != ScopeProject || scopes[0].Ref != "prod-app" {
		t.Fatalf("scopes = %+v", scopes)
	}

	// Org anchor flips the parent type.
	if _, err := adapter.DiscoverScopes(context.Background(), DiscoverRequest{
		Root:  Scope{Type: ScopeOrg, Ref: "888"},
		Token: ScopedToken{Provider: ProviderGCP, Value: "bearer"},
	}); err != nil {
		t.Fatalf("DiscoverScopes(org): %v", err)
	}
	if !strings.Contains(gotFilter, "parent.type:organization") {
		t.Fatalf("org filter = %q", gotFilter)
	}
}

// ── honest deferral: no probe / no token → sentinel, never a fabricated list ──

func TestOrgDiscoverDefersWithoutLiveWiring(t *testing.T) {
	cases := []struct {
		name    string
		adapter CloudIdentityProvider
		req     DiscoverRequest
	}{
		{"aws no probe", NewAWSAdapter(nil, nil), DiscoverRequest{Root: Scope{Type: ScopeOrg, Ref: "o-x"}, Token: ScopedToken{AWS: &AWSCredentials{AccessKeyID: "a", SecretAccessKey: "b", SessionToken: "c"}}}},
		{"aws no token", NewAWSAdapter(nil, &AWSProbeClient{}), DiscoverRequest{Root: Scope{Type: ScopeOrg, Ref: "o-x"}}},
		{"azure no probe", NewAzureAdapter(nil, nil), DiscoverRequest{Root: Scope{Type: ScopeMgmtGroup, Ref: "mg"}, Token: ScopedToken{Value: "v"}}},
		{"azure no token", NewAzureAdapter(nil, &AzureARMProbeClient{}), DiscoverRequest{Root: Scope{Type: ScopeMgmtGroup, Ref: "mg"}}},
		{"gcp no probe", NewGCPAdapter(nil, nil), DiscoverRequest{Root: Scope{Type: ScopeFolder, Ref: "1"}, Token: ScopedToken{Value: "v"}}},
		{"gcp no token", NewGCPAdapter(nil, &GCPProbeClient{}), DiscoverRequest{Root: Scope{Type: ScopeFolder, Ref: "1"}}},
	}
	for _, c := range cases {
		if _, err := c.adapter.DiscoverScopes(context.Background(), c.req); err != ErrProviderExchangeDeferred {
			t.Errorf("%s: err = %v, want ErrProviderExchangeDeferred", c.name, err)
		}
	}
}
