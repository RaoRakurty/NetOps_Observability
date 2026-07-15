package cloudconn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAWSValidateRejectsRootWildcardMissingExternalID(t *testing.T) {
	a := awsAdapter{}
	// root principal rejected
	res := a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::123456789012:root", ExternalID: NewExternalID(),
	})
	if res.OK || !hasCode(res, "root_principal_rejected") {
		t.Fatalf("root principal must be rejected: %+v", res)
	}
	// wildcard rejected
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::123456789012:role/*", ExternalID: NewExternalID(),
	})
	if res.OK || !hasCode(res, "wildcard_principal_rejected") {
		t.Fatalf("wildcard principal must be rejected: %+v", res)
	}
	// missing ExternalId rejected
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::123456789012:role/correlix-observer",
	})
	if res.OK || !hasCode(res, "external_id_missing") {
		t.Fatalf("missing ExternalId must be rejected: %+v", res)
	}
	// derived/weak ExternalId rejected
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::123456789012:role/correlix-observer", ExternalID: "acme-tenant",
	})
	if res.OK || !hasCode(res, "external_id_weak") {
		t.Fatalf("weak ExternalId must be rejected: %+v", res)
	}
	// valid role passes
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole,
		RoleARN: "arn:aws:iam::123456789012:role/correlix-observer", ExternalID: NewExternalID(),
	})
	if !res.OK {
		t.Fatalf("valid role config rejected: %+v", res)
	}
}

func TestAWSStaticKeyLegacyAndRootRejected(t *testing.T) {
	a := awsAdapter{}
	// legacy warning present + root key rejected
	res := a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodStaticKey,
		LegacySecretRef: "csr_abc", LegacyKeyID: "root",
	})
	if res.OK || !hasCode(res, "root_key_rejected") {
		t.Fatalf("root static key must be rejected: %+v", res)
	}
	if !hasCode(res, "legacy_method") {
		t.Fatal("static key must carry a legacy warning")
	}
	// valid legacy key: warned but OK
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodStaticKey,
		LegacySecretRef: "csr_abc", LegacyKeyID: "AKIAEXAMPLE",
	})
	if !res.OK || !hasCode(res, "legacy_method") {
		t.Fatalf("valid legacy key should pass with a warning: %+v", res)
	}
}

func TestAWSProhibitedMethodRejected(t *testing.T) {
	res := awsAdapter{}.ValidateConfiguration(IdentityConfig{Provider: ProviderAWS, Method: AuthMethodProhibited})
	if res.OK || !hasCode(res, "method_prohibited") {
		t.Fatalf("admin password must be rejected: %+v", res)
	}
}

func TestAWSSetupTemplatesCarryExternalIDAndPerms(t *testing.T) {
	extID := NewExternalID()
	pack := mustPack(t, "aws-observer-v1")
	bundle, err := awsAdapter{}.SetupInstructions(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodCloudRole, ExternalID: extID,
		Anchor: TrustAnchor{AWSPrincipalARN: "arn:aws:iam::999999999999:role/correlix-connector"},
	}, pack)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, art := range bundle.Artifacts {
		kinds[art.Kind] = art.Content
	}
	for _, want := range []string{"cloudformation", "terraform", "manual"} {
		c, ok := kinds[want]
		if !ok {
			t.Fatalf("missing %s artifact", want)
		}
		if !strings.Contains(c, extID) {
			t.Fatalf("%s artifact missing ExternalId", want)
		}
		if !strings.Contains(c, "arn:aws:iam::999999999999:role/correlix-connector") {
			t.Fatalf("%s artifact missing trusted principal", want)
		}
		// least-privilege actions present; no admin
		if !strings.Contains(c, "ec2:Describe*") {
			t.Fatalf("%s artifact missing pack permissions", want)
		}
		// The policy-document artifacts must never GRANT admin (the manual guide
		// may mention it in a "never attach" warning, so exclude it here).
		if want != "manual" && strings.Contains(c, "AdministratorAccess") {
			t.Fatalf("%s artifact must never grant AdministratorAccess", want)
		}
	}
}

func TestAzureValidateFederationAndLegacy(t *testing.T) {
	a := azureAdapter{}
	// federation missing issuer/subject
	res := a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAzure, Method: AuthMethodWorkloadFederation,
		AzureTenantID: "t", ClientID: "c",
	})
	if res.OK || !hasCode(res, "federation_incomplete") {
		t.Fatalf("incomplete federation must be rejected: %+v", res)
	}
	// complete federation passes
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAzure, Method: AuthMethodWorkloadFederation,
		AzureTenantID: "t", ClientID: "c", Issuer: "https://iss", FederatedSubject: "correlix:x", Audience: "api://AzureADTokenExchange",
	})
	if !res.OK {
		t.Fatalf("complete federation rejected: %+v", res)
	}
	// client secret is legacy + needs a ref
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAzure, Method: AuthMethodClientSecret, AzureTenantID: "t", ClientID: "c",
	})
	if res.OK || !hasCode(res, "secret_ref_missing") || !hasCode(res, "legacy_method") {
		t.Fatalf("client secret must warn legacy + require ref: %+v", res)
	}
}

func TestGCPValidateFederationAndOwnerSARejected(t *testing.T) {
	a := gcpAdapter{}
	res := a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderGCP, Method: AuthMethodStaticKey,
		ProjectNumber: "123", LegacySecretRef: "csr_x", ServiceAccount: "editor@proj.iam.gserviceaccount.com",
	})
	if res.OK || !hasCode(res, "owner_sa_rejected") {
		t.Fatalf("owner/editor SA must be rejected: %+v", res)
	}
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderGCP, Method: AuthMethodWorkloadFederation,
		ProjectNumber: "123", WorkloadPool: "correlix-pool", WorkloadProvider: "correlix-provider",
		ServiceAccount: "correlix-observer@proj.iam.gserviceaccount.com",
	})
	if !res.OK {
		t.Fatalf("valid GCP federation rejected: %+v", res)
	}
}

func TestLiveMethodsDeferredNotAuthFailure(t *testing.T) {
	ctx := context.Background()
	for _, a := range []CloudIdentityProvider{awsAdapter{}, azureAdapter{}, gcpAdapter{}} {
		if _, err := a.ExchangeCredential(ctx, ExchangeRequest{}); !errors.Is(err, ErrProviderExchangeDeferred) {
			t.Fatalf("%s ExchangeCredential should return deferred sentinel, got %v", a.Provider(), err)
		}
	}
}

func hasCode(r ValidationResult, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
