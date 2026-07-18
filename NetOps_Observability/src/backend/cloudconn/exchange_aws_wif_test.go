package cloudconn

// exchange_aws_wif_test.go — Wave 4 #13 slice 3: the KEYLESS AWS
// AssumeRoleWithWebIdentity exchange. Asserts the wire contract (unsigned
// request, WebIdentityToken carried, no ExternalId), the deferral when no
// workload assertion is configured, and that NO stored AWS key exists on the
// federated path.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type wifAssertion struct{ token string }

func (s wifAssertion) Assertion(context.Context, string) (string, error) { return s.token, nil }

type noAssertion struct{}

func (noAssertion) Assertion(context.Context, string) (string, error) {
	return "", ErrWorkloadAssertionMissing
}

func awsWIFRequest() ExchangeRequest {
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider:    ProviderAWS,
			Method:      AuthMethodWorkloadFederation,
			ConnectorID: "ccn_wif1",
			RoleARN:     "arn:aws:iam::123456789012:role/correlix-observer",
			Audience:    "sts.amazonaws.com",
		},
		MaxLifetime: time.Hour,
		Region:      "us-east-1",
	}
}

const awsWebIdentityOK = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAWIFKEY</AccessKeyId>
      <SecretAccessKey>wifSecretKey</SecretAccessKey>
      <SessionToken>wifSessionToken</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

func TestAWSExchangeWebIdentityKeyless(t *testing.T) {
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var gotForm url.Values
	var gotAuthz string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		gotAuthz = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, strings.ReplaceAll(awsWebIdentityOK, "%s", expiry.Format(time.RFC3339)))
	}))
	defer ts.Close()

	// NO Platform credential source at all: the keyless path must not need one.
	x := &AWSSTSExchanger{
		Client: ts.Client(), Endpoint: ts.URL,
		Assertions: wifAssertion{token: "correlix.workload.jwt"},
	}
	tok, err := x.Exchange(context.Background(), awsWIFRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Wire contract: AssumeRoleWithWebIdentity carrying the assertion, UNSIGNED,
	// and NO ExternalId (the parameter does not exist on this action).
	if gotForm.Get("Action") != "AssumeRoleWithWebIdentity" {
		t.Errorf("Action = %q", gotForm.Get("Action"))
	}
	if gotForm.Get("WebIdentityToken") != "correlix.workload.jwt" {
		t.Errorf("WebIdentityToken = %q", gotForm.Get("WebIdentityToken"))
	}
	if gotForm.Get("ExternalId") != "" {
		t.Error("ExternalId must not be sent on AssumeRoleWithWebIdentity")
	}
	if !strings.HasPrefix(gotForm.Get("RoleSessionName"), "correlix-ccn_wif1") {
		t.Errorf("RoleSessionName = %q", gotForm.Get("RoleSessionName"))
	}
	if gotAuthz != "" {
		t.Fatalf("keyless call must be UNSIGNED, got Authorization %q", gotAuthz)
	}
	// The session triplet comes back short-lived.
	if tok.AWS == nil || tok.AWS.AccessKeyID != "ASIAWIFKEY" || tok.AWS.SessionToken != "wifSessionToken" {
		t.Fatalf("token missing web-identity session triplet")
	}
	if !tok.Expiry.Equal(expiry) {
		t.Errorf("expiry = %v want %v", tok.Expiry, expiry)
	}
}

func TestAWSExchangeWebIdentityDeferrals(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("deferral paths must not reach the wire")
		w.WriteHeader(500)
	}))
	defer ts.Close()

	// No assertion source configured → assertion-missing deferral, never a
	// platform-credential requirement.
	x := &AWSSTSExchanger{Client: ts.Client(), Endpoint: ts.URL, Assertions: noAssertion{}}
	if _, err := x.Exchange(context.Background(), awsWIFRequest()); !errors.Is(err, ErrWorkloadAssertionMissing) {
		t.Fatalf("want ErrWorkloadAssertionMissing, got %v", err)
	}
	x2 := &AWSSTSExchanger{Client: ts.Client(), Endpoint: ts.URL}
	if _, err := x2.Exchange(context.Background(), awsWIFRequest()); !errors.Is(err, ErrWorkloadAssertionMissing) {
		t.Fatalf("nil assertion source: want ErrWorkloadAssertionMissing, got %v", err)
	}
}

func TestAWSExchangeWebIdentityDenied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>token rejected</Message></Error></ErrorResponse>`)
	}))
	defer ts.Close()
	x := &AWSSTSExchanger{Client: ts.Client(), Endpoint: ts.URL, Assertions: wifAssertion{token: "jwt"}}
	_, err := x.Exchange(context.Background(), awsWIFRequest())
	var xe *ExchangeError
	if !errors.As(err, &xe) || !xe.Denied() {
		t.Fatalf("want denied ExchangeError, got %v", err)
	}
}

// The federated AWS config validates WITHOUT an ExternalId (the ARN hygiene
// still applies) and NEVER holds a stored secret.
func TestAWSWebIdentityValidation(t *testing.T) {
	a := AdapterFor(ProviderAWS)
	res := a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodWorkloadFederation,
		RoleARN: "arn:aws:iam::123456789012:role/correlix-observer", Audience: "sts.amazonaws.com",
	})
	if !res.OK {
		t.Fatalf("federated config without ExternalId must validate: %+v", res.Findings)
	}
	res = a.ValidateConfiguration(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodWorkloadFederation,
		RoleARN: "arn:aws:iam::123456789012:role/*",
	})
	if res.OK {
		t.Fatal("wildcard role ARN must still be rejected on the federated path")
	}
	if AuthMethodWorkloadFederation.HoldsStoredSecret() {
		t.Fatal("federated method must never store an AWS key")
	}
}

// SetupInstructions for the federated method renders the OIDC-provider trust
// (aud+sub pin), not the ExternalId trust, and promises no stored key.
func TestAWSWebIdentitySetupInstructions(t *testing.T) {
	a := AdapterFor(ProviderAWS)
	pack, _ := Pack("aws-observer-v1")
	bundle, err := a.SetupInstructions(IdentityConfig{
		Provider: ProviderAWS, Method: AuthMethodWorkloadFederation,
		Anchor: TrustAnchor{OIDCIssuer: "https://issuer.correlix.example", OIDCSubject: "correlix:connector:ccn_1"},
		Audience: "sts.amazonaws.com",
	}, pack)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Method != AuthMethodWorkloadFederation {
		t.Fatalf("bundle method = %q", bundle.Method)
	}
	joined := ""
	for _, art := range bundle.Artifacts {
		joined += art.Content
	}
	for _, want := range []string{"sts:AssumeRoleWithWebIdentity", "issuer.correlix.example:aud", "issuer.correlix.example:sub", "correlix:connector:ccn_1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("setup artifacts missing %q", want)
		}
	}
	if strings.Contains(joined, "ExternalId") {
		t.Fatal("web-identity setup must not reference ExternalId")
	}
}
