package cloudconn

// exchange_aws_test.go — table-driven tests for the live AWS STS exchange
// against httptest fixtures: happy path (AssumeRole + GetSessionToken), denied,
// malformed, throttled(+retry), and platform-credential deferral.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticAWSCreds struct{ c AWSCredentials }

func (s staticAWSCreds) Credentials(context.Context) (AWSCredentials, error) { return s.c, nil }

type missingAWSCreds struct{}

func (missingAWSCreds) Credentials(context.Context) (AWSCredentials, error) {
	return AWSCredentials{}, ErrPlatformCredentialsMissing
}

func awsRoleRequest() ExchangeRequest {
	return ExchangeRequest{
		Identity: IdentityConfig{
			Provider:    ProviderAWS,
			Method:      AuthMethodCloudRole,
			ConnectorID: "ccn_test123",
			RoleARN:     "arn:aws:iam::123456789012:role/correlix-observer",
			ExternalID:  "correlix-b0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
		},
		MaxLifetime: time.Hour,
		Region:      "us-east-1",
	}
}

const awsAssumeRoleOK = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>testSecretKeyValue</SecretAccessKey>
      <SessionToken>testSessionTokenValue</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

func newAWSExchanger(ts *httptest.Server) *AWSSTSExchanger {
	return &AWSSTSExchanger{
		Client:   ts.Client(),
		Endpoint: ts.URL,
		Platform: staticAWSCreds{AWSCredentials{AccessKeyID: "AKIDPLATFORM", SecretAccessKey: "platform-secret"}},
		Now:      func() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) },
	}
}

func TestAWSExchangeAssumeRoleHappyPath(t *testing.T) {
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var gotForm url.Values
	var gotAuthz, gotDate string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		gotAuthz = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, strings.ReplaceAll(awsAssumeRoleOK, "%s", expiry.Format(time.RFC3339)))
	}))
	defer ts.Close()

	x := newAWSExchanger(ts)
	tok, err := x.Exchange(context.Background(), awsRoleRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// The wire request carries the exact trust parameters.
	if gotForm.Get("Action") != "AssumeRole" {
		t.Errorf("Action = %q", gotForm.Get("Action"))
	}
	if gotForm.Get("RoleArn") != "arn:aws:iam::123456789012:role/correlix-observer" {
		t.Errorf("RoleArn = %q", gotForm.Get("RoleArn"))
	}
	if gotForm.Get("ExternalId") == "" {
		t.Error("ExternalId missing from the wire request — confused-deputy protection lost")
	}
	if gotForm.Get("DurationSeconds") != "3600" {
		t.Errorf("DurationSeconds = %q", gotForm.Get("DurationSeconds"))
	}
	if !strings.HasPrefix(gotForm.Get("RoleSessionName"), "correlix-ccn_test123") {
		t.Errorf("RoleSessionName = %q", gotForm.Get("RoleSessionName"))
	}
	// The request is SigV4-signed with the PLATFORM identity.
	if !strings.HasPrefix(gotAuthz, "AWS4-HMAC-SHA256 Credential=AKIDPLATFORM/20260715/us-east-1/sts/aws4_request") {
		t.Errorf("Authorization = %q", gotAuthz)
	}
	if !strings.Contains(gotAuthz, "SignedHeaders=") || !strings.Contains(gotAuthz, "Signature=") {
		t.Errorf("Authorization missing SigV4 components: %q", gotAuthz)
	}
	if gotDate != "20260715T120000Z" {
		t.Errorf("X-Amz-Date = %q", gotDate)
	}
	// The token carries the full session triplet + expiry.
	if tok.AWS == nil || tok.AWS.AccessKeyID != "ASIATESTACCESSKEY" || tok.AWS.SecretAccessKey != "testSecretKeyValue" || tok.AWS.SessionToken != "testSessionTokenValue" {
		t.Fatalf("token missing session credential triplet: %+v", tok.AWS != nil)
	}
	if !tok.Expiry.Equal(expiry) {
		t.Errorf("expiry = %v want %v", tok.Expiry, expiry)
	}
	if tok.Provider != ProviderAWS || tok.Value != "testSessionTokenValue" {
		t.Errorf("token identity fields wrong: %s %q", tok.Provider, tok.TokenType)
	}
}

func TestAWSExchangeStaticKeyGetSessionToken(t *testing.T) {
	expiry := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	var gotForm url.Values
	var gotAuthz string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		gotAuthz = r.Header.Get("Authorization")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `<GetSessionTokenResponse><GetSessionTokenResult><Credentials>
			<AccessKeyId>ASIALEGACY</AccessKeyId><SecretAccessKey>legacySessionSecret</SecretAccessKey>
			<SessionToken>legacySessionToken</SessionToken><Expiration>`+expiry.Format(time.RFC3339)+`</Expiration>
			</Credentials></GetSessionTokenResult></GetSessionTokenResponse>`)
	}))
	defer ts.Close()

	x := newAWSExchanger(ts)
	req := ExchangeRequest{
		Identity: IdentityConfig{
			Provider: ProviderAWS, Method: AuthMethodStaticKey,
			ConnectorID: "ccn_legacy", LegacyKeyID: "AKIALEGACYKEY", LegacySecretRef: "csr_x",
		},
		LegacySecret: "legacy-secret-value",
		MaxLifetime:  time.Hour,
	}
	tok, err := x.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotForm.Get("Action") != "GetSessionToken" {
		t.Errorf("Action = %q", gotForm.Get("Action"))
	}
	// Signed with the STORED key, not the platform identity.
	if !strings.Contains(gotAuthz, "Credential=AKIALEGACYKEY/") {
		t.Errorf("legacy exchange must sign with the stored key: %q", gotAuthz)
	}
	if tok.AWS == nil || tok.AWS.SessionToken != "legacySessionToken" {
		t.Fatal("legacy exchange must still return SHORT-LIVED session credentials")
	}
}

func TestAWSExchangeErrorSurfaces(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{
			name:   "denied",
			status: 403,
			body: `<ErrorResponse><Error><Code>AccessDenied</Code>
				<Message>User is not authorized to perform sts:AssumeRole</Message></Error></ErrorResponse>`,
			wantCode: "denied",
		},
		{
			name:   "expired platform credential",
			status: 403,
			body: `<ErrorResponse><Error><Code>ExpiredToken</Code>
				<Message>The security token included in the request is expired</Message></Error></ErrorResponse>`,
			wantCode: "denied",
		},
		{
			name:     "malformed xml",
			status:   200,
			body:     `{"not":"xml"}`,
			wantCode: "malformed_response",
		},
		{
			name:     "missing credentials element",
			status:   200,
			body:     `<AssumeRoleResponse><AssumeRoleResult></AssumeRoleResult></AssumeRoleResponse>`,
			wantCode: "malformed_response",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer ts.Close()
			x := newAWSExchanger(ts)
			_, err := x.Exchange(context.Background(), awsRoleRequest())
			var xe *ExchangeError
			if !errors.As(err, &xe) {
				t.Fatalf("want *ExchangeError, got %v", err)
			}
			if xe.Code != tc.wantCode {
				t.Fatalf("code = %q want %q (err: %v)", xe.Code, tc.wantCode, err)
			}
			// Sanitized: the error text never carries request secrets.
			if strings.Contains(err.Error(), "platform-secret") {
				t.Fatal("error text leaked signing secret")
			}
		})
	}
}

func TestAWSExchangeThrottledRetriesThenSucceeds(t *testing.T) {
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>Throttling</Code></Error></ErrorResponse>`)
			return
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, strings.ReplaceAll(awsAssumeRoleOK, "%s", expiry.Format(time.RFC3339)))
	}))
	defer ts.Close()
	x := newAWSExchanger(ts)
	tok, err := x.Exchange(context.Background(), awsRoleRequest())
	if err != nil {
		t.Fatalf("throttled request should retry then succeed: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected exactly one retry, got %d calls", calls.Load())
	}
	if tok.AWS == nil {
		t.Fatal("token missing after retry")
	}
}

func TestAWSExchangeThrottledExhaustsRetries(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
	}))
	defer ts.Close()
	x := newAWSExchanger(ts)
	_, err := x.Exchange(context.Background(), awsRoleRequest())
	var xe *ExchangeError
	if !errors.As(err, &xe) || xe.Code != "throttled" {
		t.Fatalf("want throttled ExchangeError, got %v", err)
	}
	if calls.Load() != exchangeMaxAttempts {
		t.Fatalf("retry loop must be bounded at %d attempts, made %d", exchangeMaxAttempts, calls.Load())
	}
}

func TestAWSExchangePlatformCredentialsMissingIsDeferral(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no wire call should happen without platform credentials")
		w.WriteHeader(500)
	}))
	defer ts.Close()
	x := newAWSExchanger(ts)
	x.Platform = missingAWSCreds{}
	_, err := x.Exchange(context.Background(), awsRoleRequest())
	if !errors.Is(err, ErrPlatformCredentialsMissing) {
		t.Fatalf("want ErrPlatformCredentialsMissing, got %v", err)
	}
}

func TestAWSAdapterValidatesBeforeWire(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid config must never reach the wire")
		w.WriteHeader(500)
	}))
	defer ts.Close()
	a := NewAdapterWithExchanger(ProviderAWS, newAWSExchanger(ts))
	req := awsRoleRequest()
	req.Identity.ExternalID = "" // missing confused-deputy protection → blocking finding
	_, err := a.ExchangeCredential(context.Background(), req)
	var xe *ExchangeError
	if !errors.As(err, &xe) || xe.Code != "request_invalid" {
		t.Fatalf("want request_invalid, got %v", err)
	}
}
