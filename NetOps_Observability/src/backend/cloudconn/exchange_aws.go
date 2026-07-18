package cloudconn

// exchange_aws.go — LIVE AWS credential exchange via the STS Query API,
// stdlib-only (SigV4 signing from sigv4.go + encoding/xml parsing).
//
//   - workload_identity_federation → sts:AssumeRoleWithWebIdentity into the
//     customer's observer role: Correlix presents its OWN signed OIDC workload
//     assertion (projected token file / env — the platform-issuer seam) as the
//     WebIdentityToken. KEYLESS: the call is UNSIGNED by design (the web
//     identity token IS the credential) — no long-lived AWS key exists
//     anywhere on the platform for this mode. Trust is anchored on the role's
//     OIDC-provider trust policy (aud/sub conditions), not an ExternalId.
//   - cloud_role → sts:AssumeRole into the customer's observer role, gated by
//     the per-tenant+connector ExternalId (confused-deputy protection), signed
//     with the broker's PLATFORM identity.
//   - static_key (legacy) → sts:GetSessionToken signed with the Vault-decrypted
//     access key, so even the legacy path hands collectors only SHORT-LIVED
//     session credentials, never the stored key itself.

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	awsSTSVersion         = "2011-06-15"
	awsSTSGlobalEndpoint  = "https://sts.amazonaws.com"
	awsSTSGlobalSignRegion = "us-east-1"
	awsMinSessionSeconds  = 900  // STS lower bound for DurationSeconds
	awsMaxSessionSeconds  = 3600 // matches the setup templates' MaxSessionDuration
)

// AWSSTSExchanger implements TokenExchanger against the AWS STS Query API.
// All fields are injectable; the zero value of Endpoint/Client uses the real
// regional STS endpoint and a bounded default client.
type AWSSTSExchanger struct {
	Client     *http.Client
	Endpoint   string                      // override for tests (httptest server URL)
	Region     string                      // signing/endpoint region when the request has none
	Platform   AWSPlatformCredentialSource // broker platform identity (signs AssumeRole)
	Assertions WorkloadAssertionSource     // Correlix workload OIDC assertion (AssumeRoleWithWebIdentity)
	Now        func() time.Time
}

// NewAWSSTSExchanger returns the production exchanger: regional STS endpoint,
// bounded HTTP client, env-backed platform credentials + workload assertion.
func NewAWSSTSExchanger() *AWSSTSExchanger {
	return &AWSSTSExchanger{
		Client:     newExchangeHTTPClient(),
		Platform:   EnvAWSCredentialSource{},
		Assertions: EnvWorkloadAssertionSource{},
		Now:        func() time.Time { return time.Now().UTC() },
	}
}

// endpointAndRegion resolves the STS endpoint + SigV4 signing region.
func (x *AWSSTSExchanger) endpointAndRegion(reqRegion string) (endpoint, region string) {
	region = strings.TrimSpace(reqRegion)
	if region == "" {
		region = strings.TrimSpace(x.Region)
	}
	if x.Endpoint != "" {
		if region == "" {
			region = awsSTSGlobalSignRegion
		}
		return x.Endpoint, region
	}
	if region == "" {
		return awsSTSGlobalEndpoint, awsSTSGlobalSignRegion
	}
	return "https://sts." + region + ".amazonaws.com", region
}

// Exchange mints short-lived AWS session credentials for the request identity.
func (x *AWSSTSExchanger) Exchange(ctx context.Context, req ExchangeRequest) (ScopedToken, error) {
	now := time.Now().UTC()
	if x.Now != nil {
		now = x.Now().UTC()
	}
	lifetime := clampLifetime(req.MaxLifetime, time.Hour, awsMinSessionSeconds*time.Second, awsMaxSessionSeconds*time.Second)
	durationSeconds := int(lifetime / time.Second)

	form := url.Values{}
	form.Set("Version", awsSTSVersion)
	form.Set("DurationSeconds", strconv.Itoa(durationSeconds))

	var signWith AWSCredentials
	signed := true
	switch req.Identity.Method {
	case AuthMethodWorkloadFederation:
		// KEYLESS path: AssumeRoleWithWebIdentity is deliberately UNSIGNED —
		// the workload OIDC assertion is the credential. No platform AWS key
		// is required (or used) in this mode.
		roleARN := strings.TrimSpace(req.Identity.RoleARN)
		if roleARN == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "role ARN missing"}
		}
		if x.Assertions == nil {
			return ScopedToken{}, ErrWorkloadAssertionMissing
		}
		assertion, err := x.Assertions.Assertion(ctx, strings.TrimSpace(req.Identity.Audience), WorkloadSubject(req.Identity))
		if err != nil {
			return ScopedToken{}, err
		}
		form.Set("Action", "AssumeRoleWithWebIdentity")
		form.Set("RoleArn", roleARN)
		form.Set("RoleSessionName", awsRoleSessionName(req.Identity.ConnectorID))
		form.Set("WebIdentityToken", assertion)
		signed = false
	case AuthMethodCloudRole:
		roleARN := strings.TrimSpace(req.Identity.RoleARN)
		if roleARN == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "role ARN missing"}
		}
		if strings.TrimSpace(req.Identity.ExternalID) == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "ExternalId missing (confused-deputy protection)"}
		}
		form.Set("Action", "AssumeRole")
		form.Set("RoleArn", roleARN)
		form.Set("ExternalId", req.Identity.ExternalID)
		form.Set("RoleSessionName", awsRoleSessionName(req.Identity.ConnectorID))
		if x.Platform == nil {
			return ScopedToken{}, ErrPlatformCredentialsMissing
		}
		creds, err := x.Platform.Credentials(ctx)
		if err != nil {
			return ScopedToken{}, err
		}
		signWith = creds
	case AuthMethodStaticKey:
		// Legacy path: the Vault-decrypted static key signs GetSessionToken so
		// downstream consumers still only ever see short-lived credentials.
		if strings.TrimSpace(req.Identity.LegacyKeyID) == "" || strings.TrimSpace(req.LegacySecret) == "" {
			return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "static key material incomplete"}
		}
		form.Set("Action", "GetSessionToken")
		signWith = AWSCredentials{AccessKeyID: strings.TrimSpace(req.Identity.LegacyKeyID), SecretAccessKey: req.LegacySecret}
	default:
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "auth method " + string(req.Identity.Method) + " has no AWS exchange path"}
	}

	endpoint, region := x.endpointAndRegion(req.Region)
	payload := []byte(form.Encode())

	status, body, attempts, err := doExchangeHTTP(ctx, x.Client, ProviderAWS, func() (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(string(payload)))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		if signed {
			signAWSRequest(hreq, payload, signWith, region, "sts", now)
		}
		return hreq, nil
	})
	if err != nil {
		return ScopedToken{}, err
	}
	if status != http.StatusOK {
		return ScopedToken{}, awsSTSError(status, body, attempts)
	}
	return awsParseSTSCredentials(body, attempts)
}

// awsRoleSessionName builds a CloudTrail-friendly session name from the opaque
// connector id, restricted to the STS-legal charset [\w+=,.@-] and 64 chars.
func awsRoleSessionName(connectorID string) string {
	base := "correlix-" + connectorID
	var b strings.Builder
	for i := 0; i < len(base) && b.Len() < 64; i++ {
		c := base[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') ||
			c == '+' || c == '=' || c == ',' || c == '.' || c == '@' || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "correlix"
	}
	return b.String()
}

// stsCredentials is the shared Credentials element of AssumeRoleResponse /
// GetSessionTokenResponse.
type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type stsResponseEnvelope struct {
	AssumeRoleResult struct {
		Credentials stsCredentials `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
	AssumeRoleWithWebIdentityResult struct {
		Credentials stsCredentials `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
	GetSessionTokenResult struct {
		Credentials stsCredentials `xml:"Credentials"`
	} `xml:"GetSessionTokenResult"`
}

// awsParseSTSCredentials parses the Query API XML into a ScopedToken carrying
// the session-credential triplet. Never logs any part of the response.
func awsParseSTSCredentials(body []byte, attempts int) (ScopedToken, error) {
	var env stsResponseEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: "STS response is not parseable XML", Attempts: attempts}
	}
	creds := env.AssumeRoleResult.Credentials
	if creds.AccessKeyID == "" {
		creds = env.AssumeRoleWithWebIdentityResult.Credentials
	}
	if creds.AccessKeyID == "" {
		creds = env.GetSessionTokenResult.Credentials
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: "STS response missing credentials", Attempts: attempts}
	}
	expiry, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		return ScopedToken{}, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: "STS expiration unparseable", Attempts: attempts}
	}
	return ScopedToken{
		Provider:  ProviderAWS,
		Value:     creds.SessionToken,
		TokenType: "aws_session",
		Expiry:    expiry.UTC(),
		AWS: &AWSCredentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
		},
	}, nil
}

// stsErrorEnvelope is the Query API error shape.
type stsErrorEnvelope struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// awsSTSError maps a non-200 STS response to a sanitized ExchangeError. The
// provider Message is truncated; the raw body is never propagated.
func awsSTSError(status int, body []byte, attempts int) error {
	var env stsErrorEnvelope
	_ = xml.Unmarshal(body, &env) // best-effort: fall through to status mapping
	code := "provider_error"
	switch env.Error.Code {
	case "AccessDenied", "AccessDeniedException", "ExpiredToken", "InvalidClientTokenId", "SignatureDoesNotMatch", "MissingAuthenticationToken",
		"InvalidIdentityToken", "ExpiredTokenException", "IDPRejectedClaim":
		code = "denied"
	case "Throttling", "ThrottlingException", "RequestLimitExceeded":
		code = "throttled"
	case "MalformedInput", "ValidationError":
		code = "request_invalid"
	default:
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			code = "denied"
		}
	}
	msg := env.Error.Code
	if env.Error.Message != "" {
		msg += ": " + truncateForError(env.Error.Message)
	}
	if msg == "" {
		msg = "STS returned status " + strconv.Itoa(status)
	}
	return &ExchangeError{Provider: ProviderAWS, Code: code, HTTPStatus: status, Msg: msg, Attempts: attempts}
}
