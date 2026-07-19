package cloudconn

// probe_aws.go — LIVE AWS identity + permission probes (Wave 4 #13), stdlib-only.
//
// The cheapest possible checks, all read-only:
//   - sts:GetCallerIdentity — proves the exchanged credential is real and tells
//     us WHO we are (account + principal ARN). Free, unthrottled, ungated: it
//     cannot be denied by IAM policy, so it is the canonical identity probe.
//   - iam:SimulatePrincipalPolicy — a DRY permission evaluation: no target API
//     is ever invoked; IAM evaluates the principal's policies against the pack's
//     declared action set and reports allowed/denied per action.
//
// Both go through doExchangeHTTP (deadline, capped body, bounded retry) and map
// failures onto the sanitized ExchangeError surface. No secret ever leaves.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	awsIAMEndpoint   = "https://iam.amazonaws.com"
	awsIAMVersion    = "2010-05-08"
	awsIAMSignRegion = "us-east-1" // IAM is a global service signed as us-east-1

	// AWS Organizations (org-level onboarding, Wave 5 #17): JSON-1.1 protocol,
	// global endpoint signed as us-east-1.
	awsOrgsEndpoint   = "https://organizations.us-east-1.amazonaws.com"
	awsOrgsSignRegion = "us-east-1"
	awsOrgsTarget     = "AWSOrganizationsV20161128."
	// One bounded enumeration page — the discover probe answers "what members
	// are reachable", not an exhaustive crawl (§9 bounded IO; same contract as
	// the GCP projects probe).
	awsOrgAccountsPageSize = 20
)

// awsProbeActionFor maps a pack permission to the CONCRETE action name the IAM
// simulator accepts (SimulatePrincipalPolicy takes action names, not wildcards).
// A wildcard permission is probed through one representative read; concrete
// permissions are probed as themselves.
var awsProbeActionFor = map[string]string{
	"ec2:Describe*":           "ec2:DescribeInstances",
	"directconnect:Describe*": "directconnect:DescribeConnections",
}

// AWSProbeActionFor resolves the simulator action for a declared permission:
// the permission itself when concrete, the mapped representative for a known
// wildcard, "" for an unmappable wildcard (reported unverified, never guessed).
func AWSProbeActionFor(permission string) string {
	p := strings.TrimSpace(permission)
	if !strings.Contains(p, "*") {
		return p
	}
	return awsProbeActionFor[p]
}

// AWSCallerIdentity is the sts:GetCallerIdentity result — who the exchanged
// credential actually is. All fields are non-secret.
type AWSCallerIdentity struct {
	Account string
	ARN     string
	UserID  string
}

// AWSProbeClient performs the live AWS probes. All fields injectable; zero
// values use the real endpoints and a bounded default client.
type AWSProbeClient struct {
	Client       *http.Client
	STSEndpoint  string // override for tests
	IAMEndpoint  string // override for tests
	OrgsEndpoint string // override for tests (AWS Organizations)
	Region       string // STS signing/endpoint region when the request has none
	Now          func() time.Time
}

// NewAWSProbeClient returns the production probe client.
func NewAWSProbeClient() *AWSProbeClient {
	return &AWSProbeClient{
		Client: newExchangeHTTPClient(),
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

func (p *AWSProbeClient) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p *AWSProbeClient) stsEndpointAndRegion(reqRegion string) (string, string) {
	region := strings.TrimSpace(reqRegion)
	if region == "" {
		region = strings.TrimSpace(p.Region)
	}
	if p.STSEndpoint != "" {
		if region == "" {
			region = awsSTSGlobalSignRegion
		}
		return p.STSEndpoint, region
	}
	if region == "" {
		return awsSTSGlobalEndpoint, awsSTSGlobalSignRegion
	}
	return "https://sts." + region + ".amazonaws.com", region
}

// queryAWS runs one signed Query-API call and returns the 200 body (non-200 is
// mapped through the shared sanitized STS/IAM error mapper).
func (p *AWSProbeClient) queryAWS(ctx context.Context, endpoint, region, service string, form url.Values, creds AWSCredentials) ([]byte, error) {
	payload := []byte(form.Encode())
	now := p.now()
	status, body, attempts, err := doExchangeHTTP(ctx, p.Client, ProviderAWS, func() (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(string(payload)))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		signAWSRequest(hreq, payload, creds, region, service, now)
		return hreq, nil
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, awsSTSError(status, body, attempts)
	}
	return body, nil
}

type stsCallerIdentityEnvelope struct {
	GetCallerIdentityResult struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

// CallerIdentity performs sts:GetCallerIdentity signed with the exchanged
// session credentials.
func (p *AWSProbeClient) CallerIdentity(ctx context.Context, creds AWSCredentials, region string) (AWSCallerIdentity, error) {
	if creds.Empty() {
		return AWSCallerIdentity{}, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "no AWS credentials to probe with"}
	}
	endpoint, signRegion := p.stsEndpointAndRegion(region)
	form := url.Values{}
	form.Set("Action", "GetCallerIdentity")
	form.Set("Version", awsSTSVersion)
	body, err := p.queryAWS(ctx, endpoint, signRegion, "sts", form, creds)
	if err != nil {
		return AWSCallerIdentity{}, err
	}
	var env stsCallerIdentityEnvelope
	if err := xml.Unmarshal(body, &env); err != nil || env.GetCallerIdentityResult.Account == "" {
		return AWSCallerIdentity{}, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: "GetCallerIdentity response unparseable"}
	}
	res := env.GetCallerIdentityResult
	return AWSCallerIdentity{Account: res.Account, ARN: res.Arn, UserID: res.UserID}, nil
}

type iamSimulateEnvelope struct {
	SimulatePrincipalPolicyResult struct {
		EvaluationResults struct {
			Members []struct {
				EvalActionName string `xml:"EvalActionName"`
				EvalDecision   string `xml:"EvalDecision"`
			} `xml:"member"`
		} `xml:"EvaluationResults"`
	} `xml:"SimulatePrincipalPolicyResult"`
}

// SimulatePermissions runs ONE iam:SimulatePrincipalPolicy dry evaluation for
// the given concrete action names against the principal, returning
// action → allowed. The target APIs are never invoked.
func (p *AWSProbeClient) SimulatePermissions(ctx context.Context, creds AWSCredentials, principalARN string, actions []string) (map[string]bool, error) {
	if creds.Empty() {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "no AWS credentials to probe with"}
	}
	if strings.TrimSpace(principalARN) == "" || len(actions) == 0 {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "principal ARN and at least one action are required"}
	}
	endpoint := p.IAMEndpoint
	if endpoint == "" {
		endpoint = awsIAMEndpoint
	}
	form := url.Values{}
	form.Set("Action", "SimulatePrincipalPolicy")
	form.Set("Version", awsIAMVersion)
	form.Set("PolicySourceArn", principalARN)
	for i, a := range actions {
		form.Set("ActionNames.member."+strconv.Itoa(i+1), a)
	}
	body, err := p.queryAWS(ctx, endpoint, awsIAMSignRegion, "iam", form, creds)
	if err != nil {
		return nil, err
	}
	var env iamSimulateEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: "SimulatePrincipalPolicy response unparseable"}
	}
	out := make(map[string]bool, len(actions))
	for _, m := range env.SimulatePrincipalPolicyResult.EvaluationResults.Members {
		out[m.EvalActionName] = strings.EqualFold(m.EvalDecision, "allowed")
	}
	return out, nil
}

// ── AWS Organizations enumeration (org-level onboarding, Wave 5 #17) ─────────

// AWSOrgAccount is one member account of the organization/OU. Non-secret.
type AWSOrgAccount struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Status string `json:"Status"`
}

// jsonAWS runs one signed JSON-1.1 call (the Organizations wire protocol) and
// returns the 200 body; non-200 maps through the shared sanitized error mapper.
func (p *AWSProbeClient) jsonAWS(ctx context.Context, endpoint, region, service, target string, payload []byte, creds AWSCredentials) ([]byte, error) {
	now := p.now()
	status, body, attempts, err := doExchangeHTTP(ctx, p.Client, ProviderAWS, func() (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(string(payload)))
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Content-Type", "application/x-amz-json-1.1")
		hreq.Header.Set("X-Amz-Target", target)
		signAWSRequest(hreq, payload, creds, region, service, now)
		return hreq, nil
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, awsSTSError(status, body, attempts)
	}
	return body, nil
}

// OrganizationAccounts lists the ACTIVE member accounts of the organization
// (parentRef == "" or the org id) or of one OU (parentRef "ou-…"), signed with
// the exchanged MANAGEMENT-account credentials. One bounded page, read-only.
// This is the live half of "an org connector is enumerable"; deployments
// without live credentials never reach here (the adapter defers first).
func (p *AWSProbeClient) OrganizationAccounts(ctx context.Context, creds AWSCredentials, parentRef string) ([]AWSOrgAccount, error) {
	if creds.Empty() {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "no AWS credentials to probe with"}
	}
	endpoint := p.OrgsEndpoint
	if endpoint == "" {
		endpoint = awsOrgsEndpoint
	}
	action := "ListAccounts"
	req := map[string]any{"MaxResults": awsOrgAccountsPageSize}
	if ref := strings.TrimSpace(parentRef); strings.HasPrefix(ref, "ou-") {
		action = "ListAccountsForParent"
		req["ParentId"] = ref
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "request_invalid", Msg: "organizations request unserializable"}
	}
	body, err := p.jsonAWS(ctx, endpoint, awsOrgsSignRegion, "organizations", awsOrgsTarget+action, payload, creds)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Accounts []AWSOrgAccount `json:"Accounts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderAWS, Code: "malformed_response", Msg: action + " response unparseable"}
	}
	out := make([]AWSOrgAccount, 0, len(resp.Accounts))
	for _, a := range resp.Accounts {
		if a.Status == "" || strings.EqualFold(a.Status, "ACTIVE") {
			out = append(out, a)
		}
	}
	return out, nil
}

// IAMPrincipalFromCallerARN normalizes the GetCallerIdentity ARN into the IAM
// principal ARN the simulator accepts: an assumed-role STS ARN
// (arn:aws:sts::acct:assumed-role/<role>/<session>) becomes the underlying IAM
// role ARN; user/role ARNs pass through unchanged.
func IAMPrincipalFromCallerARN(arn string) string {
	a := strings.TrimSpace(arn)
	const marker = ":assumed-role/"
	i := strings.Index(a, marker)
	if i < 0 || !strings.HasPrefix(a, "arn:aws:sts::") {
		return a
	}
	account := strings.TrimPrefix(a[:i], "arn:aws:sts::")
	rest := a[i+len(marker):] // "<role>/<session>"
	role, _, _ := strings.Cut(rest, "/")
	if account == "" || role == "" {
		return a
	}
	return "arn:aws:iam::" + account + ":role/" + role
}
