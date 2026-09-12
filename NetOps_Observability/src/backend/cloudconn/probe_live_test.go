// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// probe_live_test.go — unit tests for the live identity + permission probes
// (Wave 4 #13) against httptest fixtures. NO live provider calls: every case
// classifies canned provider responses (success, denied, malformed).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func probeCreds() AWSCredentials {
	return AWSCredentials{AccessKeyID: "ASIAPROBE", SecretAccessKey: "probe-secret", SessionToken: "probe-session"}
}

// newAWSQueryFixture serves the STS/IAM Query API by Action.
func newAWSQueryFixture(t *testing.T, denySimulate bool, allowedActions map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "GetCallerIdentity":
			if r.Header.Get("Authorization") == "" {
				t.Error("GetCallerIdentity was not signed")
			}
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult>
				<Arn>arn:aws:sts::123456789012:assumed-role/correlix-observer/correlix-ccn_x</Arn>
				<UserId>AROAX:session</UserId><Account>123456789012</Account>
				</GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case "SimulatePrincipalPolicy":
			if denySimulate {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized to simulate</Message></Error></ErrorResponse>`)
				return
			}
			if form.Get("PolicySourceArn") != "arn:aws:iam::123456789012:role/correlix-observer" {
				t.Errorf("PolicySourceArn = %q (assumed-role ARN not normalized)", form.Get("PolicySourceArn"))
			}
			var members strings.Builder
			for i := 1; ; i++ {
				act := form.Get("ActionNames.member." + itoa(i))
				if act == "" {
					break
				}
				decision := "implicitDeny"
				if allowedActions[act] {
					decision = "allowed"
				}
				members.WriteString("<member><EvalActionName>" + act + "</EvalActionName><EvalDecision>" + decision + "</EvalDecision></member>")
			}
			_, _ = io.WriteString(w, `<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults>`+
				members.String()+`</EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`)
		default:
			t.Errorf("unexpected Action %q", form.Get("Action"))
			w.WriteHeader(400)
		}
	}))
}

func TestAWSProbeCallerIdentityAndSimulate(t *testing.T) {
	ts := newAWSQueryFixture(t, false, map[string]bool{"ec2:DescribeInstances": true})
	defer ts.Close()
	p := &AWSProbeClient{Client: ts.Client(), STSEndpoint: ts.URL, IAMEndpoint: ts.URL,
		Now: func() time.Time { return time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC) }}

	ident, err := p.CallerIdentity(context.Background(), probeCreds(), "")
	if err != nil {
		t.Fatalf("caller identity: %v", err)
	}
	if ident.Account != "123456789012" || !strings.Contains(ident.ARN, "assumed-role/correlix-observer") {
		t.Fatalf("identity = %+v", ident)
	}

	dec, err := p.SimulatePermissions(context.Background(), probeCreds(),
		IAMPrincipalFromCallerARN(ident.ARN), []string{"ec2:DescribeInstances", "cloudtrail:LookupEvents"})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if !dec["ec2:DescribeInstances"] || dec["cloudtrail:LookupEvents"] {
		t.Fatalf("decisions = %v", dec)
	}
}

func TestAWSProbeDeniedClassification(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>nope</Message></Error></ErrorResponse>`)
	}))
	defer ts.Close()
	p := &AWSProbeClient{Client: ts.Client(), STSEndpoint: ts.URL, IAMEndpoint: ts.URL}
	_, err := p.CallerIdentity(context.Background(), probeCreds(), "")
	var xe *ExchangeError
	if !errors.As(err, &xe) || !xe.Denied() {
		t.Fatalf("want sanitized denied ExchangeError, got %v", err)
	}
	if strings.Contains(err.Error(), "probe-secret") || strings.Contains(err.Error(), "probe-session") {
		t.Fatal("error leaked credential material")
	}
}

func TestIAMPrincipalFromCallerARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::111122223333:assumed-role/observer/sess": "arn:aws:iam::111122223333:role/observer",
		"arn:aws:iam::111122223333:user/bob":                   "arn:aws:iam::111122223333:user/bob",
		"":                                                     "",
	}
	for in, want := range cases {
		if got := IAMPrincipalFromCallerARN(in); got != want {
			t.Errorf("IAMPrincipalFromCallerARN(%q) = %q want %q", in, got, want)
		}
	}
}

func TestAWSAdapterValidateCapabilities(t *testing.T) {
	allowed := map[string]bool{
		"ec2:DescribeInstances": true, "directconnect:DescribeConnections": true,
		"cloudwatch:GetMetricData": true, "cloudwatch:ListMetrics": true,
		"cloudtrail:LookupEvents": false, // denied
		"logs:GetLogEvents":       true, "logs:DescribeLogStreams": true,
		"s3:GetObject": true, "s3:ListBucket": true,
	}
	ts := newAWSQueryFixture(t, false, allowed)
	defer ts.Close()
	pack, _ := Pack("aws-observer-v1")
	a := NewAWSAdapter(nil, &AWSProbeClient{Client: ts.Client(), STSEndpoint: ts.URL, IAMEndpoint: ts.URL})
	tok := ScopedToken{Provider: ProviderAWS, AWS: func() *AWSCredentials { c := probeCreds(); return &c }()}

	report, err := a.ValidateCapabilities(context.Background(), CapabilityCheckRequest{
		Identity: IdentityConfig{Provider: ProviderAWS}, Pack: pack, Scope: Scope{Ref: "123456789012"}, Token: tok,
	})
	if err != nil {
		t.Fatalf("validate capabilities: %v", err)
	}
	if report.AllGranted {
		t.Fatal("AllGranted must be false: cloudtrail:LookupEvents is denied")
	}
	byPerm := map[string]PermissionStatus{}
	for _, p := range report.Permissions {
		byPerm[p.Permission] = p
	}
	if !byPerm["ec2:Describe*"].Granted || !strings.Contains(byPerm["ec2:Describe*"].Detail, "ec2:DescribeInstances") {
		t.Fatalf("wildcard perm not probed via representative: %+v", byPerm["ec2:Describe*"])
	}
	if byPerm["cloudtrail:LookupEvents"].Granted {
		t.Fatal("denied permission reported granted")
	}
	found := false
	for _, f := range report.Findings {
		if f.Code == "permissions_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected permissions_missing finding, got %+v", report.Findings)
	}
}

func TestAWSAdapterValidateCapabilitiesSimulationDenied(t *testing.T) {
	ts := newAWSQueryFixture(t, true, nil)
	defer ts.Close()
	pack, _ := Pack("aws-observer-v1")
	a := NewAWSAdapter(nil, &AWSProbeClient{Client: ts.Client(), STSEndpoint: ts.URL, IAMEndpoint: ts.URL})
	tok := ScopedToken{Provider: ProviderAWS, AWS: func() *AWSCredentials { c := probeCreds(); return &c }()}

	report, err := a.ValidateCapabilities(context.Background(), CapabilityCheckRequest{
		Identity: IdentityConfig{Provider: ProviderAWS}, Pack: pack, Token: tok,
	})
	if err != nil {
		t.Fatalf("simulation-denied must not error the whole check: %v", err)
	}
	if report.AllGranted {
		t.Fatal("AllGranted must be false when unverifiable")
	}
	warn := false
	for _, f := range report.Findings {
		if f.Code == "simulation_denied" {
			warn = true
		}
	}
	if !warn {
		t.Fatalf("expected simulation_denied finding, got %+v", report.Findings)
	}
	for _, p := range report.Permissions {
		if !strings.HasPrefix(p.Detail, "unverified") {
			t.Fatalf("permission %q must be reported unverified, got %+v", p.Permission, p)
		}
	}
}

func TestAWSAdapterProbesDeferWithoutTokenOrProbe(t *testing.T) {
	pack, _ := Pack("aws-observer-v1")
	noProbe := NewAWSAdapter(nil, nil)
	if _, err := noProbe.DiscoverScopes(context.Background(), DiscoverRequest{}); !errors.Is(err, ErrProviderExchangeDeferred) {
		t.Fatalf("no probe: want deferred, got %v", err)
	}
	withProbe := NewAWSAdapter(nil, NewAWSProbeClient())
	if _, err := withProbe.ValidateCapabilities(context.Background(), CapabilityCheckRequest{Pack: pack}); !errors.Is(err, ErrProviderExchangeDeferred) {
		t.Fatalf("no token: want deferred, got %v", err)
	}
}

// ── Azure ─────────────────────────────────────────────────────────────────────

func newARMFixture(t *testing.T, actions, notActions []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer arm-token" {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":{"code":"InvalidAuthenticationToken","message":"bad token"}}`)
			return
		}
		switch {
		case r.URL.Path == "/subscriptions":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{
				{"subscriptionId": "sub-1111", "displayName": "prod", "state": "Enabled"},
				{"subscriptionId": "sub-2222", "displayName": "dev", "state": "Enabled"},
			}})
		case strings.HasSuffix(r.URL.Path, "/providers/Microsoft.Authorization/permissions"):
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
				{"actions": actions, "notActions": notActions},
			}})
		default:
			t.Errorf("unexpected ARM path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
}

func TestAzureProbeSubscriptionsAndPermissions(t *testing.T) {
	ts := newARMFixture(t, []string{"*/read", "Microsoft.Insights/metrics/read"}, nil)
	defer ts.Close()
	p := &AzureARMProbeClient{Client: ts.Client(), BaseURL: ts.URL}

	subs, err := p.Subscriptions(context.Background(), "arm-token")
	if err != nil || len(subs) != 2 || subs[0].SubscriptionID != "sub-1111" {
		t.Fatalf("subscriptions = %+v err=%v", subs, err)
	}
	perms, err := p.Permissions(context.Background(), "arm-token", "sub-1111")
	if err != nil || len(perms) != 1 {
		t.Fatalf("permissions = %+v err=%v", perms, err)
	}
}

func TestAzureActionGranted(t *testing.T) {
	reader := []AzureRBACPermission{{Actions: []string{"*/read"}}}
	cases := []struct {
		perms    []AzureRBACPermission
		required string
		want     bool
	}{
		{reader, "Microsoft.Insights/metrics/read", true},
		{reader, "*/read", true},
		{reader, "Microsoft.Compute/virtualMachines/write", false},
		{[]AzureRBACPermission{{Actions: []string{"*"}}}, "Microsoft.Insights/metrics/read", true},
		{[]AzureRBACPermission{{Actions: []string{"*"}, NotActions: []string{"Microsoft.Insights/*"}}}, "Microsoft.Insights/metrics/read", false},
		{[]AzureRBACPermission{{Actions: []string{"Microsoft.Insights/metrics/read"}}}, "Microsoft.Insights/metrics/read", true},
		{nil, "*/read", false},
	}
	for i, c := range cases {
		if got := AzureActionGranted(c.perms, c.required); got != c.want {
			t.Errorf("case %d: AzureActionGranted(%v, %q) = %v want %v", i, c.perms, c.required, got, c.want)
		}
	}
}

func TestAzureAdapterValidateCapabilities(t *testing.T) {
	// Reader-only grant: inventory (*/read family) is granted; everything in the
	// azure-observer pack is a read action, so */read covers all of it.
	ts := newARMFixture(t, []string{"*/read"}, nil)
	defer ts.Close()
	pack, _ := Pack("azure-observer-v1")
	a := NewAzureAdapter(nil, &AzureARMProbeClient{Client: ts.Client(), BaseURL: ts.URL})

	report, err := a.ValidateCapabilities(context.Background(), CapabilityCheckRequest{
		Identity: IdentityConfig{Provider: ProviderAzure}, Pack: pack,
		Scope: Scope{Type: ScopeSubscription, Ref: "sub-1111"},
		Token: ScopedToken{Provider: ProviderAzure, Value: "arm-token"},
	})
	if err != nil {
		t.Fatalf("validate capabilities: %v", err)
	}
	if !report.AllGranted {
		t.Fatalf("*/read must cover the read-only azure pack: %+v", report.Permissions)
	}

	scopes, err := a.DiscoverScopes(context.Background(), DiscoverRequest{
		Token: ScopedToken{Provider: ProviderAzure, Value: "arm-token"},
	})
	if err != nil || len(scopes) != 2 || scopes[0].Type != ScopeSubscription || !scopes[0].Discovered {
		t.Fatalf("discover = %+v err=%v", scopes, err)
	}
}

func TestAzureProbeDeniedClassification(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization"}}`)
	}))
	defer ts.Close()
	p := &AzureARMProbeClient{Client: ts.Client(), BaseURL: ts.URL}
	_, err := p.Permissions(context.Background(), "arm-token", "sub-1111")
	var xe *ExchangeError
	if !errors.As(err, &xe) || !xe.Denied() {
		t.Fatalf("want denied ExchangeError, got %v", err)
	}
}

// ── GCP ───────────────────────────────────────────────────────────────────────

func newGCPCRMFixture(t *testing.T, granted []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":{"status":"UNAUTHENTICATED","message":"bad token"}}`)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/projects") && strings.HasSuffix(r.URL.Path, ":testIamPermissions"):
			var req struct {
				Permissions []string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if len(req.Permissions) == 0 {
				t.Error("testIamPermissions got no permissions")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"permissions": granted})
		case r.URL.Path == "/v1/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"projects": []map[string]string{
				{"projectId": "prod-proj", "name": "Production"},
			}})
		default:
			t.Errorf("unexpected CRM path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
}

func TestGCPAdapterProbes(t *testing.T) {
	pack, _ := Pack("gcp-observer-v1")
	granted := pack.AllPermissions()[:2] // partial grant
	ts := newGCPCRMFixture(t, granted)
	defer ts.Close()
	a := NewGCPAdapter(nil, &GCPProbeClient{Client: ts.Client(), CRMBase: ts.URL})
	tok := ScopedToken{Provider: ProviderGCP, Value: "gcp-token"}

	scopes, err := a.DiscoverScopes(context.Background(), DiscoverRequest{Token: tok})
	if err != nil || len(scopes) != 1 || scopes[0].Ref != "prod-proj" || scopes[0].Type != ScopeProject {
		t.Fatalf("discover = %+v err=%v", scopes, err)
	}

	report, err := a.ValidateCapabilities(context.Background(), CapabilityCheckRequest{
		Pack: pack, Scope: Scope{Type: ScopeProject, Ref: "prod-proj"}, Token: tok,
	})
	if err != nil {
		t.Fatalf("validate capabilities: %v", err)
	}
	if report.AllGranted {
		t.Fatal("partial grant must not report AllGranted")
	}
	grantedSet := map[string]bool{}
	for _, g := range granted {
		grantedSet[g] = true
	}
	for _, p := range report.Permissions {
		if p.Granted != grantedSet[p.Permission] {
			t.Fatalf("permission %q granted=%v want %v", p.Permission, p.Granted, grantedSet[p.Permission])
		}
	}
}

func TestGCPProbeDeniedClassification(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":{"status":"PERMISSION_DENIED","message":"forbidden"}}`)
	}))
	defer ts.Close()
	p := &GCPProbeClient{Client: ts.Client(), CRMBase: ts.URL}
	_, err := p.TestPermissions(context.Background(), "gcp-token", "prod-proj", []string{"compute.instances.list"})
	var xe *ExchangeError
	if !errors.As(err, &xe) || !xe.Denied() {
		t.Fatalf("want denied ExchangeError, got %v", err)
	}
}
