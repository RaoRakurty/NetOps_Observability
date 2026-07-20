package main

// cloud_connectors_probe_live_test.go — Wave 4 #13: end-to-end tests for LIVE
// permission validation + scope discovery through the real stack: router +
// auth → handlers → Identity Broker → cloudconn AWS adapter → httptest
// STS/IAM fixture. Also asserts the per-permission denials land on the
// source-status surface, that a poller flush cannot erase them, and the §3a
// cross-tenant isolation of the new live surfaces.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netops/backend/cloudconn"
)

// newAWSProbeFixture serves AssumeRole + GetCallerIdentity + SimulatePrincipalPolicy
// on ONE endpoint, switching on the Query API Action.
func newAWSProbeFixture(t *testing.T, allowed map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch form.Get("Action") {
		case "AssumeRole":
			expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
			_, _ = io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>
				<AccessKeyId>ASIALIVE</AccessKeyId><SecretAccessKey>liveSecret</SecretAccessKey>
				<SessionToken>liveSessionToken</SessionToken><Expiration>`+expiry+`</Expiration>
				</Credentials></AssumeRoleResult></AssumeRoleResponse>`)
		case "GetCallerIdentity":
			_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult>
				<Arn>arn:aws:sts::123456789012:assumed-role/correlix-observer/sess</Arn>
				<UserId>AROAX:sess</UserId><Account>123456789012</Account>
				</GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case "SimulatePrincipalPolicy":
			var members strings.Builder
			for i := 1; ; i++ {
				act := form.Get("ActionNames.member." + itoaTest(i))
				if act == "" {
					break
				}
				decision := "implicitDeny"
				if allowed[act] {
					decision = "allowed"
				}
				members.WriteString("<member><EvalActionName>" + act + "</EvalActionName><EvalDecision>" + decision + "</EvalDecision></member>")
			}
			_, _ = io.WriteString(w, `<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults>`+
				members.String()+`</EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`)
		default:
			w.WriteHeader(400)
		}
	}))
}

// wireProbeBroker wires the broker to the REAL AWS adapter with both the
// exchanger and the probe client pointed at the fixture.
func wireProbeBroker(s *server, fixture *httptest.Server) {
	s.cloudConn = newMemCloudConnStore()
	s.cloudBroker = newCloudIdentityBroker(s.cloudConn, s.vault, nil)
	ex := &cloudconn.AWSSTSExchanger{Client: fixture.Client(), Endpoint: fixture.URL, Platform: testPlatformCreds{}}
	probe := &cloudconn.AWSProbeClient{Client: fixture.Client(), STSEndpoint: fixture.URL, IAMEndpoint: fixture.URL}
	s.cloudBroker.adapter = func(p cloudconn.Provider) cloudconn.CloudIdentityProvider {
		if p != cloudconn.ProviderAWS {
			return nil
		}
		return cloudconn.NewAWSAdapter(ex, probe)
	}
	if s.cloudSourceStatus == nil {
		s.cloudSourceStatus = newCloudSourceStatusStore()
	}
}

type permsResp struct {
	CapabilityPack      string                      `json:"capability_pack"`
	RequiredPermissions []string                    `json:"required_permissions"`
	LiveCheck           string                      `json:"live_check"`
	Report              *cloudconn.CapabilityReport `json:"report"`
	Note                string                      `json:"note"`
	Error               string                      `json:"error"`
}

func TestCloudConnectorLivePermissionsAndSourceStatus(t *testing.T) {
	allowed := map[string]bool{
		"ec2:DescribeInstances": true, "directconnect:DescribeConnections": true,
		"cloudwatch:GetMetricData": true, "cloudwatch:ListMetrics": true,
		"logs:GetLogEvents": true, "logs:DescribeLogStreams": true,
		"s3:GetObject": true, "s3:ListBucket": true,
		// cloudtrail:LookupEvents deliberately DENIED → change_audit chip.
	}
	fixture := newAWSProbeFixture(t, allowed)
	defer fixture.Close()
	srv, s := newTestServerState(t)
	wireProbeBroker(s, fixture)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)

	// Move the connector into a token-exchangeable state first.
	if st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil); st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/permissions", admin, nil)
	if st != 200 {
		t.Fatalf("permissions: %d %s", st, b)
	}
	var pr permsResp
	if err := json.Unmarshal(b, &pr); err != nil {
		t.Fatal(err)
	}
	if pr.LiveCheck != "ok" {
		t.Fatalf("live_check = %q (note=%q error=%q)", pr.LiveCheck, pr.Note, pr.Error)
	}
	if pr.Report == nil || pr.Report.AllGranted {
		t.Fatalf("report must show the cloudtrail denial: %+v", pr.Report)
	}
	denied := 0
	for _, p := range pr.Report.Permissions {
		if !p.Granted {
			denied++
			if p.Permission != "cloudtrail:LookupEvents" {
				t.Fatalf("unexpected denial: %+v", p)
			}
		}
	}
	if denied != 1 {
		t.Fatalf("want exactly 1 denied permission, got %d", denied)
	}
	// No credential material leaks through the API response.
	if strings.Contains(string(b), "liveSessionToken") || strings.Contains(string(b), "liveSecret") {
		t.Fatal("permissions response leaked credential material")
	}

	// The denial landed on the source-status surface, on the OWNING tenant,
	// on the change_audit chip.
	recs := s.cloudSourceStatus.ForTenant(TenantGlobal, false, time.Now().UTC())
	found := false
	for _, rec := range recs {
		if rec.SourceType == "change_audit" && rec.Status == "permission_denied" &&
			rec.ConnectorID == id && strings.Contains(rec.Detail, "cloudtrail:LookupEvents") {
			found = true
		}
		if rec.SourceType == "inventory" {
			t.Fatalf("fully-granted capability must not be flagged: %+v", rec)
		}
	}
	if !found {
		t.Fatalf("permission denial not recorded in source status: %+v", recs)
	}

	// A poller full-set flush must NOT erase the validate-origin record.
	s.cloudSourceStatus.Replace([]cloudSourceStatusRecord{}, time.Now().UTC())
	recs = s.cloudSourceStatus.ForTenant(TenantGlobal, false, time.Now().UTC())
	if len(recs) != 1 || recs[0].SourceType != "change_audit" {
		t.Fatalf("validate record erased by poller replace: %+v", recs)
	}

	// Re-running with the permission now granted clears the record.
	allowed["cloudtrail:LookupEvents"] = true
	if st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/permissions", admin, nil); st != 200 {
		t.Fatalf("permissions rerun: %d %s", st, b)
	}
	recs = s.cloudSourceStatus.ForTenant(TenantGlobal, false, time.Now().UTC())
	if len(recs) != 0 {
		t.Fatalf("granted permission must clear its record: %+v", recs)
	}
}

func TestCloudConnectorLiveDiscoverScopes(t *testing.T) {
	fixture := newAWSProbeFixture(t, nil)
	defer fixture.Close()
	srv, s := newTestServerState(t)
	wireProbeBroker(s, fixture)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)
	if st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil); st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/discover-scopes", admin, nil)
	if st != 200 {
		t.Fatalf("discover-scopes: %d %s", st, b)
	}
	var dr struct {
		LiveCheck  string            `json:"live_check"`
		Discovered []cloudconn.Scope `json:"discovered"`
	}
	if err := json.Unmarshal(b, &dr); err != nil {
		t.Fatal(err)
	}
	if dr.LiveCheck != "ok" {
		t.Fatalf("live_check = %q body=%s", dr.LiveCheck, b)
	}
	if len(dr.Discovered) != 1 || dr.Discovered[0].Ref != "123456789012" || !dr.Discovered[0].Discovered {
		t.Fatalf("discovered = %+v", dr.Discovered)
	}
}

func TestCloudConnectorProbesDeferredWithoutPlatformIdentity(t *testing.T) {
	fixture := newAWSProbeFixture(t, nil)
	defer fixture.Close()
	srv, s := newTestServerState(t)
	s.cloudConn = newMemCloudConnStore()
	s.cloudBroker = newCloudIdentityBroker(s.cloudConn, s.vault, nil)
	ex := &cloudconn.AWSSTSExchanger{Client: fixture.Client(), Endpoint: fixture.URL,
		Platform: testPlatformCreds{err: cloudconn.ErrPlatformCredentialsMissing}}
	s.cloudBroker.adapter = func(p cloudconn.Provider) cloudconn.CloudIdentityProvider {
		return cloudconn.NewAWSAdapter(ex, nil)
	}
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)
	if st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil); st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/permissions", admin, nil)
	if st != 200 {
		t.Fatalf("permissions: %d %s", st, b)
	}
	var pr permsResp
	if err := json.Unmarshal(b, &pr); err != nil {
		t.Fatal(err)
	}
	if pr.LiveCheck != "deferred" {
		t.Fatalf("live_check = %q want deferred (deferral is never a failure)", pr.LiveCheck)
	}
	if len(pr.RequiredPermissions) == 0 {
		t.Fatal("deferred response must still list the required permissions")
	}
}

// §3a isolation: the live probe surfaces are tenant-scoped — another tenant's
// admin gets 404 for the connector id, never a probe run.
func TestCloudConnectorProbeIsolation(t *testing.T) {
	fixture := newAWSProbeFixture(t, nil)
	defer fixture.Close()
	srv, s := newTestServerState(t)
	wireProbeBroker(s, fixture)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)

	// A tenant-scoped operator in another org/tenant.
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Probe Iso Org"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Probe Iso Tenant", "org_id": orgID})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tid := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "probe-iso-op", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tid,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	other := login(t, srv, "probe-iso-op", "Passw0rd!2345").Token
	for _, action := range []string{"permissions", "discover-scopes"} {
		st, _ := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/"+action, other, nil)
		if st != http.StatusNotFound {
			t.Fatalf("%s cross-tenant: got %d want 404", action, st)
		}
	}
}
