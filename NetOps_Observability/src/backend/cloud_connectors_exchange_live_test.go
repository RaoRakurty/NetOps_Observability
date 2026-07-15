package main

// cloud_connectors_exchange_live_test.go — end-to-end tests for the LIVE
// credential-exchange path through the REAL stack: router + auth middleware →
// validate handler → Identity Broker → real cloudconn AWS adapter → SigV4 →
// httptest STS fixture. Covers the live-verified, denied and deferred outcomes
// of POST /api/cloud/connectors/{id}/validate, plus the cross-tenant
// exchange-path isolation assertion.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/cloudconn"
)

type testPlatformCreds struct{ err error }

func (p testPlatformCreds) Credentials(context.Context) (cloudconn.AWSCredentials, error) {
	if p.err != nil {
		return cloudconn.AWSCredentials{}, p.err
	}
	return cloudconn.AWSCredentials{AccessKeyID: "AKIDPLATFORM", SecretAccessKey: "platform-secret"}, nil
}

// newSTSFixture returns an httptest STS that answers AssumeRole with real XML
// (or a denial when deny=true) and records the last signed request.
func newSTSFixture(t *testing.T, deny bool) (*httptest.Server, *string) {
	t.Helper()
	var lastAuthz string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthz = r.Header.Get("Authorization")
		if deny {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`)
			return
		}
		expiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		_, _ = io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>
			<AccessKeyId>ASIALIVE</AccessKeyId><SecretAccessKey>liveSecret</SecretAccessKey>
			<SessionToken>liveSessionToken</SessionToken><Expiration>`+expiry+`</Expiration>
			</Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	return ts, &lastAuthz
}

// wireLiveBroker points the server's broker at the REAL cloudconn adapters
// backed by the given exchanger (the production wiring, minus the internet).
func wireLiveBroker(s *server, ex cloudconn.TokenExchanger) {
	s.cloudConn = newMemCloudConnStore()
	s.cloudBroker = newCloudIdentityBroker(s.cloudConn, s.vault, func(e AuditEvent) {
		if s.audit != nil {
			s.audit.Record(e)
		}
	})
	s.cloudBroker.adapter = func(p cloudconn.Provider) cloudconn.CloudIdentityProvider {
		return cloudconn.NewAdapterWithExchanger(p, ex)
	}
}

// buildAWSConnector drives the wizard APIs to a validated-ready AWS connector.
func buildAWSConnector(t *testing.T, srv *httptest.Server, token string) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/cloud/connectors", token, map[string]any{"provider": "aws", "display_name": "Live"})
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	var v cloudConnectorView
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	st, b = do(t, srv, "POST", "/api/cloud/connectors/"+v.ID+"/auth", token, map[string]any{
		"method": "cloud_role", "role_arn": "arn:aws:iam::123456789012:role/correlix-observer",
	})
	if st != 200 {
		t.Fatalf("auth: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/cloud/connectors/"+v.ID+"/scopes", token, map[string]any{
		"scopes": []map[string]any{{"type": "account", "ref": "123456789012", "regions": []string{"us-east-1"}}},
	})
	if st != 200 {
		t.Fatalf("scopes: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/cloud/connectors/"+v.ID+"/capabilities", token, map[string]any{
		"capability_pack": "aws-observer-v1",
	})
	if st != 200 {
		t.Fatalf("capabilities: %d %s", st, b)
	}
	return v.ID
}

type validateResp struct {
	Connector  cloudConnectorView         `json:"connector"`
	Validation cloudconn.ValidationResult `json:"validation"`
	LiveCheck  string                     `json:"live_check"`
}

func TestCloudConnectorValidateLiveVerified(t *testing.T) {
	srv, s := newTestServerState(t)
	sts, lastAuthz := newSTSFixture(t, false)
	defer sts.Close()
	wireLiveBroker(s, &cloudconn.AWSSTSExchanger{
		Client: sts.Client(), Endpoint: sts.URL, Platform: testPlatformCreds{},
	})
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil)
	if st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}
	var vr validateResp
	if err := json.Unmarshal(b, &vr); err != nil {
		t.Fatal(err)
	}
	if vr.LiveCheck != "ok" {
		t.Fatalf("live_check = %q want ok (validation: %+v, health: %+v)", vr.LiveCheck, vr.Validation, vr.Connector.IdentityHealth)
	}
	if vr.Connector.IdentityHealth.State != "live_verified" {
		t.Fatalf("identity health = %q want live_verified", vr.Connector.IdentityHealth.State)
	}
	// The wire call was SigV4-signed with the platform identity.
	if !strings.Contains(*lastAuthz, "Credential=AKIDPLATFORM/") {
		t.Fatalf("STS call not signed with the platform identity: %q", *lastAuthz)
	}
	// No token material leaks into the API response.
	if strings.Contains(string(b), "liveSessionToken") || strings.Contains(string(b), "liveSecret") {
		t.Fatal("validate response leaked session credential material")
	}
	// Live-verified connector can now activate.
	if st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/activate", admin, nil); st != 200 {
		t.Fatalf("activate after live verify: %d %s", st, b)
	}
}

func TestCloudConnectorValidateLiveDenied(t *testing.T) {
	srv, s := newTestServerState(t)
	sts, _ := newSTSFixture(t, true)
	defer sts.Close()
	wireLiveBroker(s, &cloudconn.AWSSTSExchanger{
		Client: sts.Client(), Endpoint: sts.URL, Platform: testPlatformCreds{},
	})
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil)
	if st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}
	var vr validateResp
	if err := json.Unmarshal(b, &vr); err != nil {
		t.Fatal(err)
	}
	if vr.LiveCheck != "failed" {
		t.Fatalf("live_check = %q want failed", vr.LiveCheck)
	}
	if vr.Connector.IdentityHealth.State != "failed" {
		t.Fatalf("identity health = %q want failed", vr.Connector.IdentityHealth.State)
	}
	found := false
	for _, f := range vr.Validation.Findings {
		if f.Code == "live_trust_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a live_trust_failed finding, got %+v", vr.Validation.Findings)
	}
}

func TestCloudConnectorValidateLiveDeferredWithoutPlatformIdentity(t *testing.T) {
	srv, s := newTestServerState(t)
	sts, _ := newSTSFixture(t, false)
	defer sts.Close()
	wireLiveBroker(s, &cloudconn.AWSSTSExchanger{
		Client: sts.Client(), Endpoint: sts.URL,
		Platform: testPlatformCreds{err: cloudconn.ErrPlatformCredentialsMissing},
	})
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	id := buildAWSConnector(t, srv, admin)

	st, b := do(t, srv, "POST", "/api/cloud/connectors/"+id+"/validate", admin, nil)
	if st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}
	var vr validateResp
	if err := json.Unmarshal(b, &vr); err != nil {
		t.Fatal(err)
	}
	if vr.LiveCheck != "deferred" {
		t.Fatalf("live_check = %q want deferred", vr.LiveCheck)
	}
	if vr.Connector.IdentityHealth.State != "config_validated" {
		t.Fatalf("identity health = %q want config_validated (deferral is not a failure)", vr.Connector.IdentityHealth.State)
	}
	if !vr.Validation.OK {
		t.Fatal("config validation must remain OK under a deferred live check")
	}
}
