package ticketing

// caseconn_cisco_test.go — Cisco's two halves against fake CXD and Smart
// Bonding servers. The assertions are on the documented wire shape: the CXD
// PUT's path and Basic-auth pair, and the create response's Field80/Field81
// closing the loop back into an attach.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/ticketing/vendors/cisco"
)

type ciscoFakes struct {
	cxd, sb *httptest.Server

	cxdMethod   string
	cxdPath     string
	cxdUser     string
	cxdPass     string
	cxdBody     []byte
	cxdStatus   int
	cxdCalls    int
	sbPath      string
	sbBody      map[string]any
	sbAuth      string
	sbResponse  string
	sbStatus    int
	tokenCalls  int
	tokenServer *httptest.Server
}

func newCiscoFakes(t *testing.T) *ciscoFakes {
	t.Helper()
	f := &ciscoFakes{cxdStatus: http.StatusOK, sbStatus: http.StatusOK}
	f.cxd = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.cxdCalls++
		f.cxdMethod, f.cxdPath = r.Method, r.URL.Path
		f.cxdUser, f.cxdPass, _ = r.BasicAuth()
		f.cxdBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(f.cxdStatus)
	}))
	f.sb = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sbPath = r.URL.Path
		f.sbAuth = r.Header.Get("Authorization")
		f.sbBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&f.sbBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.sbStatus)
		body := f.sbResponse
		if body == "" {
			body = `{"srNumber":"695123456","Field80":"cxd.cisco.com","Field81":"per-case-token"}`
		}
		_, _ = io.WriteString(w, body)
	}))
	f.tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"sb-access-token","expires_in":3600}`)
	}))
	t.Cleanup(func() { f.cxd.Close(); f.sb.Close(); f.tokenServer.Close() })
	return f
}

func (f *ciscoFakes) client() *cisco.Client {
	return cisco.NewForTest(f.cxd.Client(), f.sb.URL, f.cxd.URL)
}

func ciscoCfg() TACConnectorConfig {
	return TACConnectorConfig{Cisco: CiscoConnectorConfig{Enabled: true}}
}

func TestCiscoCXDPutsToTheDocumentedPathWithSRAndTokenAsBasicAuth(t *testing.T) {
	f := newCiscoFakes(t)
	c := NewCiscoCXDConnector(f.client())

	res, err := c.AttachBundle(context.Background(), ciscoCfg(),
		CaseRef{Number: "695123456", UploadToken: "per-case-token"}, testBundle("show-tech.zip", 128))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if f.cxdMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", f.cxdMethod)
	}
	if f.cxdPath != "/home/show-tech.zip" {
		t.Errorf("path = %q, want /home/<file>", f.cxdPath)
	}
	// Basic auth = SR number as user, per-case token as password.
	if f.cxdUser != "695123456" || f.cxdPass != "per-case-token" {
		t.Errorf("basic auth = %q/%q, want the SR number and the case token", f.cxdUser, f.cxdPass)
	}
	if len(f.cxdBody) != 128 {
		t.Errorf("uploaded %d bytes, want 128", len(f.cxdBody))
	}
	if res.Transport != "cisco-cxd" || res.ID != "695123456" {
		t.Errorf("result = %+v", res)
	}
}

func TestCiscoCXDDeclaresAttachToExistingOnlyAndNoDocumentedLimit(t *testing.T) {
	c := NewCiscoCXDConnector(nil)
	caps := c.Capabilities()
	if caps.Create {
		t.Error("CXD cannot open a case")
	}
	if !caps.Attach || !caps.AttachToExistingOnly {
		t.Error("CXD is attach-to-existing, which is a first-class mode")
	}
	if caps.MaxAttachBytes != 0 {
		t.Errorf("MaxAttachBytes = %d, want 0 meaning no documented limit", caps.MaxAttachBytes)
	}
	// 0 still gets a local runaway guard rather than being unbounded.
	if caps.AttachLimit() != NoDocumentedLimitGuard {
		t.Errorf("AttachLimit = %d, want the local guard", caps.AttachLimit())
	}
	if _, err := c.CreateCase(context.Background(), ciscoCfg(), CaseRequest{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("create = %v, want ErrUnsupported", err)
	}
	if len(caps.SeverityValues) != 4 {
		t.Errorf("Cisco publishes S1–S4; got %d values", len(caps.SeverityValues))
	}
}

func TestCiscoCXDRequiresBothTheSRNumberAndTheToken(t *testing.T) {
	f := newCiscoFakes(t)
	c := NewCiscoCXDConnector(f.client())
	for _, tc := range []struct {
		name string
		ref  CaseRef
		want string
	}{
		{"no SR", CaseRef{UploadToken: "tok"}, "SR number"},
		{"no token", CaseRef{Number: "695123456"}, "upload token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.AttachBundle(context.Background(), ciscoCfg(), tc.ref, testBundle("b.zip", 8))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if f.cxdCalls != 0 {
				t.Error("an incomplete reference must not reach CXD")
			}
		})
	}
}

func TestCiscoCXDRefusesAnUploadHostOffThePinnedList(t *testing.T) {
	// A create response (or a tampered one) naming another host must not
	// redirect the upload. Use a production client so the pinning applies.
	c := NewCiscoCXDConnector(&cisco.Client{HTTP: http.DefaultClient})
	_, err := c.AttachBundle(context.Background(), ciscoCfg(),
		CaseRef{Number: "695123456", UploadToken: "tok", UploadHost: "evil.example.com"},
		testBundle("b.zip", 8))
	if err == nil || !strings.Contains(err.Error(), cisco.CXDHost) {
		t.Fatalf("err = %v, want a refusal naming the pinned host", err)
	}
}

func TestCiscoSmartBondingCreateClosesTheLoopIntoCXD(t *testing.T) {
	f := newCiscoFakes(t)
	c := NewCiscoSmartBondingConnector(f.client())
	cfg := TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true, CCOID: "cco-1",
		CustomerSourceID: "src-1", ClientID: "cid", ClientSecret: "csec",
		FieldMap: fullCiscoFieldMap(),
	}}
	// The OAuth host is PINNED, so a test server can never stand in for it —
	// which is itself the property worth asserting.
	if err := validatePinnedURL(f.tokenServer.URL, ciscoHostAllowlist("")); err == nil {
		t.Fatal("a non-Cisco token host must be refused by the pinned allowlist")
	}

	// Drive the vendor client directly to prove the wire contract, then assert
	// the connector's mapping of that response.
	out, err := f.client().CreateCase(context.Background(), "sb-access-token", cisco.CreateRequest{
		Entitlement:                 cisco.Entitlement{CCOID: "cco-1", SerialNumber: "FDO123"},
		CustomerUniqueTransactionID: "txn-1",
		Fields:                      map[string]string{"caseSynopsis": "OSPF adjacency stuck"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if f.sbPath != cisco.PushPath {
		t.Errorf("path = %q, want %q", f.sbPath, cisco.PushPath)
	}
	if f.sbBody["customerUniqueTransactionID"] != "txn-1" {
		t.Errorf("the idempotency key must ride as customerUniqueTransactionID, got %v", f.sbBody)
	}
	if out.SRNumber != "695123456" || out.CXDHost != "cxd.cisco.com" || out.CXDToken != "per-case-token" {
		t.Fatalf("create response = %+v, want Field80/Field81 mapped to the CXD host and token", out)
	}
	// Those ephemeral values then feed the attach without a second prompt.
	if _, err := c.AttachBundle(context.Background(), cfg,
		CaseRef{Number: out.SRNumber, UploadHost: out.CXDHost, UploadToken: out.CXDToken},
		testBundle("b.zip", 16)); err != nil {
		t.Fatalf("attach after create: %v", err)
	}
	if f.cxdUser != "695123456" || f.cxdPass != "per-case-token" {
		t.Errorf("the create response's token was not used for the attach")
	}
}

// fullCiscoFieldMap binds every canonical field, as a completed onboarding
// project would.
func fullCiscoFieldMap() map[string]string {
	m := map[string]string{}
	for _, f := range ciscoCanonicalFields {
		m[f] = "vendorField_" + f
	}
	return m
}

func TestCiscoSmartBondingFailsClosedWithoutTheOnboardingFieldMap(t *testing.T) {
	f := newCiscoFakes(t)
	c := NewCiscoSmartBondingConnector(f.client())
	cfg := TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true, CCOID: "cco-1",
		CustomerSourceID: "src-1", ClientID: "cid", ClientSecret: "csec",
		// no FieldMap: Cisco does not publish the push/call request schema
	}}
	err := c.ValidateConfig(cfg)
	if !errors.Is(err, ErrNotOnboarded) {
		t.Fatalf("err = %v, want ErrNotOnboarded rather than a guessed schema", err)
	}
	if !strings.Contains(err.Error(), "synopsis") {
		t.Errorf("the refusal should name the unbound fields, got %v", err)
	}
	if _, cerr := c.CreateCase(context.Background(), cfg, CaseRequest{
		Approval: Approval{Actor: "user:1", ApprovedAt: time.Now()},
	}); !errors.Is(cerr, ErrNotOnboarded) {
		t.Fatalf("create = %v, want the same fail-closed answer", cerr)
	}
	if retryable(err) {
		t.Error("an un-onboarded connector must not be retried")
	}
}

func TestCiscoEntitlementIsValidatedLocallyBeforeAnyCall(t *testing.T) {
	for _, tc := range []struct {
		name string
		ent  cisco.Entitlement
		ok   bool
	}{
		{"serial only, with CCO", cisco.Entitlement{CCOID: "c", SerialNumber: "FDO1"}, true},
		{"contract + PID, with CCO", cisco.Entitlement{CCOID: "c", ContractID: "K1", PID: "N9K"}, true},
		{"contract without PID", cisco.Entitlement{CCOID: "c", ContractID: "K1"}, false},
		{"no CCO-ID", cisco.Entitlement{SerialNumber: "FDO1"}, false},
		{"nothing", cisco.Entitlement{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ent.Validate()
			if tc.ok != (err == nil) {
				t.Fatalf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestCiscoSmartBondingRequiresHumanApproval(t *testing.T) {
	f := newCiscoFakes(t)
	c := NewCiscoSmartBondingConnector(f.client())
	cfg := TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true, CCOID: "cco-1", CustomerSourceID: "src-1",
		ClientID: "cid", ClientSecret: "csec", FieldMap: fullCiscoFieldMap(),
	}}
	_, err := c.CreateCase(context.Background(), cfg, CaseRequest{
		Synopsis: "x", SerialNumber: "FDO1", IdempotencyKey: "txn-1",
	})
	if !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}
}

func TestCiscoStagingHostMustBeOnCiscoCom(t *testing.T) {
	base := CiscoConnectorConfig{Enabled: true}
	base.StagingHost = "sb-staging.attacker.example"
	if err := validateCiscoConfig(base); err == nil {
		t.Fatal("an off-Cisco staging host must be refused")
	}
	// The published production host is always allowed.
	if got := ciscoHostAllowlist(""); len(got) != 3 {
		t.Errorf("allowlist = %v, want exactly the three published Cisco hosts", got)
	}
	if got := ciscoHostAllowlist("sb-test.cisco.com"); len(got) != 4 {
		t.Errorf("a validated staging host should extend the allowlist, got %v", got)
	}
}

func TestCiscoVendorErrorSurfacesVerbatim(t *testing.T) {
	f := newCiscoFakes(t)
	f.sbResponse = `{"errorCode":"E-ENT-01","errorMessage":"Contract expired for serial FDO123"}`
	_, err := f.client().CreateCase(context.Background(), "tok", cisco.CreateRequest{
		Entitlement: cisco.Entitlement{CCOID: "c", SerialNumber: "FDO123"}, CustomerUniqueTransactionID: "t1",
	})
	translated := translateCiscoError(err)
	var ent EntitlementError
	if !errors.As(translated, &ent) {
		t.Fatalf("err = %v, want EntitlementError", translated)
	}
	if !strings.Contains(ent.VendorMsg, "Contract expired") {
		t.Errorf("the vendor's own words must survive: %q", ent.VendorMsg)
	}
	if retryable(translated) {
		t.Error("an entitlement refusal must not be retried")
	}
}
