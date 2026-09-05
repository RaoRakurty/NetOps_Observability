package ticketing

// caseconn_juniper_test.go — the Service Case API against a fake gateway that
// also plays the S3 bucket, so the whole three-step attach flow
// (getfileuploadtoken → SigV4 PUT → attachfile) runs end to end and the
// signature is inspected on the way through.

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

	"netops/backend/internal/ticketing/vendors/juniper"
)

type juniperFake struct {
	srv *httptest.Server

	createBody map[string]any
	attachBody map[string]any
	tokenBody  map[string]any
	s3Method   string
	s3Auth     string
	s3AmzDate  string
	s3AmzHash  string
	s3Token    string
	s3Body     []byte
	lovCalls   int

	createResp string
	tokenResp  string
	attachResp string
	status     int
}

func newJuniperFake(t *testing.T) *juniperFake {
	t.Helper()
	f := &juniperFake{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decode := func() map[string]any {
			m := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&m)
			return m
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case juniper.PathCreateSR:
			f.createBody = decode()
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, orDefault(f.createResp, `{"srNumber":"2026-0905-1234"}`))
		case juniper.PathGetFileUploadToken:
			f.tokenBody = decode()
			_, _ = io.WriteString(w, orDefault(f.tokenResp,
				`{"accessKeyId":"ASIA-TEST","secretAccessKey":"sek","sessionToken":"sts-session","region":"us-west-2","bucket":"jnpr-uploads","key":"uploads/bundle.zip","documentPath":"uploads/bundle.zip"}`))
		case juniper.PathAttachFile:
			f.attachBody = decode()
			_, _ = io.WriteString(w, orDefault(f.attachResp, `{"srNumber":"2026-0905-1234"}`))
		case juniper.PathQuerySRDetails:
			_, _ = io.WriteString(w, `{"srNumber":"2026-0905-1234","status":"Open","lastUpdatedDate":"2026-09-05T10:00:00Z"}`)
		case juniper.PathGetLOV:
			f.lovCalls++
			_, _ = io.WriteString(w, `{"values":["P1","P2","P3","P4"]}`)
		case juniper.TokenPath:
			_, _ = io.WriteString(w, `{"access_token":"jnpr-token","expires_in":3600}`)
		default: // the S3 object PUT
			f.s3Method = r.Method
			f.s3Auth = r.Header.Get("Authorization")
			f.s3AmzDate = r.Header.Get("X-Amz-Date")
			f.s3AmzHash = r.Header.Get("X-Amz-Content-Sha256")
			f.s3Token = r.Header.Get("X-Amz-Security-Token")
			f.s3Body, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *juniperFake) client() *juniper.Client {
	return juniper.NewForTest(f.srv.Client(), f.srv.URL)
}

func juniperCfg() TACConnectorConfig {
	return TACConnectorConfig{Juniper: JuniperConnectorConfig{
		Enabled: true, AppID: "app-1", CustomerSourceID: "src-1", UserID: "jdoe",
		AccountID: "acct-1", AuthMode: "apikey", APIKey: "jnpr-api-key",
		DefaultContactEmail: "jane.doe@customer.example",
	}}
}

func approvedJuniperRequest() CaseRequest {
	return CaseRequest{
		Synopsis:       "OSPF adjacency stuck in ExStart on ae0",
		Description:    "Evidence-only problem statement.",
		Severity:       "P2",
		ContactEmail:   "jane.doe@customer.example",
		SerialNumber:   "JN123456",
		Fields:         map[string]string{"software_version": "22.4R3-S2", "case_type_code": "TEC"},
		IdempotencyKey: "txn-abc",
		Approval:       Approval{Actor: "user:42", ApprovedAt: time.Now()},
	}
}

func TestJuniperCreateSendsOnlyDocumentedFieldNames(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())

	ref, err := c.CreateCase(context.Background(), juniperCfg(), approvedJuniperRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.Number != "2026-0905-1234" {
		t.Errorf("ref = %+v", ref)
	}
	want := map[string]string{
		"appId": "app-1", "customerSourceID": "src-1", "userId": "jdoe", "accountID": "acct-1",
		"priority": "P2", "contactEmail": "jane.doe@customer.example",
		"softwareVersion": "22.4R3-S2", "caseTypeCode": "TEC",
		"customerUniqueTransactionID": "txn-abc", "serialNumber": "JN123456",
	}
	for k, v := range want {
		if got, _ := f.createBody[k].(string); got != v {
			t.Errorf("createsr[%q] = %v, want %q", k, f.createBody[k], v)
		}
	}
	// networkOutage applies to P1 technical SRs only: unset must stay ABSENT,
	// not sent as false.
	if _, present := f.createBody["networkOutage"]; present {
		t.Error("networkOutage must be omitted when the operator did not set it")
	}
}

func TestJuniperEnforcesTheDocumentedTextCaps(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())
	req := approvedJuniperRequest()
	req.Synopsis = strings.Repeat("x", juniper.MaxSynopsis+1)
	if _, err := c.CreateCase(context.Background(), juniperCfg(), req); err == nil ||
		!strings.Contains(err.Error(), "synopsis") {
		t.Fatalf("err = %v, want the synopsis cap enforced locally", err)
	}
	req = approvedJuniperRequest()
	req.Description = strings.Repeat("y", juniper.MaxProblemDescription+1)
	if _, err := c.CreateCase(context.Background(), juniperCfg(), req); err == nil ||
		!strings.Contains(err.Error(), "problemDescription") {
		t.Fatalf("err = %v, want the problemDescription cap enforced locally", err)
	}
}

func TestJuniperRefusesAnAliasContactEmail(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())
	req := approvedJuniperRequest()
	req.ContactEmail = "noc@customer.example"
	_, err := c.CreateCase(context.Background(), juniperCfg(), req)
	if err == nil || !strings.Contains(err.Error(), "real person") {
		t.Fatalf("err = %v, want the named-human rule enforced", err)
	}
	if f.createBody != nil {
		t.Error("an alias contact must not reach the vendor")
	}
	if retryable(err) {
		t.Error("a rejected contact is permanent")
	}
}

func TestJuniperRequiresSoftwareVersionAndApproval(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())

	req := approvedJuniperRequest()
	req.Approval = Approval{}
	if _, err := c.CreateCase(context.Background(), juniperCfg(), req); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}

	req = approvedJuniperRequest()
	delete(req.Fields, "software_version")
	if _, err := c.CreateCase(context.Background(), juniperCfg(), req); err == nil ||
		!strings.Contains(err.Error(), "softwareVersion") {
		t.Fatalf("err = %v, want the 2024-05-16 mandatory field enforced", err)
	}
}

func TestJuniperEntitlementErrorsAreSurfacedVerbatim(t *testing.T) {
	f := newJuniperFake(t)
	f.createResp = `{"errorCode":"607","errorMessage":"Warranty only - please open a Technical SR via other channels"}`
	c := NewJuniperConnector(f.client())

	_, err := c.CreateCase(context.Background(), juniperCfg(), approvedJuniperRequest())
	var ent EntitlementError
	if !errors.As(err, &ent) {
		t.Fatalf("err = %v, want EntitlementError for a 600–614 code", err)
	}
	if ent.Code != "607" || !strings.Contains(ent.VendorMsg, "Warranty only") {
		t.Errorf("entitlement error = %+v, want Juniper's own words", ent)
	}
	if retryable(err) {
		t.Error("an entitlement refusal must not be retried")
	}
	// A code outside the class is NOT an entitlement failure.
	if juniper.IsEntitlementCode("599") || juniper.IsEntitlementCode("615") {
		t.Error("the entitlement class is 600–614 inclusive")
	}
	if !juniper.IsEntitlementCode("600") || !juniper.IsEntitlementCode("614") {
		t.Error("600 and 614 are in the class")
	}
}

func TestJuniperAttachRunsTheThreeStepFlowWithASignedS3Put(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())

	res, err := c.AttachBundle(context.Background(), juniperCfg(),
		CaseRef{Number: "2026-0905-1234"}, testBundle("bundle.zip", 256))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	// 1. the upload token was requested with the documented inputs
	if f.tokenBody["srNumber"] != "2026-0905-1234" || f.tokenBody["fileName"] != "bundle.zip" {
		t.Errorf("getfileuploadtoken body = %v", f.tokenBody)
	}
	// 2. the object was PUT, signed with SigV4 and the STS session token
	if f.s3Method != http.MethodPut {
		t.Errorf("S3 method = %q, want PUT", f.s3Method)
	}
	if !strings.HasPrefix(f.s3Auth, "AWS4-HMAC-SHA256 Credential=ASIA-TEST/") {
		t.Errorf("Authorization = %q, want a SigV4 credential scope", f.s3Auth)
	}
	if !strings.Contains(f.s3Auth, "SignedHeaders=") || !strings.Contains(f.s3Auth, "Signature=") {
		t.Errorf("Authorization is missing SigV4 components: %q", f.s3Auth)
	}
	if !strings.Contains(f.s3Auth, "/us-west-2/s3/aws4_request") {
		t.Errorf("credential scope = %q, want the token's region and the s3 service", f.s3Auth)
	}
	if f.s3Token != "sts-session" {
		t.Errorf("X-Amz-Security-Token = %q, want the STS session token", f.s3Token)
	}
	if len(f.s3AmzHash) != 64 {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the payload digest", f.s3AmzHash)
	}
	if f.s3AmzDate == "" {
		t.Error("X-Amz-Date must be set")
	}
	if len(f.s3Body) != 256 {
		t.Errorf("uploaded %d bytes, want 256", len(f.s3Body))
	}
	// 3. attachfile registered the object by documentPath + sizeInBytes
	if f.attachBody["documentPath"] != "uploads/bundle.zip" {
		t.Errorf("attachfile documentPath = %v", f.attachBody["documentPath"])
	}
	if n, _ := f.attachBody["sizeInBytes"].(float64); int64(n) != 256 {
		t.Errorf("attachfile sizeInBytes = %v, want 256", f.attachBody["sizeInBytes"])
	}
	if res.Transport != "juniper-s3" {
		t.Errorf("transport = %q", res.Transport)
	}
}

func TestJuniperUploadTokenFailsClosedOnSchemaDrift(t *testing.T) {
	f := newJuniperFake(t)
	// A Beta API that changes shape must not produce a silent no-op upload.
	f.tokenResp = `{"accessKeyId":"ASIA","secretAccessKey":"sek","region":"us-west-2"}`
	c := NewJuniperConnector(f.client())

	_, err := c.AttachBundle(context.Background(), juniperCfg(),
		CaseRef{Number: "2026-0905-1234"}, testBundle("bundle.zip", 32))
	if err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("err = %v, want a fail-closed error naming the missing field", err)
	}
	if f.s3Method != "" {
		t.Error("nothing may be uploaded when the token response is incomplete")
	}
}

func TestJuniperSeverityValuesAreFetchedNotHardCoded(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())
	if got := c.Capabilities().SeverityValues; len(got) != 0 {
		t.Fatalf("SeverityValues = %v, want empty: priority comes from /getlov", got)
	}
	vals, err := c.FetchSeverityValues(context.Background(), juniperCfg())
	if err != nil {
		t.Fatalf("getlov: %v", err)
	}
	if len(vals) != 4 || vals[0] != "P1" {
		t.Errorf("values = %v", vals)
	}
	if f.lovCalls != 1 {
		t.Errorf("getlov called %d times", f.lovCalls)
	}
}

func TestJuniperPollReadsSRDetails(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client())
	rc, found, err := c.FetchCase(context.Background(), juniperCfg(), CaseRef{Number: "2026-0905-1234"})
	if err != nil || !found {
		t.Fatalf("poll: %v found=%v", err, found)
	}
	if rc.Status != "Open" || rc.UpdatedAt.IsZero() {
		t.Errorf("remote case = %+v", rc)
	}
}

func TestJuniperHonoursTheHourlyInvocationBudget(t *testing.T) {
	f := newJuniperFake(t)
	cl := f.client()
	auth := juniper.Auth{APIKey: "k"}
	for i := 0; i < juniper.HourlyInvocationLimit; i++ {
		if _, err := cl.GetLOV(context.Background(), auth, "priority"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	_, err := cl.GetLOV(context.Background(), auth, "priority")
	var rl *juniper.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want the local 1000/hour guard to fire", err)
	}
	if !strings.Contains(err.Error(), "1000") {
		t.Errorf("the message should name the documented limit: %v", err)
	}
}

func TestJuniperConfigRequiresOnboardingIdentifiers(t *testing.T) {
	full := juniperCfg().Juniper
	for _, field := range []string{"AppID", "CustomerSourceID", "UserID", "AccountID"} {
		cfg := full
		switch field {
		case "AppID":
			cfg.AppID = ""
		case "CustomerSourceID":
			cfg.CustomerSourceID = ""
		case "UserID":
			cfg.UserID = ""
		case "AccountID":
			cfg.AccountID = ""
		}
		if err := validateJuniperConfig(cfg); err == nil {
			t.Errorf("%s must be required", field)
		}
	}
	alias := full
	alias.DefaultContactEmail = "support@customer.example"
	if err := validateJuniperConfig(alias); err == nil {
		t.Error("an alias default contact must be refused at config time")
	}
}
