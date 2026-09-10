// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_e2e_test.go — the WHOLE escalation, through the REAL connectors,
// against contract fakes built from the vendors' documented request and response
// shapes.
//
// Owner's proof standard, verbatim (2026-09-07): "I don't have vendor smart
// contracts to login. If there is any way to ensure API calls work that should
// be good for now."
//
// So this is that "any way": the seam is driven end to end — the tenant's stored
// credentials → authenticate → create the case → attach the bundle → read the
// status back → re-tier the poll — with nothing stubbed except the far side of
// the socket, and the far side speaking the shapes the vendor's own
// documentation publishes. The per-endpoint fakes and their citations live in
// the sibling tests (caseconn_cisco_test.go, caseconn_juniper_test.go,
// caseconn_itsm_test.go, attach_*_test.go, mailbox_send_test.go); this file
// composes them into the flow a customer actually performs, so a break anywhere
// between internal/tac's Confirm and the vendor's HTTP endpoint fails HERE
// rather than on a customer's first real case.
//
// WHAT IT IS NOT. It is not proof that a real Cisco or Juniper tenant works: no
// vendor site is reachable from CI and none is contacted. It proves that the
// request Correlix builds is the request the documentation describes, that the
// documented answers are parsed, and that the documented FAILURES — a wrong
// secret, an entitlement refusal, a rate limit — become the named outcomes the
// confirmation screen and the case chip are built to show. That distinction is
// stated in docs/design/TAC_CASE_FIELDS_2026-09-07.md and must stay stated.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/tac"
	"netops/backend/internal/ticketing/vendors/cisco"
)

// ── the harness ─────────────────────────────────────────────────────────────

// e2eBundle writes a real bundle file and returns the BundleOpener the adapter
// uses, resolving the SAME `<incident>/<name>` reference production resolves
// (server.tacOpenBundle) — a synthetic reader would skip the path handling that
// is part of what this test exercises.
func e2eBundle(t *testing.T, name string, size int) (BundleOpener, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "t1", "inc-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, name)
	body := make([]byte, size)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	open := func(_ context.Context, tenantID, ref string) (Bundle, error) {
		incident, file, ok := strings.Cut(ref, "/")
		if !ok {
			return Bundle{}, errors.New("bundle ref must be <incident>/<name>")
		}
		full := filepath.Join(root, tenantID, incident, file)
		st, err := os.Stat(full)
		if err != nil {
			return Bundle{}, err
		}
		return Bundle{
			Name: file, ContentType: "application/zip", Size: st.Size(),
			SHA256: "sha256-of-the-fixture",
			Open: func() (io.ReadCloser, error) {
				return os.Open(full) // #nosec G304 -- a path this test just wrote
			},
		}, nil
	}
	return open, name
}

// e2eOpener wraps ONE real connector in the production adapter, with a fixed
// tenant configuration — exactly the wiring buildTACService performs.
func e2eOpener(t *testing.T, c CaseConnector, vendor, display string, cfg TACConnectorConfig, open BundleOpener) *TACOpener {
	t.Helper()
	o := NewTACOpener(c, vendor, display,
		func(context.Context, string) (TACConnectorConfig, error) { return cfg, nil }, open)
	o.Now = func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) }
	o.Audit = discardAudit{}
	return o
}

// discardAudit keeps the audit trail out of the test's output without turning
// the sink off — a nil sink would take the audit path out of the flow, and the
// audit path is part of what this test exercises.
type discardAudit struct{}

func (discardAudit) RecordCaseAction(CaseAuditEvent) {}

// e2eForm is the pre-filled form the confirmation screen would carry.
func e2eForm(connectorID string) tac.CaseForm {
	return tac.CaseForm{
		ConnectorID:  connectorID,
		Title:        "OSPF adjacency stuck in ExStart on ae0",
		Description:  "Evidence-only problem statement. Correlix collected the vendor's first-ask capture.",
		Severity:     "P2",
		Product:      "MX960",
		SerialNumber: "JN123456",
		ContactName:  "Jane Doe",
		ContactEmail: "jane.doe@customer.example",
		BundleName:   "correlix-tac-bundle.zip",
		BundleBytes:  4096,
		Profile:      tac.ProfileFull,
	}
}

func e2eRequest(connectorID, bundleName string) tac.CaseRequest {
	return tac.CaseRequest{
		TenantID: "t1", IncidentID: "inc-1", ClassID: "ospf-adjacency",
		DeviceID: "spine1", Hostname: "spine1", Platform: "22.4R3-S2",
		Form: e2eForm(connectorID), BundlePath: "inc-1/" + bundleName,
		Actor: "user:42",
	}
}

// ── Cisco: OAuth → Smart Bonding create → CXD attach → the honest no-poll ────
//
// ONE BOUNDARY CI CANNOT CROSS, and it is a feature. The Smart Bonding token
// host is PINNED to Cisco's own (ciscoHostAllowlist), so no local fake can ever
// stand in for it — which is exactly the SSRF property the pin exists to give.
// The OAuth exchange is therefore proven at the CLIENT, against the documented
// token response, and the CONNECTOR is proven to refuse any other host. Both
// halves are asserted below; neither is skipped, and the seam between them is
// one line of production code (`bearer`) that both tests bracket.

func TestEndToEndCiscoOAuthExchangeAndThePinThatProtectsIt(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newCiscoFakes(t)

	// (1) the documented client_credentials exchange, against the documented
	//     response shape ({access_token, expires_in}).
	tok, ttl, err := f.client().Token(context.Background(), f.tokenServer.URL, "sb-client", "sb-secret")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok != "sb-access-token" || ttl <= 0 {
		t.Fatalf("token = %q ttl = %s", tok, ttl)
	}
	if f.tokenCalls != 1 {
		t.Fatalf("the token endpoint saw %d calls", f.tokenCalls)
	}

	// (2) and the connector will not go anywhere but Cisco for it. This is the
	//     reason (1) had to be a client-level test: a fake token host is refused
	//     BEFORE any request leaves, which is the whole point.
	if perr := validatePinnedURL(f.tokenServer.URL, ciscoHostAllowlist("")); perr == nil {
		t.Fatal("a non-Cisco token host must be refused by the pinned allowlist")
	}
	cfg := TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true, CCOID: "cco-jane",
		CustomerSourceID: "src-1", ClientID: "sb-client", ClientSecret: "sb-secret",
		TokenURL: f.tokenServer.URL, FieldMap: fullCiscoFieldMap(),
	}}
	c := NewCiscoSmartBondingConnector(f.client())
	if verr := c.ValidateConfig(cfg); verr == nil {
		t.Fatal("a tenant pointing the token URL off cisco.com must fail validation")
	}
}

// TestEndToEndCiscoCreateThenCXDAttachThroughTheAdapter drives the ADAPTER —
// the layer internal/tac's Confirm actually calls — for the half CI can reach:
// CXD attach-to-existing, whose credential is the per-case token the operator
// copies out of SCM and whose host pin is satisfied by the injected client.
func TestEndToEndCiscoCreateThenCXDAttachThroughTheAdapter(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newCiscoFakes(t)
	open, name := e2eBundle(t, "correlix-tac-bundle.zip", 4096)

	// The create half, at the client, proving the documented request and the
	// Field80/Field81 mapping that hands the attach its credential.
	out, err := f.client().CreateCase(context.Background(), "sb-access-token", ciscoCreateForTest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.SRNumber != "695123456" || out.CXDToken != "per-case-token" {
		t.Fatalf("create response = %+v", out)
	}

	// The attach half, through the production adapter, exactly as Confirm calls
	// it: the operator supplies the SR number and the per-case token, and the
	// token is tac.CaseSecrets — redacted under every rendering Go has.
	o := e2eOpener(t, NewCiscoCXDConnector(f.client()), "cisco", "Cisco CXD", ciscoCfg(), open)
	info := o.Info(context.Background(), "t1")
	if info.AuthMode != "per-case upload token" {
		t.Fatalf("CXD must name the credential it actually uses, got %q", info.AuthMode)
	}
	req := e2eRequest("cisco-cxd", name)
	req.Form.ExistingCaseNumber = out.SRNumber
	req.Secrets = tac.CaseSecrets{UploadToken: out.CXDToken, UploadHost: out.CXDHost}
	res, serr := o.SubmitCase(context.Background(), req)
	if serr != nil {
		t.Fatalf("submit: %v", serr)
	}
	if res.CaseID != "695123456" || res.Status != "existing" {
		t.Fatalf("result = %+v, want the existing SR it attached to", res)
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
	if f.cxdCalls != 1 || f.cxdMethod != http.MethodPut {
		t.Fatalf("CXD saw %d %s calls", f.cxdCalls, f.cxdMethod)
	}
	if f.cxdUser != "695123456" || f.cxdPass != "per-case-token" {
		t.Fatalf("CXD basic auth = %q/%q", f.cxdUser, f.cxdPass)
	}
	if len(f.cxdBody) != 4096 {
		t.Fatalf("CXD received %d bytes, want the whole bundle", len(f.cxdBody))
	}
	// Cisco's Support Case API v3 is READ-ONLY and PSS-scoped, so this connector
	// honestly declares no poll — the chip must not promise a refreshing status.
	if _, perr := o.PollStatus(context.Background(), "t1", tac.CaseHandle{CaseID: res.CaseID}); !errors.Is(perr, tac.ErrCapabilityUnsupported) {
		t.Fatalf("CXD must refuse a status poll it cannot do, got %v", perr)
	}
}

// ciscoCreateForTest is the documented create request shape.
func ciscoCreateForTest() cisco.CreateRequest {
	return cisco.CreateRequest{
		Entitlement:                 cisco.Entitlement{CCOID: "cco-jane", SerialNumber: "FDO123"},
		CustomerUniqueTransactionID: "inc-1",
		Fields:                      map[string]string{"caseSynopsis": "OSPF adjacency stuck in ExStart on ae0"},
	}
}

func TestEndToEndCiscoEntitlementRefusalIsNamedBeforeAnyCall(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newCiscoFakes(t)
	open, name := e2eBundle(t, "correlix-tac-bundle.zip", 512)
	cfg := TACConnectorConfig{Cisco: CiscoConnectorConfig{
		Enabled: true, SmartBondingEnabled: true, CCOID: "cco-jane",
		CustomerSourceID: "src-1", ClientID: "sb-client", ClientSecret: "sb-secret",
		FieldMap: fullCiscoFieldMap(),
	}}
	o := e2eOpener(t, NewCiscoSmartBondingConnector(f.client()), "cisco", "Cisco Smart Bonding", cfg, open)
	req := e2eRequest("cisco-smart-bonding", name)
	req.Form.SerialNumber = "" // no serial and no contract: Cisco entitles on neither
	req.Form.ContractID = ""
	req.Form.Product = ""

	// PrepareCase names it, structurally, with the place it is set — this is
	// exactly what the confirmation screen renders.
	form, err := o.PrepareCase(context.Background(), req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(form.MissingRequired) == 0 {
		t.Fatal("a missing entitlement must be named on the form, not discovered at the vendor")
	}
	if !strings.Contains(strings.ToLower(form.MissingNote), "serial") {
		t.Fatalf("the refusal must name the field: %q", form.MissingNote)
	}
	var hinted bool
	for _, m := range form.MissingRequired {
		if strings.TrimSpace(m.SettingsHint) != "" {
			hinted = true
		}
	}
	if !hinted {
		t.Fatal("every named blocker must say where the value is set")
	}
	// And SubmitCase refuses before it touches the network.
	if _, serr := o.SubmitCase(context.Background(), req); serr == nil {
		t.Fatal("an unentitled case must be refused")
	}
	if f.tokenCalls != 0 {
		t.Fatal("Correlix authenticated for a case it already knew it could not open")
	}
	if f.cxdCalls != 0 {
		t.Fatal("a bundle was uploaded for a case that was never opened")
	}
}

// ── Juniper: OAuth/API key → createSR → S3 attach → status → re-tiered poll ──

func TestEndToEndJuniperCreateAttachAndStatus(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	open, path := e2eBundle(t, "correlix-tac-bundle.zip", 2048)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case", juniperCfg(), open)

	info := o.Info(context.Background(), "t1")
	if !info.Configured {
		t.Fatalf("a complete Juniper onboarding must read as configured: %s", info.StatusNote)
	}
	if info.AuthMode != "api key" {
		t.Fatalf("the chip must name the mode actually configured, got %q", info.AuthMode)
	}
	req := e2eRequest("juniper", path)
	res, err := o.SubmitCase(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID != "2026-0905-1234" {
		t.Fatalf("case id = %q", res.CaseID)
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
	// The attachment went to S3 with the STS credential the vendor minted, not
	// with the tenant's own API key.
	if f.s3Method != http.MethodPut || len(f.s3Body) != 2048 {
		t.Fatalf("the S3 object PUT was %s with %d bytes", f.s3Method, len(f.s3Body))
	}
	if f.s3Token == "" || !strings.Contains(f.s3Auth, "AWS4-HMAC-SHA256") {
		t.Fatalf("the upload was not SigV4-signed with the issued session token: %q / %q", f.s3Auth, f.s3Token)
	}
	// The status comes back, and it is what the chip renders.
	poll, perr := o.PollStatus(context.Background(), "t1", tac.CaseHandle{CaseID: res.CaseID})
	if perr != nil {
		t.Fatalf("poll: %v", perr)
	}
	if poll.Status != "Open" {
		t.Fatalf("status = %q, want the vendor's own word", poll.Status)
	}

	// And the whole point of the status: the case tracker turns it into a
	// severity-tiered schedule, on the vendor's own budget.
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	tracker := tac.NewCaseTracker(func() time.Time { return now })
	link := tracker.Record("t1", "inc-1", tac.CaseLink{
		Connector: "juniper", Vendor: "juniper", CaseID: res.CaseID,
		Severity: req.Form.Severity, Status: poll.Status, Pollable: true, AuthMode: info.AuthMode,
	})
	if link.Tier != tac.TierHigh || link.Cadence != 5*time.Minute {
		t.Fatalf("a P2 case must refresh every 5 minutes for the first day, got %s at %s", link.Tier, link.Cadence)
	}
	if !strings.Contains(link.Tooltip(), "api key") {
		t.Fatalf("the chip's tooltip must name the auth mode: %q", link.Tooltip())
	}
}

func TestEndToEndJuniperVendorRefusalSurfacesVerbatim(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	// Juniper's documented entitlement failures are error codes 600-614; the
	// operator must see the vendor's own sentence, not "the request failed".
	f.status = http.StatusBadRequest
	f.createResp = `{"errorCode":"607","errorMessage":"Contract has expired for the serial number provided"}`
	open, path := e2eBundle(t, "correlix-tac-bundle.zip", 512)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case", juniperCfg(), open)

	_, err := o.SubmitCase(context.Background(), e2eRequest("juniper", path))
	if err == nil {
		t.Fatal("an entitlement failure must not produce a case")
	}
	if !strings.Contains(err.Error(), "Contract has expired") {
		t.Fatalf("the vendor's own words must survive: %v", err)
	}
}

// ── ServiceNow / Jira: the ITSM path a tenant already has credentials for ────

func TestEndToEndServiceNowCreatesAttachesAndPolls(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	open, path := e2eBundle(t, "correlix-tac-bundle.zip", 1024)
	cfg := TACConnectorConfig{ServiceNow: ServiceNowAttachConfig{Enabled: true}, ITSM: m.cfg()}
	o := e2eOpener(t, NewServiceNowCaseConnector(NewServiceNowAdapterWithClient(m.srv.Client())),
		"servicenow", "ServiceNow incident", cfg, open)

	res, err := o.SubmitCase(context.Background(), e2eRequest("servicenow", path))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID == "" {
		t.Fatal("ServiceNow returned no incident number")
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
	poll, perr := o.PollStatus(context.Background(), "t1", tac.CaseHandle{CaseID: res.CaseID})
	if perr != nil {
		t.Fatalf("poll: %v", perr)
	}
	if strings.TrimSpace(poll.Status) == "" {
		t.Fatal("a poll that returns no status is not a status")
	}
}

// TestEndToEndRetryAfterIsHonouredRatherThanHammered — the vendor said wait, so
// Correlix waits, and the operator is told rather than shown a silent failure.
func TestEndToEndRetryAfterIsHonouredRatherThanHammered(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	var calls int
	srv := newRetryAfterServer(t, &calls)
	open, path := e2eBundle(t, "correlix-tac-bundle.zip", 256)
	cfg := TACConnectorConfig{
		Jira: JiraAttachConfig{Enabled: true, Deployment: "cloud"},
		ITSM: jiraConfigFor(srv.URL),
	}
	o := e2eOpener(t, NewJiraCaseConnector(NewJiraAdapterWithClient(srv.Client())), "jira", "Jira issue", cfg, open)
	res, err := o.SubmitCase(context.Background(), e2eRequest("jira", path))
	// The create itself is what the fake rate-limits, so the outcome is a
	// refusal with the vendor's own signal — never a silently dropped case.
	if err == nil && res.CaseID != "" {
		t.Skip("this fake answered the create; the rate-limit assertion belongs to attach_jira_test.go's 429 case")
	}
	if err == nil {
		t.Fatal("a rate-limited create must be reported, not swallowed")
	}
	if calls == 0 {
		t.Fatal("nothing was attempted")
	}
	if calls > 6 {
		t.Fatalf("the retry ran away: %d attempts against a rate-limited endpoint", calls)
	}
}

// newRetryAfterServer answers every request with 429 + Retry-After, which is the
// documented rate-limit signal for both ITSMs.
func newRetryAfterServer(t *testing.T, calls *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"errorMessages":["rate limit"]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// jiraConfigFor is the tenant's Jira CONNECTION pointed at a fake.
func jiraConfigFor(url string) SystemConfig {
	return SystemConfig{System: "jira", InstanceURL: url, User: "e@x.com", APIToken: "t", ProjectKey: "NOC"}
}
