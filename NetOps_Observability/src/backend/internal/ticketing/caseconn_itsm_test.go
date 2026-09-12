// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_itsm_test.go — the ServiceNow and Jira CaseConnectors driven
// end-to-end (create → attach → poll) against the existing mock instances, so
// the case-opening SHAPE is proven on top of adapters that are already tested.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func approvedRequest() CaseRequest {
	return CaseRequest{
		Synopsis: "OSPF adjacency stuck on spine1 ae0", Description: "Evidence-only statement.",
		Severity: "2", DeviceID: "spine1", IdempotencyKey: "corr-abc",
		ContactName: "Jane Doe", ContactEmail: "jane.doe@customer.example",
		Approval: Approval{Actor: "user:42", ApprovedAt: time.Now().UTC()},
	}
}

func TestServiceNowCaseConnectorCreatesThenAttachesThenPolls(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()

	adapter := NewServiceNowAdapterWithClient(m.srv.Client())
	c := NewServiceNowCaseConnector(adapter)
	cfg := TACConnectorConfig{
		ServiceNow: ServiceNowAttachConfig{Enabled: true},
		ITSM:       m.cfg(),
	}

	ref, err := c.CreateCase(context.Background(), cfg, approvedRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.ID == "" || ref.Number == "" {
		t.Fatalf("ref = %+v", ref)
	}
	if _, _, err := c.FetchCase(context.Background(), cfg, ref); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if err := c.AddNote(context.Background(), cfg, ref, "bundle uploaded"); err != nil {
		t.Fatalf("note: %v", err)
	}
}

func TestServiceNowCaseConnectorNeedsApprovalAndOptIn(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	c := NewServiceNowCaseConnector(NewServiceNowAdapterWithClient(m.srv.Client()))

	// Not opted in.
	if err := c.ValidateConfig(TACConnectorConfig{ITSM: m.cfg()}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	// Opted in but no ITSM connection resolved for the tenant.
	if err := c.ValidateConfig(TACConnectorConfig{ServiceNow: ServiceNowAttachConfig{Enabled: true}}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured without a connection", err)
	}
	// Opted in, connected, but no human approved.
	cfg := TACConnectorConfig{ServiceNow: ServiceNowAttachConfig{Enabled: true}, ITSM: m.cfg()}
	req := approvedRequest()
	req.Approval = Approval{}
	if _, err := c.CreateCase(context.Background(), cfg, req); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}
}

func TestServiceNowConnectorHonoursTheTenantsConfiguredCeiling(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	c := NewServiceNowCaseConnector(NewServiceNowAdapterWithClient(m.srv.Client()))
	cfg := TACConnectorConfig{
		ServiceNow: ServiceNowAttachConfig{Enabled: true, MaxAttachBytes: 1024},
		ITSM:       m.cfg(),
	}
	_, err := c.AttachBundle(context.Background(), cfg, CaseRef{ID: "sys-1"}, testBundle("b.zip", 2048))
	var tooBig AttachTooLargeError
	if !errors.As(err, &tooBig) || tooBig.Limit != 1024 {
		t.Fatalf("err = %v, want the tenant's 1024-byte ceiling enforced", err)
	}
}

func TestJiraCaseConnectorPollsStatusAndUpdated(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key":"NOC-42","fields":{"status":{"name":"In Progress"},"updated":"2026-09-05T09:30:00.000+0000"}}`))
	}))
	defer srv.Close()

	c := NewJiraCaseConnector(NewJiraAdapterWithClient(srv.Client()))
	cfg := TACConnectorConfig{
		Jira: JiraAttachConfig{Enabled: true, Deployment: jiraCloud},
		ITSM: SystemConfig{System: "jira", InstanceURL: srv.URL, User: "e@x.com", APIToken: "t", ProjectKey: "NOC"},
	}
	rc, found, err := c.FetchCase(context.Background(), cfg, CaseRef{Number: "NOC-42"})
	if err != nil || !found {
		t.Fatalf("poll: %v found=%v", err, found)
	}
	if !strings.HasPrefix(gotPath, "/rest/api/3/issue/NOC-42") || !strings.Contains(gotPath, "fields=status,updated") {
		t.Errorf("poll path = %q, want the documented fields query", gotPath)
	}
	if rc.Status != "in progress" || rc.UpdatedAt.IsZero() {
		t.Errorf("remote case = %+v", rc)
	}
	if !strings.HasSuffix(rc.URL, "/browse/NOC-42") {
		t.Errorf("URL = %q, want the browse link", rc.URL)
	}
}

func TestJiraCaseConnectorReportsAMissingIssueAsNotFound(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist"]}`))
	}))
	defer srv.Close()
	c := NewJiraCaseConnector(NewJiraAdapterWithClient(srv.Client()))
	cfg := TACConnectorConfig{
		Jira: JiraAttachConfig{Enabled: true},
		ITSM: SystemConfig{System: "jira", InstanceURL: srv.URL, User: "e@x.com", APIToken: "t", ProjectKey: "NOC"},
	}
	rc, found, err := c.FetchCase(context.Background(), cfg, CaseRef{Number: "NOC-9"})
	if err != nil {
		t.Fatalf("a deleted issue is not an error: %v", err)
	}
	if found {
		t.Fatalf("found = true for a deleted issue: %+v", rc)
	}
}

func TestITSMConnectorCapabilityDeclarationsMatchTheDocumentedDefaults(t *testing.T) {
	sn := NewServiceNowCaseConnector(nil).Capabilities()
	if sn.MaxAttachBytes != 1024<<20 {
		t.Errorf("ServiceNow ceiling = %d, want the 1024 MB property default", sn.MaxAttachBytes)
	}
	if sn.Webhook {
		t.Error("ServiceNow push needs a customer-built Outbound REST message; do not promise it")
	}
	jr := NewJiraCaseConnector(nil).Capabilities()
	if jr.MaxAttachBytes != 1<<30 {
		t.Errorf("Jira Cloud ceiling = %d, want the 1 GB default", jr.MaxAttachBytes)
	}
	if !strings.Contains(jr.Notes, "20 writes per 2 s") {
		t.Error("the per-issue write rate limit is the one that bites create-then-attach; it must be stated")
	}
}
