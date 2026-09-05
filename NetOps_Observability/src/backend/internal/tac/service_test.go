package tac

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testService(t *testing.T, opts ...ServiceOption) *Service {
	t.Helper()
	c := mustCatalog(t)
	s, err := NewService(c, opts...)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return s
}

// TestServiceRegisterIsTenantScoped — one tenant's escalation is invisible under
// another's key, and the answer is the same as "never escalated".
func TestServiceRegisterIsTenantScoped(t *testing.T) {
	s := testService(t)
	s.Classify("tenant-a", "inc-1", Evidence{Alerts: []string{"BGPSessionDown"}})
	if s.Get("tenant-a", "inc-1") == nil {
		t.Fatal("the owning tenant cannot read its own escalation")
	}
	if s.Get("tenant-b", "inc-1") != nil {
		t.Fatal("another tenant can read this escalation")
	}
	if s.Get("tenant-b", "inc-nothing") != nil {
		t.Fatal("an absent escalation and a foreign one must answer identically")
	}
}

// TestServiceCollectWithoutARunnerIs503Shaped — no transport means an honest
// refusal, never a fabricated capture.
func TestServiceCollectWithoutARunnerIs503Shaped(t *testing.T) {
	s := testService(t)
	if s.CanCollect() {
		t.Fatal("a service with no collector must not claim it can collect")
	}
	if _, err := s.StartCollect("t1", "inc-1", nil); !errors.Is(err, ErrNoRunner) {
		t.Fatalf("expected ErrNoRunner, got %v", err)
	}
}

// TestServiceCollectNeedsAPlan.
func TestServiceCollectNeedsAPlan(t *testing.T) {
	f := newFake()
	s := testService(t, WithCollector(testCollector(t, f)))
	if _, err := s.StartCollect("t1", "inc-1", nil); err == nil {
		t.Fatal("a collection started with no approved plan")
	}
}

// TestServiceCollectRunsAndRecords is the end-to-end async path.
func TestServiceCollectRunsAndRecords(t *testing.T) {
	f := newFake()
	cat := mustCatalog(t)
	plan, _ := cat.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	for _, st := range plan.Steps {
		f.out[st.Command] = "ok"
	}
	s := testService(t, WithCollector(testCollector(t, f)))
	if _, err := s.Plan("t1", "inc-1", "ospf-adjacency", iosxeDevice(), PlanOptions{}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	job, err := s.StartCollect("t1", "inc-1", nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if job.Status != JobRunning {
		t.Fatalf("job status = %q", job.Status)
	}
	waitJob(t, s, "t1", "inc-1")
	st := s.Get("t1", "inc-1")
	if st.Job.Status != JobDone {
		t.Fatalf("job ended %q: %s", st.Job.Status, st.Job.Err)
	}
	if st.Capture == nil || len(st.Capture.Commands) != len(plan.Steps) {
		t.Fatal("the capture was not recorded on the escalation")
	}
	if len(st.Job.Progress) == 0 {
		t.Fatal("no progress was recorded for the UI to show")
	}
}

// TestServiceRefusesASecondCollection.
func TestServiceRefusesASecondCollection(t *testing.T) {
	f := newFake()
	cat := mustCatalog(t)
	plan, _ := cat.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	f.blockCh = make(chan struct{})
	f.blockCmd = plan.Steps[0].Command
	for _, st := range plan.Steps {
		f.out[st.Command] = "ok"
	}
	s := testService(t, WithCollector(testCollector(t, f)))
	_, _ = s.Plan("t1", "inc-1", "ospf-adjacency", iosxeDevice(), PlanOptions{})
	if _, err := s.StartCollect("t1", "inc-1", nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for len(f.commands()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the collection never began")
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := s.StartCollect("t1", "inc-1", nil); !errors.Is(err, ErrCollectBusy) {
		t.Fatalf("a second collection was allowed: %v", err)
	}
	close(f.blockCh)
	waitJob(t, s, "t1", "inc-1")
}

// TestServiceReclassificationInvalidatesAStalePlan.
func TestServiceReclassificationInvalidatesAStalePlan(t *testing.T) {
	s := testService(t)
	s.Classify("t1", "inc-1", Evidence{Alerts: []string{"BGPSessionDown"}})
	if _, err := s.Plan("t1", "inc-1", "bgp-session", iosxeDevice(), PlanOptions{}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	s.Classify("t1", "inc-1", Evidence{Alerts: []string{"OSPFAdjacencyDown"}})
	if st := s.Get("t1", "inc-1"); st.Plan != nil {
		t.Fatal("a plan built for the previous class survived a reclassification")
	}
}

// TestServiceAlwaysOffersAnHonestCaseConnector.
func TestServiceAlwaysOffersAnHonestCaseConnector(t *testing.T) {
	s := testService(t)
	infos := s.Connectors(context.Background(), "t1")
	if len(infos) == 0 {
		t.Fatal("no case connectors at all")
	}
	var portal ConnectorInfo
	for _, i := range infos {
		if i.ID == PortalTextConnectorID {
			portal = i
		}
	}
	if portal.ID == "" || !portal.Configured {
		t.Fatal("the portal-text connector must always be present and configured")
	}
	if portal.Can(CapCreate) || portal.Can(CapAttach) {
		t.Fatal("portal-text must not claim a capability it does not have")
	}
	if ProfileForConnector(portal) != ProfileLinkOnly {
		t.Fatal("a connector that cannot attach must select the link-only profile")
	}
}

// TestServiceSubmitCaseReturnsPortalText — a connector with no create capability
// still succeeds, with text the operator can act on.
func TestServiceSubmitCaseReturnsPortalText(t *testing.T) {
	s := testService(t)
	req := CaseRequest{
		TenantID: "t1", IncidentID: "inc-1", ClassID: "bgp-session",
		DeviceID: "d1", Hostname: "core1", Platform: "Cisco IOS-XE 17.9",
		Form:  CaseForm{Description: "statement [I1]", Severity: "3", BundleName: "correlix-tac-x.zip", BundleBytes: 1234},
		Actor: "op@example.test",
	}
	form, info, err := s.PrepareCase(context.Background(), "t1", PortalTextConnectorID, req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if info.ID != PortalTextConnectorID {
		t.Fatalf("connector = %q", info.ID)
	}
	if form.PortalText == "" {
		t.Fatal("the pre-filled case text is empty")
	}
	if len(form.MissingFields) == 0 {
		t.Fatal("the form must name the entitlement fields the operator has to supply")
	}
	req.Form = form
	res, err := s.SubmitCase(context.Background(), "t1", "inc-1", PortalTextConnectorID, req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID != "" {
		t.Fatal("portal-text must not claim to have created a case")
	}
	if res.PortalText == "" || res.AttachNote == "" {
		t.Fatal("the result must hand the operator the text and say why nothing was attached")
	}
	if st := s.Get("t1", "inc-1"); st == nil || st.Case == nil {
		t.Fatal("the case outcome was not recorded on the escalation")
	}
}

// TestServiceUnknownConnectorIsRefused.
func TestServiceUnknownConnectorIsRefused(t *testing.T) {
	s := testService(t)
	if _, _, err := s.PrepareCase(context.Background(), "t1", "servicenow", CaseRequest{}); err == nil {
		t.Fatal("an unconfigured/unknown connector was accepted")
	}
}

func waitJob(t *testing.T, s *Service, tenant, incident string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		st := s.Get(tenant, incident)
		if st != nil && st.Job != nil && st.Job.Status != JobRunning {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the collection never finished")
		case <-time.After(2 * time.Millisecond):
		}
	}
}
