package ticketing

// caseconn_tac_test.go — the adapter onto W1's internal/tac.CaseOpener seam.
// These are the tests that stop the two vocabularies drifting apart: a
// capability we declare here must arrive as the seam's verb, and a refusal we
// raise here must arrive as the seam's typed sentinel so the route layer never
// matches on a string.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/tac"
)

func testResolver(cfg TACConnectorConfig) TenantConfigResolver {
	return func(context.Context, string) (TACConnectorConfig, error) { return cfg, nil }
}

func TestAdapterMapsCapabilitiesOntoTheSeamsVerbs(t *testing.T) {
	r := DefaultCaseConnectorRegistry()
	openers := TACOpenersFromRegistry(r, testResolver(TACConnectorConfig{}), nil)
	if len(openers) != len(r.Matrix()) {
		t.Fatalf("adapted %d of %d connectors", len(openers), len(r.Matrix()))
	}

	byID := map[string]tac.ConnectorInfo{}
	for _, o := range openers {
		info := o.Info(context.Background(), "org-a-tenant")
		byID[info.ID] = info
	}
	for id, want := range map[string][]tac.CaseCapability{
		"servicenow":      {tac.CapCreate, tac.CapAttach, tac.CapPollStatus, tac.CapLink},
		"jira":            {tac.CapCreate, tac.CapAttach, tac.CapPollStatus, tac.CapLink},
		"cisco-cxd":       {tac.CapAttach},
		"juniper":         {tac.CapCreate, tac.CapAttach, tac.CapPollStatus, tac.CapLink},
		"portal-nokia":    {},
		"portal-fortinet": {},
	} {
		got, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing from the adapted set", id)
		}
		if len(got.Capabilities) != len(want) {
			t.Errorf("%s: capabilities = %v, want %v", id, got.Capabilities, want)
			continue
		}
		for _, c := range want {
			if !got.Can(c) {
				t.Errorf("%s: missing %q", id, c)
			}
		}
	}
	// A connector that cannot attach must report 0, which is the seam's own
	// meaning for "cannot attach at all".
	if byID["portal-nokia"].MaxAttachmentBytes != 0 {
		t.Error("a portal-only connector must report a 0 attachment ceiling")
	}
	// A connector with no DOCUMENTED vendor cap must NOT report 0, which would
	// read as "cannot attach"; it reports the local runaway guard.
	if byID["cisco-cxd"].MaxAttachmentBytes != NoDocumentedLimitGuard {
		t.Errorf("cisco-cxd ceiling = %d, want the local guard (0 would read as 'cannot attach')",
			byID["cisco-cxd"].MaxAttachmentBytes)
	}
	// Profiles follow from the ceilings via the seam's own rule.
	if byID["portal-nokia"].Profile != tac.ProfileLinkOnly {
		t.Errorf("portal profile = %q, want link_only", byID["portal-nokia"].Profile)
	}
	if byID["servicenow"].Profile != tac.ProfileFull {
		t.Errorf("servicenow profile = %q, want full", byID["servicenow"].Profile)
	}
	if byID["email-arista"].Profile != tac.ProfileEmail {
		t.Errorf("email profile = %q, want email", byID["email-arista"].Profile)
	}
}

func TestAdapterReportsConfiguredPerTenantWithTheReason(t *testing.T) {
	c := NewJuniperConnector(nil)
	unconfigured := NewTACOpener(c, "juniper", "Juniper Service Case",
		testResolver(TACConnectorConfig{}), nil)
	info := unconfigured.Info(context.Background(), "org-a-tenant")
	if info.Configured {
		t.Fatal("a tenant that never opted in must not read as configured")
	}
	if info.Note == "" || !strings.Contains(info.Note, "not configured") {
		t.Errorf("the note must say WHY, got %q", info.Note)
	}

	configured := NewTACOpener(c, "juniper", "Juniper Service Case",
		testResolver(juniperCfg()), nil)
	if !configured.Info(context.Background(), "org-a-tenant").Configured {
		t.Fatal("a fully configured tenant must read as configured")
	}
}

func TestAdapterTranslatesOurErrorsIntoTheSeamsSentinels(t *testing.T) {
	for name, tc := range map[string]struct {
		in   error
		want error
	}{
		"not configured": {ErrNotConfigured, tac.ErrConnectorNotConfigured},
		"not onboarded":  {ErrNotOnboarded, tac.ErrConnectorNotConfigured},
		"unsupported":    {ErrUnsupported, tac.ErrCapabilityUnsupported},
		"not approved":   {ErrNotApproved, tac.ErrFormIncomplete},
		"too large":      {AttachTooLargeError{Transport: "jira", Size: 2, Limit: 1}, tac.ErrAttachmentTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			got := translateToTAC(tc.in)
			if !errors.Is(got, tc.want) {
				t.Fatalf("translate(%v) = %v, want it to wrap %v", tc.in, got, tc.want)
			}
			// The original must survive: the vendor's verbatim text is the whole
			// point of the entitlement path.
			if !errors.Is(got, tc.in) {
				t.Errorf("the underlying error was replaced instead of wrapped: %v", got)
			}
		})
	}
	if translateToTAC(nil) != nil {
		t.Error("nil must stay nil")
	}
}

func TestAdapterRefusesToSubmitWithoutAnAuthenticatedActor(t *testing.T) {
	o := NewTACOpener(NewJuniperConnector(nil), "juniper", "", testResolver(juniperCfg()), nil)
	_, err := o.SubmitCase(context.Background(), tac.CaseRequest{TenantID: "org-a-tenant"})
	if !errors.Is(err, tac.ErrFormIncomplete) {
		t.Fatalf("err = %v, want ErrFormIncomplete", err)
	}
	if !strings.Contains(err.Error(), "never by an engine") {
		t.Errorf("the refusal should say a case is opened by a person: %v", err)
	}
}

func TestAdapterNamesWhatAnAttachOnlyConnectorStillNeeds(t *testing.T) {
	// An attach-to-existing connector needs the case it attaches TO and the
	// per-case upload credential. With neither supplied it must refuse VISIBLY,
	// naming both, so the UI disables submit with a reason rather than failing
	// at the vendor.
	o := NewTACOpener(NewCiscoCXDConnector(nil), "cisco", "", testResolver(ciscoCfg()), nil)

	form, err := o.PrepareCase(context.Background(), tac.CaseRequest{TenantID: "org-a-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(form.MissingFields, " | ")
	for _, want := range []string{"existing_case_number", "upload_token"} {
		if !strings.Contains(joined, want) {
			t.Errorf("MissingFields should name %q so submit stays disabled with a reason: %v", want, form.MissingFields)
		}
	}
	_, err = o.SubmitCase(context.Background(), tac.CaseRequest{TenantID: "org-a-tenant", Actor: "user:42"})
	if !errors.Is(err, tac.ErrFormIncomplete) {
		t.Fatalf("err = %v, want ErrFormIncomplete naming what is missing", err)
	}

	// Supply ONLY the case number: the credential is still missing, and the
	// refusal must say so rather than repeating the field already provided.
	partial := tac.CaseRequest{
		TenantID: "org-a-tenant", Actor: "user:42",
		Form: tac.CaseForm{ExistingCaseNumber: "695123456"},
	}
	_, err = o.SubmitCase(context.Background(), partial)
	if !errors.Is(err, tac.ErrFormIncomplete) {
		t.Fatalf("err = %v, want ErrFormIncomplete", err)
	}
	if strings.Contains(err.Error(), "existing_case_number") {
		t.Fatalf("the refusal names a field the operator already supplied: %v", err)
	}
	if !strings.Contains(err.Error(), "upload_token") {
		t.Fatalf("the refusal does not name the missing credential: %v", err)
	}
	pForm, err := o.PrepareCase(context.Background(), partial)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(pForm.MissingFields, " | "), "existing_case_number") {
		t.Fatalf("PrepareCase still demands a field that is filled in: %v", pForm.MissingFields)
	}
}

// TestAdapterAttachesToAnExistingCaseWhenTheSeamCarriesBoth is the other half:
// once the operator supplies the case reference AND the per-case credential,
// the attach-to-existing path RUNS. It is the W2 seam change working end to end.
func TestAdapterAttachesToAnExistingCaseWhenTheSeamCarriesBoth(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "correlix-bundle.zip")
	if err := os.WriteFile(bundlePath, []byte("PK\x03\x04 evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := FileBundleOpener(func(string) string { return dir }, func(string) string { return "sha-of-bundle" })

	var gotRef CaseRef
	fake := &recordingAttachOnly{onAttach: func(ref CaseRef) { gotRef = ref }}
	o := NewTACOpener(fake, "cisco", "Cisco CXD", testResolver(ciscoCfg()), open)

	req := tac.CaseRequest{
		TenantID: "org-a-tenant", IncidentID: "P-000123", DeviceID: "leaf1",
		Actor: "user:42", BundlePath: bundlePath,
		Form: tac.CaseForm{
			ExistingCaseNumber: "695123456",
			Profile:            tac.ProfileFull,
		},
		Secrets: tac.CaseSecrets{UploadToken: "per-case-token", UploadHost: "cxd.example.invalid"},
	}
	res, err := o.SubmitCase(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID != "695123456" || res.Status != "existing" {
		t.Fatalf("result = %+v — the case it attached to must be reported back", res)
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
	if gotRef.Number != "695123456" || gotRef.UploadToken != "per-case-token" ||
		gotRef.UploadHost != "cxd.example.invalid" {
		t.Fatalf("the connector received %+v — the reference and the credential must both cross", gotRef)
	}
	// The credential must not have leaked into anything renderable.
	for _, rendered := range []string{res.PortalText, res.AttachNote, res.CaseURL} {
		if strings.Contains(rendered, "per-case-token") {
			t.Fatalf("the upload token appeared in a rendered field: %q", rendered)
		}
	}
}

// recordingAttachOnly is a CaseConnector with the CXD shape — attach to an
// existing case, no create — that records the CaseRef it was handed.
type recordingAttachOnly struct{ onAttach func(CaseRef) }

func (r *recordingAttachOnly) Name() string { return "cisco-cxd" }
func (r *recordingAttachOnly) Capabilities() Caps {
	return Caps{Attach: true, AttachToExistingOnly: true, MaxAttachBytes: 5 << 20}
}
func (r *recordingAttachOnly) ValidateConfig(TACConnectorConfig) error { return nil }
func (r *recordingAttachOnly) CreateCase(context.Context, TACConnectorConfig, CaseRequest) (CaseRef, error) {
	return CaseRef{}, ErrUnsupported
}
func (r *recordingAttachOnly) AttachBundle(_ context.Context, _ TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if r.onAttach != nil {
		r.onAttach(ref)
	}
	return AttachResult{Name: b.Name, Size: b.Size, Transport: "cisco-cxd"}, nil
}
func (r *recordingAttachOnly) FetchCase(context.Context, TACConnectorConfig, CaseRef) (RemoteCase, bool, error) {
	return RemoteCase{}, false, ErrUnsupported
}

func (r *recordingAttachOnly) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return ErrUnsupported
}

func TestAdapterPortalOnlySubmitIsASuccessfulOutcome(t *testing.T) {
	c, err := NewPortalOnlyConnector("fortinet")
	if err != nil {
		t.Fatal(err)
	}
	o := NewTACOpener(c, "fortinet", "", testResolver(TACConnectorConfig{}), nil)
	res, err := o.SubmitCase(context.Background(), tac.CaseRequest{
		TenantID: "org-a-tenant", Actor: "user:42",
		Form: tac.CaseForm{PortalText: "TITLE: link down"},
	})
	if err != nil {
		t.Fatalf("a portal-only submit is a successful outcome, not an error: %v", err)
	}
	if res.CaseID != "" || res.Attached {
		t.Errorf("a portal-only submit creates and attaches nothing: %+v", res)
	}
	if res.PortalText == "" {
		t.Error("the operator's next action must come back with the result")
	}
	if res.AttachNote == "" {
		t.Error("the result must say why nothing was attached")
	}
	// The portal URL reaches the form so the UI can link it.
	form, err := o.PrepareCase(context.Background(), tac.CaseRequest{TenantID: "org-a-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	if form.PortalURL == "" {
		t.Error("the portal URL must reach the form")
	}
}

func TestAdapterPollStatusIsRefusedWhereThereIsNoPoll(t *testing.T) {
	o := NewTACOpener(NewCiscoCXDConnector(nil), "cisco", "", testResolver(ciscoCfg()), nil)
	_, err := o.PollStatus(context.Background(), "org-a-tenant", "695123456")
	if !errors.Is(err, tac.ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want ErrCapabilityUnsupported — a connector with no poll says so", err)
	}
}

func TestAdapterEndToEndCreateThenAttachThroughTheSeam(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "correlix-bundle.zip")
	if err := os.WriteFile(bundlePath, []byte("PK\x03\x04 evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := FileBundleOpener(func(string) string { return dir }, func(string) string { return "sha-of-bundle" })

	cfg := TACConnectorConfig{ServiceNow: ServiceNowAttachConfig{Enabled: true}, ITSM: m.cfg()}
	o := NewTACOpener(NewServiceNowCaseConnector(NewServiceNowAdapterWithClient(m.srv.Client())),
		"servicenow", "ServiceNow incident", testResolver(cfg), open)

	req := tac.CaseRequest{
		TenantID: "org-a-tenant", IncidentID: "P-000123", DeviceID: "spine1",
		Hostname: "spine1", Platform: "22.4R3", Actor: "user:42", BundlePath: bundlePath,
		Form: tac.CaseForm{
			Title: "OSPF adjacency stuck on spine1", Description: "Evidence-only statement.",
			Severity: "2", ContactName: "Jane Doe", ContactEmail: "jane.doe@customer.example",
			SerialNumber: "FDO123", Profile: tac.ProfileFull,
		},
	}
	form, err := o.PrepareCase(context.Background(), req)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if form.BundleBytes == 0 || form.BundleName != "correlix-bundle.zip" {
		t.Errorf("the form must say up front what will be attached: %+v", form)
	}
	if len(form.MissingFields) != 0 {
		t.Errorf("a complete form should have nothing missing: %v", form.MissingFields)
	}

	res, err := o.SubmitCase(context.Background(), req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.CaseID == "" || res.Status != "created" {
		t.Fatalf("result = %+v", res)
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
}

func TestFileBundleOpenerRefusesAPathOutsideTheTenantDirectory(t *testing.T) {
	tenantDir := t.TempDir()
	elsewhere := t.TempDir()
	outside := filepath.Join(elsewhere, "someone-elses.zip")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := FileBundleOpener(func(string) string { return tenantDir }, nil)

	_, err := open(context.Background(), "org-a-tenant", outside)
	if err == nil || !strings.Contains(err.Error(), "outside this tenant's bundle directory") {
		t.Fatalf("err = %v, want a traversal refusal", err)
	}
	// The refusal must not echo the path it rejected into the message.
	if err != nil && strings.Contains(err.Error(), elsewhere) {
		t.Error("the rejected path was echoed into the error")
	}
	// A path inside the tenant's own directory is fine.
	inside := filepath.Join(tenantDir, "mine.zip")
	if err := os.WriteFile(inside, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := open(context.Background(), "org-a-tenant", inside)
	if err != nil {
		t.Fatalf("own bundle: %v", err)
	}
	if b.Size != 5 || b.Name != "mine.zip" {
		t.Errorf("bundle = %+v", b)
	}
	rc, err := b.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
}

func TestAdapterUsesTheIncidentIDAsTheIdempotencyKey(t *testing.T) {
	// Cisco and Juniper both treat a repeated transaction id as an UPDATE, so a
	// retried submit for one incident must never open a second case.
	got := tacToCaseRequest(tac.CaseRequest{
		IncidentID: "P-000123", Actor: "user:42",
		Form: tac.CaseForm{Title: "t", ContractID: "K1", Product: "MX204"},
	}, timeZero())
	if got.IdempotencyKey != "P-000123" {
		t.Errorf("idempotency key = %q, want the incident id", got.IdempotencyKey)
	}
	if got.Approval.Actor != "user:42" {
		t.Errorf("the approving human must cross the seam: %+v", got.Approval)
	}
	if got.Fields["contract_id"] != "K1" || got.Fields["software_version"] != "MX204" {
		t.Errorf("vendor fields = %v", got.Fields)
	}
}

// timeZero is a fixed instant so the mapping test asserts values, not clocks.
func timeZero() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }
