package ticketing

// caseconn_config_isolation_test.go — the CLAUDE.md §3a.5 isolation test for
// the per-tenant TAC connector store. TAC credentials are the TENANT's own
// vendor support contract: a leak here would expose one customer's Cisco CCO-ID
// or Juniper appId to another, and worse, let tenant B attach a bundle to
// tenant A's case.
//
// The four required assertions plus the two specific to this feature:
//  1. own-only list
//  2. cross-tenant get → not found (mapped to 404 by the HTTP layer)
//  3. cross-tenant put/delete → refused
//  4. as_tenant into another org is IGNORED for a non-cross caller
//  5. secrets are write-only: never returned, preserved when blank on update
//  6. a case opened under tenant A is never attachable-to from tenant B

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func seededTACStore(t *testing.T) *TACConnectorStore {
	t.Helper()
	s := NewTACConnectorStoreForTest()
	for _, tenant := range []string{"org-a-tenant", "org-b-tenant"} {
		cfg := TACConnectorConfig{
			Cisco: CiscoConnectorConfig{Enabled: true, CCOID: "cco-" + tenant},
			Juniper: JuniperConnectorConfig{
				Enabled: true, AppID: "app-" + tenant, CustomerSourceID: "src-" + tenant,
				UserID: "user-" + tenant, AccountID: "acct-" + tenant,
				AuthMode: "apikey", APIKey: "secret-key-" + tenant,
				DefaultContactEmail: "jane.doe@" + tenant + ".example",
			},
		}
		if err := s.Set(tenant, false, tenant, cfg); err != nil {
			t.Fatalf("seed %s: %v", tenant, err)
		}
	}
	return s
}

func TestTACConnectorStoreListsOnlyTheCallersOwnTenant(t *testing.T) {
	s := seededTACStore(t)

	own := s.Tenants("org-a-tenant", false)
	if len(own) != 1 || own[0] != "org-a-tenant" {
		t.Fatalf("tenant A sees %v, want only its own row", own)
	}
	// A cross-tenant principal (the platform owner) sees everything.
	all := s.Tenants("", true)
	if len(all) != 2 {
		t.Fatalf("cross-tenant sees %v, want both rows", all)
	}
}

func TestTACConnectorStoreCrossTenantGetIsNotFound(t *testing.T) {
	s := seededTACStore(t)

	_, err := s.Get("org-a-tenant", false, "org-b-tenant")
	if !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrTenantNotFound (a 404 never confirms another tenant's row)", err)
	}
	// The same call for its OWN row succeeds, so the refusal is scope, not absence.
	if _, err := s.Get("org-a-tenant", false, "org-a-tenant"); err != nil {
		t.Fatalf("own get: %v", err)
	}
	// A cross-tenant principal may narrow to either.
	if _, err := s.Get("", true, "org-b-tenant"); err != nil {
		t.Fatalf("cross-tenant narrowing: %v", err)
	}
	// …but narrowing to a tenant that has no row still answers "not found",
	// never "here is an empty config you may write to".
	if _, err := s.Get("", true, "org-c-tenant"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("unknown tenant = %v, want ErrTenantNotFound", err)
	}
}

func TestTACConnectorStoreCrossTenantWriteAndDeleteAreRefused(t *testing.T) {
	s := seededTACStore(t)
	hostile := TACConnectorConfig{Cisco: CiscoConnectorConfig{Enabled: true, CCOID: "stolen"}}

	if err := s.Set("org-a-tenant", false, "org-b-tenant", hostile); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("cross-tenant put = %v, want ErrTenantNotFound", err)
	}
	if err := s.Delete("org-a-tenant", false, "org-b-tenant"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrTenantNotFound", err)
	}
	// B's row is untouched.
	b, err := s.Get("org-b-tenant", false, "org-b-tenant")
	if err != nil {
		t.Fatal(err)
	}
	if b.Cisco.CCOID != "cco-org-b-tenant" {
		t.Fatalf("tenant B's config was mutated across the boundary: %q", b.Cisco.CCOID)
	}
}

func TestTACConnectorAsTenantIsIgnoredForANonCrossCaller(t *testing.T) {
	// ResolveTACTenant is the gate the HTTP layer calls with the as_tenant
	// selector. A non-cross caller's selector must be discarded outright — the
	// token is the ONLY source of ownership.
	if got := ResolveTACTenant("org-a-tenant", false, "org-b-tenant"); got != "org-a-tenant" {
		t.Fatalf("as_tenant honoured for a non-cross caller: got %q", got)
	}
	if got := ResolveTACTenant("org-a-tenant", false, ""); got != "org-a-tenant" {
		t.Fatalf("own scope = %q", got)
	}
	// A cross-tenant caller may narrow.
	if got := ResolveTACTenant("", true, "org-b-tenant"); got != "org-b-tenant" {
		t.Fatalf("cross-tenant narrowing = %q", got)
	}
	// "global" collapses to the platform key, matching the ITSM store.
	if got := ResolveTACTenant("global", false, ""); got != "" {
		t.Fatalf("global key = %q, want the platform key", got)
	}
}

func TestTACConnectorSecretsAreWriteOnly(t *testing.T) {
	s := seededTACStore(t)

	listed := s.List("org-a-tenant", false)["org-a-tenant"]
	if listed.Juniper.APIKey != "" || listed.Cisco.ClientSecret != "" || listed.Email.Password != "" {
		t.Fatal("a list surface returned a secret")
	}
	if !listed.SecretsPresent()["juniper.api_key"] {
		// Redacted() clears the value, so "configured" must be reported from the
		// STORED record, not from the redacted copy.
		stored, err := s.Get("org-a-tenant", false, "org-a-tenant")
		if err != nil {
			t.Fatal(err)
		}
		if !stored.SecretsPresent()["juniper.api_key"] {
			t.Fatal("the stored record lost the secret")
		}
	}

	// An update with a BLANK secret keeps the stored one (the UI masks it and
	// never re-sends it).
	updated := TACConnectorConfig{
		Cisco: CiscoConnectorConfig{Enabled: true, CCOID: "cco-updated"},
		Juniper: JuniperConnectorConfig{
			Enabled: true, AppID: "app-org-a-tenant", CustomerSourceID: "src-org-a-tenant",
			UserID: "user-org-a-tenant", AccountID: "acct-org-a-tenant",
			AuthMode: "apikey", APIKey: "", // blank: keep the stored key
			DefaultContactEmail: "jane.doe@org-a-tenant.example",
		},
	}
	if err := s.Set("org-a-tenant", false, "", updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	stored, err := s.Get("org-a-tenant", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Juniper.APIKey != "secret-key-org-a-tenant" {
		t.Fatalf("a blank secret on update wiped the stored one: %q", stored.Juniper.APIKey)
	}
	if stored.Cisco.CCOID != "cco-updated" {
		t.Fatalf("the non-secret update did not apply: %q", stored.Cisco.CCOID)
	}
}

func TestTACConnectorOwnerIsStampedFromScopeNotPayload(t *testing.T) {
	s := NewTACConnectorStoreForTest()
	// The record carries no tenant field at all, by design — but the ITSM
	// connection block, which DOES, must never be persisted from the payload.
	in := TACConnectorConfig{
		Cisco: CiscoConnectorConfig{Enabled: true, CCOID: "cco-1"},
		ITSM:  SystemConfig{TenantID: "org-b-tenant", InstanceURL: "https://b.example", Password: "leak"},
	}
	if err := s.Set("org-a-tenant", false, "", in); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("org-a-tenant", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.ITSM != (SystemConfig{}) {
		t.Fatalf("the caller-supplied ITSM connection was persisted: %+v", got.ITSM)
	}
	if _, err := s.Get("org-b-tenant", false, ""); !errors.Is(err, ErrTenantNotFound) {
		t.Fatal("the payload's tenant id created a row it should not have")
	}
}

func TestACaseOpenedUnderOneTenantIsNotAttachableFromAnother(t *testing.T) {
	// The feature-specific §3a assertion: tenant B must not be able to drive an
	// attach with tenant A's connector configuration. B cannot READ A's config,
	// so it cannot construct the call — and the connector refuses an empty one.
	s := seededTACStore(t)
	f := newCiscoFakes(t)
	c := NewCiscoCXDConnector(f.client())

	cfgForB, err := s.Get("org-b-tenant", false, "org-a-tenant")
	if !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("tenant B read tenant A's connector config: %v", err)
	}
	// cfgForB is the zero value; the connector must refuse rather than fall back
	// to some ambient default.
	_, err = c.AttachBundle(context.Background(), cfgForB,
		CaseRef{Number: "695123456", UploadToken: "stolen-token"}, testBundle("b.zip", 8))
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("attach with an unconfigured tenant = %v, want ErrNotConfigured", err)
	}
	if f.cxdCalls != 0 {
		t.Fatal("a cross-tenant attach reached the vendor")
	}
}

func TestTACConnectorConfigValidationIsOptIn(t *testing.T) {
	// A disabled connector is never validated: opt-in means an empty block is
	// legal, not an error the operator has to clear.
	if err := ValidateTACConnectorConfig(TACConnectorConfig{}); err != nil {
		t.Fatalf("an all-disabled record must validate: %v", err)
	}
	// An ENABLED but incomplete one must not.
	bad := TACConnectorConfig{Email: EmailConnectorConfig{Enabled: true}}
	if err := ValidateTACConnectorConfig(bad); err == nil {
		t.Fatal("an enabled email connector with no host must be refused")
	}
	badJira := TACConnectorConfig{Jira: JiraAttachConfig{Enabled: true, Deployment: "onprem-ish"}}
	if err := ValidateTACConnectorConfig(badJira); err == nil ||
		!strings.Contains(err.Error(), "deployment") {
		t.Fatalf("err = %v, want the deployment enum enforced", err)
	}
}

func TestNamedHumanEmailRule(t *testing.T) {
	for addr, want := range map[string]bool{
		"jane.doe@example.com": true,
		"j.smith@example.com":  true,
		"noc@example.com":      false,
		"support@example.com":  false,
		"no-reply@example.com": false,
		"tac@example.com":      false,
		"not-an-address":       false,
		"@example.com":         false,
		"jane@":                false,
	} {
		if got := isNamedHumanEmail(addr); got != want {
			t.Errorf("isNamedHumanEmail(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestTACAuditEventNeverCarriesASecret(t *testing.T) {
	var captured CaseAuditEvent
	sink := funcSink(func(e CaseAuditEvent) { captured = e })
	f := newCiscoFakes(t)
	inner := NewCiscoCXDConnector(f.client())
	a := AuditedConnector{Inner: inner, Sink: sink, TenantID: "org-a-tenant",
		Actor: "user:42", Vendor: "cisco", IncidentID: "P-000123", DeviceID: "spine1"}

	b := testBundle("bundle.zip", 64)
	if _, err := a.AttachBundle(context.Background(), ciscoCfg(),
		CaseRef{Number: "695123456", UploadToken: "per-case-token"}, b); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if captured.Action != "attach" || captured.Result != "ok" {
		t.Fatalf("event = %+v", captured)
	}
	if captured.BundleSHA256 != "abc123" || captured.BundleBytes != 64 {
		t.Errorf("the bundle digest and size are the link between collected and delivered: %+v", captured)
	}
	if captured.TenantID != "org-a-tenant" || captured.IncidentID != "P-000123" || captured.DeviceID != "spine1" {
		t.Errorf("event lost its context: %+v", captured)
	}
	// The per-case CXD token must appear nowhere in the audit row.
	blob := captured.CaseID + captured.CaseNumber + captured.Error + captured.Transport + captured.Actor
	if strings.Contains(blob, "per-case-token") {
		t.Fatal("the ephemeral upload token leaked into the audit trail")
	}
}

// funcSink adapts a function to CaseAuditSink.
type funcSink func(CaseAuditEvent)

func (f funcSink) RecordCaseAction(e CaseAuditEvent) { f(e) }

func TestAuditedCreateRecordsTheApprovingHuman(t *testing.T) {
	var captured CaseAuditEvent
	f := newCiscoFakes(t)
	a := AuditedConnector{
		Inner:    NewCiscoSmartBondingConnector(f.client()),
		Sink:     funcSink(func(e CaseAuditEvent) { captured = e }),
		TenantID: "org-a-tenant", Actor: "user:42", Vendor: "cisco",
	}
	when := time.Now().UTC().Truncate(time.Second)
	// The create fails (no onboarding), which is exactly the case worth auditing.
	_, _ = a.CreateCase(context.Background(), ciscoCfg(), CaseRequest{
		Approval: Approval{Actor: "user:42", ApprovedAt: when},
	})
	if captured.Action != "create" || captured.Result != "error" {
		t.Fatalf("event = %+v", captured)
	}
	if captured.ApprovedBy != "user:42" || !captured.ApprovedAt.Equal(when) {
		t.Errorf("the approving human must be on the record: %+v", captured)
	}
	if captured.Error == "" {
		t.Error("a failed action must record why")
	}
}
