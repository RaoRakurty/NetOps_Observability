// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// escalate_test.go — the ONE ACTION, proven end to end against fake connectors.
//
// The properties asserted here are the product promises, not implementation
// details: the route is chosen by the documented ladder and SAYS which rung it
// used; the confirmation screen arrives already filled in from the device record
// and the tenant's contract settings; a missing entitlement field REFUSES BY
// NAME with the place it is set; and nothing anywhere in Escalate or Prepare can
// cause a case to exist — only Confirm can, and only with a named human.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// recordingOpener is a connector that remembers whether anything was SENT. It
// is the instrument for the claim on the confirmation screen: if Escalate or
// Prepare ever reached a vendor, `submits` would not be zero.
type recordingOpener struct {
	info    ConnectorInfo
	submits int
	last    CaseRequest
	result  CaseResult
	err     error
	// prepared counts PrepareCase calls, which are allowed and must stay local.
	prepared int
}

func (o *recordingOpener) Info(context.Context, string) ConnectorInfo { return o.info }

func (o *recordingOpener) PrepareCase(_ context.Context, req CaseRequest) (CaseForm, error) {
	o.prepared++
	form := req.Form
	form.ConnectorID = o.info.ID
	form.PortalText = "Correlix case text for " + o.info.ID
	// A real adapter fills MissingRequired from its own vendor table; the fake
	// mirrors that from the info it declares, which is the same contract.
	have := map[string]string{
		"serial_number": form.SerialNumber,
		"contract_id":   form.ContractID,
		"contact_email": form.ContactEmail,
		"product":       form.Product,
		"pid":           form.Product,
	}
	for _, r := range o.info.Required {
		if strings.TrimSpace(have[r.Key]) == "" {
			form.MissingRequired = append(form.MissingRequired, r)
		}
	}
	if len(form.MissingRequired) > 0 {
		names := make([]string, 0, len(form.MissingRequired))
		for _, m := range form.MissingRequired {
			names = append(names, m.Label+" ("+m.SettingsHint+")")
		}
		form.MissingNote = o.info.Display + " needs " + strings.Join(names, "; ")
	}
	return form, nil
}

func (o *recordingOpener) SubmitCase(_ context.Context, req CaseRequest) (CaseResult, error) {
	o.submits++
	o.last = req
	if o.err != nil {
		return CaseResult{}, o.err
	}
	res := o.result
	res.ConnectorID = o.info.ID
	if res.CaseID == "" {
		res.CaseID = "CASE-" + o.info.ID
	}
	return res, nil
}

func (o *recordingOpener) PollStatus(_ context.Context, _, caseID string) (CaseResult, error) {
	if !o.info.Can(CapPollStatus) {
		return CaseResult{}, ErrCapabilityUnsupported
	}
	return CaseResult{ConnectorID: o.info.ID, CaseID: caseID, Status: "Open"}, nil
}

// vendorConnector builds a configured, create+attach connector for a vendor.
func vendorConnector(id, vendor, display string, required ...RequiredField) *recordingOpener {
	return &recordingOpener{info: ConnectorInfo{
		ID: id, Vendor: vendor, Display: display, Configured: true,
		Capabilities:       []CaseCapability{CapCreate, CapAttach, CapPollStatus, CapLink},
		MaxAttachmentBytes: 1 << 30, AuthMode: "oauth", Required: required,
	}}
}

func emailConnector(vendor string) *recordingOpener {
	return &recordingOpener{info: ConnectorInfo{
		ID: "email-" + vendor, Vendor: vendor, Display: strings.ToUpper(vendor[:1]) + vendor[1:] + " support email",
		Configured: true, Capabilities: []CaseCapability{CapCreate, CapAttach},
		MaxAttachmentBytes: 14_000_000, AuthMode: "smtp",
	}}
}

// escalationFixture builds a service with a collected capture ready to bundle.
func escalationFixture(t *testing.T, dev Device, openers ...CaseOpener) (*Service, *Plan) {
	t.Helper()
	cat := mustCatalog(t)
	p, err := cat.Plan("bgp-session", dev, PlanOptions{Target: Target{Peer: "192.0.2.1"}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "line one\nline two\n"
	}
	col := testCollector(t, f, WithClock(fixedClock()))
	opts := []ServiceOption{WithCollector(col), WithServiceClock(fixedClock())}
	if len(openers) > 0 {
		opts = append(opts, WithOpeners(openers...))
	}
	svc, err := NewService(cat, opts...)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return svc, p
}

// escalateAndCollect runs click one and waits for the collection to land.
func escalateAndCollect(t *testing.T, svc *Service, dev Device, req EscalateRequest,
	settings EscalationSettings) EscalationRoute {
	t.Helper()
	ctx := context.Background()
	infos := svc.Connectors(ctx, dev.TenantID)
	_, route, err := svc.Escalate(ctx, dev.TenantID, "inc-1", dev, Evidence{
		IncidentID: "inc-1", TenantID: dev.TenantID, Alerts: []string{"BGPSessionDown"},
	}, req, settings, infos)
	if err != nil {
		t.Fatalf("escalate: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := svc.Get(dev.TenantID, "inc-1")
		if st != nil && st.Capture != nil {
			return route
		}
		if time.Now().After(deadline) {
			t.Fatal("the collection never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func ciscoDevice() Device {
	d := iosxeDevice()
	d.TenantID = "t1"
	d.Vendor = "cisco"
	d.Serial = "FTX1234ABCD"
	d.Model = "C9300-48P"
	return d
}

// TestOneClickEscalationChoosesTheTenantRoute — the tenant said where Cisco
// cases go, so that is where this one goes, and the screen says why.
func TestOneClickEscalationChoosesTheTenantRoute(t *testing.T) {
	dev := ciscoDevice()
	native := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding")
	snow := vendorConnector("servicenow", "servicenow", "ServiceNow incident")
	svc, _ := escalationFixture(t, dev, native, snow)
	settings := EscalationSettings{
		ContactName: "Dana Ops", ContactEmail: "dana.ops@example.test",
		RouteByVendor: map[string]string{"cisco": "servicenow"},
		ContractID:    "CT-99",
	}
	route := escalateAndCollect(t, svc, dev, EscalateRequest{Severity: "S2"}, settings)
	if route.ConnectorID != "servicenow" {
		t.Fatalf("route = %q, want the tenant's own choice", route.ConnectorID)
	}
	if route.Reason != RouteTenantChoice {
		t.Fatalf("reason = %q, want %q", route.Reason, RouteTenantChoice)
	}
	if !strings.Contains(route.Note, "routed Cisco") {
		t.Fatalf("the note must say why: %q", route.Note)
	}
	if native.submits != 0 || snow.submits != 0 {
		t.Fatal("Escalate reached a vendor — it must not be able to")
	}
}

// TestOneClickEscalationFallsBackDownTheLadder covers the remaining rungs.
func TestOneClickEscalationFallsBackDownTheLadder(t *testing.T) {
	cases := []struct {
		name    string
		vendor  string
		openers []CaseOpener
		wantID  string
		wantWhy RouteReason
	}{
		{
			name: "vendor native API when it is configured", vendor: "juniper",
			openers: []CaseOpener{vendorConnector("juniper", "juniper", "Juniper Service Case")},
			wantID:  "juniper", wantWhy: RouteVendorNative,
		},
		{
			name: "the vendor's mailbox when that is all there is", vendor: "arista",
			openers: []CaseOpener{emailConnector("arista")},
			wantID:  "email-arista", wantWhy: RouteVendorEmail,
		},
		{
			name: "portal text when the vendor's own path is unconfigured", vendor: "nokia",
			openers: []CaseOpener{&recordingOpener{info: ConnectorInfo{
				ID: "portal-nokia", Vendor: "nokia", Display: "Nokia portal", Configured: false,
			}}},
			wantID: PortalTextConnectorID, wantWhy: RoutePortalFallback,
		},
		{
			name: "portal text when nothing is wired at all", vendor: "fortinet",
			openers: nil,
			wantID:  PortalTextConnectorID, wantWhy: RoutePortalFallback,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := ciscoDevice()
			dev.Vendor = tc.vendor
			svc, _ := escalationFixture(t, dev, tc.openers...)
			route := escalateAndCollect(t, svc, dev, EscalateRequest{}, EscalationSettings{})
			if route.ConnectorID != tc.wantID {
				t.Fatalf("route = %q, want %q", route.ConnectorID, tc.wantID)
			}
			if route.Reason != tc.wantWhy {
				t.Fatalf("reason = %q, want %q", route.Reason, tc.wantWhy)
			}
			if strings.TrimSpace(route.Note) == "" {
				t.Fatal("every route must explain itself")
			}
		})
	}
}

// TestTenantRouteToAnUnconfiguredConnectorIsHonouredAndThenRefused — a
// deliberate setting is never silently rerouted.
func TestTenantRouteToAnUnconfiguredConnectorIsHonouredAndThenRefused(t *testing.T) {
	dev := ciscoDevice()
	unconfigured := &recordingOpener{info: ConnectorInfo{
		ID: "cisco-smart-bonding", Vendor: "cisco", Display: "Cisco Smart Bonding",
		Configured: false, StatusNote: NotConfiguredNote,
		Capabilities: []CaseCapability{CapCreate, CapAttach},
	}}
	email := emailConnector("cisco")
	svc, _ := escalationFixture(t, dev, unconfigured, email)
	settings := EscalationSettings{RouteByVendor: map[string]string{"cisco": "cisco-smart-bonding"}}
	route := escalateAndCollect(t, svc, dev, EscalateRequest{}, settings)
	if route.ConnectorID != "cisco-smart-bonding" {
		t.Fatalf("the tenant's choice was silently rerouted to %q", route.ConnectorID)
	}
	if route.Configured {
		t.Fatal("an unconfigured connector must be reported as unconfigured")
	}
	if !strings.Contains(route.Note, "credentials") {
		t.Fatalf("the note must say what is missing: %q", route.Note)
	}
	p := prepare(t, svc, dev, EscalateRequest{})
	if p.Ready {
		t.Fatal("a proposal on an unconfigured connector must not be ready to send")
	}
	if _, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "dana", p.Form, CaseSecrets{}); err == nil {
		t.Fatal("Confirm must refuse when the route has no credentials")
	}
}

// NotConfiguredNote mirrors the adapter's own sentence, so the fixture reads
// like the thing it stands in for.
const NotConfiguredNote = "No credentials for this tenant yet — bring your own to use it."

func prepare(t *testing.T, svc *Service, dev Device, req EscalateRequest) *Proposal {
	t.Helper()
	ctx := context.Background()
	p, err := svc.Prepare(ctx, dev.TenantID, "inc-1", BundleInput{
		TenantID: dev.TenantID, IncidentID: "inc-1", IncidentRef: "INC-1", Title: "BGP down",
		Actor: "dana",
	}, req, "dana", svc.Connectors(ctx, dev.TenantID))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return p
}

// TestConfirmationScreenArrivesComplete is the owner's whole point: the serial
// comes from the device record, the contract and contact from the tenant's
// settings, and the operator has nothing left to type.
func TestConfirmationScreenArrivesComplete(t *testing.T) {
	dev := ciscoDevice()
	cisco := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding",
		RequiredField{Key: "serial_number", Label: "a serial number", SettingsHint: "the device record"},
		RequiredField{Key: "contact_email", Label: "a contact email", SettingsHint: "Administration → Ticket delivery"},
	)
	svc, _ := escalationFixture(t, dev, cisco)
	settings := EscalationSettings{
		ContactName: "Dana Ops", ContactEmail: "dana.ops@example.test",
		ContractID: "CT-99", AccountID: "cco-dana",
	}
	escalateAndCollect(t, svc, dev, EscalateRequest{Severity: "S2"}, settings)
	p := prepare(t, svc, dev, EscalateRequest{Severity: "S2"})

	if p.Form.SerialNumber != "FTX1234ABCD" {
		t.Fatalf("the serial must come from the device record, got %q", p.Form.SerialNumber)
	}
	if p.Form.Product != "C9300-48P" {
		t.Fatalf("the model must come from the device record, got %q", p.Form.Product)
	}
	if p.Form.ContractID != "CT-99" {
		t.Fatalf("the contract must come from the tenant's settings, got %q", p.Form.ContractID)
	}
	if p.Form.ContactEmail != "dana.ops@example.test" || p.Form.ContactName != "Dana Ops" {
		t.Fatalf("the contact must come from the tenant's settings, got %+v", p.Form)
	}
	if strings.TrimSpace(p.Form.Title) == "" || !strings.Contains(p.Form.Title, dev.Hostname) {
		t.Fatalf("the title must name the device, got %q", p.Form.Title)
	}
	if strings.TrimSpace(p.Form.Description) == "" {
		t.Fatal("the description must be the problem statement")
	}
	if p.Bundle.Name == "" || p.Bundle.Bytes <= 0 {
		t.Fatalf("the bundle must be built before the screen renders: %+v", p.Bundle)
	}
	if !p.Ready {
		t.Fatalf("a complete proposal must be ready, blockers: %+v (%s)", p.Blockers, p.BlockerNote)
	}
	if p.Approval != ApprovalSentence {
		t.Fatal("the screen must carry the approval sentence verbatim")
	}
	if !strings.Contains(p.Redaction, "[REDACTED]") {
		t.Fatal("the screen must restate the redaction promise")
	}
	if cisco.submits != 0 {
		t.Fatal("Prepare sent something — it must not be able to")
	}
}

// TestConfirmationRefusesAMissingEntitlementFieldByName — the vendor's own
// requirement, named, with the place it is set.
func TestConfirmationRefusesAMissingEntitlementFieldByName(t *testing.T) {
	dev := ciscoDevice()
	dev.Serial = "" // the inventory never learned it
	cisco := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding",
		RequiredField{
			Key: "serial_number", Label: "a serial number",
			Why:          "Cisco checks entitlement on the chassis serial at create time",
			SettingsHint: "Administration → Ticket delivery → Vendor contracts, or the device record",
			AnyOf:        "entitlement", Alt: "serial",
		},
		RequiredField{
			Key: "contract_id", Label: "a contract id", Why: "the software alternative to a serial",
			SettingsHint: "Administration → Ticket delivery → Vendor contracts",
			AnyOf:        "entitlement", Alt: "contract",
		},
		RequiredField{
			Key: "pid", Label: "a PID", Why: "Cisco takes the contract with the product id",
			SettingsHint: "Administration → Ticket delivery → Vendor contracts",
			AnyOf:        "entitlement", Alt: "contract",
		},
	)
	svc, _ := escalationFixture(t, dev, cisco)
	escalateAndCollect(t, svc, dev, EscalateRequest{}, EscalationSettings{ContactEmail: "dana@example.test"})
	p := prepare(t, svc, dev, EscalateRequest{})
	if p.Ready {
		t.Fatal("a proposal missing the vendor's entitlement data must not be ready")
	}
	if len(p.Blockers) == 0 {
		t.Fatal("the blockers must be named, not merely counted")
	}
	if !strings.Contains(p.BlockerNote, "serial number") {
		t.Fatalf("the refusal must name the field: %q", p.BlockerNote)
	}
	var hinted bool
	for _, b := range p.Blockers {
		if strings.Contains(b.SettingsHint, "Ticket delivery") {
			hinted = true
		}
	}
	if !hinted {
		t.Fatal("every blocker must say where the value is set")
	}
	// Confirm refuses with the same words.
	_, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "dana", p.Form, CaseSecrets{})
	if err == nil {
		t.Fatal("Confirm must refuse an incomplete case")
	}
	if !errors.Is(err, ErrFormIncomplete) || !strings.Contains(err.Error(), "serial number") {
		t.Fatalf("the refusal must name the field: %v", err)
	}
	if cisco.submits != 0 {
		t.Fatal("an incomplete case reached the vendor")
	}
	// Filling ONE alternative in on the screen is enough, and then it sends.
	form := p.Form
	form.SerialNumber = "FTX9999ZZZZ"
	res, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "dana", form, CaseSecrets{})
	if err != nil {
		t.Fatalf("a completed case must send: %v", err)
	}
	if cisco.submits != 1 || res.CaseID == "" {
		t.Fatalf("the case did not reach the connector: submits=%d res=%+v", cisco.submits, res)
	}
	if cisco.last.Form.SerialNumber != "FTX9999ZZZZ" {
		t.Fatalf("the operator's edit did not reach the connector: %+v", cisco.last.Form)
	}
	if cisco.last.Actor != "dana" {
		t.Fatal("the case must carry the named human who pressed the button")
	}
}

// TestConfirmRefusesWithoutANamedHuman — the whole claim in one assertion.
func TestConfirmRefusesWithoutANamedHuman(t *testing.T) {
	dev := ciscoDevice()
	cisco := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding")
	svc, _ := escalationFixture(t, dev, cisco)
	escalateAndCollect(t, svc, dev, EscalateRequest{}, EscalationSettings{})
	p := prepare(t, svc, dev, EscalateRequest{})
	if _, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "  ", p.Form, CaseSecrets{}); err == nil {
		t.Fatal("a case with no actor must be refused")
	}
	if cisco.submits != 0 {
		t.Fatal("a case was opened with no named human")
	}
}

// TestConfirmRefusesWithoutAPreparedProposal — a client cannot skip the screen.
func TestConfirmRefusesWithoutAPreparedProposal(t *testing.T) {
	dev := ciscoDevice()
	cisco := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding")
	svc, _ := escalationFixture(t, dev, cisco)
	escalateAndCollect(t, svc, dev, EscalateRequest{}, EscalationSettings{})
	_, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "dana", CaseForm{}, CaseSecrets{})
	if err == nil {
		t.Fatal("Confirm without a proposal must be refused")
	}
	if cisco.submits != 0 {
		t.Fatal("a case was opened without the confirmation screen")
	}
}

// TestPortalPathIsACompleteOutcome — the minimum an operator can have is still
// everything they need.
func TestPortalPathIsACompleteOutcome(t *testing.T) {
	dev := ciscoDevice()
	dev.Vendor = "nokia"
	svc, _ := escalationFixture(t, dev)
	escalateAndCollect(t, svc, dev, EscalateRequest{}, EscalationSettings{})
	p := prepare(t, svc, dev, EscalateRequest{})
	if !p.Route.Portal {
		t.Fatal("the fallback must be marked as a portal path")
	}
	if !p.Ready {
		t.Fatalf("the portal path is a complete outcome and must be ready: %s", p.BlockerNote)
	}
	if strings.TrimSpace(p.Form.PortalText) == "" {
		t.Fatal("the portal path must hand over pre-filled case text")
	}
	if p.Bundle.Name == "" {
		t.Fatal("the portal path must hand over the bundle")
	}
	res, err := svc.Confirm(context.Background(), dev.TenantID, "inc-1", "dana", p.Form, CaseSecrets{})
	if err != nil {
		t.Fatalf("confirming a portal path must succeed: %v", err)
	}
	if res.CaseID != "" {
		t.Fatal("a portal path opens no case, so it must return no case id")
	}
	if strings.TrimSpace(res.PortalText) == "" {
		t.Fatal("the result must echo the text the operator now pastes")
	}
}

// TestEscalationWarnsAboutAnExpiredContractWithoutBlocking — Correlix does not
// get to decide that a vendor will refuse.
func TestEscalationWarnsAboutAnExpiredContractWithoutBlocking(t *testing.T) {
	dev := ciscoDevice()
	cisco := vendorConnector("cisco-smart-bonding", "cisco", "Cisco Smart Bonding")
	svc, _ := escalationFixture(t, dev, cisco)
	settings := EscalationSettings{
		ContactEmail: "dana@example.test", ContractID: "CT-1",
		ContractExpires: "2025-01-01", ContractExpired: true,
	}
	escalateAndCollect(t, svc, dev, EscalateRequest{}, settings)
	p := prepare(t, svc, dev, EscalateRequest{})
	if !p.Ready {
		t.Fatal("an expired contract is a warning, not a refusal")
	}
	var warned bool
	for _, w := range p.Warnings {
		if strings.Contains(w, "2025-01-01") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the expiry must be shown: %v", p.Warnings)
	}
}

// TestPreferredCaptureIDReadsTheTenantSetting.
func TestPreferredCaptureIDReadsTheTenantSetting(t *testing.T) {
	settings := EscalationSettings{CaptureByDialect: map[string]string{"cisco-iosxe": "tmpl-1"}}
	if id, ok := PreferredCaptureID(settings, "Cisco-IOSXE"); !ok || id != "tmpl-1" {
		t.Fatalf("preferred capture = %q %v", id, ok)
	}
	if _, ok := PreferredCaptureID(settings, "arista-eos"); ok {
		t.Fatal("a dialect with no preference must report none")
	}
}
