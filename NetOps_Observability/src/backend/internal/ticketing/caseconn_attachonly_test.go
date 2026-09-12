// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_attachonly_test.go — what an ATTACH-TO-EXISTING route may demand of
// the operator before it will submit.
//
// There are two shapes of attach-only route and they need different things.
// Cisco CXD authenticates the upload with the SR number and a per-case token
// copied out of Support Case Manager. The email routes address the vendor's
// attach mailbox and put the SR number in the subject; they read no token and
// have nowhere to put one. Demanding a token from BOTH made the shipped
// `email-cisco` route impossible to submit: the operator was blocked on a
// credential the transport never uses.
//
// The required-field table (caseconn_required.go, source of record
// TAC_CASE_FIELDS_2026-09-07.md §3) already says exactly this, connector by
// connector. This file pins that the submit gate reads it.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/tac"
)

// recordingEmailAttachOnly has the email-attach shape: attach to an existing
// case, no create, and NO per-case upload credential.
type recordingEmailAttachOnly struct{ onAttach func(CaseRef) }

func (r *recordingEmailAttachOnly) Name() string { return "email-cisco" }
func (r *recordingEmailAttachOnly) Capabilities() Caps {
	return Caps{Attach: true, AttachToExistingOnly: true, MaxAttachBytes: 20 << 20}
}
func (r *recordingEmailAttachOnly) ValidateConfig(TACConnectorConfig) error { return nil }
func (r *recordingEmailAttachOnly) CreateCase(context.Context, TACConnectorConfig, CaseRequest) (CaseRef, error) {
	return CaseRef{}, ErrUnsupported
}
func (r *recordingEmailAttachOnly) AttachBundle(_ context.Context, _ TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if r.onAttach != nil {
		r.onAttach(ref)
	}
	return AttachResult{Name: b.Name, Size: b.Size, Transport: "email"}, nil
}
func (r *recordingEmailAttachOnly) FetchCase(context.Context, TACConnectorConfig, CaseRef) (RemoteCase, bool, error) {
	return RemoteCase{}, false, ErrUnsupported
}
func (r *recordingEmailAttachOnly) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return ErrUnsupported
}

// TestAttachOnlyUploadTokenIsAskedForOnlyWhereItIsUsed reads the rule straight
// off the table.
func TestAttachOnlyUploadTokenIsAskedForOnlyWhereItIsUsed(t *testing.T) {
	if !attachOnlyNeedsUploadToken("cisco-cxd") {
		t.Error("cisco-cxd attaches with the token as its Basic-auth password; it must still be demanded")
	}
	for _, id := range []string{"email-cisco", "email-arista"} {
		if attachOnlyNeedsUploadToken(id) {
			t.Errorf("%s reads no upload token, so demanding one blocks a route that would otherwise work", id)
		}
	}
	// Fail closed on a connector the table has never heard of.
	if !attachOnlyNeedsUploadToken("not-a-connector") {
		t.Error("an unknown connector must fail closed, not be waved through")
	}
}

// TestEmailAttachRouteSubmitsWithTheCaseNumberAlone is the regression. This is
// the whole defect: the SR number is sufficient, and the route used to be
// unsubmittable.
func TestEmailAttachRouteSubmitsWithTheCaseNumberAlone(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "correlix-bundle.zip")
	if err := os.WriteFile(bundlePath, []byte("PK\x03\x04 evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := FileBundleOpener(func(string) string { return dir }, func(string) string { return "sha-of-bundle" })

	var gotRef CaseRef
	fake := &recordingEmailAttachOnly{onAttach: func(ref CaseRef) { gotRef = ref }}
	o := NewTACOpener(fake, "cisco", "Cisco by email", testResolver(ciscoCfg()), open)

	req := tac.CaseRequest{
		TenantID: "org-a-tenant", IncidentID: "P-000123", DeviceID: "leaf1",
		Actor: "user:42", BundlePath: bundlePath,
		Form: tac.CaseForm{ExistingCaseNumber: "695123456", Profile: tac.ProfileFull},
		// No Secrets at all: the email transport reads none.
	}

	// The confirmation screen must not name a field the operator cannot fill.
	form, err := o.PrepareCase(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(form.MissingFields, " | "); strings.Contains(joined, "upload_token") {
		t.Fatalf("the email route demands a credential it never sends: %v", form.MissingFields)
	}

	res, err := o.SubmitCase(context.Background(), req)
	if err != nil {
		t.Fatalf("the email attach route refused a complete form: %v", err)
	}
	if res.CaseID != "695123456" || res.Status != "existing" {
		t.Fatalf("result = %+v — the case it attached to must be reported back", res)
	}
	if !res.Attached {
		t.Fatalf("the bundle was not attached: %s", res.AttachNote)
	}
	if gotRef.Number != "695123456" {
		t.Fatalf("the connector received %+v — the SR number must cross", gotRef)
	}
	if gotRef.UploadToken != "" {
		t.Fatalf("a token was invented for a route that reads none: %+v", gotRef)
	}
}

// TestEmailAttachRouteStillNeedsTheCaseNumber keeps the other half honest: the
// SR number is the ONE thing this route cannot do without, and the refusal
// names it.
func TestEmailAttachRouteStillNeedsTheCaseNumber(t *testing.T) {
	o := NewTACOpener(&recordingEmailAttachOnly{}, "cisco", "Cisco by email", testResolver(ciscoCfg()), nil)
	_, err := o.SubmitCase(context.Background(), tac.CaseRequest{TenantID: "org-a-tenant", Actor: "user:42"})
	if !errors.Is(err, tac.ErrFormIncomplete) {
		t.Fatalf("err = %v, want ErrFormIncomplete", err)
	}
	if !strings.Contains(err.Error(), "existing_case_number") {
		t.Fatalf("the refusal does not name the SR number: %v", err)
	}
	if strings.Contains(err.Error(), "upload_token") {
		t.Fatalf("the refusal still demands a token this route never sends: %v", err)
	}
}

// TestDryRunDoesNotPromiseATokenTheEmailRouteNeverSends — the rehearsal has to
// match what the submit actually does.
func TestDryRunDoesNotPromiseATokenTheEmailRouteNeverSends(t *testing.T) {
	req := tac.CaseRequest{
		TenantID: "org-a-tenant", Actor: "user:42",
		Form: tac.CaseForm{ExistingCaseNumber: "695123456", BundleName: "bundle.zip", BundleBytes: 1024},
	}

	email := NewTACOpener(&recordingEmailAttachOnly{}, "cisco", "Cisco by email", testResolver(ciscoCfg()), nil)
	rep, err := email.DryRun(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dryRunMentionsUploadToken(rep) {
		t.Fatalf("the email route's rehearsal shows an upload_token field: %+v", rep.Calls)
	}

	cxd := NewTACOpener(&recordingAttachOnly{}, "cisco", "Cisco CXD", testResolver(ciscoCfg()), nil)
	rep, err = cxd.DryRun(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !dryRunMentionsUploadToken(rep) {
		t.Fatalf("the CXD rehearsal dropped the credential it really does send: %+v", rep.Calls)
	}
}

func dryRunMentionsUploadToken(rep tac.DryRunReport) bool {
	for _, c := range rep.Calls {
		for _, f := range c.Fields {
			if f.Name == "upload_token" {
				return true
			}
		}
	}
	for _, b := range rep.Blockers {
		if strings.Contains(b.Key, "upload_token") || strings.Contains(b.Label, "upload_token") {
			return true
		}
	}
	return false
}
