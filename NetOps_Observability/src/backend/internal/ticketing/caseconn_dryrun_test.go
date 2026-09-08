// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_dryrun_test.go — the DRY RUN's two promises, asserted rather than
// stated: it authenticates for real, and it creates nothing.
//
// The second is the one that needs a test with teeth. A dry run that quietly
// opened a case would be the worst possible bug in this feature, so the fakes
// here COUNT create and attach calls and every case asserts they stayed at zero.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"netops/backend/internal/tac"
)

func dryRunRequest() tac.CaseRequest {
	return tac.CaseRequest{
		TenantID: "t1", IncidentID: "inc-1", DeviceID: "spine1", Hostname: "spine1",
		Platform: "22.4R3-S2", Actor: "user:42",
		Form: tac.CaseForm{
			Title: "OSPF adjacency stuck in ExStart on ae0", Description: "Evidence-only statement.",
			Severity: "P2", Product: "MX960", SerialNumber: "JN123456",
			ContactName: "Jane Doe", ContactEmail: "jane.doe@customer.example",
			BundleName: "correlix-tac-bundle.zip", BundleBytes: 4096, Profile: tac.ProfileFull,
		},
	}
}

func TestDryRunAuthenticatesDescribesAndCreatesNothing(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	open, name := e2eBundle(t, "correlix-tac-bundle.zip", 4096)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case", juniperCfg(), open)

	req := dryRunRequest()
	req.BundlePath = "inc-1/" + name
	rep, err := o.DryRun(context.Background(), req)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if rep.Outcome != tac.DryRunOK {
		t.Fatalf("outcome = %q: %s (blockers %+v)", rep.Outcome, rep.Note, rep.Blockers)
	}
	if !rep.CreatedNothing {
		t.Fatal("a dry run must state that it created nothing")
	}
	// (1) it AUTHENTICATED — the vendor's own read-only endpoint was called.
	if f.lovCalls == 0 {
		t.Fatal("the credential was never exercised — the dry run proved nothing about it")
	}
	// (2) and it created nothing: no createSR, no attach, no S3 object.
	if f.createBody != nil {
		t.Fatalf("a case was CREATED by a dry run: %+v", f.createBody)
	}
	if f.attachBody != nil || f.s3Method != "" {
		t.Fatal("a bundle was uploaded by a dry run")
	}
	// (3) the described call is the documented one, with the documented body.
	var create tac.DryRunCall
	for _, c := range rep.Calls {
		if c.Step == "open the case" {
			create = c
		}
		if c.Step == "authenticate" && !c.Performed {
			t.Fatal("the authenticate step must be marked as actually performed")
		}
	}
	if !strings.Contains(create.URL, "/createsr") {
		t.Fatalf("the described create URL is %q", create.URL)
	}
	byName := map[string]tac.DryRunField{}
	for _, fl := range create.Fields {
		byName[fl.Name] = fl
	}
	for _, want := range []string{"appId", "customerSourceID", "synopsis", "priority", "contactEmail", "softwareVersion"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("the described body is missing the documented field %q: %+v", want, create.Fields)
		}
	}
	if byName["synopsis"].Value != req.Form.Title {
		t.Fatalf("synopsis = %q", byName["synopsis"].Value)
	}
	// (4) nothing rendered is a secret.
	for _, c := range rep.Calls {
		for _, fl := range c.Fields {
			if fl.Secret && fl.Value != "[REDACTED]" {
				t.Fatalf("a secret field rendered its value: %+v", fl)
			}
			if strings.Contains(fl.Value, "jnpr-api-key") {
				t.Fatalf("the stored credential leaked into the report: %+v", fl)
			}
		}
	}
}

func TestDryRunNamesWhatIsMissingAndStillCreatesNothing(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	open, name := e2eBundle(t, "b.zip", 128)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case", juniperCfg(), open)

	req := dryRunRequest()
	req.BundlePath = "inc-1/" + name
	req.Form.SerialNumber = ""
	req.Form.Product = ""
	req.Platform = ""
	rep, err := o.DryRun(context.Background(), req)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if rep.Outcome != tac.DryRunIncomplete {
		t.Fatalf("outcome = %q, want incomplete: %s", rep.Outcome, rep.Note)
	}
	if len(rep.Blockers) == 0 {
		t.Fatal("an incomplete payload must name what is missing")
	}
	if strings.TrimSpace(rep.Note) == "" {
		t.Fatal("an incomplete outcome must carry a sentence an operator can act on")
	}
	if f.createBody != nil {
		t.Fatal("a case was created for an incomplete payload")
	}
}

func TestDryRunReportsARefusedCredentialWithTheVendorsWords(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"errorCode":"401","errorMessage":"Invalid credentials for this appId"}`)
	})
	open, name := e2eBundle(t, "b.zip", 128)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case", juniperCfg(), open)
	req := dryRunRequest()
	req.BundlePath = "inc-1/" + name
	rep, err := o.DryRun(context.Background(), req)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if rep.Outcome != tac.DryRunRefused {
		t.Fatalf("outcome = %q, want refused: %s", rep.Outcome, rep.Note)
	}
	if strings.TrimSpace(rep.Note) == "" {
		t.Fatal("a refusal must carry the vendor's own words")
	}
}

func TestDryRunOnAnUnconfiguredTenantIsAStateNotAnError(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJuniperFake(t)
	open, name := e2eBundle(t, "b.zip", 128)
	o := e2eOpener(t, NewJuniperConnector(f.client()), "juniper", "Juniper Service Case",
		TACConnectorConfig{}, open)
	req := dryRunRequest()
	req.BundlePath = "inc-1/" + name
	rep, err := o.DryRun(context.Background(), req)
	if err != nil {
		t.Fatalf("dry run must not error on an unconfigured tenant: %v", err)
	}
	if rep.Outcome != tac.DryRunNotConfigured {
		t.Fatalf("outcome = %q, want not_configured", rep.Outcome)
	}
	if strings.TrimSpace(rep.Note) == "" {
		t.Fatal("an unconfigured path must say what is missing")
	}
	if f.createBody != nil || f.lovCalls != 0 {
		t.Fatal("an unconfigured tenant must reach no vendor at all")
	}
}

func TestDryRunOnAPortalPathSaysThereIsNothingToRehearse(t *testing.T) {
	c, err := NewPortalOnlyConnector(PortalVendorIDs()[0])
	if err != nil {
		t.Fatalf("portal connector: %v", err)
	}
	open, _ := e2eBundle(t, "b.zip", 16)
	o := e2eOpener(t, c, "nokia", "Nokia portal", TACConnectorConfig{}, open)
	rep, derr := o.DryRun(context.Background(), dryRunRequest())
	// A portal path opens nothing over an API, so it answers with the SENTINEL
	// the service turns into an `unsupported` outcome — never with a validation
	// verdict, which would imply something had been checked.
	if !errors.Is(derr, tac.ErrDryRunUnsupported) {
		t.Fatalf("a portal path must answer ErrDryRunUnsupported, got %v (outcome %q)", derr, rep.Outcome)
	}
	if !rep.CreatedNothing {
		t.Fatal("a portal dry run must state that it created nothing")
	}
}
