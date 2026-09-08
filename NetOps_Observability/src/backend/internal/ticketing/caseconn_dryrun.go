// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_dryrun.go — the connector half of the DRY RUN.
//
// It answers one question a customer cannot otherwise answer without opening a
// real case during a real outage: *will this work?* Two halves, and the split
// matters:
//
//	AUTHENTICATE  a REAL call to the configured endpoint with the stored
//	              credential, through ProbeConnector — the same read-only check
//	              the Test button in Administration makes, so the two can never
//	              disagree about what "configured" means.
//	DESCRIBE      the case payload that WOULD be sent, field by field, with the
//	              vendor's own field names where the tenant's onboarding bound
//	              them, every secret redacted, and every validation the vendor's
//	              schema and this platform's required-field table impose already
//	              applied.
//
// NOTHING IS CREATED, and that is structural rather than promised: this file
// calls Probe and it calls the vendor packages' own Validate; it does not call
// CreateCase or AttachBundle, and there is no branch here that could.
//
// HONESTY ABOUT WHAT IS DESCRIBED. Where a vendor publishes its create schema
// (Juniper's createSR), the described body is that schema, validated by the
// vendor package itself. Where a vendor does NOT (Cisco's push/call body is
// issued per onboarding project), the report says so and describes the canonical
// fields plus the tenant's own field-map binding — which is the part a customer
// can actually check against their onboarding paperwork.

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/tac"
	"netops/backend/internal/ticketing/vendors/cisco"
	"netops/backend/internal/ticketing/vendors/juniper"
)

// dryRunProbeTimeout bounds the ONE real call a dry run makes (§9).
const dryRunProbeTimeout = 15 * time.Second

// DryRun implements tac.CaseDryRunner.
func (o *TACOpener) DryRun(ctx context.Context, req tac.CaseRequest) (tac.DryRunReport, error) {
	caps := o.Connector.Capabilities()
	rep := tac.DryRunReport{
		ConnectorID: o.Connector.Name(), Display: orDefault(o.Display, o.Connector.Name()),
		CreatedNothing: true, Calls: []tac.DryRunCall{},
	}
	// A path that opens nothing over an API has no call to rehearse. Saying so
	// is a COMPLETE answer — the operator still gets the case text, the bundle
	// and the portal link — and it is a different answer from "your credentials
	// are wrong", which is what a validation run against no credentials would
	// have implied.
	if !caps.Create && !caps.Attach {
		return rep, tac.ErrDryRunUnsupported
	}
	cfg, err := o.tenantConfig(ctx, req.TenantID)
	if err != nil {
		rep.Outcome, rep.Note = tac.DryRunNotConfigured, translateToTAC(err).Error()
		return rep, nil
	}
	rep.AuthMode = tacAuthMode(o.Connector.Name(), cfg)
	if verr := o.Connector.ValidateConfig(cfg); verr != nil {
		rep.Outcome, rep.Note = tac.DryRunNotConfigured, verr.Error()
		return rep, nil
	}

	// ── (1) the one real call: authenticate ─────────────────────────────────
	probe := ProbeConnector(ctx, o.Connector, cfg, dryRunProbeTimeout, o.now)
	rep.ElapsedMS = probe.ElapsedMS
	rep.Calls = append(rep.Calls, tac.DryRunCall{
		Step: "authenticate", Method: "GET", URL: dryRunAuthEndpoint(o.Connector.Name(), cfg),
		Note: probe.Note, Performed: probe.Outcome != ProbeUnsupported,
	})
	switch probe.Outcome {
	case ProbeRefused:
		rep.Outcome, rep.Note = tac.DryRunRefused, probe.Note
		return rep, nil
	case ProbeUnreachable, ProbeTimedOut:
		rep.Outcome, rep.Note = tac.DryRunUnreachable, probe.Note
		return rep, nil
	case ProbeNotConfigured:
		rep.Outcome, rep.Note = tac.DryRunNotConfigured, probe.Note
		return rep, nil
	}
	// ProbeUnsupported is NOT a failure: several paths publish no read-only
	// check (research §6). The payload half still runs and is still worth
	// having; the note says the credential could not be exercised.
	if probe.Outcome == ProbeUnsupported {
		rep.Calls[0].Note = probe.Note + " The payload below was still built and validated."
	}

	// ── (2) the payload, described and validated ────────────────────────────
	have := caseFormValuesWith(req.Form, req, cfg)
	for _, m := range MissingRequired(o.Connector.Name(), have) {
		rep.Blockers = append(rep.Blockers, tac.RequiredField{
			Key: m.Key, Label: m.Label, Why: m.Why, SettingsHint: m.SettingsHint,
			AnyOf: m.AnyOf, Alt: m.Alt,
		})
	}
	create := tacToCaseRequest(req, o.now())
	switch {
	case caps.Create:
		call, verr := o.describeCreate(cfg, create, req)
		rep.Calls = append(rep.Calls, call)
		if verr != nil {
			rep.Outcome = tac.DryRunIncomplete
			rep.Note = verr.Error()
			return rep, nil
		}
	case caps.AttachToExistingOnly:
		rep.Calls = append(rep.Calls, tac.DryRunCall{
			Step: "open the case", Method: "-", URL: "-",
			Note: "This path attaches to a case you have already opened; it opens nothing itself.",
		})
		for _, miss := range attachOnlyMissingFields(req) {
			rep.Blockers = append(rep.Blockers, tac.RequiredField{
				Key: strings.SplitN(miss, " ", 2)[0], Label: miss,
				Why:          "this path attaches to an existing case and needs its reference and per-case credential",
				SettingsHint: "the confirmation screen",
			})
		}
	}
	if caps.Attach {
		rep.Calls = append(rep.Calls, o.describeAttach(req))
	}

	if len(rep.Blockers) > 0 {
		rep.Outcome = tac.DryRunIncomplete
		rep.Note = MissingRequiredMessage(o.Connector.Name(), have)
		if strings.TrimSpace(rep.Note) == "" {
			rep.Note = "This case is not complete yet; the fields above name what is still needed."
		}
		return rep, nil
	}
	rep.Outcome = tac.DryRunOK
	rep.Note = dryRunOKNote(probe.Outcome, rep.Display)
	return rep, nil
}

// dryRunOKNote says exactly what a passing dry run proved, and no more.
func dryRunOKNote(probe ProbeOutcome, display string) string {
	base := "The case payload is complete and passes " + display + "'s own validation. "
	if probe == ProbeUnsupported {
		return base + "This vendor publishes no read-only check, so the credential itself was not exercised. " +
			"Nothing was created."
	}
	return base + "The stored credential was accepted by the vendor. Entitlement is still evaluated " +
		"when the case is actually opened, against your contract. Nothing was created."
}

// dryRunAuthEndpoint names the endpoint the authenticate step reaches, so an
// operator can check it against their onboarding paperwork. It never renders a
// credential — only a host.
func dryRunAuthEndpoint(connectorID string, cfg TACConnectorConfig) string {
	switch connectorID {
	case "cisco-smart-bonding":
		return orDefaultStr(cfg.Cisco.TokenURL, cisco.DefaultTokenURL)
	case "cisco-cxd":
		return "https://" + cisco.CXDHost + " (per-case token; nothing to pre-authenticate)"
	case "juniper":
		return "https://" + juniper.APIHost + juniper.PathGetLOV
	case "servicenow", "jira":
		return strings.TrimSuffix(strings.TrimSpace(cfg.ITSM.InstanceURL), "/")
	}
	if strings.HasPrefix(connectorID, "email-") {
		return cfg.Email.Host
	}
	return ""
}

// describeCreate renders the create body and runs the vendor's OWN validation
// where the vendor package publishes one.
func (o *TACOpener) describeCreate(cfg TACConnectorConfig, create CaseRequest, req tac.CaseRequest) (tac.DryRunCall, error) {
	call := tac.DryRunCall{Step: "open the case", Method: "POST"}
	switch o.Connector.Name() {
	case "juniper":
		call.URL = "https://" + juniper.APIHost + juniper.PathCreateSR
		body := juniperCreateForDryRun(cfg, create)
		call.Fields = dryRunFieldsFromMap(body, nil)
		call.Note = "Juniper publishes this schema; the body above was validated against it."
		if verr := juniperValidateForDryRun(cfg, create); verr != nil {
			return call, verr
		}
	case "cisco-smart-bonding":
		call.URL = "https://" + cisco.SmartBondingHost + cisco.PushPath
		call.Fields = dryRunFieldsFromMap(ciscoCanonicalForDryRun(cfg, create), cfg.Cisco.FieldMap)
		call.Note = "Cisco does not publish the push/call request schema — the field NAMES above are the " +
			"ones your Smart Bonding onboarding issued, bound in this connector's settings. " +
			"An unbound required field fails closed rather than filing a malformed case."
		ent := cisco.Entitlement{
			CCOID: cfg.Cisco.CCOID, SerialNumber: create.SerialNumber,
			ContractID: create.Fields["contract_id"], PID: create.Fields["pid"],
		}
		if verr := ent.Validate(); verr != nil {
			return call, verr
		}
	default:
		call.URL = strings.TrimSuffix(strings.TrimSpace(cfg.ITSM.InstanceURL), "/")
		call.Fields = dryRunFieldsFromMap(map[string]string{
			"short_description": create.Synopsis,
			"description":       create.Description,
			"severity":          create.Severity,
			"contact_name":      create.ContactName,
			"contact_email":     create.ContactEmail,
			"correlation_id":    create.IdempotencyKey,
		}, nil)
		call.Note = "Per-instance mandatory fields are set in your own ITSM and are not visible from here; " +
			"a field your instance requires and Correlix does not send will be refused at create time."
	}
	_ = req
	return call, nil
}

// describeAttach renders the attachment step.
func (o *TACOpener) describeAttach(req tac.CaseRequest) tac.DryRunCall {
	call := tac.DryRunCall{Step: "attach the bundle", Method: "POST"}
	name := strings.TrimSpace(req.Form.BundleName)
	if name == "" {
		name = "the redacted bundle"
	}
	call.Fields = []tac.DryRunField{
		{Name: "file", Value: name},
		{Name: "bytes", Value: strconv.FormatInt(req.Form.BundleBytes, 10)},
		{Name: "profile", Value: string(req.Form.Profile),
			Note: "the bundle profile this path's attachment ceiling implies"},
	}
	if o.Connector.Capabilities().AttachToExistingOnly {
		call.Fields = append(call.Fields, tac.DryRunField{
			Name: "upload_token", Value: "[REDACTED]", Secret: true,
			Note: "the per-case credential you copy from the vendor's portal; it is never stored",
		})
	}
	return call
}

// juniperCreateForDryRun renders the createSR body Correlix would send.
func juniperCreateForDryRun(cfg TACConnectorConfig, req CaseRequest) map[string]string {
	return map[string]string{
		"appId":                       cfg.Juniper.AppID,
		"customerSourceID":            cfg.Juniper.CustomerSourceID,
		"userId":                      cfg.Juniper.UserID,
		"accountID":                   cfg.Juniper.AccountID,
		"synopsis":                    Truncate(req.Synopsis, 250),
		"problemDescription":          Truncate(req.Description, 15000),
		"priority":                    req.Severity,
		"contactEmail":                orDefault(req.ContactEmail, cfg.Juniper.DefaultContactEmail),
		"serialNumber":                req.SerialNumber,
		"softwareVersion":             req.Fields["software_version"],
		"customerUniqueTransactionID": req.IdempotencyKey,
	}
}

// juniperValidateForDryRun runs Juniper's own request validation.
func juniperValidateForDryRun(cfg TACConnectorConfig, req CaseRequest) error {
	r := juniper.CreateSRRequest{
		AppID: cfg.Juniper.AppID, CustomerSourceID: cfg.Juniper.CustomerSourceID,
		UserID: cfg.Juniper.UserID, AccountID: cfg.Juniper.AccountID,
		Synopsis: Truncate(req.Synopsis, 250), ProblemDescription: Truncate(req.Description, 15000),
		Priority: req.Severity, ContactEmail: orDefault(req.ContactEmail, cfg.Juniper.DefaultContactEmail),
		SerialNumber: req.SerialNumber, SoftwareVersion: req.Fields["software_version"],
		CustomerUniqueTransactionID: req.IdempotencyKey,
	}
	return r.Validate()
}

// ciscoCanonicalForDryRun renders the canonical fields a Smart Bonding create
// carries, keyed by Correlix's own names so the field map can be shown beside them.
func ciscoCanonicalForDryRun(cfg TACConnectorConfig, req CaseRequest) map[string]string {
	return map[string]string{
		"synopsis":      Truncate(req.Synopsis, 250),
		"description":   req.Description,
		"severity":      req.Severity,
		"contact_email": req.ContactEmail,
		"contact_name":  req.ContactName,
		"cco_id":        cfg.Cisco.CCOID,
		"serial_number": req.SerialNumber,
		"contract_id":   req.Fields["contract_id"],
		"pid":           req.Fields["pid"],
	}
}

// dryRunFieldsFromMap renders a body as ordered, redacted fields. The order is
// the sorted key order so two dry runs of the same case read identically —
// an operator comparing a failing run against a working one should be diffing
// values, not chasing map iteration.
func dryRunFieldsFromMap(body map[string]string, vendorNames map[string]string) []tac.DryRunField {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]tac.DryRunField, 0, len(keys))
	for _, k := range keys {
		f := tac.DryRunField{Name: k, Value: Truncate(body[k], 400)}
		if vendorNames != nil {
			f.VendorName = strings.TrimSpace(vendorNames[k])
			if f.VendorName == "" && body[k] != "" {
				f.Note = "not bound in this connector's field map — the create would fail closed"
			}
		}
		out = append(out, f)
	}
	return out
}

var _ tac.CaseDryRunner = (*TACOpener)(nil)
