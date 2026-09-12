// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// dryrun.go — PROVE THE SETUP BEFORE THE FIRST REAL CASE.
//
// Owner, 2026-09-07: "I don't have vendor smart contracts to login. If there is
// any way to ensure API calls work that should be good for now."
//
// A customer who has just pasted a client secret into Administration has no way
// to find out whether it works except by opening a real case at three in the
// morning during an outage. That is the worst possible moment to discover a
// typo. So the confirmation screen carries a Dry run:
//
//	1. AUTHENTICATE against the configured endpoint with the stored credential —
//	   a real call, read-only, creating nothing. This is the half that catches a
//	   wrong secret, an expired onboarding, a firewall, a wrong instance URL.
//	2. BUILD the case payload Correlix would send, run every validation the
//	   vendor's own schema and this platform's required-field table impose, and
//	   SHOW IT — every field, with secrets redacted.
//
// Nothing is created. There is no path from this file to a create, and the
// connector method it calls is deliberately a different method from SubmitCase
// so that fact is checkable rather than argued.
//
// WHAT IT DOES NOT CLAIM. A dry run that passes proves the credential is
// accepted and the payload is complete and well-formed. It does not prove the
// vendor will accept the case: entitlement is evaluated at create time against
// the contract, and several vendors publish no create schema at all (Cisco's
// push/call body is issued per onboarding project). Each report says which of
// those it is, in its own words, rather than implying more than it checked.

import (
	"context"
	"errors"
	"strings"
	"time"
)

// DryRunOutcome is the closed set of answers a dry run can give. It mirrors the
// connector-test vocabulary on purpose: an operator who has read one screen
// should not have to learn a second set of words for the same conditions.
type DryRunOutcome string

const (
	// DryRunOK — the credential was accepted and the payload is complete.
	DryRunOK DryRunOutcome = "ok"
	// DryRunIncomplete — the payload is missing something a vendor demands. The
	// blockers name it; nothing was sent.
	DryRunIncomplete DryRunOutcome = "incomplete"
	// DryRunNotConfigured — this tenant has brought no credentials for the path.
	DryRunNotConfigured DryRunOutcome = "not_configured"
	// DryRunRefused — the vendor answered and rejected the credential.
	DryRunRefused DryRunOutcome = "refused"
	// DryRunUnreachable — the endpoint could not be reached.
	DryRunUnreachable DryRunOutcome = "unreachable"
	// DryRunUnsupported — this path publishes nothing to check against (the
	// portal connectors). It is a complete answer, not a failure.
	DryRunUnsupported DryRunOutcome = "unsupported"
)

// DryRunField is one field of the payload as it would be sent.
//
// Value is ALWAYS safe to render: a connector must redact anything secret
// before it reaches here, and the Secret flag says a value exists without
// carrying it. That is the same contract CaseSecrets enforces at the type level,
// restated at the field level because this struct is built to be displayed.
type DryRunField struct {
	// Name is the field as CORRELIX names it (synopsis, severity, serial_number).
	Name string `json:"name"`
	// VendorName is the field as the VENDOR names it, where the tenant's
	// onboarding bound one (Cisco's FieldMap). Empty when the vendor's schema
	// names it the same, or when the vendor publishes no schema.
	VendorName string `json:"vendor_name,omitempty"`
	// Value is the value that would be sent, already redacted where it is
	// sensitive. Empty means the field would go out blank.
	Value string `json:"value"`
	// Secret marks a field whose real value is deliberately not shown.
	Secret bool `json:"secret,omitempty"`
	// Note is why a field matters, when it is not obvious.
	Note string `json:"note,omitempty"`
}

// DryRunCall is one HTTP call the submit would make, described rather than made.
type DryRunCall struct {
	// Step names it in the operator's terms ("authenticate", "create the case",
	// "attach the bundle").
	Step string `json:"step"`
	// Method and URL are the request as it would go out. The URL is the
	// configured, pinned endpoint — an operator checking a staging host against
	// their onboarding paperwork is exactly who this line is for.
	Method string `json:"method"`
	URL    string `json:"url"`
	// Fields is the body, field by field, redacted.
	Fields []DryRunField `json:"fields,omitempty"`
	// Note carries anything the operator should know about this call — that the
	// vendor publishes no schema for it, that it is skipped on this path.
	Note string `json:"note,omitempty"`
	// Performed reports whether the dry run ACTUALLY MADE this call. Only the
	// authenticate step is ever performed; everything else is described. The
	// flag is on the record so nobody has to take that on trust.
	Performed bool `json:"performed"`
}

// DryRunReport is what the screen renders.
type DryRunReport struct {
	ConnectorID string        `json:"connector_id"`
	Display     string        `json:"display,omitempty"`
	Outcome     DryRunOutcome `json:"outcome"`
	// AuthMode is how it authenticated (oauth, api key, basic, smtp).
	AuthMode string `json:"auth_mode,omitempty"`
	// Note is the outcome in one sentence, in the vendor's own words where they
	// supplied any.
	Note string `json:"note"`
	// Calls is the whole sequence, in order.
	Calls []DryRunCall `json:"calls"`
	// Blockers is what is still missing, by name, with where it is set.
	Blockers []RequiredField `json:"blockers,omitempty"`
	// ElapsedMS is how long the authenticate call took, when one was made.
	ElapsedMS int64 `json:"elapsed_ms,omitempty"`
	// Limits records what this path would refuse on size, so an operator sees
	// the mailbox ceiling before a 40 MB bundle meets it.
	Limits string `json:"limits,omitempty"`
	// CreatedNothing is stated rather than assumed. It is always true; it is on
	// the wire so the screen can say it without the client asserting it.
	CreatedNothing bool      `json:"created_nothing"`
	At             time.Time `json:"at"`
}

// CaseDryRunner is the OPTIONAL half of the connector seam that supports a dry
// run. It is optional rather than part of CaseOpener because a connector that
// cannot describe its own request is better saying so than returning a fiction,
// and because adding a method to the published seam would break every
// implementation for a feature not all of them can serve.
type CaseDryRunner interface {
	// DryRun authenticates and describes. It MUST NOT create, update or attach
	// anything, and it must redact every secret it renders.
	DryRun(ctx context.Context, req CaseRequest) (DryRunReport, error)
}

// ErrDryRunUnsupported is the honest refusal from a path with nothing to check.
var ErrDryRunUnsupported = errors.New("tac: this path publishes nothing a dry run can check")

// DryRun asks the routed connector to prove the tenant's setup.
//
// It resolves the connector the same way PrepareCase does — through the
// service's own opener list, for the caller's own tenant — so a dry run can
// never be pointed at another tenant's credentials.
func (s *Service) DryRun(ctx context.Context, tenant, connectorID string, req CaseRequest) (DryRunReport, error) {
	o, info, ok := s.opener(ctx, tenant, connectorID)
	if !ok {
		return DryRunReport{}, errors.New("tac: unknown case connector")
	}
	base := DryRunReport{
		ConnectorID: info.ID, Display: info.Display, AuthMode: info.AuthMode,
		CreatedNothing: true, At: s.now().UTC(), Calls: []DryRunCall{},
	}
	dr, supports := o.(CaseDryRunner)
	if !supports {
		base.Outcome = DryRunUnsupported
		base.Note = "This path opens nothing over an API, so there is no call to rehearse. " +
			"Correlix prepares the case text and the redacted bundle, and you submit them in the vendor's portal."
		return base, nil
	}
	if !info.Configured {
		base.Outcome = DryRunNotConfigured
		base.Note = info.StatusNote
		if strings.TrimSpace(base.Note) == "" {
			base.Note = "No credentials for this tenant yet — bring your own to use it."
		}
		return base, nil
	}
	req.TenantID = tenant
	rep, err := dr.DryRun(ctx, req)
	if err != nil {
		if errors.Is(err, ErrDryRunUnsupported) {
			base.Outcome = DryRunUnsupported
			base.Note = err.Error()
			return base, nil
		}
		return DryRunReport{}, err
	}
	// The fields the SERVICE owns are stamped here rather than trusted from the
	// connector, so a connector cannot report a different id from the one that
	// was asked, and cannot claim to have created nothing while having done so —
	// that claim is this package's, and it is true because the seam has no
	// create in it.
	rep.ConnectorID, rep.Display, rep.CreatedNothing, rep.At = info.ID, info.Display, true, base.At
	if rep.AuthMode == "" {
		rep.AuthMode = info.AuthMode
	}
	if rep.Limits == "" {
		rep.Limits = attachmentLimitNote(info)
	}
	return rep, nil
}

// attachmentLimitNote states what this path would refuse on size, in bytes the
// operator can compare against the bundle they are looking at.
func attachmentLimitNote(info ConnectorInfo) string {
	switch {
	case !info.Can(CapAttach) || info.MaxAttachmentBytes <= 0:
		return "This path cannot attach a file; the bundle stays in Correlix for you to download."
	case info.MaxAttachmentBytes <= EmailProfileMaxBytes:
		return "Attachments are capped at " + itoaTAC(int(info.MaxAttachmentBytes)) +
			" bytes on this path, because an email attachment is base64-encoded in transit " +
			"and grows by a third before it reaches the vendor's mailbox."
	default:
		return "Attachments are capped at " + itoaTAC(int(info.MaxAttachmentBytes)) + " bytes on this path."
	}
}
