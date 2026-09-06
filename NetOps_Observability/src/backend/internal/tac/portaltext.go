// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// portaltext.go — the W1 CaseOpener: the one that always works.
//
// It creates nothing and attaches nothing. It produces the case text an operator
// pastes into a vendor portal or an email, alongside the bundle they download.
// That is not a placeholder for the API connectors — it is the path that covers
// the vendors research found have NO case API at all (Fortinet, Palo Alto,
// Nokia, Huawei enterprise) and the path that still works when a tenant has
// configured no integration, when a token has expired, and when the vendor's
// portal is the only thing the customer's contract permits.
//
// It therefore declares exactly two capabilities — none of create/attach/poll —
// and the UI renders it honestly as "copy this into the vendor's portal".

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PortalTextOpener is the always-available CaseOpener.
type PortalTextOpener struct {
	// Now is injected so the rendered text is deterministic in tests.
	Now func() time.Time
}

// NewPortalTextOpener builds the opener.
func NewPortalTextOpener() *PortalTextOpener { return &PortalTextOpener{Now: time.Now} }

// PortalTextConnectorID is the stable id the UI keys on.
const PortalTextConnectorID = "portal-text"

// Info implements CaseOpener. It is configured for EVERY tenant — there is
// nothing to configure — which is what makes it the honest default.
func (p *PortalTextOpener) Info(_ context.Context, _ string) ConnectorInfo {
	return ConnectorInfo{
		ID:      PortalTextConnectorID,
		Display: "Vendor portal / email (copy & paste)",
		// Capabilities: it can produce a link to the bundle inside Correlix and
		// nothing else. It deliberately does NOT claim create or attach.
		Capabilities:       []CaseCapability{CapLink},
		MaxAttachmentBytes: 0,
		Profile:            ProfileLinkOnly,
		Configured:         true,
		Note: "No integration required. Correlix pre-fills the case text and you attach the downloaded bundle " +
			"in the vendor's own portal or email. This is the only supported path for vendors that publish no " +
			"case-creation API.",
	}
}

// PrepareCase implements CaseOpener: it fills the form and the paste-ready text.
// It performs no remote call of any kind.
func (p *PortalTextOpener) PrepareCase(_ context.Context, req CaseRequest) (CaseForm, error) {
	form := req.Form
	form.ConnectorID = PortalTextConnectorID
	form.Profile = ProfileLinkOnly
	if strings.TrimSpace(form.Title) == "" {
		form.Title = defaultCaseTitle(req)
	}
	form.PortalText = renderPortalText(req, form)
	// The vendor-entitlement fields are the operator's to supply: Correlix does
	// not hold a serial-to-contract mapping and will not invent one.
	form.MissingFields = missingCaseFields(form)
	return form, nil
}

// SubmitCase implements CaseOpener. For this connector "submit" means "hand the
// operator the finished text": it is a SUCCESSFUL result with no case id, not an
// error, because the operator's next step is real and it works.
func (p *PortalTextOpener) SubmitCase(_ context.Context, req CaseRequest) (CaseResult, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	form := req.Form
	if strings.TrimSpace(form.PortalText) == "" {
		form.PortalText = renderPortalText(req, form)
	}
	return CaseResult{
		ConnectorID: PortalTextConnectorID,
		Attached:    false,
		AttachNote: "This connector cannot attach: paste the text below into the vendor's portal or email and " +
			"attach the bundle you downloaded from Correlix.",
		SubmittedAt: now().UTC(),
		PortalText:  form.PortalText,
	}, nil
}

// PollStatus implements CaseOpener. There is no case to poll.
func (p *PortalTextOpener) PollStatus(_ context.Context, _, _ string) (CaseResult, error) {
	return CaseResult{}, ErrCapabilityUnsupported
}

func defaultCaseTitle(req CaseRequest) string {
	host := req.Hostname
	if host == "" {
		host = req.DeviceID
	}
	cls := req.ClassID
	if cls == "" {
		cls = "network fault"
	}
	return fmt.Sprintf("%s on %s — evidence bundle attached", cls, host)
}

// missingCaseFields names the entitlement fields the operator must complete. It
// is what stops the UI offering a submit button for a form a vendor will reject.
func missingCaseFields(f CaseForm) []string {
	var miss []string
	if strings.TrimSpace(f.SerialNumber) == "" {
		miss = append(miss, "serial_number")
	}
	if strings.TrimSpace(f.ContractID) == "" {
		miss = append(miss, "contract_id")
	}
	if strings.TrimSpace(f.ContactEmail) == "" {
		miss = append(miss, "contact_email")
	}
	if miss == nil {
		miss = []string{}
	}
	return miss
}

// renderPortalText produces the paste-ready case description. It is plain text
// on purpose: every vendor portal accepts it and none of them render markdown
// the same way.
func renderPortalText(req CaseRequest, form CaseForm) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TITLE: %s\n", form.Title)
	if form.Severity != "" {
		fmt.Fprintf(&b, "SEVERITY: %s\n", form.Severity)
	}
	fmt.Fprintf(&b, "DEVICE: %s (%s)\n", firstNonEmpty(req.Hostname, req.DeviceID), req.Platform)
	if form.SerialNumber != "" {
		fmt.Fprintf(&b, "SERIAL: %s\n", form.SerialNumber)
	}
	if form.ContractID != "" {
		fmt.Fprintf(&b, "CONTRACT: %s\n", form.ContractID)
	}
	if form.ContactName != "" || form.ContactEmail != "" {
		fmt.Fprintf(&b, "CONTACT: %s <%s>\n", form.ContactName, form.ContactEmail)
	}
	if form.BundleName != "" {
		fmt.Fprintf(&b, "ATTACHMENT: %s (%d bytes) — download it from Correlix and attach it to this case\n",
			form.BundleName, form.BundleBytes)
	}
	b.WriteString("\n")
	b.WriteString(form.Description)
	if !strings.HasSuffix(form.Description, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\nEvery output in the attached bundle is redacted by Correlix: passwords, community strings, " +
		"authentication keys and private-key blocks are replaced with [REDACTED]; hostnames, interfaces and " +
		"addresses are kept.\n")
	return b.String()
}

var _ CaseOpener = (*PortalTextOpener)(nil)
