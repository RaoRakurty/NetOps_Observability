// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_portal.go — Tier 3: the vendors with NO case API.
//
// Fortinet, Palo Alto, Nokia and Huawei-enterprise publish no programmatic
// create-a-case path. The research states each negative WITH the pages that
// were checked, so it can be re-verified rather than re-guessed:
//
//	Fortinet    FortiCare's documented API family is asset/registration/licensing
//	            only; the FortiCare guide's full table of contents has no API
//	            section. https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/forticare
//	Palo Alto   the CSP API key is a LICENSING key; pan.dev's catalog lists no
//	            case/ticket API. https://pan.dev/
//	Nokia       NSP publishes five APIs, none of them case/ticket/TSR; the
//	            developer portal returns zero hits for those terms.
//	            https://documentation.nokia.com/nsp/24-4/NSP_System_Architecture_Guide/NSP-APIs.html
//	Huawei      only Huawei CLOUD's OSM has a ticket API, and it opens CLOUD
//	            tickets, not network-device TAC cases.
//	            https://support.huaweicloud.com/intl/en-us/api-ticket/ticket_api_00002.html
//
// THE HONESTY RULE (research §4, and the design's §3c stance on unbound
// dialects): the UI must say which mode a vendor is in and must NEVER render an
// "Open case" button that silently degrades to a download. A vendor with no API
// is a fact to display, not a gap to paper over. That is why these connectors
// exist at all rather than simply being absent from the registry: an absent
// vendor is indistinguishable from a misconfigured one, whereas a PortalOnly
// descriptor tells the operator exactly what the portal will ask for.
//
// NEGATIVES GO STALE: Fortinet's FNDN and Huawei's enterprise SR pages are
// login/JS-gated, so a private or partner-only API cannot be DISPROVEN for
// those two — only shown to be publicly undocumented. Each row carries the
// date the negative was established.

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// PortalVendor is the descriptor for a vendor whose case opening is manual.
type PortalVendor struct {
	ID        string
	Vendor    string
	PortalURL string
	// RequiredFields are the fields the portal's own case wizard asks for, in
	// the order it asks for them, so Correlix can pre-fill the paste text.
	RequiredFields []string
	// SeverityValues is the vendor's PUBLISHED vocabulary, or nil when the
	// vendor does not publish one. nil means "not published" — the UI must not
	// substitute a made-up scale.
	SeverityValues []string
	// Reason states the negative and CheckedOn dates it.
	Reason    string
	CheckedOn string
	Sources   []string
	// Notes carries the operational facts that change what the operator does.
	Notes string
}

// portalVendors is the closed Tier-3 table.
var portalVendors = map[string]PortalVendor{
	"fortinet": {
		ID: "fortinet", Vendor: "Fortinet", PortalURL: "https://support.fortinet.com/",
		RequiredFields: []string{"serial number", "request type (Technical Support Ticket)", "priority (P1–P4)", "problem description", "attachments"},
		SeverityValues: []string{
			"P1 — total loss or continuous instability of mission-critical functionality in a live or production network environment",
			"P2 — significant impact on mission-critical functionality",
			"P3 — minimal impact on business operations",
			"P4 — additional information, or minor defects that do not impact business services",
		},
		Reason:    "FortiCare's documented API family is asset/registration/licensing only; the FortiCare guide's table of contents has no API section, and no forticare/ticket client_id is documented publicly",
		CheckedOn: "2026-09-05",
		Sources: []string{
			"https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/creating-tickets",
			"https://docs.fortinet.com/document/forticloud/latest/identity-access-management-iam/19322/accessing-fortiapis",
		},
		Notes: "the diagnostic bundle is produced ON the device by `execute tac report` (or the GUI FortiCare Debug Report) and attached by a human. Files are deleted 30 days after the ticket closes. FNDN is login-gated, so a private API cannot be disproven — only shown to be publicly undocumented",
	},
	"paloalto": {
		ID: "paloalto", Vendor: "Palo Alto Networks", PortalURL: "https://support.paloaltonetworks.com/",
		RequiredFields: []string{"product", "asset / serial number", "symptoms with date and time", "problem type", "impact / severity", "TSF file", "contact phone"},
		SeverityValues: []string{
			"Sev 1 — product is down and critically affects the customer production environment; no workaround yet available",
			"Sev 2 — product is impaired; customer production is up but impacted",
			"Sev 3 — a product function has failed; customer production is not affected",
			"Sev 4 — product function is not impaired; no impact to customer business",
		},
		Reason:    "the CSP API key is a Licensing API key; pan.dev's catalog lists no Customer Support Portal, case or ticket API, and the CSP user-doc index's only API item is the Licensing key",
		CheckedOn: "2026-09-05",
		Sources: []string{
			"https://pan.dev/",
			"https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008WANCA2",
		},
		Notes: "a Tech Support File is MANDATORY for many issue concentrations and the portal accepts only .tar/.zip/.tgz/.tar.tz — so the bundle must be produced as a .zip to be acceptable. Exemptions: hard-down criticals, boot issues, US Federal/Defense/air-gapped. Phone is the channel for Sev 1",
	},
	"nokia": {
		ID: "nokia", Vendor: "Nokia", PortalURL: "https://customer.nokia.com/support/s/",
		RequiredFields: []string{"request type (Technical Problem / HRR-RMA / Feature Request)", "product", "problem details"},
		SeverityValues: nil, // NOT published: the public TSR guide contains zero occurrences of severity/Critical/Major/Minor
		Reason:         "NSP publishes exactly five APIs (NSP REST, RESTCONF, Kafka, NFM-P REST, NFM-P XML) and none is a case/ticket/TSR API; the developer portal returns zero hits for ticket, support case or TSR, and the TSR guide contains no attach or upload instruction",
		CheckedOn:      "2026-09-05",
		Sources: []string{
			"https://www.nokia.com/asset/f/215299/",
			"https://documentation.nokia.com/nsp/24-4/NSP_System_Architecture_Guide/NSP-APIs.html",
		},
		Notes: "phone is the vendor-preferred channel for outages. Replying to the case email works and is automatable, but the Subject line MUST NOT be altered — and the per-case reply address is never published, so Correlix cannot compose that mail without the operator pasting the address. The severity matrix is not published; do not substitute one",
	},
	"huawei": {
		ID: "huawei", Vendor: "Huawei (enterprise / carrier networking)", PortalURL: "https://support.huawei.com/",
		RequiredFields: []string{"product", "problem description", "attachments"},
		SeverityValues: nil, // NOT retrievable: the portal is JS-gated
		Reason:         "no public API exists for enterprise or carrier networking TAC. Huawei Cloud's OSM does publish POST /v2/servicerequest/cases, but it opens CLOUD tickets, not network-device TAC cases, so it is out of scope for the escalation pack",
		CheckedOn:      "2026-09-05",
		Sources: []string{
			"https://support.huaweicloud.com/intl/en-us/api-ticket/ticket_api_00002.html",
			"https://support.huaweicloud.com/intl/en-us/productdesc-supportplans/support-plans_01_0014.html",
		},
		Notes: "the enterprise SR portal is JS-gated, so its field list and severity table are not publicly retrievable — do not assume them. A private or partner-only API cannot be disproven from outside",
	},
}

// PortalVendorFor returns the Tier-3 descriptor for a vendor id.
func PortalVendorFor(id string) (PortalVendor, bool) {
	v, ok := portalVendors[strings.ToLower(strings.TrimSpace(id))]
	return v, ok
}

// PortalVendorIDs lists the Tier-3 vendors, sorted.
func PortalVendorIDs() []string {
	out := make([]string, 0, len(portalVendors))
	for k := range portalVendors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PortalOnlyConnector is a CaseConnector that can do NOTHING, on purpose. Every
// method fails with a message naming the portal and what it asks for, so the UI
// renders an honest "not automatable" state instead of a broken button.
type PortalOnlyConnector struct{ vendor PortalVendor }

// NewPortalOnlyConnector builds the descriptor connector for a Tier-3 vendor.
func NewPortalOnlyConnector(vendorID string) (*PortalOnlyConnector, error) {
	v, ok := PortalVendorFor(vendorID)
	if !ok {
		return nil, fmt.Errorf("portal connector: %q is not in the Tier-3 vendor table", vendorID)
	}
	return &PortalOnlyConnector{vendor: v}, nil
}

func (c *PortalOnlyConnector) Name() string { return "portal-" + c.vendor.ID }

// Vendor exposes the descriptor (the UI renders the portal URL, the field list
// and the dated negative).
func (c *PortalOnlyConnector) Vendor() PortalVendor { return c.vendor }

func (c *PortalOnlyConnector) Capabilities() Caps {
	return Caps{
		Create: false, Attach: false, Poll: false, Webhook: false, Note: false,
		PortalURL:      c.vendor.PortalURL,
		RequiredFields: append([]string(nil), c.vendor.RequiredFields...),
		SeverityValues: append([]string(nil), c.vendor.SeverityValues...),
		Notes:          c.vendor.Reason + " (checked " + c.vendor.CheckedOn + "). " + c.vendor.Notes,
	}
}

// ValidateConfig always succeeds: there is nothing to configure, and reporting
// a configuration error would imply configuration could enable an API.
func (c *PortalOnlyConnector) ValidateConfig(TACConnectorConfig) error { return nil }

func (c *PortalOnlyConnector) CreateCase(context.Context, TACConnectorConfig, CaseRequest) (CaseRef, error) {
	return CaseRef{}, c.unsupported("open a case")
}

func (c *PortalOnlyConnector) AttachBundle(context.Context, TACConnectorConfig, CaseRef, Bundle) (AttachResult, error) {
	return AttachResult{}, c.unsupported("attach a file")
}

func (c *PortalOnlyConnector) FetchCase(context.Context, TACConnectorConfig, CaseRef) (RemoteCase, bool, error) {
	return RemoteCase{}, false, c.unsupported("read case status")
}

func (c *PortalOnlyConnector) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return c.unsupported("add a note")
}

// unsupported names the vendor, the portal and the field list so the operator
// can act on the message rather than just read a refusal.
func (c *PortalOnlyConnector) unsupported(what string) error {
	return fmt.Errorf("%w: %s publishes no API to %s — %s. Open the case at %s; it asks for: %s",
		ErrUnsupported, c.vendor.Vendor, what, c.vendor.Reason, c.vendor.PortalURL,
		strings.Join(c.vendor.RequiredFields, ", "))
}

var _ CaseConnector = (*PortalOnlyConnector)(nil)
