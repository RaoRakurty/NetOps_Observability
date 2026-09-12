// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// caseopener.go — the CASE-OPENING SEAM, published early and deliberately
// stable: the ticketing connectors (internal/ticketing) are built against this
// file, and W1 ships only the portal-text implementation behind it.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md §4, corrected
// 2026-09-05 from TAC_CASE_OPENING_RESEARCH_2026-09-05.md. Three facts from that
// research shape this interface and are load-bearing, not stylistic:
//
//  1. VENDORS DIFFER IN WHAT THEY CAN DO AT ALL. ServiceNow and Jira can create
//     and attach; Cisco can attach (CXD) and create (Smart Bonding) but its
//     Support Case API v3 is read-only; Fortinet, Palo Alto, Nokia and Huawei
//     enterprise have NO case API. So a connector declares a CAPABILITY MATRIX
//     and the UI renders exactly what that connector can honestly do. A missing
//     capability is displayed, never worked around.
//
//  2. CASE CREATION IS A HUMAN ACTION. OpenCase never fires a create by itself:
//     PrepareCase returns a PRE-FILLED FORM (severity, contract/serial, contact,
//     the problem statement) that a person reviews and submits. §15's "no
//     excessive agency" rule and the vendors' own named-human requirements
//     (Juniper's contactEmail, Arista's domain-matched accounts) agree here.
//
//  3. SIZE IS A PROTOCOL CONSTRAINT. Email paths cap around 14 MB; ServiceNow
//     and Jira are far larger. The bundle therefore has PROFILES, the connector
//     declares MaxAttachmentBytes, and a bundle that does not fit is trimmed
//     honestly (largest outputs dropped, recorded in the MANIFEST) or downgraded
//     to link-only — never silently truncated.
//
// ZERO TRUST (§3a): credentials are BRING-YOUR-OWN and PER TENANT, sealed, never
// logged, never returned. The gate on every route that reaches this seam is
// requirePerm + a tenant filter — a tenant's own case is tenant data, NOT
// platform-global plumbing, so requirePlatformAdmin would be the wrong gate.

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// CaseCapability is one thing a connector can do. The set is closed: a connector
// that would need a new verb is a design change, not a data change.
type CaseCapability string

const (
	// CapCreate — the connector can create the case itself.
	CapCreate CaseCapability = "create"
	// CapAttach — the connector can attach the bundle to a case.
	CapAttach CaseCapability = "attach"
	// CapPollStatus — the connector can read a case's status back.
	CapPollStatus CaseCapability = "poll_status"
	// CapLink — the connector can produce a deep link to the case.
	CapLink CaseCapability = "link"
)

// BundleProfile selects how much of the evidence a bundle carries. The profile
// is chosen from the connector's limits, and the choice is recorded in the
// MANIFEST so a TAC engineer knows whether anything was left out.
type BundleProfile string

const (
	// ProfileFull is everything: baseline, deep-dive, optional captures,
	// evidence, topology, device facts. Used on API attachment paths.
	ProfileFull BundleProfile = "full"
	// ProfileEmail is the mail-sized profile: the largest command outputs are
	// dropped first (show tech-support before anything else) and the MANIFEST
	// names every omission.
	//
	// The CEILING IS THE CONNECTOR'S, not this package's. An email attachment is
	// base64-encoded in transit, which multiplies it by 4/3 before MIME line
	// breaks: 14 MiB of zip becomes ~20.1 MB on the wire, which is already over
	// Cisco's 20 MB mailbox cap. The email connector therefore declares a
	// smaller MaxAttachmentBytes (14,000,000) that leaves room for the encoding,
	// and BuildBundle trims to THAT number when the caller supplies it. Getting
	// this wrong does not fail loudly — it produces a case the vendor's mail
	// gateway silently rejects — so the arithmetic lives here, once, with a test
	// at the boundary.
	ProfileEmail BundleProfile = "email"
	// ProfileLinkOnly carries no attachment at all: the case text references the
	// bundle, which stays in Correlix for the operator to download. It is the
	// honest fallback when nothing else fits.
	ProfileLinkOnly BundleProfile = "link_only"
)

// EmailProfileMaxBytes is ProfileEmail's DEFAULT ceiling, used only when the
// caller supplies no connector limit. A real connector's declared
// MaxAttachmentBytes always wins, and is always the smaller number in practice.
const EmailProfileMaxBytes int64 = 14 << 20

// MIMEEncodedSize returns the size n bytes occupy once base64-encoded for a MIME
// attachment: 4 bytes out per 3 in, plus a CRLF every 76 output characters.
//
// It is exported because "will this bundle fit the vendor's mailbox limit" is a
// question the connectors, the UI and this package must all answer the SAME way.
func MIMEEncodedSize(n int64) int64 {
	if n <= 0 {
		return 0
	}
	encoded := ((n + 2) / 3) * 4
	return encoded + ((encoded+75)/76)*2
}

// ConnectorInfo is what a connector DECLARES about itself. The UI renders the
// case step straight from this: a capability the connector does not claim is
// shown as unavailable with the reason, never offered and then failed.
type ConnectorInfo struct {
	// ID is the stable connector id ("portal-text", "servicenow", "jira",
	// "email", "cisco-cxd", "juniper-sr").
	ID string `json:"id"`
	// Display is the operator-facing name.
	Display string `json:"display"`
	// Vendor is the TAC/ITSM this connector reaches ("cisco", "juniper",
	// "arista", "nokia", "servicenow", "jira", ""), for the UI to group by.
	Vendor string `json:"vendor,omitempty"`
	// Capabilities is what it can actually do.
	Capabilities []CaseCapability `json:"capabilities"`
	// MaxAttachmentBytes is the connector's own attachment ceiling; 0 means it
	// cannot attach at all.
	MaxAttachmentBytes int64 `json:"max_attachment_bytes"`
	// Profile is the bundle profile this connector needs.
	Profile BundleProfile `json:"profile"`
	// Configured reports whether this deployment/tenant has credentials for it.
	// An unconfigured connector is SHOWN, greyed, with Note explaining what is
	// missing — the operator learns the option exists.
	Configured bool `json:"configured"`
	// Note is the connector's STANDING description — the vendor research that
	// does not change from one read to the next (attachment ceilings, API
	// caveats, the dated negative for a vendor with no API). It is reference
	// material: the escalation step keeps it OFF screen and reaches it through
	// Iris and through Administration → Ticket delivery, because twelve
	// paragraphs on one step is a menu, not a study (owner, 2026-09-06).
	Note string `json:"note,omitempty"`
	// StatusNote is the short reason for the CURRENT state, and it is the only
	// connector prose the step itself renders. "Not configured" carries the
	// invitation to bring credentials; a validation refusal carries the
	// connector's own sentence; an unreadable configuration carries the cause.
	StatusNote string `json:"status_note,omitempty"`
	// ConfigSection names the SETTINGS BLOCK that configures this connector
	// ("servicenow", "jira", "email", "cisco", "juniper"), or is empty when the
	// connector holds no settings at all.
	//
	// It exists so a settings screen can offer the right form — and, more
	// importantly, so it can tell "bring credentials here" apart from "there is
	// nothing to bring". A portal-only vendor publishes no API; showing it a
	// Configure button would promise a screen that could only ever refuse.
	// Twelve connectors share five blocks, so the mapping is the server's to
	// state, never the client's to guess.
	ConfigSection string `json:"config_section,omitempty"`
	// Required is what the VENDOR demands before a case can be opened at all,
	// declared by the connector rather than guessed by the caller.
	//
	// It exists so the confirmation screen can refuse BY NAME — "Cisco needs
	// your CCO-ID; a serial number, or a contract id and a PID" — and say where
	// each missing value is set. The alternative was for this package to carry a
	// table of vendor entitlement rules, which is exactly the vendor knowledge
	// the connector already owns (docs/design/TAC_CASE_FIELDS_2026-09-07.md).
	Required []RequiredField `json:"required,omitempty"`
	// SeverityValues is the vendor's accepted severity vocabulary, in the
	// vendor's own tokens. Empty means the vendor publishes none, which is a
	// fact rather than a gap: the form then carries Correlix's mapped severity
	// as free text.
	SeverityValues []string `json:"severity_values,omitempty"`
	// NumberLookup reports a path that cannot read a case STATUS back but CAN
	// learn the case NUMBER — an email-opened Arista or Cisco case, once the
	// tenant has turned on reading the vendor's reply thread.
	//
	// It is a separate flag from CapPollStatus on purpose, and the distinction is
	// the honesty rule the email connector already states: reading our own
	// mailbox can tell us the number the vendor assigned, and it can never tell
	// us what they have done with the case. So the chip moves from "opened by
	// email · number pending" to the real number, and stops there rather than
	// inventing a status.
	NumberLookup bool `json:"number_lookup,omitempty"`
	// AuthMode names how this connector authenticates for THIS tenant ("oauth",
	// "api_token", "basic", "smtp", ""), so the case chip can say so and an
	// operator can see at a glance which paths are on the preferred OAuth path.
	AuthMode string `json:"auth_mode,omitempty"`
	// PortalOnly declares that the vendor behind this connector publishes NO
	// case-creation API at all, so the prepared case text and the downloaded
	// bundle are not a degraded fallback — they are the whole path.
	//
	// It is a SEPARATE fact from the capability list, and the distinction is the
	// one the owner caught on 2026-09-08: a connector that claims neither create
	// nor attach reads, on the step, exactly like an integration that happens to
	// be idle. "Nokia portal (copy & paste) · Ready" promised something the
	// vendor cannot give. A connector whose vendor HAS an API but which this
	// tenant has not configured is a state with a next step (bring credentials);
	// a portal-only one has no next step to offer, and the UI must chip it as
	// manual rather than ready and must never send an operator to a settings
	// form that could only ever refuse (which is why ConfigSection is empty for
	// exactly these connectors).
	//
	// The connector declares it; this package never infers it from a vendor
	// name, and the client never guesses it from an empty capability list.
	PortalOnly bool `json:"portal_only,omitempty"`
	// VendorDisplay is the vendor's name as it reads INSIDE a sentence ("Nokia",
	// "Palo Alto Networks"), supplied by the connector because the id ("paloalto")
	// does not title-case into anything a person would write. It exists so the
	// UI can state the portal-only fact in the vendor's own name without holding
	// a second copy of this platform's vendor vocabulary.
	VendorDisplay string `json:"vendor_display,omitempty"`
	// PortalURL is where a MANUAL case is actually opened: the tenant's own
	// configured portal address when they have brought one, otherwise the
	// vendor's published support portal. The UI opens it in a new tab, so it is
	// server-validated to be an http(s) address with a host before it is ever
	// stored — a link on an incident screen must never be able to carry a
	// javascript: or data: scheme from an operator's keyboard (§3, LLM02's rule
	// applied to plain operator input).
	PortalURL string `json:"portal_url,omitempty"`
	// CaseNumberPattern is the shape the case number the operator reads off the
	// vendor's portal must take before Correlix will file it on the incident. It
	// is the tenant's, configured per vendor; empty means the default shape
	// (casenumber.go). It is published here so the confirmation screen can
	// refuse a typo at the keyboard rather than after it is recorded.
	CaseNumberPattern string `json:"case_number_pattern,omitempty"`
	// Unavailable reports that this tenant's stored configuration could not be
	// READ — a storage failure, not a state.
	//
	// The distinction is the whole point (owner, 2026-09-06: every connector
	// ended with "connector configuration could not be read for this tenant" on
	// a deployment where nothing was wrong). "No credentials yet" is a PRODUCT
	// STATE with a next step; "the store did not answer" is an ERROR that must
	// name its cause and be logged (§10). Conflating them taught operators to
	// ignore a sentence that one day means something.
	Unavailable bool `json:"unavailable,omitempty"`
}

// RequiredField is one piece of data a vendor demands before it will open a
// case, named the way the operator has to think about it.
//
// It mirrors internal/ticketing.RequiredField field for field, on purpose: the
// dependency runs one way (ticketing imports tac, never the reverse), so the
// seam carries a copy of the shape and the connector fills it. The AUTHORITY is
// docs/design/TAC_CASE_FIELDS_2026-09-07.md and the table the connector holds;
// this type is how that authority crosses the seam.
type RequiredField struct {
	// Key is the CaseForm field this maps to (serial_number, contract_id,
	// contact_email, product, severity…), or a name of something set elsewhere.
	Key string `json:"key"`
	// Label reads inside a sentence: "a serial number", "your CCO-ID".
	Label string `json:"label"`
	// Why is the vendor's own reason, one sentence.
	Why string `json:"why"`
	// SettingsHint names WHERE the operator supplies it.
	SettingsHint string `json:"settings_hint"`
	// AnyOf groups alternatives: the group is satisfied by ONE of them.
	AnyOf string `json:"any_of,omitempty"`
	// Alt is the alternative id within the group; fields sharing an Alt must all
	// be present for that alternative to count.
	Alt string `json:"alt,omitempty"`
}

// Can reports whether the connector claims a capability.
func (c ConnectorInfo) Can(cap CaseCapability) bool {
	for _, have := range c.Capabilities {
		if have == cap {
			return true
		}
	}
	return false
}

// CaseForm is the PRE-FILLED form a human reviews before a case is created. It
// is what PrepareCase returns; nothing is sent anywhere until SubmitCase is
// called with the (possibly edited) form.
type CaseForm struct {
	// ConnectorID names the connector the form is for.
	ConnectorID string `json:"connector_id"`
	// Title is the pre-filled case title.
	Title string `json:"title"`
	// Description is Correlix's problem statement — evidence-only, every claim
	// carrying an evidence id.
	Description string `json:"description"`
	// Severity is the vendor/ITSM severity, pre-filled from the incident.
	Severity string `json:"severity"`
	// Product, SerialNumber and ContractID are the vendor-entitlement fields. A
	// blank one is a field the operator must fill; Correlix does not guess.
	Product      string `json:"product,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	ContractID   string `json:"contract_id,omitempty"`
	// ContactName / ContactEmail must be a NAMED HUMAN (Juniper requires it and
	// every other vendor prefers it). Correlix pre-fills from the acting
	// principal and never substitutes a shared identity.
	ContactName  string `json:"contact_name,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	// ExistingCaseNumber is the SR / case / issue this bundle attaches to, for
	// the ATTACH-TO-EXISTING connectors (Cisco CXD, an Arista email thread's
	// reference id). It is a case reference, not a credential: non-secret,
	// serialized, and shown in the form.
	ExistingCaseNumber string `json:"existing_case_number,omitempty"`
	// BundleName is the bundle that will be attached (or referenced).
	BundleName string `json:"bundle_name"`
	// BundleBytes is its size, so the UI can say up front whether it fits.
	BundleBytes int64 `json:"bundle_bytes"`
	// Profile is the bundle profile chosen for this connector.
	Profile BundleProfile `json:"profile"`
	// Fields the operator MUST complete before submit is allowed. A connector
	// that needs `existing_case_number` or an upload credential names them here,
	// so the UI can disable submit WITH A REASON rather than failing at the
	// vendor.
	MissingFields []string `json:"missing_fields,omitempty"`
	// MissingRequired is the same refusal in STRUCTURED form: each field with
	// the vendor's reason and where it is set, so the confirmation screen can
	// link the operator straight to the settings page that fixes it instead of
	// printing a sentence they have to decode.
	MissingRequired []RequiredField `json:"missing_required,omitempty"`
	// MissingNote is the one-sentence rendering of MissingRequired, in the
	// vendor's own terms. Empty when nothing is missing.
	MissingNote string `json:"missing_note,omitempty"`
	// PortalText is the paste-ready case text for connectors with no create
	// capability. It is always populated — even for an API connector — so an
	// operator always has a path that does not depend on an integration.
	PortalText string `json:"portal_text"`
	// PortalURL is where to paste it, when the vendor publishes one.
	PortalURL string `json:"portal_url,omitempty"`
}

// CaseResult is the outcome of a submitted case.
type CaseResult struct {
	ConnectorID string `json:"connector_id"`
	CaseID      string `json:"case_id,omitempty"`
	CaseURL     string `json:"case_url,omitempty"`
	Status      string `json:"status,omitempty"`
	Attached    bool   `json:"attached"`
	// AttachNote records honestly why an attachment did not happen (too large
	// for this connector, connector cannot attach, operator chose link-only).
	AttachNote  string    `json:"attach_note,omitempty"`
	SubmittedAt time.Time `json:"submitted_at"`
	// PortalText is echoed back when the connector could not create the case, so
	// the operator's next action is one copy away rather than a dead end.
	PortalText string `json:"portal_text,omitempty"`
	// ThreadSubject is the EXACT subject line the connector put on the wire when
	// it opened this case, on the one path where the case number arrives later,
	// in the vendor's reply, rather than in the create response.
	//
	// It is the only thing that ties that reply to THIS case, so it is carried
	// back with the result and kept on the case record. It never crosses the
	// wire: it is process state for the number lookup, not a fact about the case
	// that any client needs.
	ThreadSubject string `json:"-"`
}

// CaseHandle identifies ONE case to a status read.
//
// It is a struct rather than a bare case id because a case OPENED BY EMAIL has
// no id at all until the vendor answers, and the only way to tell that vendor's
// reply from every other reply in the tenant's mailbox is the message Correlix
// actually sent: its exact subject, and when it went. A read that carries only
// "some case at this tenant" can do no better than return the newest reply in
// the mailbox, which is how two cases end up sharing one number.
type CaseHandle struct {
	// CaseID is the vendor's own number. It is EMPTY on a case whose number has
	// not arrived yet, which is exactly when the reply read matters.
	CaseID string
	// ThreadSubject is the subject line the create put on the wire.
	ThreadSubject string
	// OpenedAt is when it went. A reply cannot predate the message it answers.
	OpenedAt time.Time
}

// CaseSecrets carries the WRITE-ONLY, per-case credential an attach-to-existing
// path needs — Cisco CXD's per-SR upload token and the host it was issued for.
//
// It is a SEPARATE TYPE rather than two more string fields on CaseForm for one
// reason: a form is rendered, echoed and logged, and a credential must be none
// of those things. Every way Go has of turning a value into text is overridden
// here to yield a redaction mark — Stringer, GoStringer, encoding/json and
// log/slog — so a CaseRequest can still be logged whole (which the audit trail
// does) without the token ever appearing. It is never persisted: the token is
// ephemeral, minted by the vendor's portal for one case, used immediately.
//
// A connector that can fetch the credential from the tenant's own sealed
// configuration should do that instead and leave this empty.
type CaseSecrets struct {
	// UploadToken is the per-case credential the operator copied from the
	// vendor's portal (Cisco SCM issues one per SR).
	UploadToken string
	// UploadHost is the host that token was issued for, when the vendor names
	// one. A connector MUST validate it against its own allowlist rather than
	// trusting it.
	UploadHost string
}

// Empty reports a secrets block that carries nothing.
func (s CaseSecrets) Empty() bool { return s.UploadToken == "" && s.UploadHost == "" }

// String implements fmt.Stringer so %v and %s redact.
func (CaseSecrets) String() string { return caseSecretsMark }

// GoString implements fmt.GoStringer so %#v redacts.
func (CaseSecrets) GoString() string { return caseSecretsMark }

// MarshalJSON makes the value unserialisable as anything but a mark, so a
// struct carrying it can be marshalled into an audit record safely.
func (CaseSecrets) MarshalJSON() ([]byte, error) { return []byte(`"` + caseSecretsMark + `"`), nil }

// LogValue implements slog.LogValuer so structured logging redacts too.
func (CaseSecrets) LogValue() slog.Value { return slog.StringValue(caseSecretsMark) }

const caseSecretsMark = "[REDACTED]"

// CaseRequest is everything a connector needs. It carries IDS and a FILE PATH,
// never the bundle bytes: the connector streams the file rather than receiving
// it, so this struct cannot become a way to move evidence through the audit
// trail.
//
// It is SAFE TO LOG WHOLE. The one field that can carry a credential, Secrets,
// redacts itself under every rendering Go has — that is why the credential is a
// typed value here rather than two more strings on the form.
type CaseRequest struct {
	// TenantID is the OWNING tenant, stamped upstream from the resolved
	// incident/device — never from a request body (§3a.2).
	TenantID string
	// IncidentID is the escalation's subject.
	IncidentID string
	// ClassID is the issue class the escalation was classified as.
	ClassID string
	// DeviceID / Hostname / Platform identify the subject device.
	DeviceID string
	Hostname string
	Platform string
	// Form is the human-reviewed form (PrepareCase's output, possibly edited).
	Form CaseForm
	// BundlePath is the on-disk path of the redacted bundle to attach. It is
	// inside the tenant's own bundle directory; a connector must not accept a
	// path from anywhere else.
	BundlePath string
	// Actor is the authenticated principal performing the action, for the audit
	// record and for the vendor's named-human requirement.
	Actor string
	// Secrets carries the ephemeral per-case upload credential for the
	// attach-to-existing connectors. It redacts itself in every rendering; see
	// CaseSecrets. Empty for every other path.
	Secrets CaseSecrets
}

// CaseOpener is the connector seam. Implementations live in internal/ticketing
// (ServiceNow, Jira, email, Cisco CXD + Smart Bonding, Juniper createsr) and are
// injected; this package ships ONLY PortalTextOpener, so the feature is complete
// and honest with no integration configured at all.
//
// Every method takes a context and MUST honour its deadline (§9). Every method
// is idempotent where the protocol allows it, and returns a typed error the
// caller can classify rather than a string to match on.
type CaseOpener interface {
	// Info declares what this connector is and can do, for THIS tenant (the
	// Configured flag is tenant-specific).
	Info(ctx context.Context, tenantID string) ConnectorInfo
	// PrepareCase returns the pre-filled form. It performs NO remote write. A
	// connector may consult its own configuration to fill product/contract
	// fields; it must leave a field it cannot establish BLANK and name it in
	// MissingFields rather than guessing.
	PrepareCase(ctx context.Context, req CaseRequest) (CaseForm, error)
	// SubmitCase performs the human-approved action: create the case (where
	// CapCreate is claimed), attach the bundle (where CapAttach is claimed and
	// the bundle fits), and return the id/URL. A connector without CapCreate
	// returns a CaseResult carrying PortalText and no CaseID — that is a
	// SUCCESSFUL outcome, not an error.
	SubmitCase(ctx context.Context, req CaseRequest) (CaseResult, error)
	// PollStatus reads a case's current status back. Connectors without
	// CapPollStatus return ErrCapabilityUnsupported.
	//
	// It takes the whole CaseHandle rather than a case id: a case with no number
	// yet is identified only by the message that opened it, and a connector that
	// cannot tell one such case from another must not answer for either.
	PollStatus(ctx context.Context, tenantID string, h CaseHandle) (CaseResult, error)
}

var (
	// ErrCapabilityUnsupported is the honest refusal when a connector is asked
	// for something its capability matrix does not claim.
	ErrCapabilityUnsupported = errors.New("tac: this connector does not support that action")
	// ErrConnectorNotConfigured is the honest refusal when a tenant has not
	// provided credentials. It is a 409/precondition condition for the caller,
	// never a silent fallback to another connector.
	ErrConnectorNotConfigured = errors.New("tac: this connector is not configured for this tenant")
	// ErrAttachmentTooLarge is returned when the bundle exceeds the connector's
	// declared ceiling and no smaller profile was requested.
	ErrAttachmentTooLarge = errors.New("tac: bundle exceeds this connector's attachment limit")
	// ErrFormIncomplete is returned by SubmitCase when a required field the
	// vendor demands is still blank.
	ErrFormIncomplete = errors.New("tac: the case form is incomplete")
)

// ProfileForConnector picks the bundle profile a connector needs from its
// declared limit. It is the single place that decision is made, so an
// email-class connector and an API connector cannot drift apart.
func ProfileForConnector(info ConnectorInfo) BundleProfile {
	switch {
	case !info.Can(CapAttach) || info.MaxAttachmentBytes <= 0:
		return ProfileLinkOnly
	case info.MaxAttachmentBytes <= EmailProfileMaxBytes:
		return ProfileEmail
	default:
		return ProfileFull
	}
}
