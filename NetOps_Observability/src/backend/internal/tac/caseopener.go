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
	// Note is the honest one-line explanation shown beside a connector that is
	// unconfigured or capability-limited ("Fortinet has no case-creation API —
	// portal text only").
	Note string `json:"note,omitempty"`
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
	PollStatus(ctx context.Context, tenantID, caseID string) (CaseResult, error)
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
