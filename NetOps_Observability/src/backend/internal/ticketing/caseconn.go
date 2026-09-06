// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn.go — the TAC case-opening connector port (escalation pack W2).
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md §4, corrected by
// docs/design/TAC_CASE_OPENING_RESEARCH_2026-09-05.md §6 (the capability matrix).
// Every vendor fact encoded here carries its citation in the file that uses it;
// nothing is inferred. Where a vendor publishes no programmatic path the
// connector says so through Caps rather than degrading silently — the research's
// "explicit honesty rule".
//
// This interface is deliberately the SHAPE of internal/tac's CaseOpener (owned
// by W1). It lives here because ratchet 208 keeps the connector implementations
// under internal/ticketing; internal/tac adapts to it with a one-line wrapper
// (see caseconn_registry.go, "ADAPTER POINT FOR W1"). Keeping our own port also
// means internal/ticketing never imports internal/tac, so there is no cycle and
// no cross-domain call (CLAUDE.md §2).
//
// ZERO TRUST (§3): every connector validates its own config, refuses hosts
// outside its pinned allowlist, bounds request and response bodies, applies a
// timeout to every call, and never puts a credential into an error, a log field
// or an audit row.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Caps declares what a connector can actually do. The UI renders only what is
// declared — an undeclared capability is never attempted.
// Source: TAC_CASE_OPENING_RESEARCH_2026-09-05.md §6.
type Caps struct {
	Create   bool `json:"create"`
	Attach   bool `json:"attach"`
	Poll     bool `json:"poll"`
	Webhook  bool `json:"webhook"`
	Note     bool `json:"note"`
	Escalate bool `json:"escalate"`
	Close    bool `json:"close"`
	// AttachToExistingOnly is a first-class mode, not a degraded create:
	// Cisco-CXD and Arista-email are genuinely useful in it (research §6).
	AttachToExistingOnly bool `json:"attach_to_existing_only"`
	// MaxAttachBytes is the documented per-file ceiling; 0 means "no documented
	// limit" (Cisco CXD, Juniper), NOT "unbounded by us" — see AttachLimit.
	MaxAttachBytes      int64    `json:"max_attach_bytes"`
	RequiresEntitlement bool     `json:"requires_entitlement"`
	SeverityValues      []string `json:"severity_values,omitempty"`
	// PortalURL + RequiredFields are populated by portal-only connectors so the
	// UI can render an honest "not automatable, here is what the portal asks
	// for" state instead of an Open-case button (research §4 Tier 3, §7).
	PortalURL      string   `json:"portal_url,omitempty"`
	RequiredFields []string `json:"required_fields,omitempty"`
	// Notes is operator-facing prose explaining the mode. Never templated into
	// a request; display only.
	Notes string `json:"notes,omitempty"`
}

// CaseRef identifies a vendor/ITSM case. ID is the connector's canonical handle
// (ServiceNow sys_id, Jira issue key, Cisco SR number, Juniper SR number);
// Number is the operator-visible one when it differs.
type CaseRef struct {
	ID     string `json:"id"`
	Number string `json:"number,omitempty"`
	URL    string `json:"url,omitempty"`
	// UploadHost/UploadToken carry an EPHEMERAL, per-case upload credential a
	// create response handed back (Cisco Smart Bonding Field80/Field81). They are
	// never persisted and never logged — the caller passes them straight into the
	// matching attach call and drops them.
	UploadHost  string `json:"-"`
	UploadToken string `json:"-"`
}

// CaseRequest is the connector-neutral case body. Vendor-specific identifiers
// live in Fields, keyed by the vendor's OWN documented field name, so no
// connector has to invent one. Text caps are enforced per connector
// (Juniper: problemDescription 15000 / synopsis 250 — research §1).
type CaseRequest struct {
	Synopsis    string `json:"synopsis"`
	Description string `json:"description"`
	// Severity is the vendor's OWN vocabulary value (research §2), already
	// mapped and confirmed by a human in the case form. Connectors do not
	// translate a Correlix severity here.
	Severity string `json:"severity"`
	// ContactName/ContactEmail/ContactPhone: Juniper requires a real person,
	// never an alias (research §4.5, §7).
	ContactName  string `json:"contact_name"`
	ContactEmail string `json:"contact_email"`
	ContactPhone string `json:"contact_phone,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	// IdempotencyKey becomes the vendor's caller-generated unique transaction id
	// (Cisco + Juniper customerUniqueTransactionID). A repeat is an update, not a
	// second case (research §8.5).
	IdempotencyKey string            `json:"idempotency_key"`
	Fields         map[string]string `json:"fields,omitempty"`
	// Approval records the human who approved this create. Case creation is
	// never an autonomous engine output (research §8.7, design §4).
	Approval Approval `json:"approval"`
}

// Approval is the human-in-the-loop proof carried into every create.
type Approval struct {
	Actor      string    `json:"actor"`
	ApprovedAt time.Time `json:"approved_at"`
}

// Valid reports whether a human actually approved this create.
func (a Approval) Valid() bool {
	return strings.TrimSpace(a.Actor) != "" && !a.ApprovedAt.IsZero()
}

// Bundle is the redacted evidence archive to attach. Open is called at most
// once per attempt so a retry re-reads from source rather than buffering
// hundreds of MB (§9 bounded memory).
type Bundle struct {
	Name        string                        `json:"name"`
	ContentType string                        `json:"content_type"`
	Size        int64                         `json:"size"`
	SHA256      string                        `json:"sha256"`
	Open        func() (io.ReadCloser, error) `json:"-"`
}

// AttachResult is what the vendor said about the stored file.
type AttachResult struct {
	ID        string    `json:"id,omitempty"`
	URL       string    `json:"url,omitempty"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256,omitempty"`
	At        time.Time `json:"at"`
	Transport string    `json:"transport"` // servicenow|jira|cisco-cxd|juniper-s3|email
}

// RemoteCase is the poll result. StatusTracked=false is honest: the connector
// has no poll capability, so the case link is the only status surface
// (research §6, "Poll absence").
type RemoteCase struct {
	ID        string    `json:"id"`
	Number    string    `json:"number,omitempty"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
	URL       string    `json:"url,omitempty"`
}

// CaseConnector is the port. It is the shape of internal/tac.CaseOpener.
type CaseConnector interface {
	// Name is the registry id (see caseconn_registry.go).
	Name() string
	// Capabilities is a pure declaration — no I/O, safe to call per render.
	Capabilities() Caps
	// ValidateConfig checks one tenant's configuration without calling the
	// vendor. Returns ErrNotConfigured when the tenant has not opted in.
	ValidateConfig(cfg TACConnectorConfig) error
	CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error)
	AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error)
	FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error)
	AddNote(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, note string) error
}

// ── typed outcomes ──────────────────────────────────────────────────────────

var (
	// ErrNotConfigured: the tenant has not opted this connector in. Not a failure.
	ErrNotConfigured = errors.New("tac connector: not configured for this tenant")
	// ErrUnsupported: the capability is declared false. The UI should never have
	// offered it; returning it is the fail-closed backstop.
	ErrUnsupported = errors.New("tac connector: capability not supported")
	// ErrNotOnboarded: the vendor requires a per-customer onboarding project that
	// this tenant has not completed (Cisco Smart Bonding, Juniper). Research §8.3.
	ErrNotOnboarded = errors.New("tac connector: vendor onboarding not complete")
	// ErrNotApproved: no human approved the create. Research §8.7.
	ErrNotApproved = errors.New("tac connector: case creation requires explicit human approval")
	// ErrTenantNotFound is the cross-tenant answer: never reveal another
	// tenant's row exists (CLAUDE.md §3a.1 — the caller maps this to 404).
	ErrTenantNotFound = errors.New("tac connector config: not found")
)

// AttachTooLargeError is a first-class outcome, not a transport failure: the
// bundle exceeds the path's documented ceiling, so the caller degrades to a
// smaller profile or link-only rather than retrying (research §8.2).
type AttachTooLargeError struct {
	Transport string
	Size      int64
	Limit     int64
	Advice    string
}

func (e AttachTooLargeError) Error() string {
	return fmt.Sprintf("%s: bundle is %d bytes, above the %d-byte limit for this path: %s",
		e.Transport, e.Size, e.Limit, e.Advice)
}

// EntitlementError carries the vendor's VERBATIM refusal (expired contract, no
// contract, warranty-only). Surfaced as-is: a generic failure here wastes the
// operator's time (research §8.1).
type EntitlementError struct {
	Vendor    string
	Code      string
	VendorMsg string
}

func (e EntitlementError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s entitlement check failed (%s): %s", e.Vendor, e.Code, Truncate(e.VendorMsg, 400))
	}
	return fmt.Sprintf("%s entitlement check failed: %s", e.Vendor, Truncate(e.VendorMsg, 400))
}

// AttachLimit resolves the ceiling actually enforced for one attach. A declared
// 0 ("no documented limit") still gets a hard local guard so a runaway bundle
// cannot be streamed forever (§9 bounded IO).
func (c Caps) AttachLimit() int64 {
	if c.MaxAttachBytes > 0 {
		return c.MaxAttachBytes
	}
	return NoDocumentedLimitGuard
}

// NoDocumentedLimitGuard bounds the paths whose vendors publish no size cap
// (Cisco CXD "No limit", Juniper "sizeInBytes unvalidated"). 8 GiB is far above
// any show-tech-support and far below "unbounded".
const NoDocumentedLimitGuard int64 = 8 << 30

// checkBundle is the shared pre-flight every attach runs before opening a byte.
func checkBundle(transport string, b Bundle, limit int64, advice string) error {
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("%s: bundle name is required", transport)
	}
	if b.Open == nil {
		return fmt.Errorf("%s: bundle has no reader", transport)
	}
	if b.Size <= 0 {
		return fmt.Errorf("%s: bundle size must be known before upload", transport)
	}
	if b.Size > limit {
		return AttachTooLargeError{Transport: transport, Size: b.Size, Limit: limit, Advice: advice}
	}
	return nil
}
